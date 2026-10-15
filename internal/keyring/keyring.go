// Package keyring finds the signing keys a PDU's signatures need, as
// Synapse's Keyring does (crypto/keyring.py): what Synapse holds, then the
// trusted key servers (all at once, results merged), then the server itself,
// stopping once every key is found valid for long enough.
//
// Keys fetched here are kept in memory, not stored: Synapse stores them in
// server_signature_keys and server_keys_json and invalidates its caches over
// the replication stream, which is not ours to write. Synapse fetches and
// stores a key itself whenever it needs one, as it does today.
package keyring

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"go.mau.fi/util/exhttp"
	"go.mau.fi/util/jsontime"
	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/federation/signutil"
	"maunium.net/go/mautrix/id"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
)

// DBKeys reads the keys Synapse holds (StoreKeyFetcher).
type DBKeys func(ctx context.Context, server string, keyIDs []string) (map[string]pdu.VerifyKey, error)

// Keyring looks keys up.
type Keyring struct {
	db       DBKeys
	fed      *federation.Client
	notaries []string
	server   string
	now      func() time.Time

	mu    sync.Mutex
	mem   map[string]map[string]pdu.VerifyKey
	tried map[string]time.Time // last fetch that found nothing, per server
}

// failedRefetch is how long a server whose keys could not be found is left
// alone. Synapse has no such delay; it only spares us repeating a fetch that
// just failed, and a key not found makes the transaction Synapse's anyway.
const failedRefetch = 10 * time.Minute

// New builds a keyring for serverName, asking notaries (trusted_key_servers,
// in order) before the servers themselves.
func New(serverName string, db DBKeys, notaries []string) *Keyring {
	settings := exhttp.SensibleClientSettings
	settings.GlobalTimeout = 30 * time.Second
	fed := federation.NewClient(serverName, nil, federation.NewInMemoryCache(), settings)
	return &Keyring{db: db, fed: fed, notaries: notaries, server: serverName, now: time.Now,
		mem: map[string]map[string]pdu.VerifyKey{}, tried: map[string]time.Time{}}
}

// Fetch is pdu.KeyFetch: the keys found for server among keyIDs, each the
// longest-valid one found, looking further while any is missing or not
// valid until minValidMS.
func (k *Keyring) Fetch(ctx context.Context) pdu.KeyFetch {
	return func(server string, keyIDs []string, minValidMS int64) (map[string]pdu.VerifyKey, error) {
		return k.fetch(ctx, server, keyIDs, minValidMS)
	}
}

func (k *Keyring) fetch(ctx context.Context, server string, keyIDs []string, minValid int64) (map[string]pdu.VerifyKey, error) {
	found := map[string]pdu.VerifyKey{}
	missing := map[string]bool{}
	for _, id := range keyIDs {
		missing[id] = true
	}
	merge := func(keys map[string]pdu.VerifyKey) {
		for id, key := range keys {
			if !missing[id] && found[id].ValidUntilMS >= minValid {
				continue
			}
			if cur, ok := found[id]; ok && cur.ValidUntilMS > key.ValidUntilMS {
				continue
			}
			found[id] = key
			if key.ValidUntilMS >= minValid {
				delete(missing, id)
			}
		}
	}

	held, err := k.db(ctx, server, keyIDs)
	if err != nil {
		return nil, err
	}
	merge(held)
	k.mu.Lock()
	merge(k.mem[server])
	recent := k.now().Sub(k.tried[server]) < failedRefetch
	k.mu.Unlock()
	if len(missing) == 0 || recent || server == k.server {
		return found, nil
	}

	merge(k.fromNotaries(ctx, server, setKeys(missing), minValid))
	if len(missing) > 0 {
		merge(k.direct(ctx, server))
	}
	if len(missing) > 0 {
		k.mu.Lock()
		k.tried[server] = k.now()
		k.mu.Unlock()
	}
	return found, nil
}

// fromNotaries is PerspectivesKeyFetcher: every notary at once, results
// merged. A notary's own signature is not checked: trusted_key_servers here
// names no verify_keys, so Synapse does not check it either.
func (k *Keyring) fromNotaries(ctx context.Context, server string, keyIDs []string, minValid int64) map[string]pdu.VerifyKey {
	crit := map[id.KeyID]federation.QueryKeysCriteria{}
	for _, kid := range keyIDs {
		crit[id.KeyID(kid)] = federation.QueryKeysCriteria{MinimumValidUntilTS: msTime(minValid)}
	}
	req := &federation.ReqQueryKeys{ServerKeys: map[string]map[id.KeyID]federation.QueryKeysCriteria{server: crit}}
	var mu sync.Mutex
	out := map[string]pdu.VerifyKey{}
	var wg sync.WaitGroup
	for _, notary := range k.notaries {
		if notary == k.server {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			var resp struct {
				ServerKeys []json.RawMessage `json:"server_keys"`
			}
			_, _, err := k.fed.MakeFullRequest(ctx, federation.RequestParams{
				ServerName: notary, Method: http.MethodPost,
				Path:        federation.KeyURLPath{"v2", "query"},
				RequestJSON: req, ResponseJSON: &resp,
			})
			if err != nil {
				return
			}
			for _, raw := range resp.ServerKeys {
				keys, err := k.processV2(raw, server)
				if err != nil {
					continue
				}
				mu.Lock()
				for kid, key := range keys {
					if cur, ok := out[kid]; !ok || key.ValidUntilMS >= cur.ValidUntilMS {
						out[kid] = key
					}
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	k.remember(server, out)
	return out
}

// direct is ServerKeyFetcher: GET /_matrix/key/v2/server, 10s.
func (k *Keyring) direct(ctx context.Context, server string) map[string]pdu.VerifyKey {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	body, _, err := k.fed.MakeFullRequest(ctx, federation.RequestParams{
		ServerName: server, Method: http.MethodGet, Path: federation.KeyURLPath{"v2", "server"},
	})
	if err != nil {
		return nil
	}
	keys, err := k.processV2(body, server)
	if err != nil {
		return nil
	}
	k.remember(server, keys)
	return keys
}

func (k *Keyring) remember(server string, keys map[string]pdu.VerifyKey) {
	if len(keys) == 0 {
		return
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	m := k.mem[server]
	if m == nil {
		m = map[string]pdu.VerifyKey{}
		k.mem[server] = m
	}
	for kid, key := range keys {
		if cur, ok := m[kid]; !ok || key.ValidUntilMS >= cur.ValidUntilMS {
			m[kid] = key
		}
	}
}

// processV2 is BaseV2KeyFetcher.process_v2_response for a response about
// server: its verify_keys (valid until valid_until_ts), self-signed by one
// of them, and old_verify_keys (valid until expired_ts).
func (k *Keyring) processV2(raw []byte, server string) (map[string]pdu.VerifyKey, error) {
	var resp struct {
		ServerName   string `json:"server_name"`
		ValidUntilTS int64  `json:"valid_until_ts"`
		VerifyKeys   map[string]struct {
			Key string `json:"key"`
		} `json:"verify_keys"`
		OldVerifyKeys map[string]struct {
			Key       string `json:"key"`
			ExpiredTS int64  `json:"expired_ts"`
		} `json:"old_verify_keys"`
		Signatures map[string]map[string]string `json:"signatures"`
	}
	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, err
	}
	if resp.ServerName != server {
		return nil, errors.New("keyring: response for another server")
	}
	out := map[string]pdu.VerifyKey{}
	for kid, v := range resp.VerifyKeys {
		if b, ok := decodeKey(kid, v.Key); ok {
			out[kid] = pdu.VerifyKey{Key: b, ValidUntilMS: resp.ValidUntilTS}
		}
	}
	verified := false
	for kid := range resp.Signatures[server] {
		key, ok := out[kid]
		if !ok {
			continue
		}
		if err := signutil.VerifyJSON(server, id.KeyID(kid), id.SigningKey(base64.RawStdEncoding.EncodeToString(key.Key)), json.RawMessage(raw)); err != nil {
			return nil, err
		}
		verified = true
		break
	}
	if !verified {
		return nil, errors.New("keyring: key response not signed by the origin server")
	}
	for kid, v := range resp.OldVerifyKeys {
		if b, ok := decodeKey(kid, v.Key); ok {
			out[kid] = pdu.VerifyKey{Key: b, ValidUntilMS: v.ExpiredTS}
		}
	}
	return out, nil
}

// decodeKey is is_signing_algorithm_supported plus decoding: ed25519 keys
// only.
func decodeKey(kid, b64 string) (ed25519.PublicKey, bool) {
	if !strings.HasPrefix(kid, "ed25519:") {
		return nil, false
	}
	b, err := base64.RawStdEncoding.DecodeString(strings.TrimRight(b64, "="))
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, false
	}
	return b, true
}

func setKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func msTime(ms int64) jsontime.UnixMilli { return jsontime.UM(time.UnixMilli(ms)) }
