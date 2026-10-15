package keyring

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"maunium.net/go/mautrix/crypto/canonicaljson"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
)

// keyResponse is a /_matrix/key/v2/server body for server, signed by priv.
func keyResponse(t *testing.T, server, kid string, priv ed25519.PrivateKey, validUntil int64) json.RawMessage {
	t.Helper()
	body := map[string]any{
		"server_name":     server,
		"valid_until_ts":  validUntil,
		"verify_keys":     map[string]any{kid: map[string]string{"key": base64.RawStdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey))}},
		"old_verify_keys": map[string]any{},
	}
	canon, _ := canonicaljson.Marshal(body)
	body["signatures"] = map[string]any{server: map[string]string{kid: base64.RawStdEncoding.EncodeToString(ed25519.Sign(priv, canon))}}
	b, _ := json.Marshal(body)
	return b
}

func TestKeyring(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	now := time.UnixMilli(1_000_000_000)
	var notaryHits, directHits atomic.Int32
	notaryAnswers := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/_matrix/key/v2/query":
			notaryHits.Add(1)
			if !notaryAnswers {
				w.Write([]byte(`{"server_keys":[]}`))
				return
			}
			w.Write([]byte(`{"server_keys":[` + string(keyResponse(t, "origin.example", "ed25519:a", priv, now.UnixMilli()+3600_000)) + `]}`))
		case r.URL.Path == "/_matrix/key/v2/server":
			directHits.Add(1)
			w.Write(keyResponse(t, "origin.example", "ed25519:a", priv, now.UnixMilli()+7200_000))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()
	to, _ := url.Parse(srv.URL)

	var held map[string]pdu.VerifyKey
	db := func(context.Context, string, []string) (map[string]pdu.VerifyKey, error) { return held, nil }
	k := New("us.example", db, []string{"notary.example"})
	k.now = func() time.Time { return now }
	k.fed.HTTP.Transport = rewrite{to}
	fetch := k.Fetch(context.Background())

	// Held and valid: nothing fetched.
	held = map[string]pdu.VerifyKey{"ed25519:a": {Key: priv.Public().(ed25519.PublicKey), ValidUntilMS: now.UnixMilli() + 10}}
	got, _ := fetch("origin.example", []string{"ed25519:a"}, now.UnixMilli())
	if got["ed25519:a"].ValidUntilMS != now.UnixMilli()+10 || notaryHits.Load() != 0 {
		t.Fatalf("held: %v, notary hits %d", got, notaryHits.Load())
	}
	// Held but not valid long enough: the notary's is.
	got, _ = fetch("origin.example", []string{"ed25519:a"}, now.UnixMilli()+1000)
	if got["ed25519:a"].ValidUntilMS != now.UnixMilli()+3600_000 || directHits.Load() != 0 {
		t.Fatalf("notary: %v, direct hits %d", got, directHits.Load())
	}
	// Remembered: no new request.
	n := notaryHits.Load()
	fetch("origin.example", []string{"ed25519:a"}, now.UnixMilli()+1000)
	if notaryHits.Load() != n {
		t.Error("fetched a key it had already fetched")
	}
	// The notary has nothing: the origin is asked.
	k.mem = map[string]map[string]pdu.VerifyKey{}
	held, notaryAnswers = nil, false
	got, _ = fetch("origin.example", []string{"ed25519:a"}, now.UnixMilli())
	if got["ed25519:a"].ValidUntilMS != now.UnixMilli()+7200_000 || directHits.Load() != 1 {
		t.Fatalf("direct: %v, hits %d", got, directHits.Load())
	}
	// A key nobody has is not asked for again at once.
	d := directHits.Load()
	fetch("origin.example", []string{"ed25519:nope"}, 0)
	fetch("origin.example", []string{"ed25519:nope"}, 0)
	if directHits.Load() != d+1 {
		t.Errorf("asked %d times for a missing key", directHits.Load()-d)
	}
}

func TestProcessV2RejectsForgedKeys(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(nil)
	_, other, _ := ed25519.GenerateKey(nil)
	k := New("us.example", nil, nil)
	good := keyResponse(t, "origin.example", "ed25519:a", priv, 5)
	if _, err := k.processV2(good, "origin.example"); err != nil {
		t.Fatalf("good: %v", err)
	}
	if _, err := k.processV2(good, "else.example"); err == nil {
		t.Error("a response about another server was accepted")
	}
	// Signed with a key it does not publish.
	forged := keyResponse(t, "origin.example", "ed25519:a", priv, 5)
	forged = []byte(strings.Replace(string(forged), base64.RawStdEncoding.EncodeToString(priv.Public().(ed25519.PublicKey)),
		base64.RawStdEncoding.EncodeToString(other.Public().(ed25519.PublicKey)), 1))
	if _, err := k.processV2(forged, "origin.example"); err == nil {
		t.Error("a response whose key does not match its signature was accepted")
	}
}

type rewrite struct{ to *url.URL }

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme, req.URL.Host = r.to.Scheme, r.to.Host
	return http.DefaultTransport.RoundTrip(req)
}
