package fedauth

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"go.mau.fi/util/jsontime"
	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/id"
)

func TestVerifyRejectsBadHeaders(t *testing.T) {
	v := New("example.com", Options{})

	cases := []struct {
		name string
		auth string
	}{
		{"no header at all", ""},
		{"not X-Matrix", "Bearer abcdef"},
		{"missing origin", `X-Matrix destination="example.com",key="ed25519:a",sig="AAAA"`},
		{"missing signature", `X-Matrix origin="remote.example",destination="example.com",key="ed25519:a"`},
		{"missing key id", `X-Matrix origin="remote.example",destination="example.com",sig="AAAA"`},
		// A request addressed to a different homeserver must be refused, or a
		// signature made for another server would be replayable against us.
		{"wrong destination", `X-Matrix origin="remote.example",destination="other.example",key="ed25519:a",sig="AAAA"`},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "http://example.com/_matrix/federation/v1/state_ids/%21r%3Aex", nil)
			if err != nil {
				t.Fatal(err)
			}
			if tc.auth != "" {
				req.Header.Set("Authorization", tc.auth)
			}

			res := v.Verify(req)
			if res.OK() {
				t.Fatalf("Verify accepted %q", tc.auth)
			}
			if res.Origin != "" {
				t.Errorf("Origin = %q on a failed verification, want empty", res.Origin)
			}
			if res.Status() < 400 {
				t.Errorf("Status() = %d, want a client error", res.Status())
			}
		})
	}
}

func TestResultStatus(t *testing.T) {
	if got := (Result{}).Status(); got != http.StatusOK {
		t.Errorf("successful Status() = %d, want 200", got)
	}
	if !(Result{}).OK() {
		t.Error("a Result with no error should be OK")
	}
}

func TestServerName(t *testing.T) {
	if got := New("example.com", Options{}).ServerName(); got != "example.com" {
		t.Errorf("ServerName() = %q, want example.com", got)
	}
}

// keyServerTransport answers a key fetch with a response we control, so the
// freshly-fetched path can be exercised — which is the path the production bug
// was on. Anything else 404s, which makes the client fall back to the plain
// hostname rather than following a well-known.
type keyServerTransport struct {
	body    []byte
	fetched int
}

func (k *keyServerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	reply := func(code int, body []byte) (*http.Response, error) {
		return &http.Response{
			StatusCode: code,
			Body:       io.NopCloser(bytes.NewReader(body)),
			Header:     http.Header{"Content-Type": []string{"application/json"}},
			Request:    r,
		}, nil
	}
	if strings.Contains(r.URL.Path, "/_matrix/key/v2/server") {
		k.fetched++
		return reply(http.StatusOK, k.body)
	}
	return reply(http.StatusNotFound, []byte(`{}`))
}

// signedKeyResponse builds a self-signed key response with an explicit
// valid_until_ts. valid_until_ts is covered by the self-signature, so it has to
// be re-signed after changing it or the response would be rejected for the
// wrong reason.
func signedKeyResponse(t *testing.T, key *federation.SigningKey, serverName string, validUntil time.Time) []byte {
	t.Helper()
	resp := key.GenerateKeyResponse(serverName, nil)
	resp.ValidUntilTS = jsontime.UM(validUntil)
	resp.Signatures = nil
	signature, err := key.SignJSON(resp)
	if err != nil {
		t.Fatal(err)
	}
	resp.Signatures = map[string]map[id.KeyID]string{serverName: {key.ID: signature}}
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// storeKeyResponse caches a self-signed key response with an explicit
// valid_until_ts, round-tripped through JSON because self-signature
// verification checks the raw bytes as received.
func storeKeyResponse(t *testing.T, v *Verifier, key *federation.SigningKey, serverName string, validUntil time.Time) {
	t.Helper()
	var parsed federation.ServerKeyResponse
	if err := json.Unmarshal(signedKeyResponse(t, key, serverName, validUntil), &parsed); err != nil {
		t.Fatal(err)
	}
	v.auth.Keys.StoreKeys(&parsed)
}

// A key past its own valid_until_ts must be refused, even though its
// self-signature is perfectly good and it was just fetched from the origin.
//
// mautrix checks valid_until_ts when *loading* keys from its cache, but
// GetKeysWithCache returns a freshly fetched response without that check — so a
// server publishing an already-expired key is accepted. Synapse refuses it
// (verify_json_for_server passes `now` as the minimum validity), and so must
// we: a key's expiry is the whole mechanism behind rotation, so honouring a
// signature from an expired key means a leaked key never stops working.
//
// Found in production 2026-08-25: ryuu.eu publishes ed25519:a_EMUw with a
// valid_until_ts of 2025-12-23. Synapse answered 401 after 32s of failing to
// find a usable key; we accepted the request in under a millisecond.
func TestExpiredPublishedKeyIsRejected(t *testing.T) {
	for _, tc := range []struct {
		name       string
		validUntil time.Duration
	}{
		{"valid for another hour", time.Hour},
		{"expired an hour ago", -time.Hour},
		{"expired eight months ago", -8 * 30 * 24 * time.Hour},
	} {
		wantOK := tc.validUntil > 0
		t.Run(tc.name, func(t *testing.T) {
			v := New("example.com", Options{})
			req, key := signedRequest(t, "remote.example", "example.com")

			ks := &keyServerTransport{
				body: signedKeyResponse(t, key, "remote.example", time.Now().Add(tc.validUntil)),
			}
			v.auth.Client.HTTP = &http.Client{Transport: ks}

			res := v.Verify(req)
			if ks.fetched == 0 {
				t.Fatal("the key was never fetched; this test is not exercising the fetch path")
			}
			if res.OK() != wantOK {
				t.Errorf("Verify OK = %v, want %v (err: %v)", res.OK(), wantOK, res.Err)
			}
		})
	}
}

// The expiry check must not form a second opinion about *which* key signed the
// request — only about whether the origin's published key response is still
// valid. Authenticate already settled the signature.
//
// This matters because an earlier version called HasKey, which looks only at
// verify_keys and ignores old_verify_keys. Synapse honours a rotated key until
// its expired_ts, so that version would have rejected legitimate traffic from
// any server that had recently rotated.
func TestExpiryCheckIgnoresWhichKeyWasUsed(t *testing.T) {
	v := New("example.com", Options{})
	_, key := signedRequest(t, "remote.example", "example.com")

	// A perfectly valid published response, cached.
	storeKeyResponse(t, v, key, "remote.example", time.Now().Add(time.Hour))

	// A header naming some other key id, as a rotated key would.
	const rotated = `X-Matrix origin="remote.example",destination="example.com",key="ed25519:rotated",sig="AAAA"`
	if respErr := v.requireCurrentlyValidKey(rotated); respErr != nil {
		t.Errorf("rejected because of the key id rather than the expiry: %v", respErr)
	}

	// But an expired response is still refused, whatever key is named.
	v2 := New("example.com", Options{})
	storeKeyResponse(t, v2, key, "remote.example", time.Now().Add(-time.Hour))
	if respErr := v2.requireCurrentlyValidKey(rotated); respErr == nil {
		t.Error("an expired key response was accepted")
	}
}
