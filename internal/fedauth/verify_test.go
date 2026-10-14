package fedauth

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"go.mau.fi/util/exhttp"
	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/id"
)

// captureTransport intercepts an outgoing request instead of sending it, so a
// genuinely signed federation request can be built without any network.
type captureTransport struct{ req *http.Request }

func (c *captureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	c.req = r
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(strings.NewReader("{}")),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Request:    r,
	}, nil
}

// signedRequest produces a real X-Matrix signed request from remoteServer to
// destination, using mautrix's own signing so the signature is correct by
// construction rather than by my reading of the spec.
func signedRequest(t *testing.T, remoteServer, destination string) (*http.Request, *federation.SigningKey) {
	t.Helper()

	key := federation.GenerateSigningKey()
	client := federation.NewClient(remoteServer, key, federation.NewInMemoryCache(), exhttp.SensibleClientSettings)
	ct := &captureTransport{}
	client.HTTP = &http.Client{Transport: ct}

	_, _ = client.GetStateIDs(context.Background(), destination,
		id.RoomID("!room:example.com"), id.EventID("$event"))

	if ct.req == nil {
		t.Fatal("no request was produced")
	}
	if ct.req.Header.Get("Authorization") == "" {
		t.Fatal("the produced request carries no Authorization header")
	}
	return ct.req, key
}

// trust pre-populates the key cache so verification needs no network.
//
// The response is round-tripped through JSON because self-signature
// verification checks the raw bytes as received, which only exist on a response
// that was unmarshalled. This mirrors a real key fetch.
func trust(t *testing.T, v *Verifier, serverName string, key *federation.SigningKey) {
	t.Helper()
	raw, err := json.Marshal(key.GenerateKeyResponse(serverName, nil))
	if err != nil {
		t.Fatal(err)
	}
	var parsed federation.ServerKeyResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatal(err)
	}
	v.auth.Keys.StoreKeys(&parsed)
}

func TestVerifyAcceptsGenuineSignature(t *testing.T) {
	v := New("example.com", Options{})
	req, key := signedRequest(t, "remote.example", "example.com")
	trust(t, v, "remote.example", key)

	res := v.Verify(req)
	if !res.OK() {
		t.Fatalf("a correctly signed request was rejected: %v", res.Err)
	}
	if res.Origin != "remote.example" {
		t.Errorf("Origin = %q, want remote.example", res.Origin)
	}
}

// TestVerifyRejectsTamperedURI is the point of the whole exercise. The
// signature covers the request URI, so altering the room or event being asked
// for must invalidate it. Without this, a server could take a signature it
// obtained legitimately and use it to read a different room.
func TestVerifyRejectsTamperedURI(t *testing.T) {
	cases := []struct {
		name  string
		alter func(*http.Request)
	}{
		{"different room", func(r *http.Request) {
			r.URL.Path = "/_matrix/federation/v1/state_ids/!other:example.com"
			r.URL.RawPath = ""
		}},
		{"different event", func(r *http.Request) {
			r.URL.RawQuery = "event_id=%24different"
		}},
		{"extra query parameter", func(r *http.Request) {
			r.URL.RawQuery += "&extra=1"
		}},
		{"different method", func(r *http.Request) { r.Method = http.MethodPost }},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := New("example.com", Options{})
			req, key := signedRequest(t, "remote.example", "example.com")
			trust(t, v, "remote.example", key)

			// Confirm it verifies before tampering, so a failure below is
			// really about the alteration.
			if res := v.Verify(req.Clone(context.Background())); !res.OK() {
				t.Fatalf("baseline request did not verify: %v", res.Err)
			}

			tc.alter(req)
			if res := v.Verify(req); res.OK() {
				t.Errorf("a tampered request verified: %s", tc.name)
			}
		})
	}
}

// TestVerifyRejectsWrongSigningKey covers a server presenting a signature made
// with a key it does not actually publish.
func TestVerifyRejectsWrongSigningKey(t *testing.T) {
	v := New("example.com", Options{})
	req, _ := signedRequest(t, "remote.example", "example.com")

	// Publish a different key for that server than the one which signed.
	trust(t, v, "remote.example", federation.GenerateSigningKey())

	if res := v.Verify(req); res.OK() {
		t.Error("a request signed with an unpublished key was accepted")
	}
}

// TestVerifyRejectsImpersonation covers one server's signature being presented
// as another server's.
func TestVerifyRejectsImpersonation(t *testing.T) {
	v := New("example.com", Options{})
	req, key := signedRequest(t, "remote.example", "example.com")

	// The attacker's key is published under their own name, not the victim's.
	trust(t, v, "attacker.example", key)

	if res := v.Verify(req); res.OK() && res.Origin != "remote.example" {
		t.Errorf("verification returned origin %q for a request claiming remote.example", res.Origin)
	}
}

func TestVerifyRejectsRequestForAnotherHomeserver(t *testing.T) {
	// A signature made for a different destination must not be replayable
	// against us.
	v := New("example.com", Options{})
	req, key := signedRequest(t, "remote.example", "elsewhere.example")
	trust(t, v, "remote.example", key)

	if res := v.Verify(req); res.OK() {
		t.Error("a request addressed to another homeserver was accepted")
	}
}
