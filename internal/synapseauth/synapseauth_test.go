package synapseauth

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"maunium.net/go/mautrix/federation"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/fedclient"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
)

type rewriteTo struct{ to *url.URL }

func (r rewriteTo) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme, req.URL.Host = r.to.Scheme, r.to.Host
	return http.DefaultTransport.RoundTrip(req)
}

// signedSend makes remote.test sign a /send to local.test, as another
// homeserver would, and returns it as received.
func signedSend(t *testing.T, body string) (Request, ed25519.PublicKey) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	var got Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = FromHTTP(r, b)
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	to, _ := url.Parse(srv.URL)
	fc, err := fedclient.New("remote.test", "ed25519 r "+base64.RawStdEncoding.EncodeToString(priv.Seed()), nil, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	fc.HTTP.Transport.(*fedclient.JSONContentType).Next = rewriteTo{to}
	_, _, err = fc.MakeFullRequest(context.Background(), federation.RequestParams{
		ServerName: "local.test", Method: http.MethodPut,
		Path:         federation.URLPath{"v1", "send", "txn1"},
		Authenticate: true, RequestJSON: json.RawMessage(body),
	})
	if err != nil {
		t.Fatal(err)
	}
	return got, pub
}

func keysOf(server string, pub ed25519.PublicKey) func(context.Context) pdu.KeyFetch {
	return func(context.Context) pdu.KeyFetch {
		return func(s string, ids []string, _ int64) (map[string]pdu.VerifyKey, error) {
			if s != server || pub == nil {
				return map[string]pdu.VerifyKey{}, nil
			}
			return map[string]pdu.VerifyKey{"ed25519:r": {Key: pub, ValidUntilMS: 1 << 50}}, nil
		}
	}
}

func run(a *Authenticator, req Request) Result {
	p, res := a.Precheck(req)
	if p == nil {
		return res
	}
	return a.Verify(context.Background(), req, p, 1_700_000_000_000)
}

func TestAuthenticateAsSynapse(t *testing.T) {
	body := `{"origin":"remote.test","origin_server_ts":1,"pdus":[],"edus":[{"edu_type":"m.typing","content":{"x":"<&>é"}}]}`
	req, pub := signedSend(t, body)
	a := New("local.test", nil, keysOf("remote.test", pub))

	if res := run(a, req); res.Origin != "remote.test" || res.Answer != nil {
		t.Fatalf("a good request: %+v %+v %+v", res, res.Answer, req)
	}

	answer := func(name string, res Result, status int, errcode, msg string) {
		t.Helper()
		if res.Answer == nil || res.Answer.Status != status || res.Answer.Errcode != errcode || res.Answer.Error != msg {
			t.Errorf("%s: %+v (answer %+v), want %d %s %q", name, res, res.Answer, status, errcode, msg)
		}
	}

	forged := req
	forged.Body = []byte(strings.Replace(body, `"origin_server_ts":1`, `"origin_server_ts":2`, 1))
	answer("forged", run(a, forged), 401, "M_UNAUTHORIZED",
		"Invalid signature for server remote.test with key ed25519:r: Unable to verify signature for remote.test: "+
			"<class 'nacl.exceptions.BadSignatureError'> Signature was forged or corrupt")

	answer("no key", run(New("local.test", nil, keysOf("remote.test", nil)), req), 401, "M_UNAUTHORIZED",
		"Failed to find any key to satisfy: _FetchKeyRequest(server_name='remote.test', minimum_valid_until_ts=1700000000000, key_ids=['ed25519:r'])")

	answer("destination", run(New("other.test", nil, keysOf("remote.test", pub)), req), 401, "M_UNAUTHORIZED",
		"Destination mismatch in auth header, received: 'local.test'")

	answer("whitelist", run(New("local.test", map[string]bool{"friend.test": true}, keysOf("remote.test", pub)), req), 403, "M_FORBIDDEN",
		"Federation denied with remote.test.")

	bad := req
	bad.Body = []byte(`{"pdus":`)
	answer("not JSON", run(a, bad), 400, "M_NOT_JSON", "Content not JSON.")
	bad.Body = []byte(`[]`)
	answer("not an object", run(a, bad), 400, "M_BAD_JSON", "Content must be a JSON object.")

	none := req
	none.Auth = nil
	answer("no header", run(a, none), 401, "M_UNAUTHORIZED", "Missing Authorization headers")
	none.Auth = []string{"Bearer x"}
	answer("no X-Matrix", run(a, none), 401, "M_UNAUTHORIZED", "Missing Authorization headers")
	none.Auth = []string{"X-Matrix origin=remote.test"}
	answer("malformed", run(a, none), 400, "M_UNAUTHORIZED", "Malformed Authorization header")

	// What Python would encode differently is not judged.
	dup := req
	dup.Body = []byte(`{"pdus":[],"pdus":[]}`)
	if res := run(a, dup); res.Uncertain == "" {
		t.Errorf("duplicate keys: %+v", res)
	}
}
