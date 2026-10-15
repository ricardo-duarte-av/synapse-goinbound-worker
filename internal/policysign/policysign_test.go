package policysign

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"maunium.net/go/mautrix/crypto/canonicaljson"
	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/federation/signutil"
	"maunium.net/go/mautrix/id"
)

// rewrite sends every request to the test server, keeping its path.
type rewrite struct{ to *url.URL }

func (r rewrite) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme, req.URL.Host = r.to.Scheme, r.to.Host
	return http.DefaultTransport.RoundTrip(req)
}

func TestSign(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	keyLine := "ed25519 a_test " + base64.RawStdEncoding.EncodeToString(priv.Seed())
	event := json.RawMessage(`{"type":"m.room.message","content":{"body":"<b>&</b>"}}`)

	var stable func(w http.ResponseWriter)
	var unstableHit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			// Some policy servers refuse the body without it.
			t.Errorf("Content-Type %q", ct)
		}
		xma := federation.ParseXMatrixAuth(r.Header.Get("Authorization"))
		if xma.Origin != "us.example" || xma.Destination != "policy.example" || xma.KeyID != "ed25519:a_test" {
			t.Errorf("X-Matrix header %+v", xma)
		}
		// The signed object Synapse's federation client signs.
		signed := map[string]any{"method": r.Method, "uri": r.URL.RequestURI(), "origin": xma.Origin,
			"destination": xma.Destination, "content": json.RawMessage(body)}
		b, _ := canonicaljson.Marshal(signed)
		if err := signutil.VerifyJSONCanonical(id.SigningKey(base64.RawStdEncoding.EncodeToString(pub)), xma.Signature, b); err != nil {
			t.Errorf("X-Matrix signature does not verify: %v", err)
		}
		switch r.URL.Path {
		case "/_matrix/policy/v1/sign":
			stable(w)
		case "/_matrix/policy/unstable/org.matrix.msc4284/sign":
			unstableHit = true
			w.Write([]byte(`{"policy.example":{"ed25519:policy_server":"from-unstable"}}`))
		default:
			t.Errorf("path %s", r.URL.Path)
		}
	}))
	defer srv.Close()
	to, _ := url.Parse(srv.URL)

	c, err := New("us.example", keyLine, nil)
	if err != nil {
		t.Fatal(err)
	}
	c.fed.HTTP.Transport.(*jsonContentType).next = rewrite{to}
	ctx := context.Background()

	stable = func(w http.ResponseWriter) {
		w.Write([]byte(`{"policy.example":{"ed25519:policy_server":"sig"}}`))
	}
	if sigs, err := c.Sign(ctx, "policy.example", event); err != nil || sigs["ed25519:policy_server"] != "sig" {
		t.Errorf("signed: %v, %v", sigs, err)
	}

	stable = func(w http.ResponseWriter) {
		w.WriteHeader(404)
		w.Write([]byte(`{"errcode":"M_UNRECOGNIZED"}`))
	}
	if sigs, err := c.Sign(ctx, "policy.example", event); err != nil || sigs["ed25519:policy_server"] != "from-unstable" || !unstableHit {
		t.Errorf("fallback: %v, %v", sigs, err)
	}

	for name, answer := range map[string]func(http.ResponseWriter){
		"forbidden":    func(w http.ResponseWriter) { w.WriteHeader(403); w.Write([]byte(`{"errcode":"M_FORBIDDEN"}`)) },
		"empty answer": func(w http.ResponseWriter) { w.Write([]byte(`{}`)) },
	} {
		stable, unstableHit = answer, false
		_, err := c.Sign(ctx, "policy.example", event)
		var ref *Refused
		if !errors.As(err, &ref) || unstableHit {
			t.Errorf("%s: %v (unstable asked: %v)", name, err, unstableHit)
		}
	}

	// federation_domain_whitelist.
	c2, _ := New("us.example", keyLine, func(string) bool { return false })
	if _, err := c2.Sign(ctx, "policy.example", event); err == nil {
		t.Error("a destination off the whitelist was asked")
	}
}

func TestUnknownEndpoint(t *testing.T) {
	for _, c := range []struct {
		status int
		body   string
		want   bool
	}{
		{404, ``, true}, {404, `<html>`, true}, {405, `{"errcode":"M_UNRECOGNIZED"}`, true},
		{404, `{"errcode":"M_NOT_FOUND"}`, false}, {400, `{"errcode":"M_UNRECOGNIZED"}`, true},
		{400, `{"errcode":"M_BAD_JSON"}`, false}, {403, ``, false},
	} {
		if got := unknownEndpoint(c.status, []byte(c.body)); got != c.want {
			t.Errorf("%d %s: %v", c.status, c.body, got)
		}
	}
}
