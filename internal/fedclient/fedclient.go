// Package fedclient builds the signed federation client outbound requests
// use: server discovery and X-Matrix signing from mautrix, plus what Synapse
// sends that mautrix does not.
package fedclient

import (
	"fmt"
	"net/http"
	"time"

	"go.mau.fi/util/exhttp"
	"maunium.net/go/mautrix/federation"
)

// New builds a client signing as serverName with a Synapse-format key line
// ("ed25519 <version> <seed>"). allow, when not nil, is
// federation_domain_whitelist: Synapse refuses any other destination.
func New(serverName, keyLine string, allow func(string) bool, timeout time.Duration) (*federation.Client, error) {
	key, err := federation.ParseSynapseKey(keyLine)
	if err != nil {
		return nil, fmt.Errorf("fedclient: signing key: %w", err)
	}
	settings := exhttp.SensibleClientSettings
	settings.GlobalTimeout = timeout
	c := federation.NewClient(serverName, key, federation.NewInMemoryCache(), settings)
	// mautrix sets no Content-Type; Synapse sends application/json, and
	// some servers refuse a body without it (400, then M_FORBIDDEN).
	c.HTTP.Transport = &JSONContentType{Next: c.HTTP.Transport}
	c.AllowServer = allow
	c.UserAgent = "goinbound-worker"
	return c, nil
}

// JSONContentType adds Content-Type: application/json to requests with a body.
type JSONContentType struct{ Next http.RoundTripper }

func (t *JSONContentType) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil && req.Header.Get("Content-Type") == "" {
		req = req.Clone(req.Context())
		req.Header.Set("Content-Type", "application/json")
	}
	return t.Next.RoundTrip(req)
}
