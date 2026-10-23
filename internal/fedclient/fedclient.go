// Package fedclient builds the signed federation client outbound requests
// use: server discovery and X-Matrix signing from mautrix, plus what Synapse
// sends that mautrix does not.
package fedclient

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptrace"
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
	c := federation.NewClient(serverName, key, federation.NewInMemoryCache(), clientSettings(timeout))
	// mautrix sets no Content-Type; Synapse sends application/json, and
	// some servers refuse a body without it (400, then M_FORBIDDEN).
	c.HTTP.Transport = &JSONContentType{Next: c.HTTP.Transport}
	c.AllowServer = allow
	c.UserAgent = "goinbound-worker"
	return c, nil
}

// clientSettings is mautrix's sensible settings for Synapse's request
// timeout: the response gets timeout, and the request as a whole twice that,
// the response's and then the body's (Attempt times each as Synapse does).
func clientSettings(timeout time.Duration) exhttp.ClientSettings {
	s := exhttp.SensibleClientSettings
	s.GlobalTimeout = 2 * timeout
	// SensibleClientSettings waits 10s for response headers, while Synapse
	// waits the request's whole timeout (30s for a policy server, 60s and
	// more for state). A policy server answering in 10-30s signed for
	// Synapse and timed out here, and as Synapse fails closed, that
	// soft-failed what Synapse accepted (2026-10-17: beta2.matrix.org,
	// asgard.chat). The headers get the request's timeout.
	s.ResponseHeaderTimeout = timeout
	return s
}

// Attempt is one request with Synapse's two timeouts: timeout until the
// response arrives (matrixfederationclient.py _send_request's
// timeout_deferred), then timeout again to read its body
// (_handle_response). One deadline over both cut off big bodies: Matrix
// HQ's /state_ids from matrix.org takes over a minute to arrive
// (2026-10-21).
func Attempt[T any](ctx context.Context, timeout time.Duration, send func(context.Context) (T, error)) (T, error) {
	actx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	t := time.AfterFunc(timeout, func() { cancel(ErrTimedOut) })
	defer t.Stop()
	trace := &httptrace.ClientTrace{GotFirstResponseByte: func() { t.Reset(timeout) }}
	return send(httptrace.WithClientTrace(actx, trace))
}

// ErrTimedOut is the cause of an Attempt's context ending on its timeout.
var ErrTimedOut = errors.New("fedclient: timed out")

// JSONContentType adds Content-Type: application/json to requests with a body.
type JSONContentType struct{ Next http.RoundTripper }

func (t *JSONContentType) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil && req.Header.Get("Content-Type") == "" {
		req = req.Clone(req.Context())
		req.Header.Set("Content-Type", "application/json")
	}
	return t.Next.RoundTrip(req)
}
