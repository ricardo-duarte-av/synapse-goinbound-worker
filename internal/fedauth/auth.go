// Package fedauth verifies Matrix server-server request authentication.
//
// It wraps mautrix's federation.ServerAuth rather than reimplementing any of
// it: parsing the X-Matrix header, fetching and caching the origin server's
// published keys, and checking the ed25519 signature over the canonical JSON of
// the request are all things where a subtle mistake is a security hole.
//
// Note that verifying an incoming request needs only the *remote* server's
// public keys, which are fetched over unauthenticated federation. This worker
// therefore never needs the homeserver's private signing key, and deliberately
// does not mount it.
package fedauth

import (
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog"
	"go.mau.fi/util/exhttp"
	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/federation"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/store"
)

// Verifier authenticates incoming federation requests.
type Verifier struct {
	auth       *federation.ServerAuth
	serverName string
	// notaries are the trusted key servers queried before falling back to a
	// direct fetch, mirroring Synapse's trusted_key_servers.
	notaries []string
}

// Options tunes key fetching.
type Options struct {
	// KeyRefetchDelay is the minimum time before re-querying a server whose
	// key fetch failed, so an unreachable server cannot be turned into a
	// stream of outbound requests. Zero uses one hour.
	KeyRefetchDelay time.Duration
	// Timeout bounds a key fetch. Zero uses 30s.
	Timeout time.Duration
	// Notaries are trusted key servers, queried before a direct fetch. Copy
	// these from Synapse's trusted_key_servers so both resolve keys the same
	// way; without them a server that is momentarily unreachable cannot be
	// verified even though Synapse can verify it.
	Notaries []string
	// DB is Synapse's database, read only, used to reuse its cached keys.
	// Optional; without it every unknown server needs a network fetch.
	DB KeyStore
	// MaxBodySize bounds the request body read for verification. Zero uses
	// mautrix's default of 50MB.
	MaxBodySize int64
	// Log is used for cache and notary diagnostics.
	Log zerolog.Logger
}

// New builds a Verifier for the given homeserver name.
func New(serverName string, opts Options) *Verifier {
	if opts.KeyRefetchDelay <= 0 {
		opts.KeyRefetchDelay = time.Hour
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}

	var db KeyStore
	if opts.DB != nil && !isNilStore(opts.DB) {
		db = opts.DB
	}
	cache := newLayeredCache(db, opts.KeyRefetchDelay, opts.Log)

	settings := exhttp.SensibleClientSettings
	settings.GlobalTimeout = opts.Timeout

	// No signing key: this client only fetches published keys, which is an
	// unauthenticated federation request.
	// The resolution cache (well-known and SRV lookups) is separate from the
	// key cache; only the latter is layered over Synapse's.
	client := federation.NewClient(serverName, nil, cache.mem, settings)

	auth := federation.NewServerAuth(client, cache, func(federation.XMatrixAuth) string {
		// This worker serves exactly one homeserver, so the only acceptable
		// destination is that server. Returning it unconditionally makes
		// mautrix reject a request addressed to anyone else.
		return serverName
	})
	if opts.MaxBodySize > 0 {
		auth.MaxBodySize = opts.MaxBodySize
	}

	return &Verifier{auth: auth, serverName: serverName, notaries: opts.Notaries}
}

// Result describes the outcome of verifying a request.
type Result struct {
	// Origin is the verified server name. It is only meaningful when Err is nil.
	Origin string
	// Err is the Matrix error to return when verification failed.
	Err *mautrix.RespError
}

// OK reports whether the request was authenticated.
func (r Result) OK() bool { return r.Err == nil }

// Status returns the HTTP status for a failed verification.
func (r Result) Status() int {
	if r.Err == nil {
		return http.StatusOK
	}
	if r.Err.StatusCode != 0 {
		return r.Err.StatusCode
	}
	return http.StatusUnauthorized
}

// Verify authenticates a request and returns the verified origin server.
//
// The returned origin is the only value safe to use for access control: the
// origin field of an unverified X-Matrix header is attacker-controlled, and
// trusting it would let any server inject EDUs in another server's name.
func (v *Verifier) Verify(r *http.Request) Result {
	// mautrix unconditionally closes the body, which panics when it is nil.
	// A server-built request always has one, but a request constructed in code
	// (http.NewRequest with a nil body, as verification replay does) does not.
	// Guard here rather than at every call site: a panic on the request path
	// would take down a worker that is otherwise serving correctly.
	if r.Body == nil {
		r = r.Clone(r.Context())
		r.Body = http.NoBody
	}

	// Try the cheap key sources first. mautrix falls back to fetching from the
	// origin server directly, which is the last resort in Synapse's order too.
	v.warmCache(r.Context(), r.Header.Get("Authorization"))

	modified, respErr := v.auth.Authenticate(r)
	if respErr != nil {
		return Result{Err: respErr}
	}
	if respErr := v.requireCurrentlyValidKey(r.Header.Get("Authorization")); respErr != nil {
		return Result{Err: respErr}
	}
	return Result{Origin: federation.OriginServerNameFromRequest(modified)}
}

// requireCurrentlyValidKey rejects a request signed with a key that is past its
// own valid_until_ts.
//
// Synapse calls verify_json_for_server(origin, request, now), so the key must be
// valid at the moment of the request. mautrix checks valid_until_ts when
// *loading* keys from its cache, but GetKeysWithCache returns a freshly fetched
// response without that check — so a server publishing an already-expired key
// is accepted on the first request and rejected only afterwards.
//
// That is not hypothetical: ryuu.eu publishes ed25519:a_EMUw with a
// valid_until_ts of 2025-12-23. Synapse answered 401 after 32 s of trying to
// find a usable key; we accepted the request in under a millisecond. Accepting
// a signature from a key the origin itself declares expired defeats the point
// of key rotation — if a key was rotated because it leaked, the expiry is
// exactly what stops the old one being used.
//
// The check is a cache lookup, not a second verification: both layers of the
// key cache already refuse anything past its validity, so a key that cannot be
// loaded back is a key that was not valid to use.
func (v *Verifier) requireCurrentlyValidKey(authHeader string) *mautrix.RespError {
	parsed := federation.ParseXMatrixAuth(authHeader)
	if parsed.Origin == "" || parsed.KeyID == "" {
		// Authenticate would already have rejected this; nothing to add.
		return nil
	}

	// The question is only whether the origin has a key response that is still
	// valid. Which key signed the request, and whether the signature is good,
	// was already settled by Authenticate.
	//
	// Deliberately not checking HasKey: it looks only at verify_keys and
	// ignores old_verify_keys, so a request signed with a rotated-but-still-
	// valid key — which Synapse accepts — would be refused here.
	res, err := v.auth.Keys.LoadKeys(parsed.Origin)
	if err == nil && res != nil && time.Until(res.ValidUntilTS.Time) > 0 {
		return nil
	}

	authVerdictExpiredKey.Inc()
	return &mautrix.RespError{
		ErrCode: "M_UNAUTHORIZED",
		Err: fmt.Sprintf("No currently valid key to satisfy %s for %s: the published key is past its valid_until_ts",
			parsed.KeyID, parsed.Origin),
		StatusCode: http.StatusUnauthorized,
	}
}

// ServerName returns the homeserver this verifier accepts requests for.
func (v *Verifier) ServerName() string { return v.serverName }

// authVerdictExpiredKey counts requests rejected for being signed with a key
// past its valid_until_ts. Synapse rejects these too; a non-zero rate here
// means remote servers with broken key servers, not a fault in this worker.
var authVerdictExpiredKey = promauto.NewCounter(prometheus.CounterOpts{
	Name: "goinbound_auth_expired_key_total",
	Help: "Requests rejected because the origin's published key was past its valid_until_ts.",
})

// isNilStore catches a typed nil *store.Store passed as a KeyStore, which would
// otherwise pass the nil check and panic on first use.
func isNilStore(ks KeyStore) bool {
	s, ok := ks.(*store.Store)
	return ok && s == nil
}
