package fedauth

import (
	"context"
	"time"

	"github.com/rs/zerolog"
	"go.mau.fi/util/jsontime"
	"maunium.net/go/mautrix/federation"
	"maunium.net/go/mautrix/id"
)

// queryNotaries asks the configured trusted key servers for a server's keys and
// stores any valid response in the cache.
//
// This is the tier Synapse calls "perspectives", and it sits between its local
// cache and a direct fetch. It matters because a notary can answer for an
// origin server that is unreachable right now, which a direct fetch cannot: a
// briefly-down server would otherwise have its legitimate requests rejected.
//
// A hostile notary cannot forge keys. The response it relays carries the origin
// server's own signature over its key list, and mautrix verifies that
// self-signature before trusting anything from the cache.
func (v *Verifier) queryNotaries(ctx context.Context, serverName string, keyID id.KeyID) bool {
	if len(v.notaries) == 0 {
		return false
	}

	req := &federation.ReqQueryKeys{
		ServerKeys: map[string]map[id.KeyID]federation.QueryKeysCriteria{
			serverName: {
				keyID: {
					// Ask for a key valid now. Synapse uses the request's
					// validity requirement; for verifying a live request,
					// "currently valid" is the requirement.
					MinimumValidUntilTS: jsontime.UM(time.Now()),
				},
			},
		},
	}

	for _, notary := range v.notaries {
		if notary == serverName {
			// Asking a server about itself is just a direct fetch, which
			// mautrix already does as the final tier.
			continue
		}

		resp, err := v.auth.Client.QueryKeys(ctx, notary, req)
		if err != nil {
			zerolog.Ctx(ctx).Debug().Err(err).
				Str("notary", notary).Str("server_name", serverName).
				Msg("Notary key query failed")
			continue
		}

		for _, keys := range resp.ServerKeys {
			if keys == nil || keys.ServerName != serverName {
				continue
			}
			if err := keys.VerifySelfSignature(); err != nil {
				zerolog.Ctx(ctx).Warn().Err(err).
					Str("notary", notary).Str("server_name", serverName).
					Msg("Notary returned keys with an invalid self-signature")
				continue
			}
			if !time.Now().Before(keys.ValidUntilTS.Time) {
				// Not valid for this request, so not what we asked for:
				// ask the next notary. Stopping here served a key past its
				// validity while every other notary had a current one
				// (nexy7574.co.uk, whose keys last 30 minutes, 2026-10-17).
				zerolog.Ctx(ctx).Debug().Str("notary", notary).Str("server_name", serverName).
					Msg("Notary returned keys no longer valid; asking the next one")
				continue
			}
			v.auth.Keys.StoreKeys(keys)
			if keys.HasKey(keyID) {
				return true
			}
		}
	}
	return false
}

// warmCache tries the cheap key sources before mautrix falls back to fetching
// from the origin server directly.
//
// Called off the request path in shadow mode; when serving natively
// it runs inline, which is why every tier is bounded by the request context.
func (v *Verifier) warmCache(ctx context.Context, authHeader string) {
	if len(v.notaries) == 0 {
		return
	}
	parsed := federation.ParseXMatrixAuth(authHeader)
	if parsed.Origin == "" || parsed.KeyID == "" {
		return
	}

	// LoadKeys covers memory and Synapse's on-disk cache; only go to a notary
	// if both miss.
	if res, err := v.auth.Keys.LoadKeys(parsed.Origin); err == nil && res.HasKey(parsed.KeyID) {
		return
	}
	v.queryNotaries(ctx, parsed.Origin, parsed.KeyID)
}
