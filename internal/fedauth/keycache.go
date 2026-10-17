package fedauth

import (
	"context"
	"encoding/json"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix/federation"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/store"
)

// KeyStore is Synapse's on-disk cache of published server keys.
type KeyStore interface {
	GetServerKeys(ctx context.Context, serverName string, validAtMS int64) ([]store.ServerKeyJSON, error)
}

// synapseCacheTimeout bounds the database lookup. The KeyCache interface takes
// no context, so the bound is applied here.
const synapseCacheTimeout = 3 * time.Second

// layeredCache resolves published server keys the way Synapse does, in the same
// order: in-memory first, then Synapse's own on-disk cache. mautrix supplies
// the final tier by fetching from the origin server directly when neither has
// the key.
//
// Reading Synapse's server_keys_json is what makes this cheap. That table
// already holds keys for tens of thousands of servers, so a restart does not
// start from nothing and no extra federation traffic is generated for a server
// Synapse has already seen.
type layeredCache struct {
	mem *federation.InMemoryCache
	db  KeyStore
	log zerolog.Logger
}

var _ federation.KeyCache = (*layeredCache)(nil)

func newLayeredCache(db KeyStore, refetchDelay time.Duration, log zerolog.Logger) *layeredCache {
	mem := federation.NewInMemoryCache()
	mem.MinKeyRefetchDelay = refetchDelay
	return &layeredCache{mem: mem, db: db, log: log}
}

func (c *layeredCache) LoadKeys(serverName string) (*federation.ServerKeyResponse, error) {
	if res, err := c.mem.LoadKeys(serverName); err == nil && res != nil {
		return res, nil
	}
	if c.db == nil {
		return nil, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), synapseCacheTimeout)
	defer cancel()

	rows, err := c.db.GetServerKeys(ctx, serverName, time.Now().UnixMilli())
	if err != nil {
		// A cache miss is not an error: mautrix will fetch from the origin.
		c.log.Debug().Err(err).Str("server_name", serverName).
			Msg("Failed to read Synapse's cached server keys")
		return nil, nil
	}

	// Synapse keeps a row per key ID, each holding the whole response, and
	// for a key in old_verify_keys its ts_valid_until_ms is that key's
	// expired_ts, not the response's valid_until_ts. So the column says
	// nothing of whether the response is still valid: an old key's row with
	// a far expired_ts can hold a response that expired days ago (2026-10-17:
	// nexy7574.co.uk, spiritcroc.de, refused here while Synapse accepted
	// them). Each response is judged by its own valid_until_ts, and the
	// longest-valid one used.
	now := time.Now()
	var best *federation.ServerKeyResponse
	for _, row := range rows {
		var resp federation.ServerKeyResponse
		// Unmarshalling is what populates the raw bytes that self-signature
		// verification checks, so the stored response is validated by mautrix
		// exactly as a freshly fetched one would be.
		if err := json.Unmarshal(row.JSON, &resp); err != nil {
			continue
		}
		if resp.ServerName != serverName {
			// A stored response naming a different server would let one
			// server's keys be served for another.
			continue
		}
		if !now.Before(resp.ValidUntilTS.Time) {
			continue
		}
		if best != nil && !resp.ValidUntilTS.Time.After(best.ValidUntilTS.Time) {
			continue
		}
		if err := resp.VerifySelfSignature(); err != nil {
			c.log.Debug().Err(err).Str("server_name", serverName).
				Msg("Skipping cached key response with a bad self-signature")
			continue
		}
		r := resp
		best = &r
	}
	if best == nil {
		return nil, nil
	}
	// Promote into memory so the next request skips the database.
	c.mem.StoreKeys(best)
	return best, nil
}

func (c *layeredCache) StoreKeys(resp *federation.ServerKeyResponse) {
	// Only in memory. Synapse owns server_keys_json and this worker holds a
	// read-only role, by design.
	c.mem.StoreKeys(resp)
}

func (c *layeredCache) StoreFetchError(serverName string, err error) {
	c.mem.StoreFetchError(serverName, err)
}

func (c *layeredCache) ShouldReQuery(serverName string) bool {
	return c.mem.ShouldReQuery(serverName)
}
