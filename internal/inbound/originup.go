package inbound

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// CacheRetryTimings is the cache an origin's reset invalidates
// (get_destination_retry_timings, keyed by destination).
const CacheRetryTimings = "get_destination_retry_timings"

// qResetDestination is _set_destination_retry_timings_txn with
// (origin, None, 0, 0).
const qResetDestination = `
	INSERT INTO destinations (destination, failure_ts, retry_last_ts, retry_interval)
	VALUES ($1, NULL, 0, 0)
	ON CONFLICT (destination) DO UPDATE SET
		failure_ts = EXCLUDED.failure_ts,
		retry_last_ts = EXCLUDED.retry_last_ts,
		retry_interval = EXCLUDED.retry_interval
	WHERE
		EXCLUDED.retry_interval = 0
		OR EXCLUDED.retry_last_ts = 0
		OR destinations.retry_interval IS NULL
		OR destinations.retry_interval < EXCLUDED.retry_interval
		OR destinations.retry_last_ts < EXCLUDED.retry_last_ts`

// qNextCacheID is the caches stream's MultiWriterIdGenerator.get_next_txn:
// writers=[] there, so there is no stream_positions row to keep.
const qNextCacheID = `SELECT nextval('cache_invalidation_stream_seq')`

// qInsertCacheInvalidation is _send_invalidation_to_replication.
const qInsertCacheInvalidation = `
	INSERT INTO cache_invalidation_stream_by_instance
		(stream_id, instance_name, cache_func, keys, invalidation_ts)
	VALUES ($1, $2, $3, $4, $5)`

// CacheInvalidation is a row of the caches stream, as written.
type CacheInvalidation struct {
	StreamID       int64
	Instance       string
	CacheFunc      string
	Keys           []string
	InvalidationTS int64
}

// ResetDestination is set_destination_retry_timings(origin, None, 0, 0):
// the reset, and the invalidation of every process's cached timings,
// streamed under our instance name. The caller publishes the returned row.
func (d *DB) ResetDestination(ctx context.Context, origin string) (CacheInvalidation, error) {
	inv := CacheInvalidation{Instance: d.instance, CacheFunc: CacheRetryTimings,
		Keys: []string{origin}, InvalidationTS: d.nowMS()}
	err := pgx.BeginFunc(ctx, d.pool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, qResetDestination, origin); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, qNextCacheID).Scan(&inv.StreamID); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, qInsertCacheInvalidation, inv.StreamID, inv.Instance, inv.CacheFunc, inv.Keys, inv.InvalidationTS)
		return err
	})
	if err != nil {
		return CacheInvalidation{}, fmt.Errorf("inbound: resetting %s: %w", origin, err)
	}
	return inv, nil
}
