// Package originup does what Synapse's inbound worker does when a server we
// had backed off sends us a signed request: it marks the server as up
// (Authenticator.reset_retry_timings, transport/server/_base.py:143).
//
// That is, in order:
//
//  1. set_destination_retry_timings(origin, None, 0, 0): the destinations
//     upsert, plus a row on the caches stream invalidating every process's
//     get_destination_retry_timings for the origin, under the worker's own
//     instance name (_invalidate_cache_and_stream);
//  2. the caches stream's RDATA for that row on the replication bus, which
//     is how every other process learns of it;
//  3. REMOTE_SERVER_UP, so every process (the federation sender above all)
//     wakes the destination.
//
// Every Synapse process writes the caches stream, the inbound worker
// included: its MultiWriterIdGenerator has writers=[], and a writer that
// then goes quiet holds nothing back ("nothing cares if a given worker's
// caches stream position lags", replication/tcp/resource.py).
package originup

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/inbound"
)

var resets = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "goinbound_origin_up_total",
	Help: "Origins in backoff marked as up, by outcome: reset, db_error, publish_error.",
}, []string{"outcome"})

// Store writes the reset (inbound.DB).
type Store interface {
	ResetDestination(ctx context.Context, origin string) (inbound.CacheInvalidation, error)
}

// Publisher publishes one replication command line on the bus.
type Publisher interface {
	Publish(ctx context.Context, line string) error
}

// Options builds a Resetter.
type Options struct {
	Store     Store
	Publisher Publisher
	// Instance is our instance name on the caches stream.
	Instance string
	Log      zerolog.Logger
}

// Resetter marks origins as up.
type Resetter struct {
	store    Store
	pub      Publisher
	instance string
	log      zerolog.Logger
	now      func() time.Time
	// retryDelay is between publish attempts; shortened in tests.
	retryDelay time.Duration

	mu       sync.Mutex
	inflight map[string]bool
	failedAt time.Time

	// bus serialises resets: a process drops RDATA at or below the last
	// token it saw from an instance, so ours go out in stream ID order.
	bus sync.Mutex
	// last is the last caches stream ID we wrote; unannounced says its
	// RDATA may not have reached the bus.
	last        int64
	unannounced bool
}

// failureHold is how long after a failed reset Ready says no, so that while
// Synapse's worker exists, the transactions go to it instead.
const failureHold = 5 * time.Minute

const (
	publishAttempts = 3
	stepTimeout     = 10 * time.Second
)

// New builds a Resetter.
func New(o Options) *Resetter {
	return &Resetter{store: o.Store, pub: o.Publisher, instance: o.Instance, log: o.Log,
		now: time.Now, retryDelay: time.Second, inflight: map[string]bool{}}
}

// Ready says whether origins in backoff can be served here: false for a
// while after a reset failed.
func (r *Resetter) Ready() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.failedAt.IsZero() || r.now().Sub(r.failedAt) >= failureHold
}

// Reset marks origin as up, in the background, as Synapse does: the request
// that showed the origin is alive does not wait for it. A reset already
// running for origin is not repeated.
func (r *Resetter) Reset(origin string) {
	r.mu.Lock()
	if r.inflight[origin] {
		r.mu.Unlock()
		return
	}
	r.inflight[origin] = true
	r.mu.Unlock()

	go func() {
		defer func() {
			r.mu.Lock()
			delete(r.inflight, origin)
			r.mu.Unlock()
		}()
		outcome, err := r.reset(origin)
		resets.WithLabelValues(outcome).Inc()
		if err != nil {
			r.mu.Lock()
			r.failedAt = r.now()
			r.mu.Unlock()
			r.log.Warn().Err(err).Str("origin", origin).Str("outcome", outcome).Msg("Could not mark an origin as up")
			return
		}
		r.log.Info().Str("origin", origin).Msg("Marked origin as up")
	}()
}

func (r *Resetter) reset(origin string) (string, error) {
	r.bus.Lock()
	defer r.bus.Unlock()

	if r.unannounced {
		// A POSITION makes every process read the rows it missed from the
		// database (_process_position).
		if err := r.publish(r.positionLine()); err != nil {
			return "publish_error", err
		}
		r.unannounced = false
	}

	ctx, cancel := context.WithTimeout(context.Background(), stepTimeout)
	inv, err := r.store.ResetDestination(ctx, origin)
	cancel()
	if err != nil {
		return "db_error", err
	}
	r.last, r.unannounced = inv.StreamID, true

	line, err := rdataLine(inv)
	if err != nil {
		return "publish_error", err
	}
	if err := r.publish(line); err != nil {
		return "publish_error", err
	}
	r.unannounced = false
	if err := r.publish("REMOTE_SERVER_UP " + origin); err != nil {
		return "publish_error", err
	}
	return "reset", nil
}

func (r *Resetter) publish(line string) error {
	var err error
	for i := range publishAttempts {
		if i > 0 {
			time.Sleep(r.retryDelay)
		}
		ctx, cancel := context.WithTimeout(context.Background(), stepTimeout)
		err = r.pub.Publish(ctx, line)
		cancel()
		if err == nil {
			return nil
		}
	}
	return fmt.Errorf("originup: publishing %.40q: %w", line, err)
}

// OnReplicate answers a REPLICATE as every writer does, with its position on
// each stream it writes, so a process that just connected catches up on
// rows it missed. Nothing is said before our first write.
func (r *Resetter) OnReplicate() {
	r.bus.Lock()
	defer r.bus.Unlock()
	if r.last == 0 {
		return
	}
	if err := r.publish(r.positionLine()); err != nil {
		r.log.Warn().Err(err).Msg("Could not answer REPLICATE with our caches position")
		return
	}
	r.unannounced = false
}

// positionLine is POSITION with prev_token = new_token = our last ID, as an
// instance announces itself (commands.py PositionCommand).
func (r *Resetter) positionLine() string {
	id := strconv.FormatInt(r.last, 10)
	return "POSITION caches " + r.instance + " " + id + " " + id
}

// rdataLine is the caches stream's RDATA for inv: the row is
// CachesStreamRow(cache_func, keys, invalidation_ts) as a JSON list.
func rdataLine(inv inbound.CacheInvalidation) (string, error) {
	row, err := json.Marshal([]any{inv.CacheFunc, inv.Keys, inv.InvalidationTS})
	if err != nil {
		return "", err
	}
	return "RDATA caches " + inv.Instance + " " + strconv.FormatInt(inv.StreamID, 10) + " " + string(row), nil
}
