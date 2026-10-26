// Package backoff is Synapse's per-destination retry limiter
// (util/retryutils.py), around the requests write mode makes to other
// servers, as MatrixFederationHttpClient puts it around each request.
//
// Before a request, a destination still in backoff (retry_last_ts +
// retry_interval in the future) is not contacted: NotRetrying, unless the
// request ignores backoff. After it, the outcome is stored as Synapse stores
// it (RetryDestinationLimiter.__exit__): a success clears a backoff, and a
// destination that was failing is then announced up; a failure (no response,
// a 5xx, a 401 or 429, a 404 where asked) starts or lengthens one, unless the
// request ignores backoff; any other HTTP error changes nothing.
package backoff

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/synapsecfg"
)

// Reader reads a destination's retry timings, all zero when it has none
// (get_destination_retry_timings).
type Reader interface {
	RetryTimings(ctx context.Context, dest string) (failureTS *int64, lastTS, interval int64, err error)
}

// Writer stores them, in the background (store_retry_timings); up says the
// destination was failing and no longer is.
type Writer interface {
	SetTimings(dest string, failureTS *int64, lastTS, interval int64, up bool)
}

// NotRetrying is NotRetryingDestination.
type NotRetrying struct {
	Dest             string
	LastTS, Interval int64
}

func (e *NotRetrying) Error() string {
	return fmt.Sprintf("Not retrying server %s because we tried it recently retry_last_ts=%d and we won't check for another retry_interval=%dms.", e.Dest, e.LastTS, e.Interval)
}

// Options are get_retry_limiter's.
type Options struct {
	// IgnoreBackoff contacts the destination anyway, and does not back
	// off on failure; a success still clears the backoff.
	IgnoreBackoff bool
	// BackoffOn404 counts a 404 as a failure.
	BackoffOn404 bool
}

// Limiter checks and stores retry timings.
type Limiter struct {
	r   Reader
	w   atomic.Pointer[Writer]
	cfg synapsecfg.Backoff
	// now and jitter are the clock and random.uniform(0.8, 1.4).
	now    func() time.Time
	jitter func() float64
}

// New builds a limiter. Without a writer, backoff is honoured but nothing is
// stored.
func New(r Reader, w Writer, cfg synapsecfg.Backoff) *Limiter {
	l := &Limiter{r: r, cfg: cfg, now: time.Now, jitter: func() float64 { return 0.8 + 0.6*rand.Float64() }}
	if w != nil {
		l.SetWriter(w)
	}
	return l
}

// SetWriter sets where timings are stored, at any time.
func (l *Limiter) SetWriter(w Writer) { l.w.Store(&w) }

func (l *Limiter) store(dest string, failureTS *int64, lastTS, interval int64, up bool) {
	if w := l.w.Load(); w != nil {
		(*w).SetTimings(dest, failureTS, lastTS, interval, up)
	}
}

// Do runs send under the limiter. send returns the response it got, if any,
// with its error. A nil limiter only runs send.
func (l *Limiter) Do(ctx context.Context, dest string, o Options, send func() (*http.Response, error)) error {
	if l == nil {
		_, err := send()
		return err
	}
	failureTS, lastTS, interval, err := l.r.RetryTimings(ctx, dest)
	if err != nil {
		return fmt.Errorf("backoff: retry timings of %s: %w", dest, err)
	}
	if !o.IgnoreBackoff && lastTS+interval > l.now().UnixMilli() {
		return &NotRetrying{Dest: dest, LastTS: lastTS, Interval: interval}
	}
	resp, err := send()
	if ctx.Err() != nil {
		// Our own shutdown or caller's deadline, not the destination's
		// doing.
		return err
	}
	l.exit(dest, o, failureTS, interval, resp, err)
	return err
}

// exit is RetryDestinationLimiter.__exit__.
func (l *Limiter) exit(dest string, o Options, failureTS *int64, interval int64, resp *http.Response, err error) {
	// Synapse's limiter ends once the response's headers are in: reading
	// the body comes after, outside it.
	success := err == nil || resp != nil && resp.StatusCode >= 200 && resp.StatusCode < 300
	previouslyFailing := failureTS != nil && *failureTS != 0
	if success {
		if interval == 0 {
			return
		}
		l.store(dest, nil, 0, 0, previouslyFailing)
		return
	}
	if resp != nil {
		code := resp.StatusCode
		switch {
		case code == 404 && o.BackoffOn404, code == 401, code == 429, code >= 500:
		default:
			// A CodeMessageException below 500: the destination is up.
			return
		}
	}
	if o.IgnoreBackoff {
		return
	}
	if interval != 0 {
		interval = int64(float64(interval) * l.cfg.Multiplier * l.jitter())
		if interval >= l.cfg.MaxMS {
			interval = l.cfg.MaxMS
		}
	} else {
		interval = l.cfg.MinMS
	}
	now := l.now().UnixMilli()
	if failureTS == nil {
		failureTS = &now
	}
	l.store(dest, failureTS, now, interval, false)
}
