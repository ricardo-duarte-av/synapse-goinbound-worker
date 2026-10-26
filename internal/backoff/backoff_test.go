package backoff

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/synapsecfg"
)

type timings struct {
	failureTS        *int64
	lastTS, interval int64
	up               bool
	writes           int
}

func (t *timings) RetryTimings(context.Context, string) (*int64, int64, int64, error) {
	return t.failureTS, t.lastTS, t.interval, nil
}

func (t *timings) SetTimings(_ string, f *int64, last, iv int64, up bool) {
	t.failureTS, t.lastTS, t.interval, t.up = f, last, iv, up
	t.writes++
}

func i64(v int64) *int64 { return &v }

func TestLimiter(t *testing.T) {
	cfg := synapsecfg.Backoff{MinMS: 600_000, Multiplier: 2, MaxMS: 7 * 86_400_000}
	now := time.UnixMilli(1_000_000_000)
	status := func(code int) func() (*http.Response, error) {
		return func() (*http.Response, error) {
			if code == 200 {
				return &http.Response{StatusCode: 200}, nil
			}
			return &http.Response{StatusCode: code}, errors.New("http error")
		}
	}
	noResponse := func() (*http.Response, error) { return nil, errors.New("connection refused") }

	for _, c := range []struct {
		name   string
		before timings
		opts   Options
		send   func() (*http.Response, error)
		want   timings
		refuse bool
	}{
		{name: "first failure", send: noResponse,
			want: timings{failureTS: i64(now.UnixMilli()), lastTS: now.UnixMilli(), interval: 600_000, writes: 1}},
		{name: "longer", before: timings{failureTS: i64(5), lastTS: now.UnixMilli() - 700_000, interval: 600_000}, send: status(502),
			want: timings{failureTS: i64(5), lastTS: now.UnixMilli(), interval: 1_200_000, writes: 1}},
		{name: "capped", before: timings{failureTS: i64(5), lastTS: 1, interval: 6 * 86_400_000}, send: status(429),
			want: timings{failureTS: i64(5), lastTS: now.UnixMilli(), interval: 7 * 86_400_000, writes: 1}},
		{name: "in backoff", before: timings{failureTS: i64(5), lastTS: now.UnixMilli() - 1000, interval: 600_000}, send: status(200),
			want: timings{failureTS: i64(5), lastTS: now.UnixMilli() - 1000, interval: 600_000}, refuse: true},
		{name: "ignored, cleared", before: timings{failureTS: i64(5), lastTS: now.UnixMilli() - 1000, interval: 600_000}, opts: Options{IgnoreBackoff: true}, send: status(200),
			want: timings{up: true, writes: 1}},
		{name: "ignored, failing", before: timings{failureTS: i64(5), lastTS: 1, interval: 600_000}, opts: Options{IgnoreBackoff: true}, send: noResponse,
			want: timings{failureTS: i64(5), lastTS: 1, interval: 600_000}},
		{name: "a 403 is an answer", send: status(403), want: timings{}},
		{name: "a 404 is an answer", send: status(404), want: timings{}},
		{name: "unless asked", opts: Options{BackoffOn404: true}, send: status(404),
			want: timings{failureTS: i64(now.UnixMilli()), lastTS: now.UnixMilli(), interval: 600_000, writes: 1}},
		{name: "a 401 is not", send: status(401),
			want: timings{failureTS: i64(now.UnixMilli()), lastTS: now.UnixMilli(), interval: 600_000, writes: 1}},
		{name: "success, nothing to clear", send: status(200), want: timings{}},
		{name: "backoff due, success", before: timings{failureTS: i64(5), lastTS: 1, interval: 600_000}, send: status(200),
			want: timings{up: true, writes: 1}},
	} {
		t.Run(c.name, func(t *testing.T) {
			tm := c.before
			l := New(&tm, &tm, cfg)
			l.now, l.jitter = func() time.Time { return now }, func() float64 { return 1 }
			sent := false
			err := l.Do(context.Background(), "x", c.opts, func() (*http.Response, error) { sent = true; return c.send() })
			var nr *NotRetrying
			if refused := errors.As(err, &nr); refused != c.refuse || sent == c.refuse {
				t.Errorf("refused %v, sent %v; want refused %v", refused, sent, c.refuse)
			}
			got, want := tm, c.want
			if (got.failureTS == nil) != (want.failureTS == nil) || got.failureTS != nil && *got.failureTS != *want.failureTS ||
				got.lastTS != want.lastTS || got.interval != want.interval || got.up != want.up || got.writes != want.writes {
				t.Errorf("timings %+v (failure %v), want %+v (failure %v)", got, deref(got.failureTS), want, deref(want.failureTS))
			}
		})
	}
}

func deref(p *int64) any {
	if p == nil {
		return nil
	}
	return *p
}
