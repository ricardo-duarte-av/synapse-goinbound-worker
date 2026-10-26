package fedfetch

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/backoff"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/fedclient"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/synapsecfg"
)

type rewriteTo struct{ to *url.URL }

func (r rewriteTo) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme, req.URL.Host = r.to.Scheme, r.to.Host
	return http.DefaultTransport.RoundTrip(req)
}

type timings struct {
	last, interval int64
	failure        *int64
}

func (t *timings) RetryTimings(context.Context, string) (*int64, int64, int64, error) {
	return t.failure, t.last, t.interval, nil
}

func testClient(t *testing.T, h http.HandlerFunc) *Client {
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	to, _ := url.Parse(srv.URL)
	_, priv, _ := ed25519.GenerateKey(nil)
	fc, err := fedclient.New("local.test", "ed25519 l "+base64.RawStdEncoding.EncodeToString(priv.Seed()), nil, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	fc.HTTP.Transport.(*fedclient.JSONContentType).Next = rewriteTo{to}
	return &Client{fed: fc}
}

// get_pdu asks a destination for an event at most once a minute: a second
// ask within it gets nothing, without a request.
func TestGetPDUAsksOnceAMinute(t *testing.T) {
	var n atomic.Int32
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) { n.Add(1); w.WriteHeader(404) })
	rv, _ := pdu.LookupRoomVersion("10")
	if _, err := c.Event(context.Background(), "remote.test", "$e", "!r:x", rv); err == nil {
		t.Fatal("a 404 is an error")
	}
	if p, err := c.Event(context.Background(), "remote.test", "$e", "!r:x", rv); p != nil || err != nil || n.Load() != 1 {
		t.Errorf("second ask: %v %v, %d requests", p, err, n.Load())
	}
	// Another destination, or another event, is asked.
	c.Event(context.Background(), "other.test", "$e", "!r:x", rv)
	c.Event(context.Background(), "remote.test", "$f", "!r:x", rv)
	if n.Load() != 3 {
		t.Errorf("%d requests, want 3", n.Load())
	}
}

// A destination in backoff is not contacted, and that does not count as
// asked.
func TestGetPDUInBackoff(t *testing.T) {
	var n atomic.Int32
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) { n.Add(1); w.WriteHeader(404) })
	tm := &timings{last: time.Now().UnixMilli(), interval: 600_000}
	c.Backoff = backoff.New(tm, nil, synapsecfg.Backoff{MinMS: 600_000, Multiplier: 2, MaxMS: 1 << 40})
	rv, _ := pdu.LookupRoomVersion("10")
	_, err := c.Event(context.Background(), "remote.test", "$e", "!r:x", rv)
	var nr *backoff.NotRetrying
	if !errorsAs(err, &nr) || n.Load() != 0 {
		t.Fatalf("in backoff: %v, %d requests", err, n.Load())
	}
	tm.last = 1
	c.Event(context.Background(), "remote.test", "$e", "!r:x", rv)
	if n.Load() != 1 {
		t.Errorf("%d requests once the backoff is over", n.Load())
	}
}

func errorsAs(err error, target any) bool { return errors.As(err, target) }
