package txn

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// The sweep nudge. A Synapse process starts _handle_old_staged_events, which
// takes up events left staged, only once it has received a transaction
// (on_incoming_transaction, federation_server.py:306), and then every minute.
// When write mode leaves an event to Synapse (write.fallback: synapse) and
// our upstream is a process that has had no transaction since it started --
// main, once the inbound worker is gone and we answer nearly everything --
// nothing would take the event. So we send the upstream a copy of the last
// transaction we answered and stored. Synapse answers a transaction already
// in received_transactions with the stored answer, before touching its PDUs
// or EDUs (_handle_incoming_transaction, have_responded), exactly as it
// answers the sender's own retry; the X-Matrix signature still holds, as it
// covers no timestamp. So the copy starts the sweep and does nothing else.

var nudges = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "goinbound_sweep_nudges_total",
	Help: "Copies of an answered transaction sent upstream so that Synapse starts its staged-events sweep, by outcome (stored_answer, other_answer, unreachable, nothing_to_send).",
}, []string{"outcome"})

// nudgeInterval is the least time between two nudges. Synapse's sweep runs
// every minute once started, so one a minute is plenty.
const nudgeInterval = time.Minute

// nudgeTimeout bounds a nudge's request.
const nudgeTimeout = 30 * time.Second

// answered is a transaction we answered and stored, as it arrived.
type answered struct {
	method, uri, host string
	header            http.Header
	body              []byte
	answer            []byte
}

type nudger struct {
	mu   sync.Mutex
	last *answered
	// next is when a nudge may be sent again, in Unix nanoseconds.
	next atomic.Int64
}

// remember keeps a transaction we answered and stored, as the copy to send.
func (n *nudger) remember(r *http.Request, body, answer []byte) {
	a := &answered{method: r.Method, uri: r.RequestURI, host: r.Host, header: r.Header.Clone(), body: body, answer: answer}
	n.mu.Lock()
	n.last = a
	n.mu.Unlock()
}

// NudgeSweep sends the upstream a copy of the last transaction answered
// here, so that Synapse starts its staged-events sweep, at most once a
// minute. It returns at once; the copy is sent in the background.
func (h *Handler) NudgeSweep() {
	now := time.Now()
	next := h.nudge.next.Load()
	if now.UnixNano() < next || !h.nudge.next.CompareAndSwap(next, now.Add(nudgeInterval).UnixNano()) {
		return
	}
	h.nudge.mu.Lock()
	a := h.nudge.last
	h.nudge.mu.Unlock()
	if a == nil {
		nudges.WithLabelValues("nothing_to_send").Inc()
		return
	}
	go h.sendNudge(a)
}

func (h *Handler) sendNudge(a *answered) {
	ctx, cancel := context.WithTimeout(context.Background(), nudgeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, a.method, "http://"+a.host+a.uri, bytes.NewReader(a.body))
	if err != nil {
		return
	}
	req.Header = a.header.Clone()
	req.Host = a.host
	req.RequestURI = a.uri
	req.ContentLength = int64(len(a.body))
	// Synapse re-encodes the stored answer (escaping what canonical JSON
	// does not), so it may be longer than ours, and is compared as a value.
	res := h.upstream.Forward(discard{header: http.Header{}}, req, 8*int64(len(a.answer))+1024)
	switch {
	case res.Status == 0 || res.Err != nil:
		nudges.WithLabelValues("unreachable").Inc()
		h.log.Warn().Err(res.Err).Msg("Sweep nudge: the upstream could not be reached")
	case res.Status == http.StatusOK && !res.Truncated && sameJSON(res.Body, a.answer):
		nudges.WithLabelValues("stored_answer").Inc()
		h.log.Info().Str("uri", a.uri).Msg("Sweep nudge: sent the upstream a copy of an answered transaction, so that it sweeps staged events")
	default:
		// Still a transaction received, so the sweep has started; but the
		// answer is not the one stored, which says the copy was handled
		// rather than recognised.
		nudges.WithLabelValues("other_answer").Inc()
		h.log.Warn().Str("uri", a.uri).Int("status", res.Status).Bytes("answer", res.Body).
			Msg("Sweep nudge: the upstream did not give the stored answer")
	}
}

// sameJSON says a and b decode to the same value.
func sameJSON(a, b []byte) bool {
	var x, y any
	if json.Unmarshal(a, &x) != nil || json.Unmarshal(b, &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

// discard is a ResponseWriter for a request nobody is waiting on.
type discard struct{ header http.Header }

func (d discard) Header() http.Header         { return d.header }
func (d discard) Write(b []byte) (int, error) { return len(b), nil }
func (d discard) WriteHeader(int)             {}
