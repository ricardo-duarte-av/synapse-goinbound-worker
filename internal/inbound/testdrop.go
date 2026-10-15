package inbound

import (
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog"
)

var testDropped = promauto.NewCounter(prometheus.CounterOpts{
	Name: "goinbound_write_test_dropped_total",
	Help: "PDUs answered but deliberately not staged by write.test_drop_pdus.",
})

// TestDrop makes a gap on purpose, to exercise the missing events path
// against a server we control: the next Count PDUs from Origin in Room are
// answered as staged but are not, so the next event's prev events are
// missing and are fetched. Synapse has nothing like it; config allows it
// only for a write origin.
type TestDrop struct {
	Origin, Room string
	Log          zerolog.Logger

	mu   sync.Mutex
	left int
}

// NewTestDrop drops the next count PDUs from origin in room.
func NewTestDrop(origin, room string, count int, log zerolog.Logger) *TestDrop {
	return &TestDrop{Origin: origin, Room: room, Log: log, left: count}
}

// take says whether to drop this PDU, counting it if so.
func (t *TestDrop) take(origin, room, eventID string) bool {
	if t == nil || origin != t.Origin || room != t.Room {
		return false
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.left <= 0 {
		return false
	}
	t.left--
	testDropped.Inc()
	t.Log.Warn().Str("origin", origin).Str("room_id", room).Str("event_id", eventID).Int("left", t.left).
		Msg("write.test_drop_pdus: answered but not staged, to make a gap")
	return true
}
