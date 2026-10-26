package inbound

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog"
	"github.com/tidwall/gjson"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pduverify"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/replication"
)

// fakeDecide decides by the staged event's "test" field.
type fakeDecide struct {
	mu    sync.Mutex
	order []string
	base  int64
}

func (f *fakeDecide) Decide(_ context.Context, in pduverify.DecideInput) (*pduverify.Decision, error) {
	f.mu.Lock()
	f.order = append(f.order, in.EventID)
	f.mu.Unlock()
	var v struct {
		Test string `json:"test"`
	}
	_ = json.Unmarshal(in.EventJSON, &v)
	ev, err := pdu.ParseEvent(in.EventJSON, in.EventID, in.Room, false)
	if err != nil {
		return nil, err
	}
	d := &pduverify.Decision{Event: ev, Metadata: map[string]any{}}
	switch v.Test {
	case "defer":
		d.Defer = "test"
	case "ignore":
		d.Ignore = "test"
	case "raise":
		d.Raise = "test"
		d.Entry = pduverify.NewEntry(0, f.base, pdu.StateMap{{Type: "m.room.topic"}: "$t"}, nil)
	case "raise in resolution":
		d.Raise = "test"
		d.Bump = [][]int64{{f.base}}
	default:
		d.Entry = pduverify.NewEntry(0, f.base, pdu.StateMap{{Type: "m.room.topic"}: "$t"}, nil)
		d.Push = []pduverify.PushRow{{UserID: "@u:x", Notif: true}}
	}
	return d, nil
}

type fakePersist struct {
	mu   sync.Mutex
	sent []json.RawMessage
	fail bool
	// conflicts is how many sends answer 409 first.
	conflicts int
}

func (f *fakePersist) SendEvents(_ context.Context, _ string, entries []json.RawMessage, _ bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errors.New("persister down")
	}
	if f.conflicts > 0 {
		f.conflicts--
		return replication.ErrPartialStateConflict
	}
	f.sent = append(f.sent, entries...)
	return nil
}

func (f *fakePersist) ResyncDevices(context.Context, string) error { return nil }

type fakeRead struct{}

func (fakeRead) RoomVersion(context.Context, string) (string, error) { return "1", nil }
func (fakeRead) StateForGroup(context.Context, int64) (pdu.StateMap, error) {
	return pdu.StateMap{}, nil
}

func v1Event(id, test string, ts int64) []byte {
	b, _ := json.Marshal(map[string]any{
		"event_id": id, "room_id": "!r:x", "type": "m.room.message", "sender": "@a:y", "content": map[string]any{},
		"depth": 5, "origin_server_ts": ts, "prev_events": []any{}, "auth_events": []any{},
		"hashes": map[string]any{"sha256": "x"}, "signatures": map[string]any{}, "unsigned": map[string]any{}, "test": test,
	})
	return b
}

func waitFor(t *testing.T, what string, f func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if f() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

func TestProcessorDrainsInOrder(t *testing.T) {
	ctx := context.Background()
	d := testDB(t, "goinbound-test")
	base, err := d.StoreStateGroup(ctx, "$create", "!r:x", 0, nil, pdu.StateMap{{Type: "m.room.create"}: "$create"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	dec, per := &fakeDecide{base: base}, &fakePersist{}
	p := NewProcessor(d, dec, per, fakeRead{}, "x", zerolog.Nop())
	defer p.Close()

	// Staged by "Synapse" before we take the lock: processed first.
	if err := d.Stage(ctx, "y", "!r:x", "$1", v1Event("$1", "", 1), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := p.Received(ctx, "y", "!r:x", "$2", v1Event("$2", "", 2), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "both persisted", func() bool { per.mu.Lock(); defer per.mu.Unlock(); return len(per.sent) == 2 })
	dec.mu.Lock()
	if len(dec.order) != 2 || dec.order[0] != "$1" || dec.order[1] != "$2" {
		t.Errorf("order %v", dec.order)
	}
	dec.mu.Unlock()
	waitFor(t, "queue empty", func() bool { s, _ := d.NextStaged(ctx, "!r:x"); return s == nil })
	// The lock is released once the queue is empty.
	waitFor(t, "lock released", func() bool {
		l, _ := NewLocks(otherInstance(t, d, "py")).TryAcquire(ctx, LockInboundPDU, "!r:x")
		if l != nil {
			l.Release(ctx)
		}
		return l != nil
	})

	var entry struct {
		Context struct {
			StateGroup  int64   `json:"state_group"`
			Before      int64   `json:"state_group_before_event"`
			GroupDeltas [][]any `json:"state_group_deltas"`
		} `json:"context"`
	}
	_ = json.Unmarshal(per.sent[0], &entry)
	if entry.Context.Before == 0 || entry.Context.Before == base || entry.Context.StateGroup != entry.Context.Before {
		t.Errorf("context %+v (base %d)", entry.Context, base)
	}
	if len(entry.Context.GroupDeltas) != 2 {
		t.Errorf("deltas %v", entry.Context.GroupDeltas)
	}
	c := adminConn(t)
	var n int
	c.QueryRow(ctx, `SELECT count(*) FROM event_push_actions_staging`).Scan(&n)
	if n != 2 {
		t.Errorf("%d push rows staged", n)
	}
}

// An event whose auth raises is Synapse's "Failed to handle PDU": its state
// group is stored (compute_event_context ran first), nothing is persisted,
// it is unstaged, and the room's queue goes on.
func TestProcessorFailsAnEventWhoseAuthRaises(t *testing.T) {
	ctx := context.Background()
	d := testDB(t, "goinbound-test")
	base, _ := d.StoreStateGroup(ctx, "$create", "!r:x", 0, nil, pdu.StateMap{{Type: "m.room.create"}: "$create"}, nil)
	dec, per := &fakeDecide{base: base}, &fakePersist{}
	p := NewProcessor(d, dec, per, fakeRead{}, "x", zerolog.Nop())
	defer p.Close()
	if err := d.Stage(ctx, "y", "!r:x", "$1", v1Event("$1", "raise", 1), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := p.Received(ctx, "y", "!r:x", "$2", v1Event("$2", "", 2), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "queue empty", func() bool { s, _ := d.NextStaged(ctx, "!r:x"); return s == nil })
	per.mu.Lock()
	if len(per.sent) != 1 || gjson.GetBytes(per.sent[0], "event.event_id").Str != "$2" {
		t.Errorf("persisted %d entries, want only $2", len(per.sent))
	}
	per.mu.Unlock()
	if p.isDeferred("!r:x") {
		t.Error("deferred")
	}
	c := adminConn(t)
	var n int
	c.QueryRow(ctx, `SELECT count(*) FROM state_groups WHERE event_id = '$1'`).Scan(&n)
	if n != 1 {
		t.Errorf("%d state groups stored for the failed event, want 1", n)
	}
	c.QueryRow(ctx, `SELECT count(*) FROM event_push_actions_staging WHERE event_id = '$1'`).Scan(&n)
	if n != 0 {
		t.Errorf("%d push rows staged for the failed event", n)
	}
}

// State resolution raising leaves only its bumps: no group is stored.
func TestProcessorFailsAnEventWhoseResolutionRaises(t *testing.T) {
	ctx := context.Background()
	d := testDB(t, "goinbound-test")
	base, _ := d.StoreStateGroup(ctx, "$create", "!r:x", 0, nil, pdu.StateMap{{Type: "m.room.create"}: "$create"}, nil)
	dec, per := &fakeDecide{base: base}, &fakePersist{}
	p := NewProcessor(d, dec, per, fakeRead{}, "x", zerolog.Nop())
	defer p.Close()
	if err := p.Received(ctx, "y", "!r:x", "$1", v1Event("$1", "raise in resolution", 1), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "queue empty", func() bool { s, _ := d.NextStaged(ctx, "!r:x"); return s == nil })
	if p.isDeferred("!r:x") {
		t.Error("deferred")
	}
	per.mu.Lock()
	if len(per.sent) != 0 {
		t.Errorf("persisted %d entries", len(per.sent))
	}
	per.mu.Unlock()
	var n int
	adminConn(t).QueryRow(ctx, `SELECT count(*) FROM state_groups WHERE event_id = '$1'`).Scan(&n)
	if n != 0 {
		t.Errorf("%d state groups stored", n)
	}
}

// The persister's 409 (the room was un-partial stated meanwhile): decided
// and written once more; a second one fails the event, as in Synapse.
func TestProcessorRetriesAPartialStateConflict(t *testing.T) {
	for _, c := range []struct {
		conflicts, decisions, sent int
	}{{1, 2, 1}, {2, 2, 0}} {
		ctx := context.Background()
		d := testDB(t, "goinbound-test")
		base, _ := d.StoreStateGroup(ctx, "$create", "!r:x", 0, nil, pdu.StateMap{{Type: "m.room.create"}: "$create"}, nil)
		dec, per := &fakeDecide{base: base}, &fakePersist{conflicts: c.conflicts}
		p := NewProcessor(d, dec, per, fakeRead{}, "x", zerolog.Nop())
		if err := p.Received(ctx, "y", "!r:x", "$1", v1Event("$1", "", 1), []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "unstaged", func() bool { s, _ := d.NextStaged(ctx, "!r:x"); return s == nil })
		dec.mu.Lock()
		per.mu.Lock()
		if len(dec.order) != c.decisions || len(per.sent) != c.sent || p.isDeferred("!r:x") {
			t.Errorf("%d conflicts: %d decisions, %d sent, deferred %v", c.conflicts, len(dec.order), len(per.sent), p.isDeferred("!r:x"))
		}
		per.mu.Unlock()
		dec.mu.Unlock()
		p.Close()
	}
}

func TestProcessorDefersAndKeepsTheQueue(t *testing.T) {
	ctx := context.Background()
	d := testDB(t, "goinbound-test")
	dec, per := &fakeDecide{}, &fakePersist{}
	p := NewProcessor(d, dec, per, fakeRead{}, "x", zerolog.Nop())
	defer p.Close()

	if err := p.Received(ctx, "y", "!r:x", "$1", v1Event("$1", "defer", 1), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := p.Received(ctx, "y", "!r:x", "$2", v1Event("$2", "ignore", 2), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	// The deferred head stays staged, and so does everything behind it, for
	// Synapse's worker to take with the lock.
	waitFor(t, "lock free", func() bool {
		l, _ := NewLocks(otherInstance(t, d, "py")).TryAcquire(ctx, LockInboundPDU, "!r:x")
		if l != nil {
			l.Release(ctx)
		}
		return l != nil
	})
	if _, id, ok, _ := d.NextStagedID(ctx, "!r:x"); !ok || id != "$1" {
		t.Errorf("head %s %v", id, ok)
	}
	if !p.isDeferred("!r:x") {
		t.Error("room not remembered as deferred")
	}
	// Once Synapse has handled the head, the room is ours again.
	d.Unstage(ctx, "y", "$1")
	if p.isDeferred("!r:x") {
		t.Error("still deferred after the head went")
	}
}

// With write.fallback: none, nobody else takes a deferred event: it is
// retried at each sweep, then dropped, and the room's queue moves on.
func TestProcessorWithoutFallbackDropsAfterAttempts(t *testing.T) {
	ctx := context.Background()
	d := testDB(t, "goinbound-test")
	p := NewProcessor(d, &fakeDecide{}, &fakePersist{}, fakeRead{}, "x", zerolog.Nop())
	p.WithoutFallback()
	p.spacing = 0
	defer p.Close()
	c := adminConn(t)

	if err := p.Received(ctx, "y", "!r:x", "$1", v1Event("$1", "defer", 1), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if err := p.Received(ctx, "y", "!r:x", "$2", v1Event("$2", "ignore", 2), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	// Each attempt ends with the room remembered as deferred, or with the
	// queue drained.
	attempted := func() {
		waitFor(t, "attempt", func() bool {
			p.mu.Lock()
			_, deferred := p.deferred["!r:x"]
			delete(p.deferred, "!r:x")
			p.mu.Unlock()
			return deferred || stagedCount(t, c) == 0
		})
	}
	attempted()
	for i := 0; i < 2*fallbackAttempts && stagedCount(t, c) > 0; i++ {
		p.sweep()
		attempted()
	}
	waitFor(t, "queue drained", func() bool { return stagedCount(t, c) == 0 })
	if len(p.attempts) != 0 {
		t.Errorf("attempts left: %v", p.attempts)
	}
}

// Attempts closer together than the spacing count once.
func TestFallbackAttemptsAreSpaced(t *testing.T) {
	p := &Processor{noFallback: true, attempts: map[string]attempt{}, spacing: time.Hour}
	for i := 0; i < 10; i++ {
		if p.giveUp("$e") {
			t.Fatal("gave up inside the spacing")
		}
	}
	if p.attempts["$e"].n != 1 {
		t.Errorf("%d attempts counted, want 1", p.attempts["$e"].n)
	}
	p.spacing = 0
	if p.giveUp("$e") || !p.giveUp("$e") {
		t.Error("did not give up on the third counted attempt")
	}
	if (&Processor{attempts: map[string]attempt{}}).giveUp("$e") {
		t.Error("gave up with a fallback")
	}
}

func TestProcessorLeavesAFailedPersistStaged(t *testing.T) {
	ctx := context.Background()
	d := testDB(t, "goinbound-test")
	base, _ := d.StoreStateGroup(ctx, "$create", "!r:x", 0, nil, pdu.StateMap{{Type: "m.room.create"}: "$create"}, nil)
	dec, per := &fakeDecide{base: base}, &fakePersist{fail: true}
	p := NewProcessor(d, dec, per, fakeRead{}, "x", zerolog.Nop())
	defer p.Close()
	if err := p.Received(ctx, "y", "!r:x", "$1", v1Event("$1", "", 1), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "deferred", func() bool { return p.isDeferred("!r:x") })
	c := adminConn(t)
	var n int
	c.QueryRow(ctx, `SELECT count(*) FROM event_push_actions_staging`).Scan(&n)
	if n != 0 {
		t.Errorf("%d push rows left after a failed persist", n)
	}
	if _, id, ok, _ := d.NextStagedID(ctx, "!r:x"); !ok || id != "$1" {
		t.Errorf("event not left staged: %s %v", id, ok)
	}
}

func stagedCount(t *testing.T, c *pgx.Conn) int {
	t.Helper()
	var n int
	if err := c.QueryRow(context.Background(), `SELECT count(*) FROM federation_inbound_events_staging`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A deferral under write.fallback: synapse calls OnDefer (the sweep nudge);
// under none nobody is nudged, as nobody takes the event.
func TestProcessorNudgesOnDefer(t *testing.T) {
	ctx := context.Background()
	for _, none := range []bool{false, true} {
		d := testDB(t, "goinbound-test")
		p := NewProcessor(d, &fakeDecide{}, &fakePersist{}, fakeRead{}, "x", zerolog.Nop())
		var mu sync.Mutex
		calls := 0
		p.OnDefer(func() { mu.Lock(); calls++; mu.Unlock() })
		if none {
			p.WithoutFallback()
		}
		if err := p.Received(ctx, "y", "!r:x", "$1", v1Event("$1", "defer", 1), []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
		waitFor(t, "deferred", func() bool {
			p.mu.Lock()
			defer p.mu.Unlock()
			_, ok := p.deferred["!r:x"]
			return ok
		})
		p.Close()
		mu.Lock()
		got := calls
		mu.Unlock()
		if want := map[bool]int{false: 1, true: 0}[none]; got != want {
			t.Errorf("fallback none %v: %d nudges, want %d", none, got, want)
		}
	}
}
