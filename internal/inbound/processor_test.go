package inbound

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pduverify"
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
}

func (f *fakePersist) SendEvents(_ context.Context, _ string, entries []json.RawMessage) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errors.New("persister down")
	}
	f.sent = append(f.sent, entries...)
	return nil
}

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
