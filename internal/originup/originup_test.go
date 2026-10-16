package originup

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/inbound"
)

type fakeStore struct {
	mu   sync.Mutex
	next int64
	err  error
	gate chan struct{}
	seen []string
}

func (s *fakeStore) ResetDestination(_ context.Context, origin string) (inbound.CacheInvalidation, error) {
	if s.gate != nil {
		<-s.gate
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return inbound.CacheInvalidation{}, s.err
	}
	s.next++
	s.seen = append(s.seen, origin)
	return inbound.CacheInvalidation{StreamID: 100 + s.next, Instance: "goinbound-worker",
		CacheFunc: inbound.CacheRetryTimings, Keys: []string{origin}, InvalidationTS: 1700000000000}, nil
}

type fakePub struct {
	mu    sync.Mutex
	lines []string
	// fail fails publishes whose line starts with it.
	fail string
}

func (p *fakePub) Publish(_ context.Context, line string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.fail != "" && strings.HasPrefix(line, p.fail) {
		return errors.New("bus down")
	}
	p.lines = append(p.lines, line)
	return nil
}

func (p *fakePub) list() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.lines...)
}

func setup(s *fakeStore, p *fakePub) *Resetter {
	r := New(Options{Store: s, Publisher: p, Instance: "goinbound-worker", Log: zerolog.Nop()})
	r.retryDelay = time.Millisecond
	return r
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// The reset, then its row on the caches stream, then REMOTE_SERVER_UP, in
// Synapse's wire format.
func TestResetPublishesInvalidationThenServerUp(t *testing.T) {
	s, p := &fakeStore{}, &fakePub{}
	r := setup(s, p)
	r.Reset("down.example", "")
	waitFor(t, func() bool { return len(p.list()) == 2 })
	want := []string{
		`RDATA caches goinbound-worker 101 ["get_destination_retry_timings",["down.example"],1700000000000]`,
		`REMOTE_SERVER_UP down.example`,
	}
	for i, l := range p.list() {
		if l != want[i] {
			t.Errorf("line %d = %s\nwant      %s", i, l, want[i])
		}
	}
	if !r.Ready() {
		t.Error("not ready after a reset that worked")
	}
}

func TestDatabaseErrorPublishesNothing(t *testing.T) {
	s, p := &fakeStore{err: errors.New("db down")}, &fakePub{}
	r := setup(s, p)
	now := time.Unix(1000, 0)
	r.now = func() time.Time { return now }
	r.Reset("down.example", "")
	waitFor(t, func() bool { return !r.Ready() })
	if len(p.list()) != 0 {
		t.Errorf("published after a failed reset: %v", p.list())
	}
	now = now.Add(failureHold)
	if !r.Ready() {
		t.Error("still unready after the hold")
	}
}

// An RDATA that never reached the bus is announced by a POSITION before
// the next one, so every process reads the row from the database.
func TestLostRDATAIsAnnouncedByPosition(t *testing.T) {
	s, p := &fakeStore{}, &fakePub{fail: "RDATA"}
	r := setup(s, p)
	r.Reset("a.example", "")
	waitFor(t, func() bool { return !r.Ready() })
	r.mu.Lock()
	r.failedAt = time.Time{}
	r.mu.Unlock()
	waitFor(t, func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return !r.inflight["a.example"]
	})

	p.mu.Lock()
	p.fail = ""
	p.mu.Unlock()
	r.Reset("b.example", "")
	waitFor(t, func() bool { return len(p.list()) == 3 })
	got := p.list()
	if got[0] != "POSITION caches goinbound-worker 101 101" || !strings.HasPrefix(got[1], "RDATA caches goinbound-worker 102 ") {
		t.Errorf("published %v", got)
	}
}

// A REPLICATE is answered with our caches position, once we have one.
func TestReplicateIsAnsweredWithOurPosition(t *testing.T) {
	s, p := &fakeStore{}, &fakePub{}
	r := setup(s, p)
	r.OnReplicate()
	if len(p.list()) != 0 {
		t.Fatalf("announced a position before writing anything: %v", p.list())
	}
	r.Reset("down.example", "")
	waitFor(t, func() bool { return len(p.list()) == 2 })
	r.OnReplicate()
	if got := p.list(); got[2] != "POSITION caches goinbound-worker 101 101" {
		t.Errorf("answer = %q", got[2])
	}
}

// A process drops RDATA at or below the last token it saw from us, so
// concurrent resets publish in stream ID order.
func TestConcurrentResetsPublishInOrder(t *testing.T) {
	s, p := &fakeStore{}, &fakePub{}
	r := setup(s, p)
	for i := range 20 {
		r.Reset("o"+strconv.Itoa(i)+".example", "")
	}
	waitFor(t, func() bool { return len(p.list()) == 40 })
	last := int64(0)
	for _, l := range p.list() {
		if !strings.HasPrefix(l, "RDATA") {
			continue
		}
		id, _ := strconv.ParseInt(strings.Fields(l)[3], 10, 64)
		if id <= last {
			t.Fatalf("RDATA %d after %d", id, last)
		}
		last = id
	}
}

func TestResetIsNotRepeatedWhileRunning(t *testing.T) {
	s, p := &fakeStore{gate: make(chan struct{})}, &fakePub{}
	r := setup(s, p)
	for range 5 {
		r.Reset("down.example", "")
	}
	close(s.gate)
	waitFor(t, func() bool { return len(p.list()) == 2 })
	time.Sleep(20 * time.Millisecond)
	if len(s.seen) != 1 {
		t.Errorf("%d resets, want 1", len(s.seen))
	}
}
