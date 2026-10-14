package acl

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/store"
)

type fakeLookup struct {
	events map[string]*store.ServerACLEvent
	calls  int
	err    error
}

func (f *fakeLookup) CurrentServerACL(_ context.Context, roomID string) (*store.ServerACLEvent, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.events[roomID], nil
}

func aclEvent(id, content string) *store.ServerACLEvent {
	return &store.ServerACLEvent{EventID: id, JSON: []byte(`{"type":"m.room.server_acl","content":` + content + `}`)}
}

func TestCheckerAppliesTheRoomsACL(t *testing.T) {
	db := &fakeLookup{events: map[string]*store.ServerACLEvent{
		"!acl:x": aclEvent("$1", `{"allow":["*"],"deny":["evil.example"]}`),
	}}
	c := NewChecker(db, time.Minute)

	if ok, err := c.Allowed(context.Background(), "evil.example", "!acl:x"); err != nil || ok {
		t.Errorf("denied server: %v, %v", ok, err)
	}
	if ok, err := c.Allowed(context.Background(), "good.example", "!acl:x"); err != nil || !ok {
		t.Errorf("allowed server: %v, %v", ok, err)
	}
	// No ACL event, or an unknown room: no restriction.
	if ok, err := c.Allowed(context.Background(), "evil.example", "!none:x"); err != nil || !ok {
		t.Errorf("room without ACL: %v, %v", ok, err)
	}
}

func TestCheckerCachesForTTL(t *testing.T) {
	db := &fakeLookup{events: map[string]*store.ServerACLEvent{}}
	c := NewChecker(db, 5*time.Second)
	now := time.Unix(1000, 0)
	c.now = func() time.Time { return now }

	_, _ = c.Allowed(context.Background(), "a", "!r:x")
	_, _ = c.Allowed(context.Background(), "b", "!r:x")
	if db.calls != 1 {
		t.Errorf("%d lookups within the TTL, want 1", db.calls)
	}

	// The room gains an ACL; it takes effect once the entry expires.
	db.events["!r:x"] = aclEvent("$2", `{"allow":[]}`)
	now = now.Add(6 * time.Second)
	if ok, _ := c.Allowed(context.Background(), "a", "!r:x"); ok {
		t.Error("a new ban-everyone ACL did not take effect after the TTL")
	}
	if db.calls != 2 {
		t.Errorf("%d lookups, want 2", db.calls)
	}
}

// A redacted ACL bans everyone in Synapse's eyes -- if the redaction applies,
// which depends on room version rules. Too consequential to guess.
func TestRedactedACLIsUncertain(t *testing.T) {
	ev := aclEvent("$3", `{"allow":["*"]}`)
	ev.Redacted = true
	c := NewChecker(&fakeLookup{events: map[string]*store.ServerACLEvent{"!r:x": ev}}, time.Minute)
	if _, err := c.Allowed(context.Background(), "a", "!r:x"); !errors.Is(err, ErrUncertain) {
		t.Errorf("err = %v, want ErrUncertain", err)
	}
}

func TestCheckerDoesNotCacheErrors(t *testing.T) {
	db := &fakeLookup{err: errors.New("db down")}
	c := NewChecker(db, time.Minute)
	if _, err := c.Allowed(context.Background(), "a", "!r:x"); err == nil {
		t.Fatal("a database error was swallowed")
	}
	db.err = nil
	db.events = map[string]*store.ServerACLEvent{}
	if ok, err := c.Allowed(context.Background(), "a", "!r:x"); err != nil || !ok {
		t.Errorf("after recovery: %v, %v", ok, err)
	}
}

func TestServerHost(t *testing.T) {
	cases := map[string]string{
		"example.com":      "example.com",
		"example.com:8448": "example.com",
		"1.2.3.4:8448":     "1.2.3.4",
		"[::1]":            "[::1]",
		"[::1]:8448":       "[::1]",
	}
	for in, want := range cases {
		if got := ServerHost(in); got != want {
			t.Errorf("ServerHost(%q) = %q, want %q", in, got, want)
		}
	}
}
