package txn

import (
	"strings"
	"sync"
	"testing"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/config"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/store"
)

type fakeOriginUp struct {
	mu     sync.Mutex
	ready  bool
	resets []string
}

func (f *fakeOriginUp) Ready() bool { return f.ready }
func (f *fakeOriginUp) Reset(origin string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resets = append(f.resets, origin)
}

// With origin_up, an origin in backoff is served here and marked as up, as
// Synapse marks it on any signed request (transport/server/_base.py:143).
func TestOriginInBackoffIsServedAndMarkedUp(t *testing.T) {
	r := newRig(t, config.Mode{Kind: config.ModeNative})
	up := &fakeOriginUp{ready: true}
	r.h.originUp = up
	r.store.state["down.example"] = store.TxnState{RetryLastTS: 12345}
	rec := send(t, r.h, "down.example", "t1", eduOnly)
	if rec.Code != 200 || r.up.count() != 0 {
		t.Fatalf("answer %d %s, Synapse got %d; want ours", rec.Code, rec.Body, r.up.count())
	}
	if len(up.resets) != 1 || up.resets[0] != "down.example" {
		t.Errorf("resets = %v, want [down.example]", up.resets)
	}

	// A transaction already answered marks the origin too: Synapse resets
	// before it looks at the transaction.
	r.store.state["down.example"] = store.TxnState{RetryLastTS: 12345, Previous: &store.StoredResponse{Code: 200, JSON: []byte(`{"pdus":{}}`)}}
	send(t, r.h, "down.example", "t2", eduOnly)
	if len(up.resets) != 2 {
		t.Errorf("a stored answer did not mark the origin as up: %v", up.resets)
	}

	// An origin not in backoff is not reset.
	send(t, r.h, "remote.example", "t3", eduOnly)
	if len(up.resets) != 2 {
		t.Errorf("an origin not in backoff was reset: %v", up.resets)
	}
}

// While resets fail, Synapse's worker gets the transaction and resets the
// origin itself.
func TestOriginInBackoffProxiedWhileResetsFail(t *testing.T) {
	r := newRig(t, config.Mode{Kind: config.ModeNative})
	up := &fakeOriginUp{ready: false}
	r.h.originUp = up
	r.store.state["down.example"] = store.TxnState{RetryLastTS: 12345}
	rec := send(t, r.h, "down.example", "t1", eduOnly)
	if r.up.count() != 1 || !strings.Contains(rec.Body.String(), `"from":"synapse"`) {
		t.Fatalf("not proxied: %d %s", rec.Code, rec.Body)
	}
	if len(up.resets) != 0 {
		t.Errorf("reset although proxied: %v", up.resets)
	}
}
