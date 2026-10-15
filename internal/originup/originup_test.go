package originup

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"
)

type fakePub struct {
	mu    sync.Mutex
	lines []string
	err   error
}

func (p *fakePub) Publish(_ context.Context, channel, line string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.err != nil {
		return p.err
	}
	p.lines = append(p.lines, channel+": "+line)
	return nil
}

func (p *fakePub) list() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.lines...)
}

// fakeMain stands in for Synapse's main process. status is reset_connection's
// answer; gate, when set, holds every reset until closed.
type fakeMain struct {
	mu     sync.Mutex
	paths  []string
	status int
	body   string
	admin  bool
	gate   chan struct{}
}

func (m *fakeMain) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	gate := m.gate
	m.mu.Unlock()
	if r.Header.Get("Authorization") != "Bearer tok" {
		w.WriteHeader(401)
		_, _ = io.WriteString(w, `{"errcode":"M_UNKNOWN_TOKEN"}`)
		return
	}
	switch r.URL.Path {
	case "/_matrix/client/v3/account/whoami":
		_, _ = io.WriteString(w, `{"user_id":"@admin:hs"}`)
		return
	case "/_synapse/admin/v1/users/@admin:hs/admin":
		if m.admin {
			_, _ = io.WriteString(w, `{"admin":true}`)
		} else {
			_, _ = io.WriteString(w, `{"admin":false}`)
		}
		return
	}
	if gate != nil {
		<-gate
	}
	m.mu.Lock()
	m.paths = append(m.paths, r.Method+" "+r.URL.EscapedPath())
	status, body := m.status, m.body
	m.mu.Unlock()
	if status == 0 {
		status = 200
	}
	if body == "" {
		body = `{}`
	}
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func (m *fakeMain) calls() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]string(nil), m.paths...)
}

func setup(t *testing.T, m *fakeMain, pub *fakePub, token string) *Resetter {
	srv := httptest.NewServer(m)
	t.Cleanup(srv.Close)
	return New(Options{AdminAPI: srv.URL, AccessToken: token, Channel: "hs", Publisher: pub, Log: zerolog.Nop()})
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestResetCallsSynapseThenPublishes(t *testing.T) {
	m, pub := &fakeMain{}, &fakePub{}
	r := setup(t, m, pub, "tok")
	r.Reset("down.example")
	waitFor(t, func() bool { return len(pub.list()) == 1 })
	if got := m.calls(); len(got) != 1 || got[0] != "POST /_synapse/admin/v1/federation/destinations/down.example/reset_connection" {
		t.Errorf("admin calls = %v", got)
	}
	if got := pub.list()[0]; got != "hs: REMOTE_SERVER_UP down.example" {
		t.Errorf("published %q", got)
	}
	if !r.Ready() {
		t.Error("not ready after a reset that worked")
	}
}

// Someone reset it since we read it, and they told everyone.
func TestAlreadyUpIsNotPublished(t *testing.T) {
	m := &fakeMain{status: 400, body: `{"errcode":"M_UNKNOWN","error":"The retry timing does not need to be reset for this destination."}`}
	pub := &fakePub{}
	r := setup(t, m, pub, "tok")
	r.Reset("down.example")
	waitFor(t, func() bool { return len(m.calls()) == 1 })
	time.Sleep(50 * time.Millisecond)
	if len(pub.list()) != 0 {
		t.Errorf("published for an origin already up: %v", pub.list())
	}
	if !r.Ready() {
		t.Error("already up counted as a failure")
	}
}

func TestFailureMakesItUnready(t *testing.T) {
	for name, tc := range map[string]struct {
		m   *fakeMain
		pub *fakePub
	}{
		"admin api error": {&fakeMain{status: 500}, &fakePub{}},
		"publish error":   {&fakeMain{}, &fakePub{err: errors.New("redis down")}},
	} {
		t.Run(name, func(t *testing.T) {
			r := setup(t, tc.m, tc.pub, "tok")
			now := time.Unix(1000, 0)
			r.now = func() time.Time { return now }
			r.Reset("down.example")
			waitFor(t, func() bool { return !r.Ready() })
			now = now.Add(failureHold)
			if !r.Ready() {
				t.Error("still unready after the hold")
			}
		})
	}
}

// A reset already running is not repeated.
func TestResetIsNotRepeatedWhileRunning(t *testing.T) {
	m, pub := &fakeMain{gate: make(chan struct{})}, &fakePub{}
	r := setup(t, m, pub, "tok")
	for range 5 {
		r.Reset("down.example")
	}
	close(m.gate)
	waitFor(t, func() bool { return len(pub.list()) == 1 })
	time.Sleep(50 * time.Millisecond)
	if n := len(m.calls()); n != 1 {
		t.Errorf("%d admin calls, want 1", n)
	}
}

func TestCheck(t *testing.T) {
	if err := setup(t, &fakeMain{admin: true}, &fakePub{}, "tok").Check(context.Background()); err != nil {
		t.Errorf("admin token: %v", err)
	}
	if err := setup(t, &fakeMain{admin: false}, &fakePub{}, "tok").Check(context.Background()); err == nil {
		t.Error("a non-admin token passed")
	}
	if err := setup(t, &fakeMain{admin: true}, &fakePub{}, "wrong").Check(context.Background()); err == nil {
		t.Error("a wrong token passed")
	}
}
