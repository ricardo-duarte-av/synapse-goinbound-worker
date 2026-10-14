package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/config"
)

// TestForwardPreservesRequestURI is the load-bearing test of the proxy.
//
// A Matrix server-server request is signed over its URI, so if any part of the
// chain re-encodes the path the signature breaks and Synapse returns 401 for
// every request. These cases cover the characters that actually appear in room
// and event IDs.
func TestForwardPreservesRequestURI(t *testing.T) {
	cases := []struct {
		name string
		uri  string
	}{
		{
			name: "percent encoded room id",
			uri:  "/_matrix/federation/v1/state/%21abcdef%3Aexample.com?event_id=%24evt",
		},
		{
			name: "literal sigil and colon in room id",
			uri:  "/_matrix/federation/v1/state/!abcdef:example.com?event_id=$evt",
		},
		{
			name: "base64 event id with plus and slash",
			uri:  "/_matrix/federation/v1/event/%24abc%2Bdef%2Fghi",
		},
		{
			name: "encoded hash in room id",
			uri:  "/_matrix/federation/v1/state_ids/%23alias%3Aexample.com?event_id=%24a",
		},
		{
			name: "encoded space and unicode",
			uri:  "/_matrix/federation/v1/event/%24a%20b%C3%A9c",
		},
		{
			name: "empty query value",
			uri:  "/_matrix/federation/v1/state/%21r%3Aex.com?event_id=",
		},
		{
			name: "repeated query keys preserved in order",
			uri:  "/_matrix/federation/v1/state/%21r%3Aex.com?event_id=%241&event_id=%242",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotURI := make(chan string, 1)
			gotAuth := make(chan string, 1)
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotURI <- r.URL.RequestURI()
				gotAuth <- r.Header.Get("Authorization")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"ok":true}`))
			}))
			defer upstream.Close()

			p := newTestProxy(t, strings.TrimPrefix(upstream.URL, "http://"))
			front := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				p.Forward(w, r, 0)
			}))
			defer front.Close()

			const auth = `X-Matrix origin="a.example",destination="b.example",key="ed25519:1",sig="AAAA"`
			status := rawRequest(t, front.Listener.Addr().String(), tc.uri, auth)

			if status != 200 {
				t.Fatalf("status = %d, want 200", status)
			}
			if got := <-gotURI; got != tc.uri {
				t.Errorf("upstream URI\n got: %q\nwant: %q", got, tc.uri)
			}
			if got := <-gotAuth; got != auth {
				t.Errorf("upstream Authorization\n got: %q\nwant: %q", got, auth)
			}
		})
	}
}

func TestForwardCapturesBody(t *testing.T) {
	const body = `{"pdu_ids":["$a","$b"],"auth_chain_ids":["$c"]}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer upstream.Close()

	p := newTestProxy(t, strings.TrimPrefix(upstream.URL, "http://"))

	t.Run("captures full body within limit", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/_matrix/federation/v1/state_ids/%21r%3Aex", nil)
		res := p.Forward(rec, req, 1024)

		if res.Status != 200 {
			t.Fatalf("status = %d", res.Status)
		}
		if string(res.Body) != body {
			t.Errorf("captured body = %q, want %q", res.Body, body)
		}
		if res.Truncated {
			t.Error("Truncated = true, want false")
		}
		if rec.Body.String() != body {
			t.Errorf("client body = %q, want %q", rec.Body.String(), body)
		}
		if res.Bytes != int64(len(body)) {
			t.Errorf("Bytes = %d, want %d", res.Bytes, len(body))
		}
	})

	t.Run("marks truncation past the limit", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/_matrix/federation/v1/state_ids/%21r%3Aex", nil)
		res := p.Forward(rec, req, 10)

		if !res.Truncated {
			t.Error("Truncated = false, want true")
		}
		if len(res.Body) != 10 {
			t.Errorf("captured %d bytes, want 10", len(res.Body))
		}
		// The client must still receive the whole body regardless of capture.
		if rec.Body.String() != body {
			t.Errorf("client body = %q, want full body", rec.Body.String())
		}
	})

	t.Run("no capture by default", func(t *testing.T) {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/_matrix/federation/v1/state_ids/%21r%3Aex", nil)
		res := p.Forward(rec, req, 0)
		if res.Body != nil {
			t.Errorf("Body = %q, want nil", res.Body)
		}
	})
}

func TestForwardPropagatesUpstreamStatus(t *testing.T) {
	// Synapse returns 404 with an empty body for an unknown event, and 403 with
	// a JSON error for an unauthorised one. Both must pass through unchanged.
	for _, tc := range []struct {
		status int
		body   string
	}{
		{http.StatusNotFound, ""},
		{http.StatusForbidden, `{"errcode":"M_FORBIDDEN","error":"Host not in room."}`},
		{http.StatusUnauthorized, `{"errcode":"M_UNAUTHORIZED"}`},
	} {
		t.Run(fmt.Sprint(tc.status), func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer upstream.Close()

			p := newTestProxy(t, strings.TrimPrefix(upstream.URL, "http://"))
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/_matrix/federation/v1/event/%24a", nil)
			res := p.Forward(rec, req, 0)

			if res.Status != tc.status {
				t.Errorf("Status = %d, want %d", res.Status, tc.status)
			}
			if rec.Code != tc.status {
				t.Errorf("client status = %d, want %d", rec.Code, tc.status)
			}
			if rec.Body.String() != tc.body {
				t.Errorf("client body = %q, want %q", rec.Body.String(), tc.body)
			}
			if res.Err != nil {
				t.Errorf("Err = %v, want nil", res.Err)
			}
		})
	}
}

func TestForwardReportsUnreachableUpstream(t *testing.T) {
	// Bind and immediately close, so the port is almost certainly dead.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	p := newTestProxy(t, addr)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/_matrix/federation/v1/event/%24a", nil)
	res := p.Forward(rec, req, 0)

	if res.Err == nil {
		t.Error("Err = nil, want an error for an unreachable upstream")
	}
	if res.Status != http.StatusBadGateway {
		t.Errorf("Status = %d, want 502", res.Status)
	}
}

func TestForwardOverUnixSocket(t *testing.T) {
	// The real deployment talks to Synapse over unix sockets, so cover that path.
	dir := t.TempDir()
	sock := dir + "/upstream.sock"
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	const uri = "/_matrix/federation/v1/state/%21r%3Aex.com?event_id=%24e"
	gotURI := make(chan string, 1)
	go func() {
		_ = http.Serve(l, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotURI <- r.URL.RequestURI()
			_, _ = w.Write([]byte("{}"))
		}))
	}()

	p, err := New(config.Upstream{Sockets: []string{sock}}, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	res := p.Forward(rec, httptest.NewRequest(http.MethodGet, uri, nil), 0)

	if res.Status != 200 {
		t.Fatalf("status = %d, want 200", res.Status)
	}
	select {
	case got := <-gotURI:
		if got != uri {
			t.Errorf("upstream URI = %q, want %q", got, uri)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("upstream never received the request")
	}
}

func TestPickRoundRobins(t *testing.T) {
	p, err := New(config.Upstream{Addrs: []string{"a:1", "b:2", "c:3"}}, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for range 6 {
		got = append(got, p.pick().name)
	}
	want := []string{"a:1", "b:2", "c:3", "a:1", "b:2", "c:3"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("pick sequence = %v, want %v", got, want)
		}
	}
}

func newTestProxy(t *testing.T, addr string) *Proxy {
	t.Helper()
	p, err := New(config.Upstream{Addrs: []string{addr}}, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// rawRequest sends a hand-built HTTP request so the target URI reaches the
// proxy exactly as written, bypassing any client-side URL normalisation.
func rawRequest(t *testing.T, addr, uri, auth string) int {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: fed.example\r\nAuthorization: %s\r\nConnection: close\r\n\r\n", uri, auth)
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatal(err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func TestForwardMarksClientCancellation(t *testing.T) {
	// Remote servers hang up on slow /state requests routinely. When that
	// happens no status is ever written, and reporting it as status 0 would
	// pollute the metrics with a meaningless series.
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
		_, _ = w.Write([]byte("{}"))
	}))
	defer upstream.Close()
	defer close(release)

	p := newTestProxy(t, strings.TrimPrefix(upstream.URL, "http://"))

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/_matrix/federation/v1/state/%21r%3Aex", nil).WithContext(ctx)

	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	res := p.Forward(httptest.NewRecorder(), req, 0)

	if !res.Canceled {
		t.Errorf("Canceled = false, want true (status was %d)", res.Status)
	}
	if res.Err != nil {
		t.Errorf("Err = %v, want nil: a client hang-up is not our error", res.Err)
	}
}

// A /send body buffered for verification must reach Synapse whole: the
// signature covers it, and Synapse verifies it again.
func TestForwardReplaysBufferedBody(t *testing.T) {
	var got string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
		w.WriteHeader(http.StatusOK)
	}))
	defer up.Close()

	p, err := New(config.Upstream{Addrs: []string{strings.TrimPrefix(up.URL, "http://")}}, zerolog.Nop())
	if err != nil {
		t.Fatal(err)
	}
	body := `{"edus":[{"edu_type":"m.typing","content":{}}]}`
	in := httptest.NewRequest(http.MethodPut, "/_matrix/federation/v1/send/t1", strings.NewReader(body))
	b, _ := io.ReadAll(in.Body)
	in.Body = io.NopCloser(strings.NewReader(string(b)))
	in.ContentLength = int64(len(b))

	if res := p.Forward(httptest.NewRecorder(), in, 0); res.Status != http.StatusOK {
		t.Fatalf("status %d", res.Status)
	}
	if got != body {
		t.Errorf("upstream got %q", got)
	}
}
