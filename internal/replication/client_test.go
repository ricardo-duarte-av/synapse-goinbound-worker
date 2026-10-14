package replication

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/synapsecfg"
)

// writer is a fake stream writer listening on a unix socket, as the Synapse
// workers here do.
type writer struct {
	mu       sync.Mutex
	paths    []string
	auth     []string
	bodies   []string
	statuses []int // returned in order; 200 once exhausted
}

func (w *writer) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	w.mu.Lock()
	w.paths = append(w.paths, r.URL.EscapedPath())
	w.auth = append(w.auth, r.Header.Get("Authorization"))
	w.bodies = append(w.bodies, string(b))
	status := http.StatusOK
	if len(w.statuses) > 0 {
		status, w.statuses = w.statuses[0], w.statuses[1:]
	}
	w.mu.Unlock()
	rw.WriteHeader(status)
	_, _ = rw.Write([]byte(`{"_INT_STREAM_POS":{}}`))
}

func serve(t *testing.T, h http.Handler) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "w.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: h}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

func client(sock, secret string) *Client {
	c := NewClient(&synapsecfg.Config{
		ReplicationSecret: secret,
		InstanceMap: map[string]synapsecfg.Instance{
			"av-edu-worker": {Name: "av-edu-worker", Socket: sock},
			"master":        {Name: "master", Socket: sock},
		},
	})
	c.sleep = func(context.Context, time.Duration) error { return nil }
	return c
}

func TestSendEDUWireFormat(t *testing.T) {
	w := &writer{}
	c := client(serve(t, w), "s3cret")

	content := json.RawMessage(`{"room_id":"!r:x","typing":true}`)
	if err := c.SendEDU(context.Background(), "av-edu-worker", "m.typing", "remote.example", content); err != nil {
		t.Fatal(err)
	}

	// POST /_synapse/replication/fed_send_edu/<quoted edu_type>/<txn_id>
	parts := strings.Split(w.paths[0], "/")
	if len(parts) != 6 || parts[1] != "_synapse" || parts[2] != "replication" || parts[3] != "fed_send_edu" {
		t.Fatalf("path = %s", w.paths[0])
	}
	if parts[4] != "m.typing" {
		t.Errorf("edu_type path segment = %q", parts[4])
	}
	if len(parts[5]) != 10 {
		t.Errorf("txn_id = %q, want Synapse's random_string(10)", parts[5])
	}
	if w.auth[0] != "Bearer s3cret" {
		t.Errorf("Authorization = %q", w.auth[0])
	}

	var body struct {
		Origin  string          `json:"origin"`
		Content json.RawMessage `json:"content"`
	}
	if err := json.Unmarshal([]byte(w.bodies[0]), &body); err != nil {
		t.Fatal(err)
	}
	if body.Origin != "remote.example" || string(body.Content) != string(content) {
		t.Errorf("body = %s", w.bodies[0])
	}
	if strings.Contains(w.bodies[0], "_INT_STREAM_POS") {
		t.Error("stream positions were sent; this process writes nothing, so it has none to wait for")
	}
}

func TestNoSecretNoAuthorization(t *testing.T) {
	w := &writer{}
	c := client(serve(t, w), "")
	if err := c.SendEDU(context.Background(), "master", "m.receipt", "r.example", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if w.auth[0] != "" {
		t.Errorf("sent Authorization %q without a configured secret", w.auth[0])
	}
}

// "main" is how the yaml names the main process; it must reach "master".
func TestMainIsMaster(t *testing.T) {
	w := &writer{}
	c := client(serve(t, w), "")
	if !c.Has("main") {
		t.Fatal(`Has("main") = false`)
	}
	if err := c.SendEDU(context.Background(), "main", "x.custom", "r.example", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
}

// A 504 is retried with the SAME txn_id, so the writer's ResponseCache makes
// the retry a no-op if the first attempt did land.
func TestTimeoutIsRetriedWithTheSameTxnID(t *testing.T) {
	w := &writer{statuses: []int{http.StatusGatewayTimeout, http.StatusGatewayTimeout}}
	c := client(serve(t, w), "")
	if err := c.SendEDU(context.Background(), "master", "m.direct_to_device", "r.example", json.RawMessage(`{}`)); err != nil {
		t.Fatal(err)
	}
	if len(w.paths) != 3 {
		t.Fatalf("%d attempts, want 3", len(w.paths))
	}
	if w.paths[0] != w.paths[1] || w.paths[1] != w.paths[2] {
		t.Errorf("retries changed the txn_id: %v", w.paths)
	}
}

func TestServerErrorIsNotRetried(t *testing.T) {
	w := &writer{statuses: []int{http.StatusInternalServerError}}
	c := client(serve(t, w), "")
	err := c.SendEDU(context.Background(), "master", "m.receipt", "r.example", json.RawMessage(`{}`))
	var he *HTTPError
	if !errors.As(err, &he) || he.Status != 500 {
		t.Fatalf("err = %v, want HTTP 500", err)
	}
	if len(w.paths) != 1 {
		t.Errorf("%d attempts at a 500, want 1", len(w.paths))
	}
}

func TestConnectErrorsAreRetriedThenGiveUp(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nobody-home.sock")
	c := client(missing, "")
	var slept []time.Duration
	c.sleep = func(_ context.Context, d time.Duration) error { slept = append(slept, d); return nil }

	if err := c.SendEDU(context.Background(), "master", "m.receipt", "r.example", json.RawMessage(`{}`)); err == nil {
		t.Fatal("sending to a socket nobody listens on succeeded")
	}
	want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second}
	if len(slept) != len(want) {
		t.Fatalf("backoff = %v, want %v", slept, want)
	}
	for i := range want {
		if slept[i] != want[i] {
			t.Fatalf("backoff = %v, want %v", slept, want)
		}
	}
}

func TestUnknownInstance(t *testing.T) {
	c := client("/nonexistent", "")
	if err := c.SendEDU(context.Background(), "nobody", "m.typing", "r", json.RawMessage(`{}`)); err == nil {
		t.Error("forwarded to an instance that is not in instance_map")
	}
}

func TestQuoteIsPythonQuoteSafeEmpty(t *testing.T) {
	cases := map[string]string{
		"m.typing":                      "m.typing",
		"org.matrix.signing_key_update": "org.matrix.signing_key_update",
		"a/b c:d~e":                     "a%2Fb%20c%3Ad~e",
	}
	for in, want := range cases {
		if got := quote(in); got != want {
			t.Errorf("quote(%q) = %q, want %q", in, got, want)
		}
	}
}
