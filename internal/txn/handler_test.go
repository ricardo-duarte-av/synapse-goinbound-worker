package txn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/rs/zerolog"
	"maunium.net/go/mautrix"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/config"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/edu"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/fedauth"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/proxy"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/store"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/synapsecfg"
)

// fakeVerifier accepts a request whose X-Matrix origin is not "forged.example",
// and checks it got the whole body.
type fakeVerifier struct{ calls atomic.Int32 }

func (f *fakeVerifier) Verify(r *http.Request) fedauth.Result {
	f.calls.Add(1)
	_, _ = io.ReadAll(r.Body)
	origin := ""
	if i := strings.Index(r.Header.Get("Authorization"), `origin="`); i >= 0 {
		rest := r.Header.Get("Authorization")[i+len(`origin="`):]
		origin = rest[:strings.IndexByte(rest, '"')]
	}
	if origin == "" || origin == "forged.example" {
		return fedauth.Result{Err: &mautrix.RespError{ErrCode: "M_UNAUTHORIZED", StatusCode: 401}}
	}
	return fedauth.Result{Origin: origin}
}

// fakeUpstream stands in for the Python inbound worker.
type fakeUpstream struct {
	mu     sync.Mutex
	bodies []string
	uris   []string
	status int
	// gate, when set, blocks each forward until it is closed.
	gate chan struct{}
	// onForward runs at the start of each forward.
	onForward func()
}

func (f *fakeUpstream) Forward(w http.ResponseWriter, r *http.Request, _ int64) proxy.Result {
	if f.onForward != nil {
		f.onForward()
	}
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.bodies = append(f.bodies, string(b))
	f.uris = append(f.uris, r.RequestURI)
	status := f.status
	gate := f.gate
	f.mu.Unlock()
	if gate != nil {
		<-gate
	}
	if status == 0 {
		status = http.StatusOK
	}
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"pdus":{},"from":"synapse"}`))
	return proxy.Result{Status: status}
}

func (f *fakeUpstream) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.bodies)
}

type fakeStore struct {
	mu    sync.Mutex
	state map[string]store.TxnState // by origin
	err   error
	calls int
}

func (f *fakeStore) GetTxnState(_ context.Context, origin, _ string) (store.TxnState, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return store.TxnState{}, f.err
	}
	return f.state[origin], nil
}

type allowAll struct{}

func (allowAll) Allowed(context.Context, string, string) (bool, error) { return true, nil }

type sender struct {
	mu   sync.Mutex
	sent []string
	fail atomic.Bool
}

func (s *sender) SendEDU(_ context.Context, instance, eduType, origin string, content json.RawMessage) error {
	if s.fail.Load() {
		return errors.New("writer down")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sent = append(s.sent, instance+" "+eduType+" "+origin)
	return nil
}

func (s *sender) list() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.sent...)
}

type rig struct {
	h        *Handler
	verifier *fakeVerifier
	up       *fakeUpstream
	store    *fakeStore
	sender   *sender
}

func newRig(t *testing.T, mode config.Mode) *rig {
	t.Helper()
	r := &rig{
		verifier: &fakeVerifier{},
		up:       &fakeUpstream{},
		store:    &fakeStore{state: map[string]store.TxnState{}},
		sender:   &sender{},
	}
	router := edu.NewRouter(synapsecfg.Writers{
		Typing: []string{"edu-w"}, Receipts: []string{"edu-w"}, ToDevice: []string{"edu-w"},
		Presence: []string{"edu-w"}, DeviceLists: []string{"edu-w"}, Events: []string{"p"},
	})
	proc := edu.NewProcessor(router, allowAll{}, r.sender, false, zerolog.Nop())
	r.h = NewHandler(Options{
		EDUMode:        mode,
		Verifier:       r.verifier,
		Upstream:       r.up,
		Store:          r.store,
		EDUs:           proc,
		MaxBody:        1 << 20,
		ForwardTimeout: 5 * time.Second,
		Log:            zerolog.Nop(),
	})
	t.Cleanup(r.h.Close)
	return r
}

const eduOnly = `{"origin":"remote.example","pdus":[],"edus":[
	{"edu_type":"m.typing","content":{"room_id":"!r:x","user_id":"@u:remote.example","typing":true}},
	{"edu_type":"m.presence","content":{"push":[]}},
	{"edu_type":"m.receipt","content":{"!r:x":{"m.read":{}}}}]}`

const withPDU = `{"origin":"remote.example","pdus":[{"type":"m.room.message"}],"edus":[]}`

func send(t *testing.T, h http.Handler, origin, txnID, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, "/_matrix/federation/v1/send/"+txnID, strings.NewReader(body))
	req.Header.Set("Authorization", `X-Matrix origin="`+origin+`",key="ed25519:a",sig="x"`)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestNativeForwardsEDUsAndAnswers(t *testing.T) {
	r := newRig(t, config.Mode{Kind: config.ModeNative})
	rec := send(t, r.h, "remote.example", "t1", eduOnly)

	if rec.Code != 200 || rec.Body.String() != `{"pdus":{}}` {
		t.Fatalf("answer = %d %s", rec.Code, rec.Body)
	}
	if r.up.count() != 0 {
		t.Error("an EDU-only transaction reached Synapse")
	}
	got := r.sender.list()
	// Presence is dropped (track_presence off); typing and receipt forwarded.
	if len(got) != 2 {
		t.Fatalf("forwarded %v, want typing and receipt only", got)
	}
	for _, s := range got {
		if !strings.HasPrefix(s, "edu-w ") || !strings.HasSuffix(s, " remote.example") {
			t.Errorf("forward %q: wrong instance or origin", s)
		}
	}
}

// Everything that is not a clean EDU-only transaction is Synapse's, and
// reaches it byte for byte.
func TestNativeProxiesWhatItDoesNotHandle(t *testing.T) {
	cases := []struct {
		name, origin, body string
		state              store.TxnState
	}{
		{"has PDUs", "remote.example", withPDU, store.TxnState{}},
		{"not an object", "remote.example", `[1,2]`, store.TxnState{}},
		{"edu without type", "remote.example", `{"edus":[{"content":{}}]}`, store.TxnState{}},
		{"edu content not an object", "remote.example", `{"edus":[{"edu_type":"m.typing","content":[]}]}`, store.TxnState{}},
		{"over the EDU limit", "remote.example", `{"edus":[` + strings.Repeat(`{"edu_type":"x","content":{}},`, 100) + `{"edu_type":"x","content":{}}]}`, store.TxnState{}},
		{"typing without room", "remote.example", `{"edus":[{"edu_type":"m.typing","content":{}}]}`, store.TxnState{}},
		{"auth fails", "forged.example", eduOnly, store.TxnState{}},
		{"origin in backoff", "down.example", eduOnly, store.TxnState{RetryLastTS: 12345}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, config.Mode{Kind: config.ModeNative})
			r.store.state[tc.origin] = tc.state
			rec := send(t, r.h, tc.origin, "t1", tc.body)
			if r.up.count() != 1 {
				t.Fatalf("Synapse got %d requests, want 1", r.up.count())
			}
			if r.up.bodies[0] != tc.body {
				t.Errorf("Synapse got a different body:\n%s", r.up.bodies[0])
			}
			if !strings.Contains(rec.Body.String(), `"from":"synapse"`) {
				t.Errorf("answer %q is not Synapse's", rec.Body)
			}
			if len(r.sender.list()) != 0 {
				t.Errorf("EDUs were forwarded for a proxied transaction: %v", r.sender.list())
			}
		})
	}
}

func TestDatabaseErrorProxies(t *testing.T) {
	r := newRig(t, config.Mode{Kind: config.ModeNative})
	r.store.err = errors.New("db down")
	send(t, r.h, "remote.example", "t1", eduOnly)
	if r.up.count() != 1 || len(r.sender.list()) != 0 {
		t.Error("a transaction whose state could not be read was not left to Synapse")
	}
}

// A transaction Synapse already answered gets Synapse's stored answer, as
// have_responded does (federation_server.py:400), and nothing is redone.
func TestStoredResponseIsReturned(t *testing.T) {
	r := newRig(t, config.Mode{Kind: config.ModeNative})
	r.store.state["remote.example"] = store.TxnState{Previous: &store.StoredResponse{Code: 200, JSON: []byte(`{"pdus":{"$e":{}}}`)}}
	rec := send(t, r.h, "remote.example", "t1", eduOnly)
	if rec.Code != 200 || rec.Body.String() != `{"pdus":{"$e":{}}}` {
		t.Errorf("answer = %d %s", rec.Code, rec.Body)
	}
	if len(r.sender.list()) != 0 || r.up.count() != 0 {
		t.Error("a transaction already answered was processed again")
	}
}

// A retry within 30s gets the first answer without reprocessing.
func TestRetryIsAnsweredFromCache(t *testing.T) {
	r := newRig(t, config.Mode{Kind: config.ModeNative})
	send(t, r.h, "remote.example", "t1", eduOnly)
	first := len(r.sender.list())
	rec := send(t, r.h, "remote.example", "t1", eduOnly)
	if rec.Code != 200 || len(r.sender.list()) != first {
		t.Errorf("retry: %d, forwarded %d more", rec.Code, len(r.sender.list())-first)
	}
}

// A forwarding failure is a 500 so the sender retries, and is not cached: the
// retry is actually retried.
func TestForwardFailureIsRetryable(t *testing.T) {
	r := newRig(t, config.Mode{Kind: config.ModeNative})
	r.sender.fail.Store(true)
	rec := send(t, r.h, "remote.example", "t1", eduOnly)
	if rec.Code != 500 || !strings.Contains(rec.Body.String(), "Error handing EDU of type") {
		t.Fatalf("answer = %d %s", rec.Code, rec.Body)
	}
	r.sender.fail.Store(false)
	rec = send(t, r.h, "remote.example", "t1", eduOnly)
	if rec.Code != 200 || len(r.sender.list()) == 0 {
		t.Errorf("the retry was answered from the failed attempt: %d %s", rec.Code, rec.Body)
	}
}

// One transaction per origin at a time -- across the native and proxied paths.
func TestConcurrentTransactionFromSameOriginIs429(t *testing.T) {
	r := newRig(t, config.Mode{Kind: config.ModeNative})
	gate := make(chan struct{})
	r.up.gate = gate

	done := make(chan *httptest.ResponseRecorder)
	go func() { done <- send(t, r.h, "remote.example", "slow", withPDU) }()
	waitFor(t, func() bool { return r.up.count() == 1 })

	rec := send(t, r.h, "remote.example", "next", eduOnly)
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("second transaction while one is proxied: %d, want 429", rec.Code)
	}
	// Another origin is unaffected.
	if rec := send(t, r.h, "other.example", "next", eduOnly); rec.Code != 200 {
		t.Errorf("other origin: %d", rec.Code)
	}

	close(gate)
	<-done
	if rec := send(t, r.h, "remote.example", "next", eduOnly); rec.Code != 200 {
		t.Errorf("after the first finished: %d", rec.Code)
	}
}

// A retry of the transaction in progress waits for it rather than being
// refused, and then gets its answer.
func TestRetryOfInProgressTransactionWaits(t *testing.T) {
	r := newRig(t, config.Mode{Kind: config.ModeNative})
	gate := make(chan struct{})
	r.up.gate = gate

	first := make(chan *httptest.ResponseRecorder)
	go func() { first <- send(t, r.h, "remote.example", "t1", withPDU) }()
	waitFor(t, func() bool { return r.up.count() == 1 })

	second := make(chan *httptest.ResponseRecorder)
	go func() { second <- send(t, r.h, "remote.example", "t1", withPDU) }()
	time.Sleep(20 * time.Millisecond)
	close(gate)

	if rec := <-first; rec.Code != 200 {
		t.Errorf("first: %d", rec.Code)
	}
	if rec := <-second; rec.Code != 200 {
		t.Errorf("retry: %d, want it to wait and succeed", rec.Code)
	}
}

func TestProxyModeTouchesNothing(t *testing.T) {
	r := newRig(t, config.Mode{Kind: config.ModeProxy})
	send(t, r.h, "remote.example", "t1", eduOnly)
	if r.up.count() != 1 || r.verifier.calls.Load() != 0 || r.store.calls != 0 || len(r.sender.list()) != 0 {
		t.Errorf("proxy mode did more than proxy: up=%d verify=%d db=%d sent=%d",
			r.up.count(), r.verifier.calls.Load(), r.store.calls, len(r.sender.list()))
	}
}

func TestNonSendIsProxied(t *testing.T) {
	r := newRig(t, config.Mode{Kind: config.ModeNative})
	for _, target := range []string{
		"/_matrix/federation/v2/send/t1",
		"/_matrix/federation/v1/send/",
		"/_matrix/federation/v1/send/a/b",
		"/_matrix/federation/v1/event/$e",
	} {
		req := httptest.NewRequest(http.MethodPut, target, strings.NewReader(eduOnly))
		req.Header.Set("Authorization", `X-Matrix origin="remote.example",key="k",sig="s"`)
		r.h.ServeHTTP(httptest.NewRecorder(), req)
	}
	req := httptest.NewRequest(http.MethodGet, "/_matrix/federation/v1/send/t1", nil)
	r.h.ServeHTTP(httptest.NewRecorder(), req)

	if r.up.count() != 5 || len(r.sender.list()) != 0 {
		t.Errorf("up=%d sent=%v; everything that is not PUT v1 /send/<id> belongs to Synapse", r.up.count(), r.sender.list())
	}
}

// The path is matched raw and the id decoded after, as Synapse does.
func TestEncodedTxnID(t *testing.T) {
	req := httptest.NewRequest(http.MethodPut, "/_matrix/federation/v1/send/abc%2Fdef/", nil)
	id, version, ok := matchSend(req)
	if !ok || version != "v1" || id != "abc/def" {
		t.Errorf("matchSend = %q %q %v", id, version, ok)
	}
}

func TestCanarySelectsByOrigin(t *testing.T) {
	r := newRig(t, config.Mode{Kind: config.ModeCanary, CanaryPercent: 50})
	var native, proxied int
	for i := 0; i < 200; i++ {
		origin := "o" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + ".example"
		before := r.up.count()
		send(t, r.h, origin, "t", eduOnly)
		send(t, r.h, origin, "t2", eduOnly)
		switch r.up.count() - before {
		case 0:
			native++
		case 2:
			proxied++
		default:
			t.Fatalf("origin %s was split between paths", origin)
		}
	}
	if native < 60 || proxied < 60 {
		t.Errorf("canary:50 put %d origins native and %d proxied", native, proxied)
	}
}

func TestCanaryZeroAndHundred(t *testing.T) {
	r := newRig(t, config.Mode{Kind: config.ModeCanary, CanaryPercent: 0})
	send(t, r.h, "remote.example", "t", eduOnly)
	if r.up.count() != 1 {
		t.Error("canary:0 served natively")
	}
	r = newRig(t, config.Mode{Kind: config.ModeCanary, CanaryPercent: 100})
	send(t, r.h, "remote.example", "t", eduOnly)
	if r.up.count() != 0 {
		t.Error("canary:100 proxied")
	}
}

// Shadow mode proxies everything, forwards nothing, and reads the
// transaction's state before Synapse can have answered it.
func TestShadowReadsStateBeforeSynapse(t *testing.T) {
	r := newRig(t, config.Mode{Kind: config.ModeShadow})
	var dbBeforeUpstream atomic.Bool
	r.up.onForward = func() {
		// Give the prefetch goroutine a moment; it was started first.
		waitFor(t, func() bool { r.store.mu.Lock(); defer r.store.mu.Unlock(); return r.store.calls == 1 })
		dbBeforeUpstream.Store(true)
	}

	rec := send(t, r.h, "remote.example", "t1", eduOnly)
	if !strings.Contains(rec.Body.String(), `"from":"synapse"`) {
		t.Fatalf("shadow mode did not serve Synapse's answer: %s", rec.Body)
	}
	if !dbBeforeUpstream.Load() {
		t.Error("state was not read before the request reached Synapse")
	}
	waitFor(t, func() bool { return r.verifier.calls.Load() == 1 })
	if len(r.sender.list()) != 0 {
		t.Errorf("shadow mode forwarded EDUs: %v", r.sender.list())
	}
}

func TestBodyOverLimitIsStreamedWhole(t *testing.T) {
	r := newRig(t, config.Mode{Kind: config.ModeNative})
	r.h.maxBody = 16
	send(t, r.h, "remote.example", "t1", eduOnly)
	if r.up.count() != 1 || r.up.bodies[0] != eduOnly {
		t.Error("an oversized body did not reach Synapse intact")
	}
}

func TestClassify(t *testing.T) {
	if edus, reason := classify([]byte(`{"origin":"x"}`)); reason != "" || len(edus) != 0 {
		t.Errorf("no pdus, no edus: %v %q (absent lists are empty, units.py:101)", edus, reason)
	}
	if _, reason := classify([]byte(`{"pdus":null,"edus":null}`)); reason != "" {
		t.Errorf("null lists: %q", reason)
	}
	if _, reason := classify([]byte(`{"pdus":"x"}`)); reason != reasonMalformed {
		t.Errorf("pdus not a list: %q", reason)
	}
	if _, reason := classify([]byte(`{"pdus":[` + strings.Repeat(`{},`, 50) + `{}]}`)); reason != reasonLimits {
		t.Errorf("51 PDUs: %q, want the limit (Synapse answers 400)", reason)
	}
	edus, reason := classify([]byte(`{"edus":[{"edu_type":"a","content":{"k":1}},{"edu_type":"b","content":{}}]}`))
	if reason != "" || len(edus) != 2 || edus[0].Type != "a" || edus[1].Type != "b" {
		t.Errorf("order or content lost: %+v %q", edus, reason)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(time.Millisecond)
	}
}

// At debug level every transaction gets exactly one line saying where it went
// and why; at info, none.
func TestDebugLogsEachTransaction(t *testing.T) {
	r := newRig(t, config.Mode{Kind: config.ModeNative})
	var buf bytes.Buffer
	r.h.log = zerolog.New(&buf).Level(zerolog.DebugLevel)

	send(t, r.h, "remote.example", "t1", eduOnly)
	send(t, r.h, "remote.example", "t2", withPDU)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("%d log lines for 2 transactions:\n%s", len(lines), buf.String())
	}
	var native, proxied map[string]any
	_ = json.Unmarshal([]byte(lines[0]), &native)
	_ = json.Unmarshal([]byte(lines[1]), &proxied)

	if native["route"] != "native" || native["reason"] != "ok" || native["origin"] != "remote.example" ||
		native["txn_id"] != "t1" || native["verified"] != true {
		t.Errorf("native line: %s", lines[0])
	}
	edus, _ := native["edus"].(string)
	for _, want := range []string{"m.typing:forward@edu-w=1", "m.presence:drop_presence_untracked=1", "m.receipt:forward@edu-w=1"} {
		if !strings.Contains(edus, want) {
			t.Errorf("edus %q lacks %q", edus, want)
		}
	}
	if proxied["route"] != "proxy" || proxied["reason"] != reasonHasPDUs {
		t.Errorf("proxied line: %s", lines[1])
	}

	buf.Reset()
	r.h.log = zerolog.New(&buf).Level(zerolog.InfoLevel)
	send(t, r.h, "remote.example", "t3", eduOnly)
	if buf.Len() != 0 {
		t.Errorf("info level logged a routine transaction: %s", buf.String())
	}
}

type pduSink struct {
	mu       sync.Mutex
	bodies   []string
	prepared int
}

type pduPending struct {
	s    *pduSink
	body string
}

func (p *pduSink) Prepare(b []byte) PDUPending {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.prepared++
	return &pduPending{s: p, body: string(b)}
}

func (p *pduPending) Commit() {
	p.s.mu.Lock()
	defer p.s.mu.Unlock()
	p.s.bodies = append(p.s.bodies, p.body)
}

func (p *pduPending) Discard() {}

// modes.pdu: shadow hands every PDU transaction Synapse accepted to the PDU
// shadow -- and nothing else, and not when Synapse refused it.
func TestPDUShadowGetsAcceptedPDUTransactions(t *testing.T) {
	for _, mode := range []string{config.ModeProxy, config.ModeShadow, config.ModeNative} {
		t.Run(mode, func(t *testing.T) {
			r := newRig(t, config.Mode{Kind: mode})
			sink := &pduSink{}
			r.h.pdus = sink

			send(t, r.h, "remote.example", "t1", withPDU)
			send(t, r.h, "remote.example", "t2", eduOnly)
			r.up.status = http.StatusTooManyRequests
			send(t, r.h, "remote.example", "t3", withPDU)

			if len(sink.bodies) != 1 || sink.bodies[0] != withPDU {
				t.Errorf("shadow got %d bodies %v; want only the accepted PDU transaction", len(sink.bodies), sink.bodies)
			}
			if sink.prepared != 2 {
				t.Errorf("prepared %d transactions; want both PDU ones, before Synapse answered", sink.prepared)
			}
			if r.up.count() < 2 {
				t.Errorf("PDU transactions did not reach Synapse")
			}
		})
	}
}
