package edu

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/acl"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/edutype"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/synapsecfg"
)

func writers() synapsecfg.Writers {
	return synapsecfg.Writers{
		Events:      []string{"persister"},
		Typing:      []string{"typing-w"},
		ToDevice:    []string{"todevice-w"},
		Receipts:    []string{"receipts-w"},
		Presence:    []string{"presence-w"},
		DeviceLists: []string{"devices-1", "devices-2"},
	}
}

func TestRouterMatchesSynapse(t *testing.T) {
	r := NewRouter(writers())
	r.pick = func(n int) int { return n - 1 } // would pick the LAST if allowed to choose
	cases := map[string]string{
		edutype.Typing:         "typing-w",
		edutype.Receipt:        "receipts-w",
		edutype.DirectToDevice: "todevice-w",
		edutype.Presence:       "presence-w",
		// Only the FIRST device_lists writer handles these
		// (device.py:196, e2e_keys.py:94), however many there are.
		edutype.DeviceListUpdate:         "devices-1",
		edutype.SigningKeyUpdate:         "devices-1",
		edutype.UnstableSigningKeyUpdate: "devices-1",
		// No registered instance: the main process (federation_server.py:1698).
		"org.example.custom": "master",
	}
	for typ, want := range cases {
		if got := r.Instance(typ); got != want {
			t.Errorf("%s -> %s, want %s", typ, got, want)
		}
	}
}

func TestRouterPicksAmongSeveralWriters(t *testing.T) {
	w := writers()
	w.Typing = []string{"a", "b", "c"}
	r := NewRouter(w)
	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		r.pick = func(int) int { return i }
		seen[r.Instance(edutype.Typing)] = true
	}
	if len(seen) != 3 {
		t.Errorf("only %v were ever chosen", seen)
	}
}

func TestRouterValidate(t *testing.T) {
	r := NewRouter(writers())
	all := func(string) bool { return true }
	if err := r.Validate(all); err != nil {
		t.Fatal(err)
	}
	missing := func(name string) bool { return name != "receipts-w" }
	if err := r.Validate(missing); err == nil {
		t.Error("a writer missing from instance_map passed validation")
	}
	// devices-2 is never chosen, so it need not be reachable.
	if slices.Contains(r.Instances(), "devices-2") {
		t.Error("the second device_lists writer is listed, but Synapse never sends EDUs to it")
	}
}

// fakeACL denies the listed (host, room) pairs.
type fakeACL struct {
	deny      map[string]bool
	uncertain map[string]bool
	err       error
}

func (f fakeACL) Allowed(_ context.Context, host, room string) (bool, error) {
	if f.err != nil {
		return false, f.err
	}
	if f.uncertain[room] {
		return false, acl.ErrUncertain
	}
	return !f.deny[host+"|"+room], nil
}

func processor(a ACL, s Sender, trackPresence bool) *Processor {
	return NewProcessor(NewRouter(writers()), a, s, trackPresence, zerolog.Nop())
}

func raw(s string) json.RawMessage { return json.RawMessage(s) }

func TestPlanPresence(t *testing.T) {
	edus := []EDU{{Type: edutype.Presence, Content: raw(`{"push":[]}`)}}

	steps, err := processor(fakeACL{}, nil, false).Plan(context.Background(), "remote.example", edus)
	if err != nil {
		t.Fatal(err)
	}
	if steps[0].Action != DropPresenceUntracked {
		t.Errorf("untracked presence: %+v, want dropped", steps[0])
	}

	steps, _ = processor(fakeACL{}, nil, true).Plan(context.Background(), "remote.example", edus)
	if steps[0].Action != Forward || steps[0].Instance != "presence-w" {
		t.Errorf("tracked presence: %+v, want forwarded to the presence writer", steps[0])
	}
}

func TestPlanTypingACL(t *testing.T) {
	a := fakeACL{deny: map[string]bool{"banned.example|!room:x": true}}
	p := processor(a, nil, false)
	edus := []EDU{{Type: edutype.Typing, Content: raw(`{"room_id":"!room:x","user_id":"@u:banned.example","typing":true}`)}}

	// The ACL is checked against the host WITHOUT the port.
	steps, err := p.Plan(context.Background(), "banned.example:8448", edus)
	if err != nil {
		t.Fatal(err)
	}
	if steps[0].Action != DropACL {
		t.Errorf("banned origin's typing: %+v, want dropped", steps[0])
	}

	steps, _ = p.Plan(context.Background(), "good.example", edus)
	if steps[0].Action != Forward || steps[0].Instance != "typing-w" {
		t.Errorf("allowed origin's typing: %+v", steps[0])
	}
}

// Synapse reads content["room_id"] where a failure fails the transaction. That
// answer is Synapse's to give, so the transaction is left to it.
func TestPlanTypingWithoutRoomIsUncertain(t *testing.T) {
	p := processor(fakeACL{}, nil, false)
	for _, c := range []string{`{}`, `{"room_id":5}`} {
		_, err := p.Plan(context.Background(), "a.example", []EDU{{Type: edutype.Typing, Content: raw(c)}})
		if !errors.Is(err, ErrUncertain) {
			t.Errorf("typing content %s: err = %v, want ErrUncertain", c, err)
		}
	}
}

func TestPlanReceiptsFiltersBannedRooms(t *testing.T) {
	a := fakeACL{deny: map[string]bool{"r.example|!banned:x": true}}
	p := processor(a, nil, false)

	both := raw(`{"!banned:x":{"m.read":{}},"!ok:x":{"m.read":{}}}`)
	steps, err := p.Plan(context.Background(), "r.example", []EDU{{Type: edutype.Receipt, Content: both}})
	if err != nil {
		t.Fatal(err)
	}
	s := steps[0]
	if s.Action != Forward || s.RemovedRooms != 1 {
		t.Fatalf("partly banned receipts: %+v", s)
	}
	var got map[string]any
	if err := json.Unmarshal(s.Content, &got); err != nil {
		t.Fatal(err)
	}
	if _, ok := got["!banned:x"]; ok || len(got) != 1 {
		t.Errorf("forwarded content %s still names the banned room", s.Content)
	}

	// Every room banned: the whole EDU is ignored (federation_server.py:622).
	steps, _ = p.Plan(context.Background(), "r.example",
		[]EDU{{Type: edutype.Receipt, Content: raw(`{"!banned:x":{}}`)}})
	if steps[0].Action != DropACL {
		t.Errorf("fully banned receipts: %+v, want dropped", steps[0])
	}

	// Nothing banned: forwarded byte for byte.
	orig := raw(`{"!ok:x":{"m.read":{"@u:r.example":{"event_ids":["$e"]}}}}`)
	steps, _ = p.Plan(context.Background(), "r.example", []EDU{{Type: edutype.Receipt, Content: orig}})
	if string(steps[0].Content) != string(orig) {
		t.Errorf("unfiltered receipts were re-encoded: %s", steps[0].Content)
	}
}

func TestPlanPropagatesUncertainAndErrors(t *testing.T) {
	typing := []EDU{{Type: edutype.Typing, Content: raw(`{"room_id":"!r:x"}`)}}

	p := processor(fakeACL{uncertain: map[string]bool{"!r:x": true}}, nil, false)
	if _, err := p.Plan(context.Background(), "a.example", typing); !errors.Is(err, ErrUncertain) {
		t.Errorf("redacted ACL: err = %v, want ErrUncertain", err)
	}

	dbErr := errors.New("db down")
	p = processor(fakeACL{err: dbErr}, nil, false)
	if _, err := p.Plan(context.Background(), "a.example", typing); !errors.Is(err, dbErr) {
		t.Errorf("db failure: err = %v, want it returned", err)
	}
}

func TestPlanUnknownTypeGoesToMain(t *testing.T) {
	steps, err := processor(fakeACL{}, nil, false).Plan(context.Background(), "a.example",
		[]EDU{{Type: "io.element.whatever", Content: raw(`{}`)}})
	if err != nil {
		t.Fatal(err)
	}
	if steps[0].Action != Forward || steps[0].Instance != "master" {
		t.Errorf("unknown EDU type: %+v, want forwarded to master", steps[0])
	}
}

// recordingSender records forwards, optionally failing one type.
type recordingSender struct {
	mu    sync.Mutex
	sent  []string
	fail  string
	delay map[string]time.Duration
}

func (r *recordingSender) SendEDU(_ context.Context, instance, eduType, origin string, content json.RawMessage) error {
	if d := r.delay[eduType]; d > 0 {
		time.Sleep(d)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if eduType == r.fail {
		return errors.New("writer down")
	}
	r.sent = append(r.sent, eduType+"@"+instance+":"+string(content))
	return nil
}

func TestExecuteKeepsOrderWithinAType(t *testing.T) {
	s := &recordingSender{delay: map[string]time.Duration{edutype.DeviceListUpdate: time.Millisecond}}
	p := processor(fakeACL{}, s, false)
	var edus []EDU
	for i := 0; i < 20; i++ {
		edus = append(edus, EDU{Type: edutype.DeviceListUpdate, Content: raw(`{"stream_id":` + itoa(i) + `}`)})
		edus = append(edus, EDU{Type: edutype.Typing, Content: raw(`{"room_id":"!r:x","n":` + itoa(i) + `}`)})
	}
	steps, err := p.Plan(context.Background(), "a.example", edus)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Execute(context.Background(), "a.example", steps); err != nil {
		t.Fatal(err)
	}

	var devices, typing []string
	for _, e := range s.sent {
		if len(e) > len(edutype.Typing) && e[:len(edutype.Typing)] == edutype.Typing {
			typing = append(typing, e)
		} else {
			devices = append(devices, e)
		}
	}
	for i := range devices {
		want := edutype.DeviceListUpdate + "@devices-1:" + `{"stream_id":` + itoa(i) + `}`
		if devices[i] != want {
			t.Fatalf("device list update %d out of order: %s", i, devices[i])
		}
	}
	for i := range typing {
		want := edutype.Typing + "@typing-w:" + `{"room_id":"!r:x","n":` + itoa(i) + `}`
		if typing[i] != want {
			t.Fatalf("typing update %d out of order: %s", i, typing[i])
		}
	}
	if len(devices) != 20 || len(typing) != 20 {
		t.Errorf("forwarded %d device and %d typing EDUs, want 20 of each", len(devices), len(typing))
	}
}

func TestExecuteSkipsDropped(t *testing.T) {
	s := &recordingSender{}
	p := processor(fakeACL{}, s, false)
	steps, _ := p.Plan(context.Background(), "a.example",
		[]EDU{{Type: edutype.Presence, Content: raw(`{}`)}})
	if err := p.Execute(context.Background(), "a.example", steps); err != nil {
		t.Fatal(err)
	}
	if len(s.sent) != 0 {
		t.Errorf("a dropped EDU was forwarded: %v", s.sent)
	}
}

func TestExecuteReportsForwardFailure(t *testing.T) {
	s := &recordingSender{fail: edutype.DirectToDevice}
	p := processor(fakeACL{}, s, false)
	steps, _ := p.Plan(context.Background(), "a.example", []EDU{
		{Type: edutype.DirectToDevice, Content: raw(`{"message_id":"1"}`)},
		{Type: edutype.Receipt, Content: raw(`{}`)},
	})
	err := p.Execute(context.Background(), "a.example", steps)
	var fe *ForwardError
	if !errors.As(err, &fe) || fe.Type != edutype.DirectToDevice {
		t.Fatalf("err = %v, want a ForwardError for the to-device EDU", err)
	}
	// Synapse's message, typo included (federation_server.py:639).
	if fe.Error() != "Error handing EDU of type m.direct_to_device" {
		t.Errorf("message = %q", fe.Error())
	}
}

func TestExecuteWithoutSenderRefuses(t *testing.T) {
	p := processor(fakeACL{}, nil, false)
	if err := p.Execute(context.Background(), "a", []Step{{Action: Forward}}); err == nil {
		t.Error("a planning-only processor forwarded something")
	}
}

func itoa(i int) string { return strconv.Itoa(i) }
