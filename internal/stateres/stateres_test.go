package stateres

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"testing"

	"github.com/tidwall/gjson"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
)

// A port of Synapse's tests/state/test_v2.py harness and cases: a small room
// built by hand, each event authed from the state before it, and the state at
// END resolved and compared with the answer Synapse's own test expects.

const (
	alice   = "@alice:example.com"
	bob     = "@bob:example.com"
	charlie = "@charlie:example.com"
	evelyn  = "@evelyn:example.com"
	zara    = "@zara:example.com"
	roomID  = "!test:example.com"
)

type fakeEvent struct {
	id, sender, typ string
	stateKey        *string
	content         map[string]any
}

func sk(s string) *string { return &s }

func fe(id, sender, typ string, stateKey *string, content map[string]any) fakeEvent {
	return fakeEvent{id: id, sender: sender, typ: typ, stateKey: stateKey, content: content}
}

func eventID(node string) string { return "$" + node + ":example.com" }

var join = map[string]any{"membership": "join"}

var initialEvents = []fakeEvent{
	fe("CREATE", alice, "m.room.create", sk(""), map[string]any{"creator": alice}),
	fe("IMA", alice, "m.room.member", sk(alice), join),
	fe("IPOWER", alice, "m.room.power_levels", sk(""), map[string]any{"users": map[string]any{alice: 100}}),
	fe("IJR", alice, "m.room.join_rules", sk(""), map[string]any{"join_rule": "public"}),
	fe("IMB", bob, "m.room.member", sk(bob), join),
	fe("IMC", charlie, "m.room.member", sk(charlie), join),
	fe("IMZ", zara, "m.room.member", sk(zara), join),
	fe("START", zara, "m.room.message", nil, map[string]any{}),
	fe("END", zara, "m.room.message", nil, map[string]any{}),
}

var initialEdges = []string{"START", "IMZ", "IMC", "IMB", "IJR", "IPOWER", "IMA", "CREATE"}

// memStore is TestStateResolutionStore.
type memStore struct{ events map[string]*pdu.Event }

func (m *memStore) GetEvents(_ context.Context, ids []string) (map[string]*pdu.Event, error) {
	out := map[string]*pdu.Event{}
	for _, id := range ids {
		if e, ok := m.events[id]; ok {
			out[id] = e
		}
	}
	return out, nil
}

func (m *memStore) AuthEdges(_ context.Context, ids []string) (map[string][]string, error) {
	out := map[string][]string{}
	for _, id := range ids {
		if e, ok := m.events[id]; ok {
			out[id] = e.AuthEvents
		}
	}
	return out, nil
}

// buildEventGraph is StateTestCase.build_event_graph.
func buildEventGraph(t *testing.T, events []fakeEvent, edges [][]string) (*memStore, map[string]pdu.StateMap) {
	t.Helper()
	rv, _ := pdu.LookupRoomVersion("2")

	graph := map[string]map[string]bool{}
	fakes := map[string]fakeEvent{}
	for _, ev := range append(append([]fakeEvent{}, initialEvents...), events...) {
		graph[ev.id] = map[string]bool{}
		fakes[ev.id] = ev
	}
	addChain := func(chain []string) {
		for i := 0; i+1 < len(chain); i++ {
			graph[chain[i]][chain[i+1]] = true
		}
	}
	addChain(initialEdges)
	for _, c := range edges {
		addChain(c)
	}

	copyG := map[string]map[string]bool{}
	for k, v := range graph {
		copyG[k] = map[string]bool{}
		for e := range v {
			copyG[k][e] = true
		}
	}
	order := lexicographicalTopologicalSort(copyG, func(n string) powerItem { return powerItem{id: n, node: n} })

	store := &memStore{events: map[string]*pdu.Event{}}
	stateAt := map[string]pdu.StateMap{}
	ts := int64(0)
	for _, node := range order {
		f := fakes[node]
		var prevs []string
		for p := range graph[node] {
			prevs = append(prevs, p)
		}
		sort.Strings(prevs)

		var before pdu.StateMap
		switch len(prevs) {
		case 0:
			before = pdu.StateMap{}
		case 1:
			before = copyState(stateAt[prevs[0]])
		default:
			var sets []pdu.StateMap
			for _, p := range prevs {
				sets = append(sets, stateAt[p])
			}
			res, err := Resolve(context.Background(), roomID, rv, sets, store)
			if err != nil {
				t.Fatalf("resolving before %s: %v", node, err)
			}
			before = res
		}

		after := copyState(before)
		if f.stateKey != nil {
			after[pdu.StateKey{Type: f.typ, StateKey: *f.stateKey}] = eventID(node)
		}

		// Auth events: the auth types (as for room v6) present in the state.
		probe := &pdu.Event{Type: f.typ, Sender: f.sender, StateKey: f.stateKey, Content: mustContent(t, f.content), Room: rv}
		types, err := pdu.AuthTypesForEvent(rv, probe)
		if err != nil {
			t.Fatal(err)
		}
		var auth []string
		for _, k := range types {
			if id, ok := before[k]; ok {
				auth = append(auth, id)
			}
		}

		raw := map[string]any{
			"event_id":         eventID(node),
			"sender":           f.sender,
			"type":             f.typ,
			"content":          f.content,
			"origin_server_ts": ts,
			"room_id":          roomID,
			"auth_events":      pairs(auth),
			"prev_events":      pairs(mapIDs(prevs)),
		}
		if f.stateKey != nil {
			raw["state_key"] = *f.stateKey
		}
		ts++
		b, _ := json.Marshal(raw)
		ev, err := pdu.ParseEvent(b, "", rv, false)
		if err != nil {
			t.Fatalf("%s: %v", node, err)
		}
		store.events[ev.ID] = ev
		stateAt[node] = after
	}
	return store, stateAt
}

func mustContent(t *testing.T, c map[string]any) gjson.Result {
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return gjson.ParseBytes(b)
}

func pairs(ids []string) [][]any {
	out := [][]any{}
	for _, id := range ids {
		out = append(out, []any{id, map[string]any{}})
	}
	return out
}

func mapIDs(nodes []string) []string {
	out := make([]string, len(nodes))
	for i, n := range nodes {
		out[i] = eventID(n)
	}
	return out
}

func copyState(s pdu.StateMap) pdu.StateMap {
	out := make(pdu.StateMap, len(s))
	for k, v := range s {
		out[k] = v
	}
	return out
}

// doCheck is StateTestCase.do_check: the state at END, restricted to the
// expected keys and anything that changed since START.
func doCheck(t *testing.T, events []fakeEvent, edges [][]string, expected []string) {
	t.Helper()
	store, stateAt := buildEventGraph(t, events, edges)
	want := pdu.StateMap{}
	for _, node := range expected {
		ev := store.events[eventID(node)]
		want[ev.Key()] = ev.ID
	}
	start, end := stateAt["START"], stateAt["END"]
	got := pdu.StateMap{}
	for k, v := range end {
		if _, ok := want[k]; ok || start[k] != v {
			got[k] = v
		}
	}
	if !reflect.DeepEqual(want, got) {
		t.Errorf("state at END:\n got  %s\n want %s", show(got), show(want))
	}
}

func show(s pdu.StateMap) string {
	var out []string
	for k, v := range s {
		out = append(out, fmt.Sprintf("%s|%s=%s", k.Type, k.StateKey, v))
	}
	sort.Strings(out)
	return fmt.Sprint(out)
}

func TestBanVsPL(t *testing.T) {
	doCheck(t, []fakeEvent{
		fe("PA", alice, "m.room.power_levels", sk(""), map[string]any{"users": map[string]any{alice: 100, bob: 50}}),
		fe("MA", alice, "m.room.member", sk(alice), map[string]any{"membership": "join"}),
		fe("MB", alice, "m.room.member", sk(bob), map[string]any{"membership": "ban"}),
		fe("PB", bob, "m.room.power_levels", sk(""), map[string]any{"users": map[string]any{alice: 100, bob: 50}}),
	}, [][]string{{"END", "MB", "MA", "PA", "START"}, {"END", "PB", "PA"}},
		[]string{"PA", "MA", "MB"})
}

func TestJoinRuleEvasion(t *testing.T) {
	doCheck(t, []fakeEvent{
		fe("JR", alice, "m.room.join_rules", sk(""), map[string]any{"join_rules": "private"}),
		fe("ME", evelyn, "m.room.member", sk(evelyn), map[string]any{"membership": "join"}),
	}, [][]string{{"END", "JR", "START"}, {"END", "ME", "START"}},
		[]string{"JR"})
}

func TestOfftopicPL(t *testing.T) {
	doCheck(t, []fakeEvent{
		fe("PA", alice, "m.room.power_levels", sk(""), map[string]any{"users": map[string]any{alice: 100, bob: 50}}),
		fe("PB", bob, "m.room.power_levels", sk(""), map[string]any{"users": map[string]any{alice: 100, bob: 50, charlie: 50}}),
		fe("PC", charlie, "m.room.power_levels", sk(""), map[string]any{"users": map[string]any{alice: 100, bob: 50, charlie: 0}}),
	}, [][]string{{"END", "PC", "PB", "PA", "START"}, {"END", "PA"}},
		[]string{"PC"})
}

func TestTopicBasic(t *testing.T) {
	doCheck(t, []fakeEvent{
		fe("T1", alice, "m.room.topic", sk(""), map[string]any{}),
		fe("PA1", alice, "m.room.power_levels", sk(""), map[string]any{"users": map[string]any{alice: 100, bob: 50}}),
		fe("T2", alice, "m.room.topic", sk(""), map[string]any{}),
		fe("PA2", alice, "m.room.power_levels", sk(""), map[string]any{"users": map[string]any{alice: 100, bob: 0}}),
		fe("PB", bob, "m.room.power_levels", sk(""), map[string]any{"users": map[string]any{alice: 100, bob: 50}}),
		fe("T3", bob, "m.room.topic", sk(""), map[string]any{}),
	}, [][]string{{"END", "PA2", "T2", "PA1", "T1", "START"}, {"END", "T3", "PB", "PA1"}},
		[]string{"PA2", "T2"})
}

func TestTopicReset(t *testing.T) {
	doCheck(t, []fakeEvent{
		fe("T1", alice, "m.room.topic", sk(""), map[string]any{}),
		fe("PA", alice, "m.room.power_levels", sk(""), map[string]any{"users": map[string]any{alice: 100, bob: 50}}),
		fe("T2", bob, "m.room.topic", sk(""), map[string]any{}),
		fe("MB", alice, "m.room.member", sk(bob), map[string]any{"membership": "ban"}),
	}, [][]string{{"END", "MB", "T2", "PA", "T1", "START"}, {"END", "T1"}},
		[]string{"T1", "MB", "PA"})
}

func TestTopic(t *testing.T) {
	doCheck(t, []fakeEvent{
		fe("T1", alice, "m.room.topic", sk(""), map[string]any{}),
		fe("PA1", alice, "m.room.power_levels", sk(""), map[string]any{"users": map[string]any{alice: 100, bob: 50}}),
		fe("T2", alice, "m.room.topic", sk(""), map[string]any{}),
		fe("PA2", alice, "m.room.power_levels", sk(""), map[string]any{"users": map[string]any{alice: 100, bob: 0}}),
		fe("PB", bob, "m.room.power_levels", sk(""), map[string]any{"users": map[string]any{alice: 100, bob: 50}}),
		fe("T3", bob, "m.room.topic", sk(""), map[string]any{}),
		fe("MZ1", zara, "m.room.message", nil, map[string]any{}),
		fe("T4", alice, "m.room.topic", sk(""), map[string]any{}),
	}, [][]string{
		{"END", "T4", "MZ1", "PA2", "T2", "PA1", "T1", "START"},
		{"END", "MZ1", "T3", "PB", "PA1"},
	}, []string{"T4", "PA2"})
}

func TestMainlineSort(t *testing.T) {
	doCheck(t, []fakeEvent{
		fe("T1", alice, "m.room.topic", sk(""), map[string]any{}),
		fe("PA1", alice, "m.room.power_levels", sk(""), map[string]any{"users": map[string]any{alice: 100, bob: 50}}),
		fe("T2", alice, "m.room.topic", sk(""), map[string]any{}),
		fe("PA2", alice, "m.room.power_levels", sk(""), map[string]any{
			"users":  map[string]any{alice: 100, bob: 50},
			"events": map[string]any{"m.room.power_levels": 100},
		}),
		fe("PB", bob, "m.room.power_levels", sk(""), map[string]any{"users": map[string]any{alice: 100, bob: 50}}),
		fe("T3", bob, "m.room.topic", sk(""), map[string]any{}),
		fe("T4", alice, "m.room.topic", sk(""), map[string]any{}),
	}, [][]string{
		{"END", "T3", "PA2", "T2", "PA1", "T1", "START"},
		{"END", "T4", "PB", "PA1"},
	}, []string{"T3", "PA2"})
}

// LexicographicalTestCase.test_simple.
func TestLexicographicalSort(t *testing.T) {
	graph := map[string]map[string]bool{
		"l": {"o": true},
		"m": {"n": true, "o": true},
		"n": {"o": true},
		"o": {},
		"p": {"o": true},
	}
	got := lexicographicalTopologicalSort(graph, func(n string) powerItem { return powerItem{id: n, node: n} })
	if want := []string{"o", "l", "n", "m", "p"}; !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
