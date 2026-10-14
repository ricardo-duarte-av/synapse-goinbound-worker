// Package stateres is a port of Synapse's state resolution v2 and v2.1
// (synapse/state/v2.py), the algorithm that decides a room's state where its
// DAG has forked.
//
// It follows Synapse, including where Synapse departs from the spec: the
// auth checks are Synapse's (package pdu), a previously rejected event is never
// admitted into state, and the unconflicted state is laid over the result.
// Function names match v2.py so each can be read beside its original.
//
// Room version 1 uses state resolution v1 (v1.go).
package stateres

import (
	"container/heap"
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/tidwall/gjson"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
)

// Store supplies events and auth edges. Both must include rejected events.
type Store interface {
	// GetEvents returns the events found; missing ones are simply absent.
	GetEvents(ctx context.Context, ids []string) (map[string]*pdu.Event, error)
	// AuthEdges returns each found event's auth event IDs, as Synapse's
	// event_auth table holds them (for room v12, including the create
	// event).
	AuthEdges(ctx context.Context, ids []string) (map[string][]string, error)
}

// ErrUnsupported is a room version whose state resolution is not ported.
var ErrUnsupported = errors.New("stateres: state resolution for this room version is not implemented")

// Tracer receives a line per decision when set; for debugging a mismatch.
type Tracer func(format string, args ...any)

// Resolve is resolve_events_with_store (v2.py:89).
//
// An error that is a *pdu.RaiseError means Synapse itself would have raised
// during this resolution; any other error is a failure here.
func Resolve(ctx context.Context, roomID string, rv *pdu.RoomVersion, stateSets []pdu.StateMap, store Store) (pdu.StateMap, error) {
	return ResolveTraced(ctx, roomID, rv, stateSets, store, nil)
}

// Options tunes a resolution.
type Options struct {
	// Trace receives each decision, for debugging a mismatch.
	Trace Tracer
	// WalkDAG computes the auth chain difference by walking the DAG even
	// when the store has a chain cover index.
	WalkDAG bool
	// CrossCheck computes it both ways and fails on any disagreement.
	CrossCheck bool
}

// ResolveTraced is Resolve, reporting each decision to trace.
func ResolveTraced(ctx context.Context, roomID string, rv *pdu.RoomVersion, stateSets []pdu.StateMap, store Store, trace Tracer) (pdu.StateMap, error) {
	return ResolveWith(ctx, roomID, rv, stateSets, store, Options{Trace: trace})
}

// ResolveWith is Resolve with options.
func ResolveWith(ctx context.Context, roomID string, rv *pdu.RoomVersion, stateSets []pdu.StateMap, store Store, opts Options) (pdu.StateMap, error) {
	trace := opts.Trace
	if trace == nil {
		trace = func(string, ...any) {}
	}
	r := &resolver{ctx: ctx, roomID: roomID, rv: rv, store: store, events: map[string]*pdu.Event{}, trace: trace, opts: opts}
	switch rv.StateRes {
	case pdu.StateResV1:
		return r.resolveV1(stateSets)
	case pdu.StateResV2, pdu.StateResV21:
	default:
		return nil, ErrUnsupported
	}

	unconflicted, conflicted := separate(stateSets)
	if len(conflicted) == 0 {
		return unconflicted, nil
	}
	for k, ids := range conflicted {
		r.trace("conflicted %s|%s: %v", k.Type, k.StateKey, setKeys(ids))
	}

	conflictedIDs := map[string]bool{}
	for _, ids := range conflicted {
		for id := range ids {
			conflictedIDs[id] = true
		}
	}

	authDiff, err := r.authChainDifference(stateSets, conflictedIDs)
	if err != nil {
		return nil, err
	}
	full := map[string]bool{}
	for id := range conflictedIDs {
		full[id] = true
	}
	for id := range authDiff {
		full[id] = true
	}

	if err := r.load(setKeys(full)); err != nil {
		return nil, err
	}
	for id := range full {
		ev, ok := r.events[id]
		if !ok {
			// full_conflicted_set = {eid for eid in ... if eid in event_map}
			delete(full, id)
			continue
		}
		if ev.RoomID != roomID {
			return nil, &pdu.RaiseError{Msg: fmt.Sprintf("event %s is in room %s", id, ev.RoomID)}
		}
	}

	// v2 starts from the unconflicted state, restricted to the keys that can
	// matter; v2.1 starts from nothing.
	base := pdu.StateMap{}
	if rv.StateRes != pdu.StateResV21 {
		want := map[pdu.StateKey]bool{{Type: "m.room.power_levels"}: true}
		for id := range full {
			types, err := pdu.AuthTypesForEvent(rv, r.events[id])
			if err != nil {
				return nil, err
			}
			for _, k := range types {
				want[k] = true
			}
		}
		for k := range want {
			if id, ok := unconflicted[k]; ok {
				base[k] = id
			}
		}
	}

	r.trace("full conflicted set: %d events (%d conflicted, %d auth difference)", len(full), len(conflictedIDs), len(authDiff))
	resolved, err := r.resolveConflictedSet(full, base)
	if err != nil {
		return nil, err
	}

	// ChainMap(unconflicted, resolved): the unconflicted state wins.
	out := make(pdu.StateMap, len(resolved)+len(unconflicted))
	for k, v := range resolved {
		out[k] = v
	}
	for k, v := range unconflicted {
		out[k] = v
	}
	return out, nil
}

type resolver struct {
	ctx    context.Context
	roomID string
	rv     *pdu.RoomVersion
	store  Store
	// events is Synapse's event_map: everything fetched so far.
	events map[string]*pdu.Event
	// edges caches auth edges for the auth chain walks.
	edges map[string][]string
	trace Tracer
	opts  Options
}

func (r *resolver) load(ids []string) error {
	var missing []string
	for _, id := range ids {
		if _, ok := r.events[id]; !ok {
			missing = append(missing, id)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	got, err := r.store.GetEvents(r.ctx, missing)
	if err != nil {
		return err
	}
	for id, ev := range got {
		r.events[id] = ev
	}
	return nil
}

// getEvent is _get_event (v2.py:1030).
func (r *resolver) getEvent(id string, allowNone bool) (*pdu.Event, error) {
	if err := r.load([]string{id}); err != nil {
		return nil, err
	}
	ev := r.events[id]
	if ev == nil {
		if allowNone {
			return nil, nil
		}
		return nil, &pdu.RaiseError{Msg: "unknown event " + id}
	}
	if ev.RoomID != r.roomID {
		return nil, &pdu.RaiseError{Msg: fmt.Sprintf("event %s is in room %s", id, ev.RoomID)}
	}
	return ev, nil
}

// separate is _seperate (v2.py:658): a key is conflicted when the sets
// disagree on it, including when some set lacks it.
func separate(stateSets []pdu.StateMap) (pdu.StateMap, map[pdu.StateKey]map[string]bool) {
	unconflicted := pdu.StateMap{}
	conflicted := map[pdu.StateKey]map[string]bool{}
	all := map[pdu.StateKey]bool{}
	for _, s := range stateSets {
		for k := range s {
			all[k] = true
		}
	}
	for k := range all {
		ids := map[string]bool{}
		missing := false
		for _, s := range stateSets {
			if id, ok := s[k]; ok {
				ids[id] = true
			} else {
				missing = true
			}
		}
		if !missing && len(ids) == 1 {
			for id := range ids {
				unconflicted[k] = id
			}
			continue
		}
		conflicted[k] = ids
	}
	return unconflicted, conflicted
}

// isPowerEvent is _is_power_event (v2.py:688).
func isPowerEvent(ev *pdu.Event) (bool, error) {
	if ev.IsState() && *ev.StateKey == "" {
		switch ev.Type {
		case "m.room.power_levels", "m.room.join_rules", "m.room.create":
			return true, nil
		}
	}
	if ev.Type == "m.room.member" {
		m, err := ev.Membership()
		if err != nil {
			return false, err
		}
		if m == "leave" || m == "ban" {
			return ev.StateKey == nil || ev.Sender != *ev.StateKey, nil
		}
	}
	return false, nil
}

// resolveConflictedSet is _resolve_conflicted_set (v2.py:287).
func (r *resolver) resolveConflictedSet(full map[string]bool, base pdu.StateMap) (pdu.StateMap, error) {
	var power []string
	for _, id := range sortedIDs(full) {
		is, err := isPowerEvent(r.events[id])
		if err != nil {
			return nil, err
		}
		if is {
			power = append(power, id)
		}
	}
	sortedPower, err := r.reverseTopologicalPowerSort(power, full)
	if err != nil {
		return nil, err
	}
	r.trace("power events sorted: %v", sortedPower)
	resolved, err := r.iterativeAuthChecks(sortedPower, base)
	if err != nil {
		return nil, err
	}

	isPower := map[string]bool{}
	for _, id := range sortedPower {
		isPower[id] = true
	}
	var leftover []string
	for _, id := range sortedIDs(full) {
		if !isPower[id] {
			leftover = append(leftover, id)
		}
	}
	pl := resolved[pdu.StateKey{Type: "m.room.power_levels"}]
	leftover, err = r.mainlineSort(leftover, pl)
	if err != nil {
		return nil, err
	}
	r.trace("resolved power levels %s; leftover in mainline order: %v", pl, leftover)
	return r.iterativeAuthChecks(leftover, resolved)
}

// getPowerLevelForSender is _get_power_level_for_sender (v2.py:373).
func (r *resolver) getPowerLevelForSender(id string) (int64, error) {
	ev, err := r.getEvent(id, false)
	if err != nil {
		return 0, err
	}
	var pl, create *pdu.Event
	for _, aid := range ev.AuthEvents {
		aev, err := r.getEvent(aid, true)
		if err != nil {
			return 0, err
		}
		if aev == nil || !aev.IsState() || *aev.StateKey != "" {
			continue
		}
		switch aev.Type {
		case "m.room.power_levels":
			pl = aev
		case "m.room.create":
			create = aev
		}
	}
	if ev.Type != "m.room.create" && create == nil {
		return 0, &pdu.RaiseError{Msg: "AssertionError: no create event in auth events of " + id}
	}
	if create != nil && create.Room.MSC4289CreatorPower {
		if is, err := pdu.IsCreator(create, ev.Sender); err != nil {
			return 0, err
		} else if is {
			return pdu.CreatorPowerLevel, nil
		}
	}
	if pl == nil {
		// The first create event among the auth events decides.
		for _, aid := range ev.AuthEvents {
			aev, err := r.getEvent(aid, true)
			if err != nil {
				return 0, err
			}
			if aev == nil || aev.Type != "m.room.create" || !aev.IsState() || *aev.StateKey != "" {
				continue
			}
			var creator gjson.Result
			if ev.Room.ImplicitRoomCreator {
				creator = gjson.Result{Type: gjson.String, Str: aev.Sender}
			} else {
				creator = pdu.Get(aev.Content, "creator")
			}
			if creator.Type == gjson.String && creator.Str == ev.Sender {
				return 100, nil
			}
			break
		}
		return 0, nil
	}
	return pdu.UserLevelFromPowerLevels(pl, ev.Sender)
}

// powerItem is an entry in the zero-outdegree heap: (key(node), node).
type powerItem struct {
	pl   int64
	ts   int64
	id   string
	node string
}

type powerHeap []powerItem

func (h powerHeap) Len() int { return len(h) }
func (h powerHeap) Less(i, j int) bool {
	a, b := h[i], h[j]
	// key = (-pl, origin_server_ts, event_id)
	if a.pl != b.pl {
		return a.pl > b.pl
	}
	if a.ts != b.ts {
		return a.ts < b.ts
	}
	return a.id < b.id
}
func (h powerHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *powerHeap) Push(x any)   { *h = append(*h, x.(powerItem)) }
func (h *powerHeap) Pop() any {
	old := *h
	it := old[len(old)-1]
	*h = old[:len(old)-1]
	return it
}

// reverseTopologicalPowerSort is _reverse_topological_power_sort (v2.py:746).
func (r *resolver) reverseTopologicalPowerSort(ids []string, full map[string]bool) ([]string, error) {
	graph := map[string]map[string]bool{}
	for _, id := range ids {
		// _add_event_and_auth_chain_to_graph
		stack := []string{id}
		for len(stack) > 0 {
			eid := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if graph[eid] == nil {
				graph[eid] = map[string]bool{}
			}
			ev, err := r.getEvent(eid, false)
			if err != nil {
				return nil, err
			}
			for _, aid := range ev.AuthEvents {
				if full[aid] {
					if graph[aid] == nil {
						stack = append(stack, aid)
					}
					graph[eid][aid] = true
				}
			}
		}
	}

	pls := map[string]int64{}
	for eid := range graph {
		pl, err := r.getPowerLevelForSender(eid)
		if err != nil {
			return nil, err
		}
		pls[eid] = pl
	}
	key := func(eid string) powerItem {
		return powerItem{pl: pls[eid], ts: r.events[eid].OriginServerTS, id: eid, node: eid}
	}
	return lexicographicalTopologicalSort(graph, key), nil
}

// lexicographicalTopologicalSort is lexicographical_topological_sort
// (v2.py:1069): Kahn's algorithm over nodes with no outgoing edges, ties broken
// by key. graph is consumed.
func lexicographicalTopologicalSort(graph map[string]map[string]bool, key func(string) powerItem) []string {
	reverse := map[string][]string{}
	h := &powerHeap{}
	for node, edges := range graph {
		if len(edges) == 0 {
			*h = append(*h, key(node))
		}
		if _, ok := reverse[node]; !ok {
			reverse[node] = nil
		}
		for e := range edges {
			reverse[e] = append(reverse[e], node)
		}
	}
	heap.Init(h)
	var out []string
	for h.Len() > 0 {
		node := heap.Pop(h).(powerItem).node
		for _, parent := range reverse[node] {
			outEdges := graph[parent]
			delete(outEdges, node)
			if len(outEdges) == 0 {
				heap.Push(h, key(parent))
			}
		}
		out = append(out, node)
	}
	return out
}

// iterativeAuthChecks is _iterative_auth_checks (v2.py:805).
func (r *resolver) iterativeAuthChecks(ids []string, base pdu.StateMap) (pdu.StateMap, error) {
	resolved := make(pdu.StateMap, len(base))
	for k, v := range base {
		resolved[k] = v
	}
	for _, id := range ids {
		ev := r.events[id]

		// auth_events: the event's own (non-rejected) auth events, then
		// overridden by the resolved state for its auth types. Insertion
		// order is kept, as in the dict Synapse builds.
		order := []pdu.StateKey{}
		authEvents := map[pdu.StateKey]*pdu.Event{}
		put := func(k pdu.StateKey, e *pdu.Event) {
			if _, ok := authEvents[k]; !ok {
				order = append(order, k)
			}
			authEvents[k] = e
		}
		for _, aid := range ev.AuthEvents {
			aev, err := r.getEvent(aid, true)
			if err != nil {
				return nil, err
			}
			if aev != nil && !aev.Rejected {
				put(stateKeyOf(aev), aev)
			}
		}
		types, err := pdu.AuthTypesForEvent(r.rv, ev)
		if err != nil {
			return nil, err
		}
		for _, k := range types {
			rid, ok := resolved[k]
			if !ok {
				continue
			}
			rev, err := r.getEvent(rid, false)
			if err != nil {
				return nil, err
			}
			if !rev.Rejected {
				put(k, rev)
			}
		}

		if ev.Rejected {
			// Synapse never admits a previously rejected event, which is
			// not what the spec says (v2.py:856).
			r.trace("  %s %s|%s: skipped, previously rejected", id, ev.Type, deref(ev.StateKey))
			continue
		}

		list := make([]*pdu.Event, 0, len(order))
		for _, k := range order {
			list = append(list, authEvents[k])
		}
		err = pdu.CheckStateDependentAuthRules(ev, list)
		switch {
		case err == nil:
			r.trace("  %s %s|%s: accepted (ts %d)", id, ev.Type, deref(ev.StateKey), ev.OriginServerTS)
			resolved[ev.Key()] = id
		case pdu.IsAuthError(err):
			// except AuthError: pass
			r.trace("  %s %s|%s: refused: %v", id, ev.Type, deref(ev.StateKey), err)
		default:
			return nil, err
		}
	}
	return resolved, nil
}

// stateKeyOf keys an auth event as Synapse's dict does: (type, state_key),
// where a non-state event's state_key is None. The marker keeps such an event
// from ever matching a real state key.
func stateKeyOf(e *pdu.Event) pdu.StateKey {
	if !e.IsState() {
		return pdu.StateKey{Type: e.Type, StateKey: "\x00none"}
	}
	return e.Key()
}

// mainlineSort is _mainline_sort (v2.py:889).
func (r *resolver) mainlineSort(ids []string, resolvedPL string) ([]string, error) {
	if len(ids) == 0 {
		return nil, nil
	}
	var mainline []string
	for pl := resolvedPL; pl != ""; {
		mainline = append(mainline, pl)
		plEv, err := r.getEvent(pl, false)
		if err != nil {
			return nil, err
		}
		pl = ""
		for _, aid := range plEv.AuthEvents {
			aev, err := r.getEvent(aid, true)
			if err != nil {
				return nil, err
			}
			if aev != nil && aev.Type == "m.room.power_levels" && aev.IsState() && *aev.StateKey == "" {
				pl = aid
				break
			}
		}
	}
	depthOf := map[string]int{}
	for i := range mainline {
		depthOf[mainline[len(mainline)-1-i]] = i + 1
	}

	type ordered struct {
		id    string
		depth int
		ts    int64
	}
	out := make([]ordered, 0, len(ids))
	for _, id := range ids {
		d, err := r.mainlineDepth(r.events[id], depthOf)
		if err != nil {
			return nil, err
		}
		out = append(out, ordered{id: id, depth: d, ts: r.events[id].OriginServerTS})
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.depth != b.depth {
			return a.depth < b.depth
		}
		if a.ts != b.ts {
			return a.ts < b.ts
		}
		return a.id < b.id
	})
	res := make([]string, len(out))
	for i, o := range out {
		res[i] = o.id
	}
	return res, nil
}

// mainlineDepth is _get_mainline_depth_for_event (v2.py:960).
func (r *resolver) mainlineDepth(ev *pdu.Event, depthOf map[string]int) (int, error) {
	for tmp := ev; tmp != nil; {
		if d, ok := depthOf[tmp.ID]; ok {
			return d, nil
		}
		next := (*pdu.Event)(nil)
		for _, aid := range tmp.AuthEvents {
			aev, err := r.getEvent(aid, true)
			if err != nil {
				return 0, err
			}
			if aev != nil && aev.Type == "m.room.power_levels" && aev.IsState() && *aev.StateKey == "" {
				next = aev
				break
			}
		}
		tmp = next
	}
	return 0, nil
}

func setKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// sortedIDs iterates a set deterministically. Synapse iterates a Python set,
// whose order is arbitrary; nothing in v2 depends on that order (power events
// are sorted, leftovers are sorted), so any fixed order reproduces it.
func sortedIDs(m map[string]bool) []string {
	out := setKeys(m)
	sort.Strings(out)
	return out
}

func deref(s *string) string {
	if s == nil {
		return "<none>"
	}
	return *s
}
