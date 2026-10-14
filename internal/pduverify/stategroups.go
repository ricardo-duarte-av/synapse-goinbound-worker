package pduverify

import (
	"context"
	"fmt"
	"slices"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
)

// The state groups an event's context points at, as Synapse 1.162 chooses
// them (state/__init__.py calculate_context_info, resolve_state_groups_for_events,
// _make_state_cache_entry; events/snapshot.py UnpersistedEventContext.persist;
// state/store.py store_state_group). These are rows the inbound worker
// writes itself, before handing the event to the persister, so write mode
// must reproduce them exactly.
const (
	planReuse = "reuse"     // an existing group is the state before
	planDelta = "new_delta" // a new group: a prev group plus a delta
	planFull  = "new_full"  // a new group holding the whole state
)

// maxStateDeltaHops is MAX_STATE_DELTA_HOPS (state/bg_updates.py:46): a
// group built on a chain this long is stored in full instead.
const maxStateDeltaHops = 100

// groupPlan is the state group before the event Synapse should end up with.
type groupPlan struct {
	kind  string
	group int64        // planReuse
	prev  int64        // planDelta
	delta pdu.StateMap // planDelta
	// tie means Synapse's choice depends on the order it iterates the
	// prev groups (a Python set), which is not reproduced.
	tie bool
}

func (p groupPlan) String() string {
	switch p.kind {
	case planReuse:
		return fmt.Sprintf("reuse %d", p.group)
	case planDelta:
		return fmt.Sprintf("new from %d +%d", p.prev, len(p.delta))
	}
	return p.kind
}

// planOrdered is planBefore with the groups in the order Synapse iterates
// them: a Python set's, which depends on the order the groups were added.
// That comes from a frozenset of event IDs, whose string hashes are seeded
// per process, so every insertion order is tried. The plan is a tie only
// when they disagree.
func planOrdered(groups []int64, sets []pdu.StateMap, resolved pdu.StateMap) groupPlan {
	first := planBefore(groups, sets, resolved)
	if !first.tie {
		return first
	}
	if len(groups) > maxPermutedGroups {
		return first
	}
	byID := make(map[int64]pdu.StateMap, len(groups))
	for i, g := range groups {
		byID[g] = sets[i]
	}
	var plan *groupPlan
	tried := map[string]bool{}
	tie := false
	permute(slices.Clone(groups), 0, func(insertion []int64) bool {
		order := pySetOrder(insertion)
		key := fmt.Sprint(order)
		if tried[key] {
			return true
		}
		tried[key] = true
		ordered := make([]pdu.StateMap, len(order))
		for i, g := range order {
			ordered[i] = byID[g]
		}
		p := planBefore(order, ordered, resolved)
		p.tie = false
		if plan == nil {
			plan = &p
			return true
		}
		if p.kind != plan.kind || p.group != plan.group || p.prev != plan.prev {
			tie = true
			return false
		}
		return true
	})
	plan.tie = tie
	return *plan
}

// maxPermutedGroups bounds the insertion orders tried (7! = 5040).
const maxPermutedGroups = 7

// permute calls f with every ordering of a[k:], stopping when f returns false.
func permute(a []int64, k int, f func([]int64) bool) bool {
	if k == len(a) {
		return f(a)
	}
	for i := k; i < len(a); i++ {
		a[k], a[i] = a[i], a[k]
		if !permute(a, k+1, f) {
			return false
		}
		a[k], a[i] = a[i], a[k]
	}
	return true
}

// planBefore picks the state group before the event from the prevs'
// distinct groups, in the order given, and their resolved state. tie says
// whether another order could pick differently.
func planBefore(groups []int64, sets []pdu.StateMap, resolved pdu.StateMap) groupPlan {
	switch len(groups) {
	case 0:
		return groupPlan{kind: planFull}
	case 1:
		// One group: used as is, with no resolution.
		return groupPlan{kind: planReuse, group: groups[0]}
	}

	// An exact match, compared as Synapse does: the resolved state's set of
	// event IDs against each group's, sized by the group's key count.
	newIDs := make(map[string]struct{}, len(resolved))
	for _, id := range resolved {
		newIDs[id] = struct{}{}
	}
	var exact *groupPlan
	for i, old := range sets {
		if len(newIDs) != len(old) || !sameIDs(newIDs, old) {
			continue
		}
		if exact != nil {
			exact.tie = true
			break
		}
		exact = &groupPlan{kind: planReuse, group: groups[i]}
	}
	if exact != nil {
		return *exact
	}

	// Failing that, the group the smallest delta builds on. A group with a
	// key the resolved state lacks cannot be built on: deltas never remove.
	plan := groupPlan{kind: planFull}
	var best pdu.StateMap
	for i, old := range sets {
		if hasKeyNotIn(old, resolved) {
			continue
		}
		d := pdu.StateMap{}
		for k, v := range resolved {
			if ov, ok := old[k]; !ok || ov != v {
				d[k] = v
			}
		}
		// Synapse: `if not delta_ids or len(n_delta_ids) < len(delta_ids)`.
		switch {
		case len(best) == 0:
			if best != nil {
				plan.tie = true
			}
			best, plan.kind, plan.prev = d, planDelta, groups[i]
		case len(d) < len(best):
			best, plan.prev, plan.tie = d, groups[i], false
		case len(d) == len(best):
			plan.tie = true
		}
	}
	plan.delta = best
	return plan
}

func sameIDs(ids map[string]struct{}, m pdu.StateMap) bool {
	seen := make(map[string]struct{}, len(m))
	for _, id := range m {
		if _, ok := ids[id]; !ok {
			return false
		}
		seen[id] = struct{}{}
	}
	return len(seen) == len(ids)
}

func hasKeyNotIn(a, b pdu.StateMap) bool {
	for k := range a {
		if _, ok := b[k]; !ok {
			return true
		}
	}
	return false
}

func sameStateMap(a, b pdu.StateMap) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if bv, ok := b[k]; !ok || bv != v {
			return false
		}
	}
	return true
}

// StateGroups checks the state groups Synapse stored for the event against
// the ones write mode would store. It needs a Replay result that matched:
// that already compares the state itself, so this compares only the shape
// (which group, built on which, with which delta).
//
// prevsHeld says every prev was in the timeline when Synapse handled the
// event (the live snapshot saw them). Otherwise Synapse may have computed
// the state before from a remote's /state_ids and stored it in full
// (calculate_context_info with state_ids_before_event), which a full group
// where a reuse or a delta was possible is then taken to mean.
func (s *Verifier) StateGroups(ctx context.Context, r *Result, prevsHeld bool) *Result {
	res := &Result{EventID: r.EventID, RoomID: r.RoomID, Type: r.Type, Version: r.Version, Prevs: r.Prevs, Resolved: r.Resolved}
	rp := r.replay
	if rp == nil {
		return res.fail(OutcomeSkipped, "no replay")
	}
	ev := rp.ev
	if ev.Rejected {
		return res.fail(OutcomeSkipped, "rejected")
	}

	plan := planOrdered(rp.groups, rp.sets, r.before)
	res.GroupPlan = plan.String()
	mismatch := func(reason, why string) *Result {
		if plan.tie {
			return res.fail(OutcomeSkipped, "tie")
		}
		res.Outcome, res.Reason = OutcomeMismatch, reason
		res.StateDiff = []string{why}
		return res
	}

	// The group after: for a state event, a new group on the group before
	// with the event as its one row; otherwise the group before itself.
	before := rp.ownGroup
	if ev.IsState() {
		prev, hasPrev, _, err := s.st.StateDelta(ctx, rp.ownGroup)
		if err != nil {
			return res.fail(OutcomeError, err.Error())
		}
		after := groupPlan{kind: planDelta, prev: prev, delta: pdu.StateMap{ev.Key(): ev.ID}}
		if !hasPrev {
			// Stored in full, so the group before is not recorded. That
			// is right only when the group before's chain is too long,
			// which storedAs checks for a known group before.
			if plan.kind != planReuse {
				return res.fail(OutcomeSkipped, "group after stored in full")
			}
			after.prev = plan.group
		}
		if why, err := s.storedAs(ctx, rp.ownGroup, ev.ID, after); err != nil {
			return res.fail(OutcomeError, err.Error())
		} else if why != "" {
			return mismatch("group after", why)
		}
		if !hasPrev {
			res.Outcome = OutcomeMatch
			return res
		}
		before = prev
	}

	// A full group stored for this event where we would not store one.
	fetched := func() (bool, error) {
		if prevsHeld || plan.kind == planFull {
			return false, nil
		}
		creator, err := s.st.StateGroupEvent(ctx, before)
		if err != nil || creator != ev.ID {
			return false, err
		}
		_, hasPrev, _, err := s.st.StateDelta(ctx, before)
		return !hasPrev, err
	}
	if plan.kind == planReuse {
		if before != plan.group {
			if f, err := fetched(); err != nil {
				return res.fail(OutcomeError, err.Error())
			} else if f {
				return res.fail(OutcomeSkipped, "stored in full: prevs may have been missing")
			}
			return mismatch("group before", fmt.Sprintf("Synapse used group %d", before))
		}
		res.Outcome = OutcomeMatch
		return res
	}
	creator, err := s.st.StateGroupEvent(ctx, before)
	if err != nil {
		return res.fail(OutcomeError, err.Error())
	}
	why, err := s.storedAs(ctx, before, creator, plan)
	if err != nil {
		return res.fail(OutcomeError, err.Error())
	}
	if why != "" {
		if f, err := fetched(); err != nil {
			return res.fail(OutcomeError, err.Error())
		} else if f {
			return res.fail(OutcomeSkipped, "stored in full: prevs may have been missing")
		}
		return mismatch("group before", why)
	}
	if creator != ev.ID {
		// The group Synapse would have stored, stored for another event
		// with the same prev groups: its resolution cache (_state_cache,
		// keyed by the set of groups, kept an hour) remembered it.
		return res.fail(OutcomeSkipped, "resolution cached by Synapse")
	}
	res.Outcome = OutcomeMatch
	return res
}

// storedAs checks that group was stored for event as plan says: a delta on
// plan.prev, or in full when that delta's chain would be too long (or the
// plan is a full group). It returns why not.
func (s *Verifier) storedAs(ctx context.Context, group int64, event string, plan groupPlan) (string, error) {
	creator, err := s.st.StateGroupEvent(ctx, group)
	if err != nil {
		return "", err
	}
	if creator != event {
		return fmt.Sprintf("group %d stored for %s, not %s", group, creator, event), nil
	}
	prev, hasPrev, delta, err := s.st.StateDelta(ctx, group)
	if err != nil {
		return "", err
	}
	wantFull := plan.kind == planFull
	if plan.kind == planDelta {
		hops, err := s.st.StateHops(ctx, plan.prev)
		if err != nil {
			return "", err
		}
		wantFull = hops >= maxStateDeltaHops
	}
	switch {
	case wantFull && hasPrev:
		return fmt.Sprintf("group %d built on %d with %d rows, expected in full", group, prev, len(delta)), nil
	case wantFull:
		return "", nil
	case !hasPrev:
		return fmt.Sprintf("group %d stored in full, expected on %d", group, plan.prev), nil
	case prev != plan.prev:
		return fmt.Sprintf("group %d built on %d, expected on %d", group, prev, plan.prev), nil
	case !sameStateMap(delta, plan.delta):
		return fmt.Sprintf("group %d delta of %d rows, expected %d", group, len(delta), len(plan.delta)), nil
	}
	return "", nil
}
