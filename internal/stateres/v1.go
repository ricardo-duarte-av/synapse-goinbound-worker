package stateres

import (
	"crypto/sha1"
	"encoding/hex"
	"sort"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
)

// State resolution v1 (synapse/state/v1.py), used by room version 1 only.
// Unlike v2 it has no auth chains and no iterative auth over the whole
// conflicted set: conflicts are settled key by key, in a fixed order -- power
// levels, then join rules, then memberships, then everything else -- by depth,
// with a hash of the event ID as the tiebreak.

func (r *resolver) resolveV1(stateSets []pdu.StateMap) (pdu.StateMap, error) {
	if len(stateSets) == 1 {
		return stateSets[0], nil
	}
	unconflicted, conflicted := separateV1(stateSets)

	needed := map[string]bool{}
	for _, ids := range conflicted {
		for id := range ids {
			needed[id] = true
		}
	}
	if err := r.load(setKeys(needed)); err != nil {
		return nil, err
	}
	for id := range needed {
		if ev := r.events[id]; ev != nil && ev.RoomID != r.roomID {
			return nil, &pdu.RaiseError{Msg: "event " + id + " is in another room"}
		}
	}

	// _create_auth_events_from_maps: the auth events of the conflicted
	// events, picked only from the unconflicted state.
	authIDs := map[pdu.StateKey]string{}
	for _, ids := range conflicted {
		for id := range ids {
			ev := r.events[id]
			if ev == nil {
				continue
			}
			types, err := pdu.AuthTypesForEvent(r.rv, ev)
			if err != nil {
				return nil, err
			}
			for _, k := range types {
				if _, ok := authIDs[k]; ok {
					continue
				}
				if id, ok := unconflicted[k]; ok && id != "" {
					authIDs[k] = id
				}
			}
		}
	}
	var more []string
	for _, id := range authIDs {
		more = append(more, id)
	}
	if err := r.load(more); err != nil {
		return nil, err
	}
	for _, id := range more {
		if ev := r.events[id]; ev != nil && ev.RoomID != r.roomID {
			return nil, &pdu.RaiseError{Msg: "event " + id + " is in another room"}
		}
	}

	// _resolve_with_state
	conflictedEvents := map[pdu.StateKey][]*pdu.Event{}
	for k, ids := range conflicted {
		var evs []*pdu.Event
		for id := range ids {
			if ev := r.events[id]; ev != nil {
				evs = append(evs, ev)
			}
		}
		switch {
		case len(evs) > 1:
			conflictedEvents[k] = evs
		case len(evs) == 1:
			unconflicted[k] = evs[0].ID
		}
	}
	auth := map[pdu.StateKey]*pdu.Event{}
	for k, id := range authIDs {
		if ev := r.events[id]; ev != nil {
			auth[k] = ev
		}
	}

	resolved, err := r.resolveStateEventsV1(conflictedEvents, auth)
	if err != nil {
		return nil, err
	}
	out := make(pdu.StateMap, len(unconflicted)+len(resolved))
	for k, v := range unconflicted {
		out[k] = v
	}
	for k, ev := range resolved {
		out[k] = ev.ID
	}
	return out, nil
}

// separateV1 is v1's _seperate: a key is conflicted only when two sets hold
// DIFFERENT events for it. A key missing from some sets is not a conflict,
// which is the main way v1 differs from v2 here.
func separateV1(stateSets []pdu.StateMap) (pdu.StateMap, map[pdu.StateKey]map[string]bool) {
	unconflicted := pdu.StateMap{}
	for k, v := range stateSets[0] {
		unconflicted[k] = v
	}
	conflicted := map[pdu.StateKey]map[string]bool{}
	for _, set := range stateSets[1:] {
		for k, v := range set {
			u, ok := unconflicted[k]
			switch {
			case !ok:
				if ls, conf := conflicted[k]; conf {
					ls[v] = true
				} else {
					unconflicted[k] = v
				}
			case u != v:
				conflicted[k] = map[string]bool{v: true, u: true}
				delete(unconflicted, k)
			}
		}
	}
	return unconflicted, conflicted
}

// resolveStateEventsV1 is _resolve_state_events. Within each phase every key
// is resolved against the auth events as they stood before the phase, so the
// order keys are visited in does not matter.
func (r *resolver) resolveStateEventsV1(conflicted map[pdu.StateKey][]*pdu.Event, auth map[pdu.StateKey]*pdu.Event) (map[pdu.StateKey]*pdu.Event, error) {
	resolved := map[pdu.StateKey]*pdu.Event{}
	update := func() {
		for k, ev := range resolved {
			auth[k] = ev
		}
	}

	powerKey := pdu.StateKey{Type: "m.room.power_levels"}
	if evs, ok := conflicted[powerKey]; ok {
		ev, err := r.resolveAuthEventsV1(evs, auth)
		if err != nil {
			return nil, err
		}
		resolved[powerKey] = ev
	}
	update()

	for _, phase := range []string{"m.room.join_rules", "m.room.member"} {
		for k, evs := range conflicted {
			if k.Type != phase {
				continue
			}
			ev, err := r.resolveAuthEventsV1(evs, auth)
			if err != nil {
				return nil, err
			}
			resolved[k] = ev
		}
		update()
	}

	for k, evs := range conflicted {
		if _, ok := resolved[k]; ok {
			continue
		}
		ev, err := r.resolveNormalEventsV1(evs, auth)
		if err != nil {
			return nil, err
		}
		resolved[k] = ev
	}
	return resolved, nil
}

// resolveAuthEventsV1 is _resolve_auth_events: walk the candidates from the
// shallowest, each authed against the previous one; the last that passes wins.
func (r *resolver) resolveAuthEventsV1(evs []*pdu.Event, auth map[pdu.StateKey]*pdu.Event) (*pdu.Event, error) {
	ordered := orderedEventsV1(evs)
	reverse := make([]*pdu.Event, len(ordered))
	for i, ev := range ordered {
		reverse[len(ordered)-1-i] = ev
	}

	keys := map[pdu.StateKey]bool{}
	for _, ev := range evs {
		types, err := pdu.AuthTypesForEvent(r.rv, ev)
		if err != nil {
			return nil, err
		}
		for _, k := range types {
			keys[k] = true
		}
	}
	local := map[pdu.StateKey]*pdu.Event{}
	for k := range keys {
		if ev, ok := auth[k]; ok && ev != nil {
			local[k] = ev
		}
	}

	prev := reverse[0]
	var last *pdu.Event
	for _, ev := range reverse[1:] {
		last = ev
		local[prev.Key()] = prev
		err := pdu.CheckStateDependentAuthRules(ev, authList(local))
		switch {
		case err == nil:
			prev = ev
		case pdu.IsAuthError(err):
			return prev, nil
		default:
			return nil, err
		}
	}
	return last, nil
}

// resolveNormalEventsV1 is _resolve_normal_events: the deepest candidate that
// passes auth, or failing that the shallowest.
func (r *resolver) resolveNormalEventsV1(evs []*pdu.Event, auth map[pdu.StateKey]*pdu.Event) (*pdu.Event, error) {
	ordered := orderedEventsV1(evs)
	list := authList(auth)
	for _, ev := range ordered {
		err := pdu.CheckStateDependentAuthRules(ev, list)
		switch {
		case err == nil:
			return ev, nil
		case pdu.IsAuthError(err):
		default:
			return nil, err
		}
	}
	return ordered[len(ordered)-1], nil
}

// orderedEventsV1 is _ordered_events: deepest first, then by the SHA-1 of
// the event ID.
func orderedEventsV1(evs []*pdu.Event) []*pdu.Event {
	out := append([]*pdu.Event(nil), evs...)
	hash := func(id string) string {
		h := sha1.Sum([]byte(id))
		return hex.EncodeToString(h[:])
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Depth != out[j].Depth {
			return out[i].Depth > out[j].Depth
		}
		return hash(out[i].ID) < hash(out[j].ID)
	})
	return out
}

func authList(m map[pdu.StateKey]*pdu.Event) []*pdu.Event {
	out := make([]*pdu.Event, 0, len(m))
	for _, ev := range m {
		out = append(out, ev)
	}
	return out
}
