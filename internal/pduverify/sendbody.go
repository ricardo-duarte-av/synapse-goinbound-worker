package pduverify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/tidwall/gjson"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
)

// sendEntry is one event of a fed_send_events request, as the inbound worker
// hands a received PDU to the persister (replication/http/federation.py
// _serialize_payload), with its context (events/snapshot.py
// EventContext.serialize). Write mode sends this; the send_body check builds
// it and compares every field with what Synapse persisted.
type sendEntry struct {
	Event              map[string]any `json:"event"`
	RoomVersion        string         `json:"room_version"`
	EventFormatVersion int            `json:"event_format_version"`
	InternalMetadata   map[string]any `json:"internal_metadata"`
	Outlier            bool           `json:"outlier"`
	RejectedReason     *string        `json:"rejected_reason"`
	Context            sendContext    `json:"context"`
}

type sendContext struct {
	StateGroup            int64   `json:"state_group"`
	StateGroupBeforeEvent int64   `json:"state_group_before_event"`
	Rejected              *string `json:"rejected"`
	// StateGroupDeltas is _encode_state_group_delta: [prev, group, delta]
	// per edge the context knows, in the dict's insertion order.
	StateGroupDeltas     []groupDelta `json:"state_group_deltas"`
	StateDeltaDueToEvent []stateRow   `json:"state_delta_due_to_event"`
	AppServiceID         *string      `json:"app_service_id"`
	PartialState         bool         `json:"partial_state"`
}

// groupDelta encodes as Python's (int, int, [[type, state_key, event_id]]).
type groupDelta struct {
	From, To int64
	Delta    []stateRow
}

func (d groupDelta) MarshalJSON() ([]byte, error) {
	return json.Marshal([]any{d.From, d.To, d.Delta})
}

// stateRow encodes as _encode_state_dict's (type, state_key, event_id).
type stateRow [3]string

func encodeStateDict(m pdu.StateMap) []stateRow {
	out := make([]stateRow, 0, len(m))
	for k, v := range m {
		out = append(out, stateRow{k.Type, k.StateKey, v})
	}
	// A Python dict's order is its insertion order, which a Go map does not
	// keep. The persister reads it back into a dict, so order is immaterial;
	// sorted, the body is at least deterministic.
	sort.Slice(out, func(i, j int) bool {
		if out[i][0] != out[j][0] {
			return out[i][0] < out[j][0]
		}
		return out[i][1] < out[j][1]
	})
	return out
}

// pduEventDict is the event as Synapse holds it after event_from_pdu_json
// (federation_base.py:320) and calculate_context_info, which is what
// get_pdu_json sends: unsigned stripped to its whitelist, age turned into
// age_ts against the request time, and replaces_state added for a state
// event that replaces another. unsigned is always there, {} when the PDU had
// none: the Rust event's field is serde(default) and always serialized.
func pduEventDict(raw []byte, received time.Time, replaces string) (map[string]any, error) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var ev map[string]any
	if err := d.Decode(&ev); err != nil {
		return nil, err
	}
	if u, ok := ev["unsigned"]; ok {
		unsigned, isObj := u.(map[string]any)
		if !isObj {
			// _strip_unsigned_values then calls .items() on it, which
			// raises: Synapse drops the PDU.
			return nil, fmt.Errorf("unsigned is not an object")
		}
		allowed := map[string]bool{"age": true}
		if ev["type"] == "m.room.member" {
			allowed["knock_room_state"], allowed["invite_room_state"] = true, true
		}
		kept := map[string]any{}
		for k, v := range unsigned {
			if allowed[k] {
				kept[k] = v
			}
		}
		age, hasAge := kept["age"]
		delete(kept, "age")
		if n, ok := pyInt(age); hasAge && ok && !received.IsZero() {
			kept["age_ts"] = json.Number(fmt.Sprint(received.UnixMilli() - n))
		}
		ev["unsigned"] = kept
	}
	unsigned, _ := ev["unsigned"].(map[string]any)
	if unsigned == nil {
		unsigned = map[string]any{}
		ev["unsigned"] = unsigned
	}
	if replaces != "" {
		unsigned["replaces_state"] = replaces
	}
	return ev, nil
}

// pyInt is isinstance(v, int) then int(v), for a decoded JSON value: an
// integer literal, or a bool, which Python counts as an int.
func pyInt(v any) (int64, bool) {
	switch v := v.(type) {
	case bool:
		if v {
			return 1, true
		}
		return 0, true
	case json.Number:
		if strings.ContainsAny(string(v), ".eE") {
			return 0, false
		}
		n, err := v.Int64()
		return n, err == nil
	}
	return 0, false
}

// SendInput is what the send_body check builds on: the PDU as received,
// and the other checks' results for it.
type SendInput struct {
	Raw      []byte
	Received time.Time
	// Replay, StateGroups and SoftFail are those checks' results; each
	// must have matched.
	Replay, StateGroups, SoftFail *Result
	// PolicySigned is the policy server Synapse asked, and got a
	// signature from: write mode adds the one it is given, which the
	// check takes from Synapse's copy.
	PolicySigned string
	// PolicySigs, when set, are the signatures the policy server gave us,
	// added in place of Synapse's.
	PolicySigs map[string]string
}

// SendBody builds the fed_send_events entry write mode would send for the
// event and compares it with what Synapse persisted: the event JSON, its
// internal metadata, outlier and rejection, and the context's groups.
func (s *Verifier) SendBody(ctx context.Context, in SendInput) *Result {
	r := in.Replay
	res := &Result{EventID: r.EventID, RoomID: r.RoomID, Type: r.Type, Version: r.Version}
	switch {
	case in.StateGroups == nil || in.StateGroups.Outcome != OutcomeMatch || in.StateGroups.plan == nil:
		return res.fail(OutcomeSkipped, "state_groups did not match")
	case in.SoftFail == nil || in.SoftFail.Outcome != OutcomeMatch:
		return res.fail(OutcomeSkipped, "soft_fail did not match")
	}
	entry, why, err := s.buildSendEntry(ctx, in)
	if err != nil {
		return res.fail(OutcomeError, err.Error())
	}
	if why != "" {
		return res.fail(OutcomeSkipped, why)
	}

	diffs, skip, err := s.compareEntry(ctx, r.EventID, r.replay.ev, entry)
	switch {
	case err != nil:
		return res.fail(OutcomeError, err.Error())
	case skip != "":
		return res.fail(OutcomeSkipped, skip)
	case len(diffs) > 0:
		res.Outcome, res.Reason, res.StateDiff = OutcomeMismatch, "send body", diffs
		return res
	}
	res.Outcome = OutcomeMatch
	return res
}

// compareEntry compares a fed_send_events entry with what Synapse persisted
// for the event: the event JSON (get_dict_for_persistence), its internal
// metadata, and the context's group.
func (s *Verifier) compareEntry(ctx context.Context, id string, stored *pdu.Event, entry sendEntry) (diffs []string, skip string, err error) {
	add := func(format string, a ...any) { diffs = append(diffs, fmt.Sprintf(format, a...)) }

	var storedEv map[string]any
	d := json.NewDecoder(bytes.NewReader(stored.JSON))
	d.UseNumber()
	if err := d.Decode(&storedEv); err != nil {
		return nil, "", fmt.Errorf("stored event: %w", err)
	}
	oursAge, storedAge := popAgeTS(entry.Event), popAgeTS(storedEv)
	switch {
	case (oursAge == nil) != (storedAge == nil):
		add("unsigned.age_ts: ours %v, stored %v", oursAge, storedAge)
	case oursAge != nil:
		// Synapse takes the request time on its own clock, a moment after
		// ours.
		if dt := *storedAge - *oursAge; dt < -2000 || dt > 10000 {
			add("unsigned.age_ts: stored is %dms after ours", dt)
		}
	}
	for _, k := range unionKeys(entry.Event, storedEv) {
		if !reflect.DeepEqual(entry.Event[k], storedEv[k]) {
			a, _ := json.Marshal(entry.Event[k])
			b, _ := json.Marshal(storedEv[k])
			add("event.%s: ours %s, stored %s", k, clip(a), clip(b))
		}
	}

	meta, err := s.st.InternalMetadata(ctx, id)
	if err != nil {
		return nil, "", err
	}
	for _, k := range []string{"txn_id", "token_id", "device_id", "proactively_send"} {
		if _, ok := meta[k]; ok {
			// Made here: sent by one of our clients (txn_id, token_id,
			// device_id), or a dummy event to tidy forward extremities
			// (proactively_send, as on our own remote joins). Never a
			// PDU received over /send; sweeps sample them.
			return nil, "local event", nil
		}
	}
	if _, ok := meta["policy_server_spammy"]; ok {
		return nil, "policy server soft-failed it", nil
	}
	if !reflect.DeepEqual(jsonNormal(entry.InternalMetadata), jsonNormal(meta)) {
		a, _ := json.Marshal(entry.InternalMetadata)
		b, _ := json.Marshal(meta)
		add("internal_metadata: ours %s, stored %s", a, b)
	}

	// A rejected event gets the state before it (_store_event_state_mappings_txn).
	want := entry.Context.StateGroup
	if entry.RejectedReason != nil {
		want = entry.Context.StateGroupBeforeEvent
	}
	if g, err := s.st.StateGroupForEvent(ctx, id); err != nil {
		return nil, "", err
	} else if g != want {
		add("context.state_group: ours %d, stored %d", want, g)
	}
	return diffs, "", nil
}

// buildSendEntry is the entry for an event the other checks agreed on. why
// is set when one cannot be built the way Synapse would.
func (s *Verifier) buildSendEntry(ctx context.Context, in SendInput) (sendEntry, string, error) {
	rp := in.Replay.replay
	ev := rp.ev
	plan := *in.StateGroups.plan
	switch {
	case ev.Rejected:
		return sendEntry{}, "rejected", nil
	case !gjson.GetBytes(in.Raw, "hashes").Exists():
		return sendEntry{}, "no hashes", nil
	}
	if ok, err := pdu.CheckContentHash(in.Raw); err != nil || !ok {
		// Synapse sends, and stores, its redacted copy (prune_event).
		return sendEntry{}, "redacted on receipt", nil
	}

	var replaces string
	if ev.IsState() {
		if old := in.Replay.before[ev.Key()]; old != ev.ID {
			replaces = old
		}
	}
	evDict, err := pduEventDict(in.Raw, in.Received, replaces)
	if err != nil {
		return sendEntry{}, "event_from_pdu_json: " + err.Error(), nil
	}
	if in.PolicySigs != nil {
		sigs, _ := evDict["signatures"].(map[string]any)
		if sigs != nil {
			mine, _ := sigs[in.PolicySigned].(map[string]any)
			if mine == nil {
				mine = map[string]any{}
				sigs[in.PolicySigned] = mine
			}
			for k, v := range in.PolicySigs {
				mine[k] = v
			}
		}
	} else if in.PolicySigned != "" {
		sigs, _ := evDict["signatures"].(map[string]any)
		var stored map[string]any
		d := json.NewDecoder(bytes.NewReader([]byte(gjson.GetBytes(ev.JSON, "signatures").Get(gjson.Escape(in.PolicySigned)).Raw)))
		d.UseNumber()
		if sigs != nil && d.Decode(&stored) == nil {
			sigs[in.PolicySigned] = stored
		}
	}

	meta := map[string]any{}
	if in.SoftFail.OurRej {
		meta["soft_failed"] = true
	}
	if ev.RecheckRedaction {
		meta["recheck_redaction"] = true
	}

	// The groups: before, and after for a state event (calculate_context_info,
	// UnpersistedEventContext.persist).
	before := rp.ownGroup
	after := rp.ownGroup
	if ev.IsState() {
		prev, hasPrev, _, err := s.st.StateDelta(ctx, rp.ownGroup)
		if err != nil {
			return sendEntry{}, "", err
		}
		before = plan.group
		if hasPrev {
			before = prev
		}
	}
	// The edge into the group before, as the resolved entry carries it.
	var into *groupDelta
	switch {
	case plan.kind == planReuse && len(rp.groups) == 1:
		// resolve_state_groups_for_events: the one group, with its stored
		// edge (get_state_group_delta).
		prev, hasPrev, delta, err := s.st.StateDelta(ctx, plan.group)
		if err != nil {
			return sendEntry{}, "", err
		}
		if hasPrev {
			into = &groupDelta{From: prev, To: before, Delta: encodeStateDict(delta)}
		}
	case plan.kind == planDelta:
		// Even when the group was stored in full for a long chain, the
		// entry keeps the prev group and delta it was built from.
		into = &groupDelta{From: plan.prev, To: before, Delta: encodeStateDict(plan.delta)}
	}
	// _build_state_group_deltas: before -> after first (for a non-state
	// event the same group, with an empty delta), then the edge in.
	dueToEvent := pdu.StateMap{}
	if ev.IsState() {
		dueToEvent[ev.Key()] = ev.ID
	}
	deltas := []groupDelta{{From: before, To: after, Delta: encodeStateDict(dueToEvent)}}
	if into != nil {
		deltas = append(deltas, *into)
	}

	return sendEntry{
		Event:              evDict,
		RoomVersion:        ev.Room.ID,
		EventFormatVersion: ev.Room.EventFormat,
		InternalMetadata:   meta,
		Outlier:            false,
		RejectedReason:     nil,
		Context: sendContext{
			StateGroup:            after,
			StateGroupBeforeEvent: before,
			StateGroupDeltas:      deltas,
			StateDeltaDueToEvent:  encodeStateDict(dueToEvent),
		},
	}, "", nil
}

// jsonEqual compares decoded JSON values by their encoding (map keys are
// sorted).
func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

// popAgeTS removes unsigned.age_ts, returning it.
func popAgeTS(ev map[string]any) *int64 {
	u, _ := ev["unsigned"].(map[string]any)
	if u == nil {
		return nil
	}
	v, ok := u["age_ts"]
	if !ok {
		return nil
	}
	delete(u, "age_ts")
	n, ok := pyInt(v)
	if !ok {
		return nil
	}
	return &n
}

func unionKeys(a, b map[string]any) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range []map[string]any{a, b} {
		for k := range m {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
	}
	sort.Strings(out)
	return out
}

func clip(b []byte) string {
	if len(b) > 200 {
		return string(b[:200]) + "..."
	}
	return string(b)
}

// SweepSendInput rebuilds, for a sweep over stored events, what the
// send_body check is given live: the PDU as it arrived (the stored JSON,
// with replaces_state taken out and age_ts turned back into an age at
// received_ts) and a soft-fail result agreeing with Synapse's. It tests the
// builder, not the age or soft-fail handling.
func (s *Verifier) SweepSendInput(ctx context.Context, replay, groups *Result) (SendInput, error) {
	in := SendInput{Replay: replay, StateGroups: groups}
	got, _, err := s.st.GetStoredEvents(ctx, []string{replay.EventID})
	if err != nil {
		return in, err
	}
	se := got[replay.EventID]
	if se == nil {
		return in, fmt.Errorf("%s not found", replay.EventID)
	}
	var ev map[string]any
	d := json.NewDecoder(bytes.NewReader(se.JSON))
	d.UseNumber()
	if err := d.Decode(&ev); err != nil {
		return in, err
	}
	if u, ok := ev["unsigned"].(map[string]any); ok {
		delete(u, "replaces_state")
		if ts, ok := pyInt(u["age_ts"]); ok {
			delete(u, "age_ts")
			u["age"] = se.ReceivedTS - ts
		}
	}
	in.Raw, err = json.Marshal(ev)
	if err != nil {
		return in, err
	}
	in.Received = time.UnixMilli(se.ReceivedTS)
	softFailed, err := s.st.SoftFailed(ctx, replay.EventID)
	if err != nil {
		return in, err
	}
	in.SoftFail = &Result{Outcome: OutcomeMatch, OurRej: softFailed}
	return in, nil
}

// SendEntry is the fed_send_events entry for a decided event, with the
// state groups write mode stored: before, and after (before again for a
// non-state event, and for a rejected one only as Synapse sends it).
// staged is the staged event JSON (get_dict()). It is what
// UnpersistedEventContext.persist and EventContext.serialize produce.
func (d *Decision) SendEntry(staged []byte, before, after int64) (json.RawMessage, error) {
	e, err := d.sendEntry(staged, before, after)
	if err != nil {
		return nil, err
	}
	return json.Marshal(e)
}

func (d *Decision) sendEntry(staged []byte, before, after int64) (sendEntry, error) {
	ev := d.Event
	dec := json.NewDecoder(bytes.NewReader(staged))
	dec.UseNumber()
	var evDict map[string]any
	if err := dec.Decode(&evDict); err != nil {
		return sendEntry{}, err
	}
	if d.Replaces != "" {
		u, _ := evDict["unsigned"].(map[string]any)
		if u == nil {
			u = map[string]any{}
			evDict["unsigned"] = u
		}
		u["replaces_state"] = d.Replaces
	}
	dueToEvent := pdu.StateMap{}
	if ev.IsState() {
		dueToEvent[ev.Key()] = ev.ID
	}
	// _build_state_group_deltas: before -> after, then the edge into the
	// group before that the state entry was built from.
	deltas := []groupDelta{{From: before, To: after, Delta: encodeStateDict(dueToEvent)}}
	if p, delta := d.Entry.PrevGroup(); p != 0 {
		deltas = append(deltas, groupDelta{From: p, To: before, Delta: encodeStateDict(delta)})
	}
	var rejected *string
	if d.Rejected != "" {
		r := d.Rejected
		rejected = &r
	}
	meta := d.Metadata
	if meta == nil {
		meta = map[string]any{}
	}
	return sendEntry{
		Event:              evDict,
		RoomVersion:        ev.Room.ID,
		EventFormatVersion: ev.Room.EventFormat,
		InternalMetadata:   meta,
		RejectedReason:     rejected,
		Context: sendContext{
			StateGroup:            after,
			StateGroupBeforeEvent: before,
			Rejected:              rejected,
			StateGroupDeltas:      deltas,
			StateDeltaDueToEvent:  encodeStateDict(dueToEvent),
		},
	}, nil
}
