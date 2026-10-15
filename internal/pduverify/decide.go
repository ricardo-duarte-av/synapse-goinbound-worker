package pduverify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tidwall/gjson"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdustore"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pyset"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/stateres"
)

// Write mode's decisions: on_receive_pdu (handlers/federation_event.py:193)
// for an event write mode holds the room lock for, computed with the same
// code the shadow checks against Synapse. Decide writes nothing; the caller
// (package inbound) stores the state groups, the push rows, and sends the
// event to the persister.

// StateEntry is _StateCacheEntry (state/__init__.py:96): the state before an
// event, as a group (Group), as a delta on a group (PrevGroup and Delta), or
// in full (State). Entries are shared with the StateCache, so storing a group
// for one (SetGroup) is seen by every later event resolving the same groups.
type StateEntry struct {
	mu        sync.Mutex
	group     int64
	prevGroup int64
	delta     pdu.StateMap
	state     pdu.StateMap
}

// Group, PrevGroup and Delta read the entry.
func (e *StateEntry) Group() int64 { e.mu.Lock(); defer e.mu.Unlock(); return e.group }
func (e *StateEntry) PrevGroup() (int64, pdu.StateMap) {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.prevGroup, e.delta
}

// State is the full state, held only when there is neither a group nor a
// group to build on.
func (e *StateEntry) State() pdu.StateMap { e.mu.Lock(); defer e.mu.Unlock(); return e.state }

// SetGroup is set_state_group: the state now has a group, and the full map
// is dropped.
func (e *StateEntry) SetGroup(g int64) {
	e.mu.Lock()
	e.group, e.state = g, nil
	e.mu.Unlock()
}

// DropPrev forgets the group to build on, as calculate_context_info does
// when that group turns out to be deleted.
func (e *StateEntry) DropPrev() {
	e.mu.Lock()
	e.prevGroup, e.delta = 0, nil
	e.mu.Unlock()
}

// StateCache is StateResolutionHandler._state_cache: resolutions by the set
// of state groups resolved, an hour each, at most 100,000. It is per
// process in Synapse too; ours is a process of its own.
type StateCache struct {
	mu  sync.Mutex
	m   map[string]stateCacheItem
	ttl time.Duration
	max int
	now func() time.Time
}

type stateCacheItem struct {
	e  *StateEntry
	at time.Time
}

// NewStateCache is an empty cache with Synapse's limits.
func NewStateCache() *StateCache {
	return &StateCache{m: map[string]stateCacheItem{}, ttl: time.Hour, max: 100000, now: time.Now}
}

func cacheKey(groups []int64) string {
	g := slices.Clone(groups)
	slices.Sort(g)
	return fmt.Sprint(g)
}

func (c *StateCache) get(groups []int64) *StateEntry {
	c.mu.Lock()
	defer c.mu.Unlock()
	it, ok := c.m[cacheKey(groups)]
	if !ok || c.now().Sub(it.at) > c.ttl {
		return nil
	}
	return it.e
}

func (c *StateCache) put(groups []int64, e *StateEntry) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	if len(c.m) >= c.max {
		for k, it := range c.m {
			if now.Sub(it.at) > c.ttl {
				delete(c.m, k)
			}
		}
		for k := range c.m {
			if len(c.m) < c.max {
				break
			}
			delete(c.m, k)
		}
	}
	c.m[cacheKey(groups)] = stateCacheItem{e: e, at: now}
}

// Pop drops the entry for groups: resolve_state_groups does when a cached
// entry points at a deleted group.
func (c *StateCache) Pop(groups []int64) {
	c.mu.Lock()
	delete(c.m, cacheKey(groups))
	c.mu.Unlock()
}

// Rejection reasons (RejectedReason, api/constants.py).
const (
	RejectedAuthError = "auth_error"
	RejectedOversized = "oversized_event"
)

// PushRow is a row for event_push_actions_staging.
type PushRow struct {
	UserID    string
	Actions   string // the column, as _serialize_action writes it
	Notif     bool
	Highlight bool
	Unread    bool
	ThreadID  string
}

// DecideInput is a staged event.
type DecideInput struct {
	Origin string
	// EventJSON and Metadata are the staged copy: event.get_dict() and
	// internal_metadata.get_dict().
	EventJSON []byte
	Metadata  []byte
	EventID   string
	Room      *pdu.RoomVersion
	// OurServer is our server name.
	OurServer string
	// Cache is write mode's state cache.
	Cache *StateCache
	// Snapshot, when set, is the room as found before Synapse handled the
	// event (the shadow's); otherwise one is taken now.
	Snapshot *pdustore.Snapshot
}

// Decision is what to do with a staged event.
type Decision struct {
	// Exactly one of Ignore, Drop and Defer is set, or none when the event
	// is to be persisted.
	//
	// Ignore: Synapse ignores the event (already seen, not in the room).
	// Drop: Synapse fails it and persists nothing (FederationError).
	// Defer: write mode does not do this exactly as Synapse would, so the
	// event stays staged for Synapse's own inbound worker.
	Ignore, Drop, Defer string

	Event *pdu.Event
	// Groups are the prev events' distinct state groups, the cache key.
	Groups []int64
	// Entry is the state before: reuse Entry.Group(), else store a group
	// built on Entry.PrevGroup(), else store Entry.State() in full.
	Entry *StateEntry
	// Before is the state before the event.
	Before pdu.StateMap
	// Bump are groups whose pending deletion is bumped before the event's
	// groups are stored (check_state_groups_and_bump_deletion), in order.
	Bump [][]int64

	Rejected   string
	SoftFailed bool
	// Metadata is the event's internal metadata to persist.
	Metadata map[string]any
	// Replaces is unsigned.replaces_state.
	Replaces string
	// Push are the push action rows to stage.
	Push []PushRow
	// pushRows are Push, for the decide check.
	pushRows map[string]pushRow
	// pushSkipped says Synapse computes no rows (min depth).
	pushSkipped bool
}

// Decide works out how Synapse would handle a staged event, up to but not
// including its writes.
func (s *Verifier) Decide(ctx context.Context, in DecideInput) (*Decision, error) {
	d := &Decision{}
	ev, err := pdu.ParseEvent(in.EventJSON, in.EventID, in.Room, false)
	if err != nil {
		// make_event_from_dict raises on it, in the room's processing loop.
		d.Defer = "unparseable: " + err.Error()
		return d, nil
	}
	d.Event = ev
	meta, err := decodeObject(in.Metadata)
	if err != nil {
		d.Defer = "internal metadata: " + err.Error()
		return d, nil
	}
	if meta["outlier"] == true {
		d.Defer = "staged as an outlier"
		return d, nil
	}

	// We reprocess an event we hold only as an outlier; that path is
	// Synapse's for now.
	if in.Snapshot == nil {
		got, bad, err := s.st.GetStoredEvents(ctx, []string{in.EventID})
		if err != nil {
			return nil, err
		}
		if bad[in.EventID] != nil {
			d.Defer = "already held, unparseable"
			return d, nil
		}
		if se := got[in.EventID]; se != nil {
			if !se.Outlier {
				d.Ignore = "already seen"
				return d, nil
			}
			d.Defer = "de-outliering"
			return d, nil
		}
	} else if in.Snapshot.EventPresent {
		d.Defer = "held when the snapshot was taken"
		return d, nil
	}

	// _sanity_check_event.
	if len(ev.PrevEvents) > 20 {
		d.Drop = fmt.Sprintf("too many prev_events (%d)", len(ev.PrevEvents))
		return d, nil
	}
	if len(ev.AuthEvents) > 10 {
		d.Drop = fmt.Sprintf("too many auth_events (%d)", len(ev.AuthEvents))
		return d, nil
	}

	joined, ok, err := s.st.HostJoined(ctx, ev.RoomID, in.OurServer)
	if err != nil {
		return nil, err
	}
	if !ok {
		d.Defer = "host joined unknown"
		return d, nil
	}
	if !joined {
		if rescindsInvite(ev, in.OurServer) {
			d.Defer = "not in room, invite rescission"
			return d, nil
		}
		d.Ignore = "not in room"
		return d, nil
	}

	// Missing prev events are fetched from the origin; that is Synapse's
	// for now.
	snap := in.Snapshot
	if snap == nil {
		types, err := pdu.AuthTypesForEvent(in.Room, ev)
		if err != nil {
			d.Defer = "auth types: " + err.Error()
			return d, nil
		}
		if snap, err = s.st.TakeSnapshot(ctx, ev.RoomID, in.EventID, ev.PrevEvents, types); err != nil {
			return nil, err
		}
	}
	if !snap.PrevsInTimeline {
		d.Defer = "missing prevs"
		return d, nil
	}
	if snap.PartialState {
		d.Defer = "partial state room"
		return d, nil
	}

	// compute_event_context: the state before, through the cache.
	if why, err := s.resolveForEvent(ctx, in, ev, d); err != nil || why != "" {
		if err != nil {
			return nil, err
		}
		d.Defer = why
		return d, nil
	}

	if ev.IsState() {
		if old := d.Before[ev.Key()]; old != "" && old != ev.ID {
			d.Replaces = old
		}
	}

	// _check_event_auth.
	rej, why, err := s.checkEventAuth(ctx, ev, d.Before)
	if err != nil {
		var re *pdu.RaiseError
		if errors.As(err, &re) {
			// Missing auth events are fetched from the origin, and
			// Synapse's other exceptions fail the event; neither is ours
			// to decide yet.
			d.Defer = "auth: " + err.Error()
			return d, nil
		}
		return nil, err
	}
	if rej {
		d.Rejected = RejectedAuthError
		if strings.HasPrefix(why, "oversized") {
			d.Rejected = RejectedOversized
		}
	}

	// The internal metadata persisted: what staging held, plus soft-fail
	// and recheck_redaction.
	d.Metadata = map[string]any{}
	for k, v := range meta {
		d.Metadata[k] = v
	}
	if ev.RecheckRedaction {
		d.Metadata["recheck_redaction"] = true
	}
	d.SoftFailed = meta["soft_failed"] == true
	if !rej {
		soft, _, err := s.softFailed(ctx, ev, snap)
		if err != nil {
			var re *pdu.RaiseError
			if errors.As(err, &re) {
				d.Defer = "soft fail: " + err.Error()
				return d, nil
			}
			return nil, err
		}
		d.SoftFailed = d.SoftFailed || soft
	}
	if d.SoftFailed {
		d.Metadata["soft_failed"] = true
	}

	// _run_push_actions_and_persist_event: not for rejected events, nor
	// those older than the room's min depth.
	if !rej {
		rows, why, err := s.decidePush(ctx, ev, d, snap)
		if err != nil {
			return nil, err
		}
		if why != "" {
			d.Defer = why
			return d, nil
		}
		d.Push = rows
	}
	return d, nil
}

// resolveForEvent is calculate_context_info's resolve_state_groups_for_events,
// with resolve_state_groups' cache. It fills in Groups, Entry, Before and
// Bump, or says why it cannot.
func (s *Verifier) resolveForEvent(ctx context.Context, in DecideInput, ev *pdu.Event, d *Decision) (string, error) {
	// get_state_group_for_events, then set(state_groups.values()): the
	// groups in some order Synapse cannot predict either.
	var insertion []int64
	seen := map[int64]bool{}
	for _, p := range ev.PrevEvents {
		g, err := s.st.StateGroupForEvent(ctx, p)
		if errors.Is(err, pdustore.ErrNoStateGroup) {
			return "prev event without state group", nil
		}
		if err != nil {
			return "", err
		}
		if !seen[g] {
			seen[g] = true
			insertion = append(insertion, g)
		}
	}
	switch len(insertion) {
	case 0:
		return "no prev events", nil
	case 1:
		g := insertion[0]
		prev, hasPrev, delta, err := s.st.StateDelta(ctx, g)
		if err != nil {
			return "", err
		}
		e := &StateEntry{group: g}
		if hasPrev {
			e.prevGroup, e.delta = prev, delta
		}
		before, err := s.groups.get(ctx, s.st, g)
		if err != nil {
			return "", err
		}
		d.Groups, d.Entry, d.Before = insertion, e, before
		// calculate_context_info bumps the group it relies on.
		d.Bump = [][]int64{{g}}
		return "", nil
	}

	groups := pyset.Order(insertion)
	d.Groups = groups
	if e := in.Cache.get(groups); e != nil {
		// A cache hit is checked against deletion; the caller bumps the
		// entry's groups, and on a missing one pops the entry and asks
		// again.
		var check []int64
		if g := e.Group(); g != 0 {
			check = append(check, g)
		}
		if p, _ := e.PrevGroup(); p != 0 {
			check = append(check, p)
		}
		before, err := s.entryState(ctx, e)
		if err != nil {
			return "", err
		}
		d.Entry, d.Before = e, before
		d.Bump = [][]int64{check}
		if g := e.Group(); g != 0 {
			d.Bump = append(d.Bump, []int64{g})
		} else if p, _ := e.PrevGroup(); p != 0 {
			d.Bump = append(d.Bump, []int64{p})
		}
		return "", nil
	}

	sets := make([]pdu.StateMap, len(groups))
	for i, g := range groups {
		m, err := s.groups.get(ctx, s.st, g)
		if err != nil {
			return "", err
		}
		sets[i] = m
	}
	before, err := stateres.ResolveWith(ctx, ev.RoomID, ev.Room, sets, s.st, s.opts)
	if errors.Is(err, stateres.ErrUnsupported) {
		return "state resolution v1", nil
	}
	if err != nil {
		var re *pdu.RaiseError
		if errors.As(err, &re) {
			return "state resolution: " + err.Error(), nil
		}
		return "", err
	}
	plan := planBefore(groups, sets, before)
	e := &StateEntry{}
	switch plan.kind {
	case planReuse:
		e.group = plan.group
	case planDelta:
		e.prevGroup, e.delta = plan.prev, plan.delta
	default:
		e.state = before
	}
	in.Cache.put(groups, e)
	d.Entry, d.Before = e, before
	// resolve_state_groups checks every group resolved, then
	// calculate_context_info the one it relies on.
	d.Bump = [][]int64{slices.Clone(groups)}
	if e.group != 0 {
		d.Bump = append(d.Bump, []int64{e.group})
	} else if e.prevGroup != 0 {
		d.Bump = append(d.Bump, []int64{e.prevGroup})
	}
	return "", nil
}

// entryState is _StateCacheEntry.get_state.
func (s *Verifier) entryState(ctx context.Context, e *StateEntry) (pdu.StateMap, error) {
	if st := e.State(); st != nil {
		return st, nil
	}
	if g := e.Group(); g != 0 {
		return s.groups.get(ctx, s.st, g)
	}
	p, delta := e.PrevGroup()
	prev, err := s.groups.get(ctx, s.st, p)
	if err != nil {
		return nil, err
	}
	out := make(pdu.StateMap, len(prev)+len(delta))
	for k, v := range prev {
		out[k] = v
	}
	for k, v := range delta {
		out[k] = v
	}
	return out, nil
}

// decidePush is the push rows Synapse would stage, or why write mode does
// not compute them.
func (s *Verifier) decidePush(ctx context.Context, ev *pdu.Event, d *Decision, snap *pdustore.Snapshot) ([]PushRow, string, error) {
	if s.push == nil {
		return nil, "push not configured", nil
	}
	md, err := s.st.MinDepth(ctx, ev.RoomID)
	if err != nil {
		return nil, "", err
	}
	if md == nil || *md > ev.Depth {
		// "Skipping push actions for old event".
		d.pushSkipped = true
		return nil, "", nil
	}
	if ev.Type == "m.room.member" {
		if m, err := ev.Membership(); err == nil && m == "invite" {
			// Invite filtering (MSC4155/MSC4380) is not reproduced.
			return nil, "push for an invite", nil
		}
	}
	if d.SoftFailed {
		// filter_event_for_clients_with_state shows it to nobody.
		d.pushRows = map[string]pushRow{}
		return nil, "", nil
	}
	rows, err := s.pushRows(ctx, ev, d.Before, snap)
	if err != nil {
		var re *pdu.RaiseError
		if errors.As(err, &re) {
			return nil, "push: " + err.Error(), nil
		}
		return nil, "", err
	}
	d.pushRows = rows
	out := make([]PushRow, 0, len(rows))
	for u, r := range rows {
		out = append(out, PushRow{UserID: u, Actions: r.column, Notif: r.notif, Highlight: r.highlight, Unread: r.unread, ThreadID: r.thread})
	}
	slices.SortFunc(out, func(a, b PushRow) int { return strings.Compare(a.UserID, b.UserID) })
	return out, "", nil
}

func decodeObject(b []byte) (map[string]any, error) {
	r := gjson.ParseBytes(b)
	if !r.IsObject() {
		return nil, fmt.Errorf("not an object")
	}
	out := map[string]any{}
	if v, ok := r.Value().(map[string]any); ok {
		out = v
	}
	return out, nil
}

// CheckDecision compares a decision, made when the PDU arrived, with what
// Synapse did once it had persisted the event: rejected or not, soft-failed
// or not, the state group before (reused, or stored for the event as the
// entry says), and the push rows. Synapse's group then goes into our cache
// entry, so the cache stays the one Synapse's process holds.
func (s *Verifier) CheckDecision(ctx context.Context, id string, d *Decision, snap *pdustore.Snapshot, staged []byte) *Result {
	res := &Result{EventID: id}
	switch {
	case d == nil:
		return res.fail(OutcomeSkipped, "no decision")
	case d.Defer != "":
		return res.fail(OutcomeSkipped, "deferred: "+d.Defer)
	}
	got, _, err := s.st.GetStoredEvents(ctx, []string{id})
	if err != nil {
		return res.fail(OutcomeError, err.Error())
	}
	se := got[id]
	if d.Ignore != "" || d.Drop != "" {
		if se == nil {
			res.Outcome, res.Reason = OutcomeMatch, "not persisted"
			return res
		}
		res.Outcome, res.Reason = OutcomeMismatch, "decide"
		res.StateDiff = []string{"we would not persist it (" + d.Ignore + d.Drop + "); Synapse did"}
		return res
	}
	if se == nil {
		return res.fail(OutcomeSkipped, "not found")
	}
	ev := se.Event
	res.RoomID, res.Type, res.Version = ev.RoomID, ev.Type, ev.Room.ID
	res.SynapseRej, res.OurRej = ev.Rejected, d.Rejected != ""
	if se.Outlier {
		return res.fail(OutcomeSkipped, "outlier")
	}
	var diffs []string
	if res.SynapseRej != res.OurRej {
		diffs = append(diffs, fmt.Sprintf("rejected: ours %q, Synapse %v", d.Rejected, ev.Rejected))
	}
	soft, err := s.st.SoftFailed(ctx, id)
	if err != nil {
		return res.fail(OutcomeError, err.Error())
	}
	if !ev.Rejected && soft != d.SoftFailed {
		diffs = append(diffs, fmt.Sprintf("soft_failed: ours %v, Synapse %v", d.SoftFailed, soft))
	}

	// The group before: the group itself for a non-state event, the after
	// group's prev for a state event.
	own, err := s.st.StateGroupForEvent(ctx, id)
	if err != nil {
		return res.fail(OutcomeSkipped, "no state group for the event")
	}
	// A rejected event maps to the state before it, state event or not.
	before := own
	if ev.IsState() && !ev.Rejected {
		prev, hasPrev, _, err := s.st.StateDelta(ctx, own)
		if err != nil {
			return res.fail(OutcomeError, err.Error())
		}
		if !hasPrev {
			return res.fail(OutcomeSkipped, "group after stored in full")
		}
		before = prev
	}
	if g := d.Entry.Group(); g != 0 {
		if before != g {
			diffs = append(diffs, fmt.Sprintf("group before: ours %d, Synapse %d", g, before))
		}
	} else {
		plan := groupPlan{kind: planFull}
		if p, delta := d.Entry.PrevGroup(); p != 0 {
			plan = groupPlan{kind: planDelta, prev: p, delta: delta}
		}
		why, err := s.storedAs(ctx, before, id, plan)
		if err != nil {
			return res.fail(OutcomeError, err.Error())
		}
		if why != "" {
			creator, _ := s.st.StateGroupEvent(ctx, before)
			if creator != id {
				// Synapse's cache held a group ours did not: its
				// process saw these groups resolved before ours did.
				return res.fail(OutcomeSkipped, "resolution cached by Synapse")
			}
			diffs = append(diffs, "group before: "+why)
		} else {
			// What write mode does once it has stored the group.
			d.Entry.SetGroup(before)
		}
	}

	if !ev.Rejected && d.pushRows != nil {
		p := s.pushCheck(ctx, id, d.Before, snap, d.pushRows)
		switch p.Outcome {
		case OutcomeMismatch:
			diffs = append(diffs, p.PushDiff...)
		case OutcomeMatch:
		default:
			res.PushDiff = []string{"push not compared: " + p.Reason}
		}
	}
	// The fed_send_events entry, with Synapse's groups.
	if staged != nil && len(diffs) == 0 {
		// For a rejected state event Synapse's after group is not
		// recorded anywhere; compareEntry checks the group it maps to.
		after := own
		{
			entry, err := d.sendEntry(staged, before, after)
			if err != nil {
				return res.fail(OutcomeError, err.Error())
			}
			ed, skip, err := s.compareEntry(ctx, id, ev, entry)
			switch {
			case err != nil:
				return res.fail(OutcomeError, err.Error())
			case skip != "":
				res.PushDiff = append(res.PushDiff, "entry not compared: "+skip)
			default:
				diffs = append(diffs, ed...)
			}
		}
	}
	if len(diffs) > 0 {
		res.Outcome, res.Reason, res.StateDiff = OutcomeMismatch, "decide", diffs
		return res
	}
	res.Outcome = OutcomeMatch
	return res
}

// NewEntry is a state entry: reuse group, or build on prev with delta, or
// store state in full. For tests of write mode.
func NewEntry(group, prev int64, delta, state pdu.StateMap) *StateEntry {
	return &StateEntry{group: group, prevGroup: prev, delta: delta, state: state}
}

// StagedEvent is the copy of a received PDU Synapse stages: event.get_dict()
// after event_from_pdu_json (unsigned stripped, age as age_ts against the
// request time) and _check_sigs_and_hash (with a policy server's signatures
// added, when it was asked and signed).
func StagedEvent(raw []byte, received time.Time, policyServer string, policySigs map[string]string) ([]byte, error) {
	dict, err := pduEventDict(raw, received, "")
	if err != nil {
		return nil, err
	}
	b, err := json.Marshal(dict)
	if err != nil {
		return nil, err
	}
	if len(policySigs) > 0 {
		return addSignatures(b, policyServer, policySigs)
	}
	return b, nil
}
