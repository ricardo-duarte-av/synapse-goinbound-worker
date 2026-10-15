package pduverify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"time"

	"github.com/tidwall/gjson"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/appservice"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdustore"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/push"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/synapsecfg"
)

// PushConfig is what push evaluation takes from homeserver.yaml.
type PushConfig struct {
	ServerName string
	// AppServiceUsers matches the users appservices claim exclusively;
	// nil when none do.
	AppServiceUsers *regexp.Regexp
	Flags           push.Flags
	// UnreadCounts is msc2654_enabled: count_as_unread rows.
	UnreadCounts bool
}

// EnablePush turns on the push check.
func (s *Verifier) EnablePush(c PushConfig) { s.push = &c }

var (
	defaultNotifAction     = []any{"notify", map[string]any{"set_tweak": "highlight", "value": false}}
	defaultHighlightAction = []any{"notify", map[string]any{"set_tweak": "sound", "value": "default"}, map[string]any{"set_tweak": "highlight"}}
)

// pushRow is one user's event_push_actions row, as Synapse would write it.
type pushRow struct {
	actions any // decoded JSON
	// column is the actions column as stored (_serialize_action): what
	// write mode must write byte for byte.
	column           string
	notif, highlight bool
	unread           bool
	thread           string
}

// Push reproduces BulkPushRuleEvaluator._action_for_event_by_user
// (bulk_push_rule_evaluator.py) for a received event, and compares the rows
// with those Synapse stored in event_push_actions.
//
// before is the state before the event (Replay computes it); nil falls back
// to the event's own state group, which is the state before a non-state
// event. snap, from the live shadow, holds the room as Synapse found it; nil
// in the sweep. Who is in the room, and their display names, are read from
// current state, so the check is skipped when any member event has been
// persisted since -- the reads would not be what Synapse saw.
func (s *Verifier) Push(ctx context.Context, id string, before pdu.StateMap, snap *pdustore.Snapshot) *Result {
	res := &Result{EventID: id}
	if s.push == nil {
		return res.fail(OutcomeSkipped, "push not configured")
	}
	got, bad, err := s.st.GetStoredEvents(ctx, []string{id})
	if err != nil {
		return res.fail(OutcomeError, err.Error())
	}
	if e := bad[id]; e != nil {
		return res.fail(OutcomeSkipped, "unparseable: "+e.Error())
	}
	se := got[id]
	if se == nil {
		return res.fail(OutcomeSkipped, "not found")
	}
	ev := se.Event
	res.RoomID, res.Type, res.Version = ev.RoomID, ev.Type, ev.Room.ID
	switch {
	case se.Outlier:
		return res.fail(OutcomeSkipped, "outlier")
	case ev.Rejected:
		return res.fail(OutcomeSkipped, "rejected")
	case se.StreamOrdering <= 0:
		return res.fail(OutcomeSkipped, "backfilled")
	case snap != nil && snap.EventPresent:
		return res.fail(OutcomeSkipped, "snapshot taken after the event")
	case time.Since(time.UnixMilli(se.ReceivedTS)) > 20*time.Hour:
		// Rows a day old are deleted once summarised
		// (_remove_old_push_actions_that_have_rotated).
		return res.fail(OutcomeSkipped, "pruned")
	}
	if ev.Type == "m.room.member" {
		if m, err := ev.Membership(); err == nil && m == "invite" {
			// Invite filtering (MSC4155/MSC4380) is not reproduced.
			return res.fail(OutcomeSkipped, "invite")
		}
	}

	// _run_push_actions_and_persist_event skips an event older than the
	// room's min_depth. Persisting the event lowered min_depth to at most
	// its depth, so only a min_depth still below it proves the check ran.
	md, err := s.st.MinDepth(ctx, ev.RoomID)
	if err != nil {
		return res.fail(OutcomeError, err.Error())
	}
	if md == nil || *md >= ev.Depth {
		return res.fail(OutcomeSkipped, "min depth")
	}

	after := se.StreamOrdering
	if snap != nil {
		after = snap.MaxStream
	}
	n, err := s.st.MemberEventsAfter(ctx, ev.RoomID, after, id)
	if err != nil {
		return res.fail(OutcomeError, err.Error())
	}
	if n > 0 {
		return res.fail(OutcomeSkipped, "race")
	}

	// Persisting a redaction deletes the redacted event's rows.
	redacted, err := s.st.IsRedacted(ctx, id)
	if err != nil {
		return res.fail(OutcomeError, err.Error())
	}
	if redacted {
		return res.fail(OutcomeSkipped, "redacted")
	}

	stored, err := s.st.PushActions(ctx, id)
	if err != nil {
		return res.fail(OutcomeError, err.Error())
	}
	storedRows := map[string]pushRow{}
	for _, r := range stored {
		var actions any
		if r.Actions == "" {
			actions = jsonNormal(defaultNotifAction)
			if r.Highlight {
				actions = jsonNormal(defaultHighlightAction)
			}
		} else if err := json.Unmarshal([]byte(r.Actions), &actions); err != nil {
			return res.fail(OutcomeError, "stored actions: "+err.Error())
		}
		storedRows[r.UserID] = pushRow{actions: actions, column: r.Actions, notif: r.Notif, highlight: r.Highlight, unread: r.Unread, thread: r.ThreadID}
	}

	if before == nil {
		if ev.IsState() {
			return res.fail(OutcomeSkipped, "no state before")
		}
		g, err := s.st.StateGroupForEvent(ctx, id)
		if err != nil {
			return res.fail(OutcomeSkipped, "no state group for the event")
		}
		if before, err = s.groups.get(ctx, s.st, g); err != nil {
			return res.fail(OutcomeError, err.Error())
		}
	}

	softFailed, err := s.st.SoftFailed(ctx, id)
	if err != nil {
		return res.fail(OutcomeError, err.Error())
	}
	ours := map[string]pushRow{}
	if !softFailed {
		// filter_event_for_clients_with_state shows a soft-failed event
		// to nobody, so it has no rows.
		ours, err = s.pushRows(ctx, ev, before, snap)
		if err != nil {
			var re *pdu.RaiseError
			if errors.As(err, &re) {
				return res.fail(OutcomeRaise, "push: "+err.Error())
			}
			return res.fail(OutcomeError, "push: "+err.Error())
		}
	}

	// A read receipt at or after the event deletes the reader's
	// non-highlight rows -- but in a background loop
	// (_handle_new_receipts_for_notifs_txn), so the row may or may not
	// still be there. Such a reader is left out on both sides.
	readerThread := map[string]string{}
	for u, r := range ours {
		if !r.highlight {
			readerThread[u] = r.thread
		}
	}
	for u, r := range storedRows {
		if !r.highlight {
			if o, ok := ours[u]; !ok || !o.highlight {
				readerThread[u] = r.thread
			}
		}
	}
	if len(readerThread) > 0 {
		readers := make([]string, 0, len(readerThread))
		for u := range readerThread {
			readers = append(readers, u)
		}
		receipts, err := s.st.Receipts(ctx, ev.RoomID, readers)
		if err != nil {
			return res.fail(OutcomeError, err.Error())
		}
		for u, rs := range receipts {
			for _, rc := range rs {
				if rc.StreamOrdering >= se.StreamOrdering && (rc.ThreadID == nil || *rc.ThreadID == readerThread[u]) {
					if o, ok := ours[u]; !ok || !o.highlight {
						delete(ours, u)
					}
					if st, ok := storedRows[u]; ok && !st.highlight {
						delete(storedRows, u)
					}
					break
				}
			}
		}
	}

	for _, r := range storedRows {
		res.PushRows++
		if r.notif {
			res.PushNotify++
		}
	}
	res.PushDiff = diffPush(ours, storedRows)
	if len(res.PushDiff) > 0 {
		res.Outcome, res.Reason = OutcomeMismatch, "push"
		return res
	}
	res.Outcome = OutcomeMatch
	return res
}

// pushRows is _action_for_event_by_user up to add_push_actions_to_staging.
func (s *Verifier) pushRows(ctx context.Context, ev *pdu.Event, before pdu.StateMap, snap *pdustore.Snapshot) (map[string]pushRow, error) {
	cfg := s.push
	countAsUnread := cfg.UnreadCounts && shouldCountAsUnread(ev)

	// _get_rules_for_event: who might be notified.
	var users []string
	var target struct {
		priorID string // the target's member event before this one
		joined  bool
	}
	isMember := ev.Type == "m.room.member"
	if isMember {
		sk := *ev.StateKey
		if ev.Sender != sk && domain(sk) == cfg.ServerName {
			key := pdu.StateKey{Type: "m.room.member", StateKey: sk}
			if snap != nil {
				target.priorID = snap.Current[key]
			} else {
				target.priorID = before[key]
			}
			if target.priorID != "" {
				prior, err := s.st.GetEvents(ctx, []string{target.priorID})
				if err != nil {
					return nil, err
				}
				if p := prior[target.priorID]; p != nil {
					m, _ := p.Membership()
					target.joined = m == "join"
				}
			}
			if target.joined {
				users = []string{sk}
			}
		}
	} else {
		var err error
		if users, err = s.st.LocalJoined(ctx, ev.RoomID); err != nil {
			return nil, err
		}
	}
	kept := users[:0]
	for _, u := range users {
		if u == ev.Sender || (cfg.AppServiceUsers != nil && cfg.AppServiceUsers.MatchString(u)) {
			continue
		}
		kept = append(kept, u)
	}
	users = kept
	if len(users) == 0 {
		return map[string]pushRow{}, nil
	}

	rules, err := s.rulesFor(ctx, users)
	if err != nil {
		return nil, err
	}

	members, err := s.st.JoinedCount(ctx, ev.RoomID)
	if err != nil {
		return nil, err
	}
	if isMember {
		// The count now includes this event; Synapse counted before it.
		if m, _ := ev.Membership(); m == "join" {
			members--
		}
		if target.joined {
			members++
		}
	}

	notifLevels, senderLevel, err := s.powerLevels(ctx, ev, before)
	if err != nil {
		return nil, err
	}
	related, err := s.relatedEvents(ctx, ev)
	if err != nil {
		return nil, err
	}

	var profiles map[string]*string
	if isMember {
		profiles = map[string]*string{}
		if target.joined {
			dn, err := s.st.MemberDisplayName(ctx, target.priorID)
			if err != nil {
				return nil, err
			}
			profiles[*ev.StateKey] = dn
		}
	} else if profiles, err = s.st.Profiles(ctx, ev.RoomID, users); err != nil {
		return nil, err
	}

	thread := "main"
	if rel, ok := relationOf(ev); ok {
		if rel.relType == "m.thread" {
			thread = rel.parent
		} else if thread, err = s.st.ThreadID(ctx, rel.parent); err != nil {
			return nil, err
		}
	}
	var subscribers map[string]bool
	if cfg.Flags.MSC4306 && thread != "main" {
		if subscribers, err = s.st.ThreadSubscribers(ctx, ev.RoomID, thread); err != nil {
			return nil, err
		}
	}

	e := push.NewEvaluator(push.Evaluator{
		Flat:               push.Flatten(ev.JSON),
		HasMentions:        hasKey(ev.Content, "m.mentions"),
		RoomMemberCount:    uint64(max(members, 0)),
		NotificationLevels: notifLevels,
		SenderPowerLevel:   senderLevel,
		Related:            related,
		RelatedEventMatch:  cfg.Flags.MSC3664,
		MSC3931:            cfg.Flags.MSC1767,
		MSC4210:            cfg.Flags.MSC4210,
		MSC4306:            cfg.Flags.MSC4306,
	})

	byUser := map[string][]json.RawMessage{}
	for _, uid := range users {
		dn := ""
		if p := profiles[uid]; p != nil {
			dn = *p
		}
		if dn == "" && isMember && *ev.StateKey == uid {
			if v := pdu.Get(ev.Content, "displayname"); v.Type == gjson.String {
				dn = v.Str
			}
		}
		if countAsUnread {
			byUser[uid] = []json.RawMessage{}
		}
		var sub *bool
		if subscribers != nil {
			b := subscribers[uid]
			sub = &b
		}
		actions := e.Run(rules[uid], uid, dn, sub)
		if push.Notifies(actions) {
			byUser[uid] = actions
		}
	}
	if len(byUser) == 0 {
		return map[string]pushRow{}, nil
	}

	visible, err := s.visibleTo(ctx, ev, before, byUser)
	if err != nil {
		return nil, err
	}
	out := map[string]pushRow{}
	for uid, actions := range byUser {
		if !visible[uid] {
			continue
		}
		raw, _ := json.Marshal(actions)
		var decoded any
		_ = json.Unmarshal(raw, &decoded)
		highlight := push.Highlights(actions)
		out[uid] = pushRow{actions: decoded, column: push.SerializeActions(actions, highlight), notif: push.Notifies(actions),
			highlight: highlight, unread: countAsUnread, thread: thread}
	}
	return out, nil
}

// rulesFor is bulk_get_push_rules then _load_rules, per user.
func (s *Verifier) rulesFor(ctx context.Context, users []string) (map[string]*push.Filtered, error) {
	rows, err := s.st.PushRules(ctx, users)
	if err != nil {
		return nil, err
	}
	enabled, err := s.st.PushRulesEnabled(ctx, users)
	if err != nil {
		return nil, err
	}
	out := make(map[string]*push.Filtered, len(users))
	for _, u := range users {
		rs := rows[u]
		sort.SliceStable(rs, func(i, j int) bool {
			if rs[i].PriorityClass != rs[j].PriorityClass {
				return rs[i].PriorityClass > rs[j].PriorityClass
			}
			return rs[i].Priority > rs[j].Priority
		})
		var parsed []push.Rule
		for _, r := range rs {
			pr, err := push.RuleFromDB(r.RuleID, r.PriorityClass, r.Conditions, r.Actions)
			if err != nil {
				// PushRule.from_db raises, and the event's push
				// evaluation with it.
				return nil, &pdu.RaiseError{Msg: fmt.Sprintf("push rule %s of %s: %v", r.RuleID, u, err)}
			}
			parsed = append(parsed, pr)
		}
		en := enabled[u]
		if en == nil {
			en = map[string]bool{}
		}
		out[u] = push.Filter(push.NewRuleset(parsed), en, s.push.Flags)
	}
	return out, nil
}

// powerLevels is _get_power_levels_and_sender_level plus the notification
// levels' coercion in _action_for_event_by_user.
func (s *Verifier) powerLevels(ctx context.Context, ev *pdu.Event, before pdu.StateMap) (map[string]int64, *int64, error) {
	plKey, createKey := pdu.StateKey{Type: "m.room.power_levels"}, pdu.StateKey{Type: "m.room.create"}
	ids := []string{before[createKey]}
	if id := before[plKey]; id != "" {
		ids = append(ids, id)
	}
	if ids[0] == "" {
		return nil, nil, &pdu.RaiseError{Msg: "no create event in the state before"}
	}
	evs, err := s.asSynapseReads(ctx, ids)
	if err != nil {
		return nil, nil, err
	}
	auth := pdu.AuthState{}
	if c := evs[before[createKey]]; c != nil {
		auth[createKey] = c
	}
	pl := evs[before[plKey]]
	if pl != nil {
		auth[plKey] = pl
	}
	level, err := pdu.UserPowerLevel(ev.Sender, auth)
	if err != nil {
		return nil, nil, err
	}

	levels := map[string]int64{}
	if pl == nil {
		return levels, &level, nil
	}
	notif, ok := fieldOf(pl.Content, "notifications")
	if !ok {
		return levels, &level, nil
	}
	if !notif.IsObject() {
		return nil, nil, &pdu.RaiseError{Msg: "power levels notifications is not a mapping"}
	}
	var bad error
	notif.ForEach(func(k, v gjson.Result) bool {
		if ev.Room.EnforceIntPowerLevels {
			if !pdu.IsPyInt(v) {
				// The Rust evaluator takes integers only.
				bad = &pdu.RaiseError{Msg: "notification level " + k.Str + " is not an integer"}
				return false
			}
			levels[k.Str] = v.Int()
			return true
		}
		// int(level), and a level int() refuses is dropped.
		if n, err := pdu.PyInt(v); err == nil {
			levels[k.Str] = n
		} else {
			delete(levels, k.Str)
		}
		return true
	})
	if bad != nil {
		return nil, nil, bad
	}
	return levels, &level, nil
}

// relatedEvents is _related_events (MSC3664).
func (s *Verifier) relatedEvents(ctx context.Context, ev *pdu.Event) (map[string]push.Flat, error) {
	out := map[string]push.Flat{}
	if !s.push.Flags.MSC3664 {
		return out, nil
	}
	// event.content.get("m.relates_to", {}): a present non-mapping raises
	// at the next .get.
	rel, ok := fieldOf(ev.Content, "m.relates_to")
	if !ok {
		return out, nil
	}
	if !rel.IsObject() {
		return nil, &pdu.RaiseError{Msg: "m.relates_to is not a mapping"}
	}
	relID, relType := pdu.Get(rel, "event_id"), pdu.Get(rel, "rel_type")
	if relID.Exists() && relType.Exists() {
		if relID.Type != gjson.String || relType.Type != gjson.String {
			return nil, &pdu.RaiseError{Msg: "m.relates_to with a non-string event_id or rel_type"}
		}
		f, err := s.flatRelated(ctx, relID.Str)
		if err != nil {
			return nil, err
		}
		if f != nil {
			out[relType.Str] = f
		}
	}
	reply, ok := fieldOf(rel, "m.in_reply_to")
	if !ok {
		return out, nil
	}
	if !reply.IsObject() {
		return nil, &pdu.RaiseError{Msg: "m.in_reply_to is not a mapping"}
	}
	replyID := pdu.Get(reply, "event_id")
	if !replyID.Exists() {
		return out, nil
	}
	if replyID.Type != gjson.String {
		return nil, &pdu.RaiseError{Msg: "m.in_reply_to event_id is not a string"}
	}
	f, err := s.flatRelated(ctx, replyID.Str)
	if err != nil {
		return nil, err
	}
	if f != nil {
		if relType.Type == gjson.String && relType.Str == "m.thread" && pyTruthy(pdu.Get(rel, "is_falling_back")) {
			f["im.vector.is_falling_back"] = push.FlatValue{V: push.Value{Kind: 's'}}
		}
		out["m.in_reply_to"] = f
	}
	return out, nil
}

// flatRelated is get_event(id, allow_none=True), flattened: nil when the
// event is not held or was rejected.
func (s *Verifier) flatRelated(ctx context.Context, id string) (push.Flat, error) {
	evs, err := s.asSynapseReads(ctx, []string{id})
	if err != nil {
		return nil, err
	}
	e := evs[id]
	if e == nil || e.Rejected {
		return nil, nil
	}
	return push.Flatten(e.JSON), nil
}

// asSynapseReads loads events as get_events returns them: a redacted event
// in its redacted form.
func (s *Verifier) asSynapseReads(ctx context.Context, ids []string) (map[string]*pdu.Event, error) {
	evs, err := s.st.GetEvents(ctx, ids)
	if err != nil {
		return nil, err
	}
	for id, e := range evs {
		red, err := s.st.IsRedacted(ctx, id)
		if err != nil {
			return nil, err
		}
		if !red {
			continue
		}
		pruned, err := pdu.Redact(e.JSON, e.Room)
		if err != nil {
			return nil, err
		}
		pe, err := pdu.ParseEvent(pruned, id, e.Room, e.Rejected)
		if err != nil {
			return nil, err
		}
		evs[id] = pe
	}
	return evs, nil
}

var membershipPriority = []string{"join", "invite", "knock", "leave", "ban"}
var visibilityPriority = []string{"world_readable", "shared", "invited", "joined"}

// visibleTo is filter_event_for_clients_with_state for a non-soft-failed,
// non-outlier event, as push evaluation calls it.
func (s *Verifier) visibleTo(ctx context.Context, ev *pdu.Event, before pdu.StateMap, users map[string][]json.RawMessage) (map[string]bool, error) {
	allowed := map[string]bool{}
	// _check_filter_send_to_client. Retention is not enabled here.
	if ev.Type == "org.matrix.dummy_event" || ev.Type == "m.room.aliases" {
		return allowed, nil
	}
	ignoredBy, err := s.st.IgnoredBy(ctx, ev.Sender)
	if err != nil {
		return nil, err
	}
	for u := range users {
		if !ev.IsState() && ignoredBy[u] {
			continue
		}
		allowed[u] = true
	}

	// The state before the event, with the event itself if it is state.
	stateEvent := func(k pdu.StateKey) (*pdu.Event, error) {
		if ev.IsState() && ev.Key() == k {
			return ev, nil
		}
		id := before[k]
		if id == "" {
			return nil, nil
		}
		evs, err := s.asSynapseReads(ctx, []string{id})
		if err != nil {
			return nil, err
		}
		return evs[id], nil
	}

	hv, err := stateEvent(pdu.StateKey{Type: "m.room.history_visibility"})
	if err != nil {
		return nil, err
	}
	visibility := "shared"
	if hv != nil {
		if v := pdu.Get(hv.Content, "history_visibility"); v.Type == gjson.String && indexOf(visibilityPriority, v.Str) >= 0 {
			visibility = v.Str
		}
	}
	// _check_history_visibility. A history visibility event is judged by
	// the laxer of it and the one it replaces -- whose content would be in
	// unsigned.prev_content, which federation strips: "shared".
	effective := visibility
	if ev.Type == "m.room.history_visibility" && indexOf(visibilityPriority, "shared") < indexOf(visibilityPriority, visibility) {
		effective = "shared"
	}
	if effective == "shared" || effective == "world_readable" {
		return allowed, nil
	}

	out := map[string]bool{}
	for u := range allowed {
		// _check_membership.
		membership := ""
		if ev.Type == "m.room.member" && *ev.StateKey == u {
			membership = "leave"
			if v := pdu.Get(ev.Content, "membership"); v.Type == gjson.String && indexOf(membershipPriority, v.Str) >= 0 {
				membership = v.Str
			}
			// prev_content is stripped too: the previous membership is
			// "leave", so no own-leave exemption, and a ban reads as leave.
			if indexOf(membershipPriority, "leave") < indexOf(membershipPriority, membership) {
				membership = "leave"
			}
		} else {
			m, err := stateEvent(pdu.StateKey{Type: "m.room.member", StateKey: u})
			if err != nil {
				return nil, err
			}
			if m != nil {
				membership, _ = m.Membership()
			}
		}
		switch {
		case membership == "join":
			out[u] = true
		case visibility == "joined":
		case visibility == "invited":
			out[u] = membership == "invite"
		default:
			out[u] = true
		}
	}
	return out, nil
}

// shouldCountAsUnread is _should_count_as_unread for an accepted event that
// was not soft-failed.
func shouldCountAsUnread(ev *pdu.Event) bool {
	if !ev.IsState() && ev.Type == "m.room.message" {
		if v := pdu.Get(ev.Content, "msgtype"); v.Type == gjson.String && v.Str == "m.notice" {
			return false
		}
	}
	if rel, ok := relationOf(ev); ok && rel.relType == "m.replace" {
		return false
	}
	if v := pdu.Get(ev.Content, "body"); v.Type == gjson.String && v.Str != "" {
		return true
	}
	if ev.IsState() {
		switch ev.Type {
		case "m.room.topic", "m.room.name", "m.room.avatar", "m.room.tombstone":
			return true
		}
	}
	return !ev.IsState() && ev.Type == "m.room.encrypted"
}

type relation struct{ parent, relType string }

// relationOf is relation_from_event: m.relates_to as a mapping with string
// rel_type and event_id.
func relationOf(ev *pdu.Event) (relation, bool) {
	rel := pdu.Get(ev.Content, "m.relates_to")
	if !rel.IsObject() {
		return relation{}, false
	}
	t, p := pdu.Get(rel, "rel_type"), pdu.Get(rel, "event_id")
	if t.Type != gjson.String || p.Type != gjson.String {
		return relation{}, false
	}
	return relation{parent: p.Str, relType: t.Str}, true
}

// diffPush lists the users whose rows differ.
func diffPush(ours, stored map[string]pushRow) []string {
	var out []string
	show := func(r pushRow, ok bool) string {
		if !ok {
			return "<none>"
		}
		b, _ := json.Marshal(r.actions)
		return fmt.Sprintf("%s column=%q notif=%v highlight=%v unread=%v thread=%s", b, r.column, r.notif, r.highlight, r.unread, r.thread)
	}
	for u, o := range ours {
		st, ok := stored[u]
		if !ok || !reflect.DeepEqual(o.actions, st.actions) || o.column != st.column || o.notif != st.notif ||
			o.highlight != st.highlight || o.unread != st.unread || o.thread != st.thread {
			out = append(out, fmt.Sprintf("%s: ours=%s stored=%s", u, show(o, true), show(st, ok)))
		}
	}
	for u, st := range stored {
		if _, ok := ours[u]; !ok {
			out = append(out, fmt.Sprintf("%s: ours=<none> stored=%s", u, show(st, true)))
		}
	}
	sort.Strings(out)
	if len(out) > 20 {
		out = append(out[:20], fmt.Sprintf("... and %d more", len(out)-20))
	}
	return out
}

// jsonNormal round-trips v through JSON, so it compares equal to decoded
// JSON.
func jsonNormal(v any) any {
	b, _ := json.Marshal(v)
	var out any
	_ = json.Unmarshal(b, &out)
	return out
}

// fieldOf is key presence in a JSON object, the last of duplicates winning,
// with keys taken literally (no gjson path syntax).
func fieldOf(obj gjson.Result, key string) (gjson.Result, bool) {
	var v gjson.Result
	found := false
	obj.ForEach(func(k, val gjson.Result) bool {
		if k.Str == key {
			v, found = val, true
		}
		return true
	})
	return v, found
}

func hasKey(obj gjson.Result, key string) bool {
	_, ok := fieldOf(obj, key)
	return ok
}

// pyTruthy is bool(v) for a decoded JSON value; absent or null is false.
func pyTruthy(v gjson.Result) bool {
	switch v.Type {
	case gjson.Null:
		return false
	case gjson.False:
		return false
	case gjson.True:
		return true
	case gjson.Number:
		return v.Num != 0
	case gjson.String:
		return v.Str != ""
	}
	if v.IsArray() {
		return len(v.Array()) > 0
	}
	if v.IsObject() {
		return len(v.Map()) > 0
	}
	return false
}

func indexOf(list []string, s string) int {
	for i, x := range list {
		if x == s {
			return i
		}
	}
	return -1
}

// PushConfigFor reads the push configuration from homeserver.yaml, with
// Synapse 1.162's defaults.
func PushConfigFor(hs *synapsecfg.Config) (PushConfig, error) {
	as, err := appservice.ExclusiveUsers(hs.AppServiceFiles)
	if err != nil {
		return PushConfig{}, err
	}
	return PushConfig{
		ServerName:      hs.ServerName,
		AppServiceUsers: as,
		UnreadCounts:    hs.Flag("msc2654_enabled", false),
		Flags: push.Flags{
			MSC1767:              hs.Flag("msc1767_enabled", false),
			MSC3381Polls:         hs.Flag("msc3381_polls_enabled", false),
			MSC3664:              hs.Flag("msc3664_enabled", false),
			MSC4028EncryptedPush: hs.Flag("msc4028_push_encrypted_events", false),
			// 1.162 has no msc4075 switch: its rules always apply.
			MSC4075: true,
			MSC4210: hs.Flag("msc4210_enabled", false),
			MSC4306: hs.Flag("msc4306_enabled", false),
		},
	}, nil
}
