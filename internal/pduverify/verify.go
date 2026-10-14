// Package pduverify replays events through the Go port of Synapse's PDU
// handling -- signatures, content hash, state resolution, the receive-path
// auth pipeline -- and compares each outcome with what Synapse decided and
// stored. The offline sweep (cmd/pdusweep) and the live PDU shadow share it.
package pduverify

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdustore"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/stateres"
)

// Outcomes, in increasing order of interest.
const (
	OutcomeMatch    = "match"
	OutcomeSkipped  = "skipped"
	OutcomeRaise    = "raise"    // Synapse would have raised; not comparable
	OutcomeError    = "error"    // failed here
	OutcomeMismatch = "mismatch" // disagrees with Synapse
)

type Result struct {
	EventID      string   `json:"event_id"`
	RoomID       string   `json:"room_id,omitempty"`
	Type         string   `json:"type,omitempty"`
	Version      string   `json:"room_version,omitempty"`
	Prevs        int      `json:"prevs,omitempty"`
	Resolved     bool     `json:"resolved,omitempty"` // state resolution ran
	Outcome      string   `json:"outcome"`
	Reason       string   `json:"reason,omitempty"`
	SynapseRej   bool     `json:"synapse_rejected"`
	OurRej       bool     `json:"our_rejected"`
	OurReason    string   `json:"our_reason,omitempty"`
	StateDiff    []string `json:"state_diff,omitempty"`
	ResolveMS    int64    `json:"resolve_ms,omitempty"`
	AuthMismatch bool     `json:"auth_mismatch,omitempty"`
	PushDiff     []string `json:"push_diff,omitempty"`
	// PushRows counts the push action rows compared, notifying ones apart.
	PushRows   int `json:"push_rows,omitempty"`
	PushNotify int `json:"push_notify,omitempty"`

	// before is Replay's state before the event, for the push check.
	before pdu.StateMap
}

// Before is the state before the event, when Replay computed it.
func (r *Result) Before() pdu.StateMap { return r.before }

// Verifier replays events through the Go port of Synapse's PDU handling and
// compares the outcome with what Synapse decided and stored.
type Verifier struct {
	st     *pdustore.Store
	groups *groupCache
	opts   stateres.Options
	push   *PushConfig
}

// New builds a Verifier over st.
func New(st *pdustore.Store, opts stateres.Options) *Verifier {
	return &Verifier{st: st, groups: newGroupCache(DefaultStateCacheEntries), opts: opts}
}

// Replay recomputes an event's state before, auth verdict and state after,
// and compares them with what Synapse stored.
func (s *Verifier) Replay(ctx context.Context, id string) *Result {
	res := &Result{EventID: id}
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
	res.RoomID, res.Type, res.Version, res.Prevs = ev.RoomID, ev.Type, ev.Room.ID, len(ev.PrevEvents)
	res.SynapseRej = ev.Rejected
	if se.Outlier {
		return res.fail(OutcomeSkipped, "outlier")
	}
	if ev.Type == "m.room.create" {
		return res.fail(OutcomeSkipped, "create event")
	}

	// The event's own state group, first: it dates the computation.
	ownGroup, err := s.st.StateGroupForEvent(ctx, id)
	if errors.Is(err, pdustore.ErrNoStateGroup) {
		return res.fail(OutcomeSkipped, "no state group for the event")
	}
	if err != nil {
		return res.fail(OutcomeError, err.Error())
	}

	// 1. State after each prev event, deduplicated by state group as
	// Synapse does before resolving.
	var sets []pdu.StateMap
	seen := map[int64]bool{}
	for _, p := range ev.PrevEvents {
		g, err := s.st.StateGroupForEvent(ctx, p)
		if errors.Is(err, pdustore.ErrNoStateGroup) {
			// A prev we hold only as an outlier, or not at all: Synapse
			// computed this event's state from a remote's /state_ids.
			return res.fail(OutcomeSkipped, "prev event without state group")
		}
		if err != nil {
			return res.fail(OutcomeError, err.Error())
		}
		if g > ownGroup {
			// State groups are allocated in order, so this prev's state
			// was computed AFTER the event's: when Synapse handled the
			// event the prev had none, and the state came from elsewhere
			// (a remote's /state_ids for a missing prev). Not replayable
			// from what is stored now.
			return res.fail(OutcomeSkipped, "a prev's state was computed after the event's")
		}
		if seen[g] {
			continue
		}
		seen[g] = true
		m, err := s.groups.get(ctx, s.st, g)
		if err != nil {
			return res.fail(OutcomeError, err.Error())
		}
		sets = append(sets, m)
	}

	// 2. The state before the event.
	var before pdu.StateMap
	if len(sets) == 1 {
		before = sets[0]
	} else {
		res.Resolved = true
		start := time.Now()
		before, err = stateres.ResolveWith(ctx, ev.RoomID, ev.Room, sets, s.st, s.opts)
		res.ResolveMS = time.Since(start).Milliseconds()
		if errors.Is(err, stateres.ErrUnsupported) {
			return res.fail(OutcomeSkipped, "state resolution v1")
		}
		if err != nil {
			var re *pdu.RaiseError
			if errors.As(err, &re) {
				return res.fail(OutcomeRaise, "state resolution: "+err.Error())
			}
			return res.fail(OutcomeError, "state resolution: "+err.Error())
		}
	}

	// 3. Auth, as _check_event_auth does it.
	rej, why, err := s.checkEventAuth(ctx, ev, before)
	if err != nil {
		var re *pdu.RaiseError
		if errors.As(err, &re) {
			return res.fail(OutcomeRaise, "auth: "+err.Error())
		}
		return res.fail(OutcomeError, "auth: "+err.Error())
	}
	res.OurRej, res.OurReason = rej, why
	res.before = before

	// 4. State after, against Synapse's.
	stored, err := s.groups.get(ctx, s.st, ownGroup)
	if err != nil {
		return res.fail(OutcomeError, err.Error())
	}
	// The state after is the state before plus the event, compared as an
	// overlay: copying a 150k-entry map per event is what the cache saves.
	// Synapse's own verdict decides whether the event entered its state;
	// ours is compared separately, so one disagreement does not show up
	// twice.
	var own *pdu.StateKey
	if ev.IsState() && !ev.Rejected {
		k := ev.Key()
		own = &k
	}
	res.StateDiff = diffAfter(before, own, ev.ID, stored)

	res.AuthMismatch = rej != ev.Rejected
	if res.AuthMismatch || len(res.StateDiff) > 0 {
		res.Outcome = OutcomeMismatch
	} else {
		res.Outcome = OutcomeMatch
	}
	return res
}

func (r *Result) fail(outcome, reason string) *Result {
	r.Outcome, r.Reason = outcome, reason
	return r
}

// checkEventAuth reproduces FederationEventHandler._check_event_auth
// (federation_event.py:1830) for a fully stated room: rejected or not, and why.
// validate_event_for_room_version comes first: the field size limits, then
// the signature presence checks.
func (s *Verifier) checkEventAuth(ctx context.Context, ev *pdu.Event, before pdu.StateMap) (bool, string, error) {
	if se := pdu.CheckFieldSizes(ev); se != nil {
		if se.Unpersistable {
			// Synapse raises, and never stores the event.
			return false, "", &pdu.RaiseError{Msg: "unpersistable: " + se.Msg}
		}
		return true, "oversized: " + se.Msg, nil
	}
	if why := validateSignatures(ev); why != "" {
		return true, "validate: " + why, nil
	}

	claimed, err := s.st.GetEvents(ctx, ev.AuthEvents)
	if err != nil {
		return false, "", err
	}
	if len(claimed) != len(uniq(ev.AuthEvents)) {
		// _load_or_fetch_auth_events_for_event would have fetched them
		// from the origin; we cannot follow that.
		return false, "", &pdu.RaiseError{Msg: "missing auth events"}
	}
	if err := pdu.CheckStateIndependentAuthRules(ev, claimed); err != nil {
		if pdu.IsAuthError(err) {
			return true, "auth events: " + err.Error(), nil
		}
		return false, "", err
	}
	claimedList := make([]*pdu.Event, 0, len(ev.AuthEvents))
	for _, id := range ev.AuthEvents {
		claimedList = append(claimedList, claimed[id])
	}
	if err := pdu.CheckStateDependentAuthRules(ev, claimedList); err != nil {
		if pdu.IsAuthError(err) {
			return true, "auth events: " + err.Error(), nil
		}
		return false, "", err
	}

	calculated, err := pdu.ComputeAuthEvents(ev.Room, ev, before)
	if err != nil {
		return false, "", err
	}
	if sameMultiset(calculated, ev.AuthEvents) {
		return false, "", nil
	}
	calc, err := s.st.GetEvents(ctx, calculated)
	if err != nil {
		return false, "", err
	}
	calcList := make([]*pdu.Event, 0, len(calculated))
	for _, id := range calculated {
		if e := calc[id]; e != nil {
			calcList = append(calcList, e)
		}
	}
	if err := pdu.CheckStateDependentAuthRules(ev, calcList); err != nil {
		if pdu.IsAuthError(err) {
			return true, "state before: " + err.Error(), nil
		}
		return false, "", err
	}
	return false, "", nil
}

// validateSignatures is the signature-presence part of
// validate_event_for_room_version (event_auth.py:96).
func validateSignatures(ev *pdu.Event) string {
	signedBy := func(server string) bool { return pdu.Get(ev.Signatures, server).IsObject() }
	senderDomain := domain(ev.Sender)
	tpi := false
	if ev.Type == "m.room.member" {
		if m, err := ev.Membership(); err == nil && m == "invite" && pdu.Get(ev.Content, "third_party_invite").Exists() {
			tpi = true
		}
	}
	if !signedBy(senderDomain) && !tpi {
		return "not signed by sender's server"
	}
	if ev.Room.EventFormat == pdu.FormatV1V2 && !signedBy(domain(ev.ID)) {
		return "not signed by sending server"
	}
	if ev.Room.RestrictedJoinRule && ev.Type == "m.room.member" {
		if m, err := ev.Membership(); err == nil && m == "join" {
			if au := pdu.Get(ev.Content, "join_authorised_via_users_server"); au.Exists() {
				if !signedBy(domain(au.String())) {
					return "not signed by authorising server"
				}
			}
		}
	}
	return ""
}

func domain(id string) string {
	if i := strings.IndexByte(id, ':'); i >= 0 {
		return id[i+1:]
	}
	return id
}

func uniq(ids []string) map[string]bool {
	m := map[string]bool{}
	for _, id := range ids {
		m[id] = true
	}
	return m
}

func sameMultiset(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	count := map[string]int{}
	for _, x := range a {
		count[x]++
	}
	for _, x := range b {
		count[x]--
	}
	for _, c := range count {
		if c != 0 {
			return false
		}
	}
	return true
}

// diffAfter lists the keys whose event differs between the state after --
// before, with own (when set) mapped to ownID -- and the stored state, as
// "type|state_key: ours != stored".
func diffAfter(before pdu.StateMap, own *pdu.StateKey, ownID string, stored pdu.StateMap) []string {
	var out []string
	ours := func(k pdu.StateKey) (string, bool) {
		if own != nil && k == *own {
			return ownID, true
		}
		v, ok := before[k]
		return v, ok
	}
	check := func(k pdu.StateKey) {
		v, _ := ours(k)
		if stored[k] != v {
			out = append(out, fmt.Sprintf("%s|%s: ours=%s stored=%s", k.Type, k.StateKey, v, stored[k]))
		}
	}
	for k := range before {
		check(k)
	}
	if own != nil {
		if _, ok := before[*own]; !ok {
			check(*own)
		}
	}
	for k, v := range stored {
		if _, ok := ours(k); !ok {
			out = append(out, fmt.Sprintf("%s|%s: ours=<none> stored=%s", k.Type, k.StateKey, v))
		}
	}
	sort.Strings(out)
	if len(out) > 20 {
		out = append(out[:20], fmt.Sprintf("... and %d more", len(out)-20))
	}
	return out
}

// CheckSigs recomputes what Synapse checked when the event arrived: its event
// ID (v3 and later), its content hash, and its signatures, against the keys
// Synapse holds. Every persisted event passed the signature check, rejected
// ones included, so any failure here is ours.
func (s *Verifier) CheckSigs(ctx context.Context, id string) *Result {
	res := &Result{EventID: id}
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

	if ev.Room.EventFormat != pdu.FormatV1V2 {
		calc, err := pdu.CalculateEventID(ev.JSON, ev.Room)
		if err != nil {
			return res.fail(OutcomeError, "event id: "+err.Error())
		}
		if calc != id {
			res.Outcome, res.Reason = OutcomeMismatch, "event id: computed "+calc
			return res
		}
	}

	ok, err := pdu.CheckContentHash(ev.JSON)
	if err != nil {
		return res.fail(OutcomeRaise, "content hash: "+err.Error())
	}
	if !ok {
		redacted, err := s.st.IsRedacted(ctx, id)
		if err != nil {
			return res.fail(OutcomeError, err.Error())
		}
		if !redacted {
			// Synapse redacts an event whose hash fails and stores the
			// redacted form, which can no longer match its hash. So a
			// failing event must already be in redacted form.
			pruned, err := pdu.IsRedactedForm(ev.JSON, ev.Room)
			if err != nil {
				return res.fail(OutcomeError, err.Error())
			}
			if !pruned {
				res.Outcome, res.Reason = OutcomeMismatch, "content hash does not match, and the event is not in redacted form"
				return res
			}
		}
	}

	lookup := func(server string, keyIDs []string) (map[string]pdu.VerifyKey, error) {
		return s.st.VerifyKeys(ctx, server, keyIDs)
	}
	if err := pdu.CheckSignatures(ev, ev.JSON, lookup); err != nil {
		switch {
		case errors.Is(err, pdu.ErrKeyUnknown):
			return res.fail(OutcomeSkipped, "signing key not held")
		case isSignatureError(err):
			var sigErr *pdu.SignatureError
			errors.As(err, &sigErr)
			if sigErr.Key != nil && sigErr.Key.AddedMS > se.ReceivedTS {
				// The key Synapse holds now was stored after the event
				// arrived: the server reissued a key ID, and Synapse
				// checked the event with the one it replaced.
				return res.fail(OutcomeSkipped, "signing key replaced since the event arrived")
			}
			res.Outcome, res.Reason = OutcomeMismatch, err.Error()
			return res
		default:
			return res.fail(OutcomeRaise, "signatures: "+err.Error())
		}
	}
	res.Outcome = OutcomeMatch
	return res
}

func isSignatureError(err error) bool {
	var se *pdu.SignatureError
	return errors.As(err, &se)
}
