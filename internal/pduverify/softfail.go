package pduverify

import (
	"context"
	"errors"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdustore"
)

// SoftFail reproduces FederationEventHandler._check_for_soft_fail
// (federation_event.py:2000) from a snapshot of the room taken just before
// Synapse saw the event, and compares the verdict with the soft_failed flag
// Synapse stored.
//
// An event is soft-failed when it passes auth against the state before it but
// not against the room's current state: a ban that arrived on another branch,
// say. The current state is what it was at the moment Synapse processed the
// event, which only a snapshot can approximate -- so whenever another event of
// the room was persisted between the snapshot and this one, the comparison is
// skipped as a race rather than trusted.
func (s *Verifier) SoftFail(ctx context.Context, id string, snap *pdustore.Snapshot) *Result {
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
	switch {
	case se.Outlier:
		return res.fail(OutcomeSkipped, "outlier")
	case ev.Rejected:
		// Only accepted events are checked for soft failure.
		return res.fail(OutcomeSkipped, "rejected")
	case snap.PartialState:
		// Synapse does not soft-fail anything in a partial state room.
		return res.fail(OutcomeSkipped, "partial state room")
	case snap.EventPresent:
		return res.fail(OutcomeSkipped, "snapshot taken after the event")
	case se.StreamOrdering <= 0:
		return res.fail(OutcomeSkipped, "backfilled")
	case !snap.PrevsInTimeline:
		// Synapse then resolves the extremities' state with the state it
		// fetched for the missing prevs; not reproduced.
		return res.fail(OutcomeSkipped, "missing prevs")
	}
	n, err := s.st.RoomEventsBetween(ctx, ev.RoomID, snap.MaxStream, se.StreamOrdering, id)
	if err != nil {
		return res.fail(OutcomeError, err.Error())
	}
	if n > 0 {
		return res.fail(OutcomeSkipped, "race")
	}

	stored, err := s.st.SoftFailed(ctx, id)
	if err != nil {
		return res.fail(OutcomeError, err.Error())
	}
	res.SynapseRej = stored // reused: Synapse's soft-fail verdict

	ours, why, err := s.softFailed(ctx, ev, snap)
	if err != nil {
		var re *pdu.RaiseError
		if errors.As(err, &re) {
			return res.fail(OutcomeRaise, "soft fail: "+err.Error())
		}
		return res.fail(OutcomeError, "soft fail: "+err.Error())
	}
	res.OurRej, res.OurReason = ours, why
	if ours != stored {
		res.Outcome, res.Reason = OutcomeMismatch, "soft fail"
		res.AuthMismatch = true
		return res
	}
	res.Outcome = OutcomeMatch
	return res
}

func (s *Verifier) softFailed(ctx context.Context, ev *pdu.Event, snap *pdustore.Snapshot) (bool, string, error) {
	// extrem_ids == prev_event_ids: the current state is the state at the
	// event, which the event already passed.
	if sameSet(snap.Extremities, ev.PrevEvents) {
		return false, "", nil
	}
	types, err := pdu.AuthTypesForEvent(ev.Room, ev)
	if err != nil {
		return false, "", err
	}
	var ids []string
	for _, k := range types {
		if id, ok := snap.Current[k]; ok {
			ids = append(ids, id)
		}
	}
	events, err := s.st.GetEvents(ctx, ids)
	if err != nil {
		return false, "", err
	}
	var current []*pdu.Event
	for _, id := range ids {
		e := events[id]
		if e == nil || e.Rejected {
			// get_events_as_list leaves out what it cannot return.
			continue
		}
		redacted, err := s.st.IsRedacted(ctx, id)
		if err != nil {
			return false, "", err
		}
		if redacted {
			// Synapse would see the redacted content; not reproduced.
			return false, "", &pdu.RaiseError{Msg: "a current auth event is redacted"}
		}
		current = append(current, e)
	}
	if err := pdu.CheckStateDependentAuthRules(ev, current); err != nil {
		if pdu.IsAuthError(err) {
			return true, err.Error(), nil
		}
		return false, "", err
	}
	return false, "", nil
}

func sameSet(a, b []string) bool {
	as, bs := map[string]bool{}, map[string]bool{}
	for _, x := range a {
		as[x] = true
	}
	for _, x := range b {
		bs[x] = true
	}
	if len(as) != len(bs) {
		return false
	}
	for x := range as {
		if !bs[x] {
			return false
		}
	}
	return true
}
