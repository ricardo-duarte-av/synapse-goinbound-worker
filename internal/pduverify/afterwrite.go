package pduverify

import (
	"context"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
)

// AfterWrite checks, once they are persisted, the events write mode
// persists that no /send shadow sees: events pulled for missing prevs, and
// the outliers fetched for their state or auth. (PDUs received on /send are
// checked by Live, against what our writer stored.)
//
//   - A pulled event whose prevs were held: Replay re-derives its state
//     before from the prevs' groups and its auth from that, and the
//     state_groups check compares the groups we stored.
//   - A pulled event whose state came from a remote (/state_ids): its auth
//     is checked again against the group stored before it.
//   - An outlier: its auth is run again against its auth events as stored,
//     and compared with the rejection written.
//
// A disagreement is logged at WARN and counted as a mismatch.
type AfterWrite struct {
	v     *Verifier
	log   zerolog.Logger
	queue chan written
	wg    sync.WaitGroup
	stop  chan struct{}
	once  sync.Once
	// OnResult, when set before anything is queued, sees every result.
	OnResult func(check string, r *Result)
}

type written struct {
	id string
	// kind: a pulled event with its prevs held, one with remote state, or
	// an outlier.
	kind writtenKind
}

type writtenKind int

const (
	pulledHeld writtenKind = iota
	pulledRemoteState
	outlier
)

// NewAfterWrite starts a checker with a queue of n events; past that, an
// event is not checked, and counted as dropped.
func NewAfterWrite(v *Verifier, n int, log zerolog.Logger) *AfterWrite {
	a := &AfterWrite{v: v, log: log, queue: make(chan written, n), stop: make(chan struct{})}
	a.wg.Add(1)
	go a.run()
	return a
}

// Pulled queues a pulled event; remoteState says its state before came
// from a remote's /state_ids.
func (a *AfterWrite) Pulled(id string, remoteState bool) {
	k := pulledHeld
	if remoteState {
		k = pulledRemoteState
	}
	a.add(written{id, k})
}

// Outlier queues an outlier.
func (a *AfterWrite) Outlier(id string) { a.add(written{id, outlier}) }

func (a *AfterWrite) add(w written) {
	if a == nil {
		return
	}
	select {
	case a.queue <- w:
	default:
		afterWriteChecks.WithLabelValues("queue", OutcomeSkipped, "dropped").Inc()
	}
}

// Close stops the checker, leaving what is queued.
func (a *AfterWrite) Close() {
	if a == nil {
		return
	}
	a.once.Do(func() { close(a.stop) })
	a.wg.Wait()
}

func (a *AfterWrite) run() {
	defer a.wg.Done()
	for {
		select {
		case <-a.stop:
			return
		case w := <-a.queue:
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			a.check(ctx, w)
			cancel()
		}
	}
}

func (a *AfterWrite) check(ctx context.Context, w written) {
	switch w.kind {
	case pulledHeld:
		r := a.v.Replay(ctx, w.id)
		a.record("state_auth", r)
		if r.Outcome == OutcomeMatch {
			a.record("state_groups", a.v.StateGroups(ctx, r, true))
		}
	case pulledRemoteState:
		a.record("auth_at_stored", a.v.AuthAtStored(ctx, w.id))
	case outlier:
		a.record("outlier_auth", a.v.OutlierAuth(ctx, w.id))
	}
}

func (a *AfterWrite) record(check string, r *Result) {
	afterWriteChecks.WithLabelValues(check, r.Outcome, reasonLabel(r.Outcome, r.Reason)).Inc()
	if a.OnResult != nil {
		a.OnResult(check, r)
	}
	switch r.Outcome {
	case OutcomeMismatch, OutcomeRaise, OutcomeError:
		a.log.Warn().Str("check", check).Str("event_id", r.EventID).Str("room_id", r.RoomID).
			Str("outcome", r.Outcome).Str("reason", r.Reason).Strs("diff", r.StateDiff).
			Bool("stored_rejected", r.SynapseRej).Bool("our_rejected", r.OurRej).Str("our_reason", r.OurReason).
			Msg("Write mode: what was written disagrees with a fresh derivation")
	}
}

// AuthAtStored checks a stored event's auth against the state stored
// before it: rejected or not, as checkEventAuth decides it.
func (s *Verifier) AuthAtStored(ctx context.Context, id string) *Result {
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
	res.RoomID, res.Type, res.Version, res.SynapseRej = ev.RoomID, ev.Type, ev.Room.ID, ev.Rejected
	if se.Outlier {
		return res.fail(OutcomeSkipped, "outlier")
	}
	own, err := s.st.StateGroupForEvent(ctx, id)
	if err != nil {
		return res.fail(OutcomeSkipped, "no state group for the event")
	}
	// The group before: the event's own for a rejected or non-state
	// event, the after group's prev for an accepted state event.
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
	st, err := s.groups.get(ctx, s.st, before)
	if err != nil {
		return res.fail(OutcomeError, err.Error())
	}
	rej, why, err := s.checkEventAuth(ctx, ev, st)
	if err != nil {
		return res.fail(OutcomeError, "auth: "+err.Error())
	}
	res.OurRej, res.OurReason = rej, why
	res.AuthMismatch = rej != ev.Rejected
	if res.AuthMismatch {
		res.Outcome = OutcomeMismatch
		return res
	}
	res.Outcome = OutcomeMatch
	return res
}

// OutlierAuth checks a stored outlier's rejection against
// _auth_and_persist_outliers' checks, run again with its auth events as
// stored.
func (s *Verifier) OutlierAuth(ctx context.Context, id string) *Result {
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
	res.RoomID, res.Type, res.Version, res.SynapseRej = ev.RoomID, ev.Type, ev.Room.ID, ev.Rejected
	if !se.Outlier {
		// De-outliered since: the timeline checks cover it.
		return res.fail(OutcomeSkipped, "not an outlier")
	}
	auth, err := s.st.GetEvents(ctx, ev.AuthEvents)
	if err != nil {
		return res.fail(OutcomeError, err.Error())
	}
	authMap := map[string]*pdu.Event{}
	for k, e := range auth {
		authMap[k] = e
	}
	rejected, drop, err := OutlierVerdict(ev, authMap)
	if err != nil {
		return res.fail(OutcomeRaise, err.Error())
	}
	if drop {
		// An auth event we no longer hold: nothing to compare.
		return res.fail(OutcomeSkipped, "auth event not held")
	}
	res.OurRej, res.OurReason = rejected != "", rejected
	res.AuthMismatch = res.OurRej != ev.Rejected
	if res.AuthMismatch {
		res.Outcome = OutcomeMismatch
		return res
	}
	res.Outcome = OutcomeMatch
	return res
}

var afterWriteChecks = promauto.NewCounterVec(prometheus.CounterOpts{
	Name: "goinbound_write_verify_total",
	Help: "Checks of what write mode persisted outside /send (pulled events, outliers), against a fresh derivation, by check, outcome and reason.",
}, []string{"check", "outcome", "reason"})
