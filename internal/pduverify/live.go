package pduverify

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog"
	"github.com/tidwall/gjson"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdustore"
)

// Live is the PDU shadow: for each PDU of a transaction Synapse answered, it
// waits for Synapse to persist the event, then checks what we would have
// decided against what Synapse did. It never forwards or writes anything.
type Live struct {
	v       *Verifier
	st      *pdustore.Store
	log     zerolog.Logger
	queue   chan *job
	maxWait time.Duration
	onRes   func(string, *Result)
	wg      sync.WaitGroup
	ctx     context.Context
	cancel  context.CancelFunc
}

type job struct {
	raw      []byte
	received time.Time

	// Set by prepare, before snapDone closes.
	snapDone chan struct{}
	roomID   string
	rv       *pdu.RoomVersion
	eventID  string
	snap     *pdustore.Snapshot
	skip     string // a reason not to check, if any
	fail     string // an error preparing, if any
}

// LiveOptions tunes the shadow.
type LiveOptions struct {
	// Concurrency bounds PDUs checked at once. Zero uses 2.
	Concurrency int
	// Queue bounds PDUs waiting. A PDU that does not fit is dropped and
	// counted. Zero uses 1000.
	Queue int
	// MaxWait bounds waiting for Synapse to persist a PDU. A PDU whose
	// prev events Synapse must fetch can take minutes. Zero uses 5m.
	MaxWait time.Duration
	// OnResult, when set, is called with every check's result. For tests.
	OnResult func(check string, r *Result)
}

// NewLive starts the shadow's workers.
func NewLive(v *Verifier, st *pdustore.Store, o LiveOptions, log zerolog.Logger) *Live {
	if o.Concurrency <= 0 {
		o.Concurrency = 2
	}
	if o.Queue <= 0 {
		o.Queue = 1000
	}
	if o.MaxWait <= 0 {
		o.MaxWait = 5 * time.Minute
	}
	ctx, cancel := context.WithCancel(context.Background())
	l := &Live{v: v, st: st, log: log, queue: make(chan *job, o.Queue), maxWait: o.MaxWait, onRes: o.OnResult, ctx: ctx, cancel: cancel}
	for i := 0; i < o.Concurrency; i++ {
		l.wg.Add(1)
		go l.work()
	}
	return l
}

// Close stops the workers, abandoning PDUs still queued.
func (l *Live) Close() {
	l.cancel()
	close(l.queue)
	l.wg.Wait()
}

// Pending is a transaction's PDUs, prepared before Synapse sees them.
type Pending struct {
	l    *Live
	jobs []*job
}

// Prepare identifies each PDU of a transaction and starts a snapshot of its
// room, before the transaction is handed to Synapse: the soft-fail check needs
// the room as Synapse found it, and Synapse starts processing as soon as it
// has the transaction. Commit once Synapse has accepted it, or Discard.
func (l *Live) Prepare(txnBody []byte) *Pending {
	p := &Pending{l: l}
	pdus := gjson.GetBytes(txnBody, "pdus")
	if !pdus.IsArray() {
		return p
	}
	now := time.Now()
	pdus.ForEach(func(_, raw gjson.Result) bool {
		if len(l.queue)+len(p.jobs) >= cap(l.queue) {
			liveDropped.Inc()
			return true
		}
		j := &job{raw: []byte(raw.Raw), received: now, snapDone: make(chan struct{})}
		p.jobs = append(p.jobs, j)
		go l.prepare(j)
		return true
	})
	return p
}

// Commit queues the PDUs for checking. It never blocks.
func (p *Pending) Commit() {
	for _, j := range p.jobs {
		select {
		case p.l.queue <- j:
		default:
			liveDropped.Inc()
		}
	}
}

// Discard abandons the PDUs: Synapse did not accept the transaction.
func (p *Pending) Discard() {}

// prepare works out the PDU's room version and event ID and snapshots its
// room. Failures are recorded on the job and reported when it is checked.
func (l *Live) prepare(j *job) {
	defer close(j.snapDone)
	ctx, cancel := context.WithTimeout(l.ctx, 30*time.Second)
	defer cancel()

	roomID := gjson.GetBytes(j.raw, "room_id")
	if roomID.Type != gjson.String {
		j.skip = "no room_id"
		return
	}
	j.roomID = roomID.Str
	rvID, err := l.st.RoomVersion(ctx, roomID.Str)
	if errors.Is(err, pdustore.ErrUnknownRoom) {
		// Synapse ignores PDUs for rooms it does not know
		// (federation_server.py:478); so do we.
		j.skip = "unknown room"
		return
	}
	if err != nil {
		j.fail = "room version lookup"
		return
	}
	rv, ok := pdu.LookupRoomVersion(rvID)
	if !ok {
		j.skip = "unsupported room version"
		return
	}
	j.rv = rv

	if rv.EventFormat == pdu.FormatV1V2 {
		j.eventID = gjson.GetBytes(j.raw, "event_id").Str
	} else if j.eventID, err = pdu.CalculateEventID(j.raw, rv); err != nil {
		j.skip = "event id not computable"
		return
	}
	if j.eventID == "" {
		j.skip = "no event id"
		return
	}

	ev, err := pdu.ParseEvent(j.raw, j.eventID, rv, false)
	if err != nil {
		return // reported by the checks, which parse the stored copy
	}
	types, err := pdu.AuthTypesForEvent(rv, ev)
	if err != nil {
		return
	}
	snap, err := l.st.TakeSnapshot(ctx, j.roomID, j.eventID, ev.PrevEvents, types)
	if err == nil {
		j.snap = snap
	}
}

func (l *Live) work() {
	defer l.wg.Done()
	for j := range l.queue {
		if l.ctx.Err() != nil {
			continue
		}
		l.check(j)
	}
}

// check handles one PDU.
func (l *Live) check(j *job) {
	ctx := l.ctx
	select {
	case <-j.snapDone:
	case <-ctx.Done():
		return
	}
	switch {
	case j.skip != "":
		l.record("received", OutcomeSkipped, j.skip)
		return
	case j.fail != "":
		l.record("received", OutcomeError, j.fail)
		return
	}
	eventID, rv := j.eventID, j.rv
	log := l.log.With().Str("event_id", eventID).Str("room_id", j.roomID).Logger()

	persisted, err := l.waitPersisted(ctx, eventID, j.received)
	if err != nil {
		if ctx.Err() == nil {
			l.record("received", OutcomeError, "waiting for persistence")
		}
		return
	}
	if !persisted {
		l.notPersisted(ctx, j.raw, rv, eventID, log)
		return
	}

	softFail := func(ctx context.Context, id string) *Result {
		if j.snap == nil {
			return &Result{EventID: id, Outcome: OutcomeSkipped, Reason: "no snapshot"}
		}
		return l.v.SoftFail(ctx, id, j.snap)
	}
	var before pdu.StateMap
	replay := func(ctx context.Context, id string) *Result {
		r := l.v.Replay(ctx, id)
		if r.Outcome == OutcomeMatch {
			// Push reads the state before from Replay, when it agrees
			// with Synapse's.
			before = r.Before()
		}
		return r
	}
	pushCheck := func(ctx context.Context, id string) *Result {
		if j.snap == nil {
			return &Result{EventID: id, Outcome: OutcomeSkipped, Reason: "no snapshot"}
		}
		return l.v.Push(ctx, id, before, j.snap)
	}

	for _, c := range []struct {
		name string
		run  func(context.Context, string) *Result
	}{{"signatures", l.v.CheckSigs}, {"state_auth", replay}, {"soft_fail", softFail}, {"push", pushCheck}} {
		res := c.run(ctx, eventID)
		res.EventID = eventID
		l.recordResult(c.name, res)
		ev := log.Debug()
		if res.Outcome == OutcomeMismatch {
			ev = log.Warn()
		}
		ev.Str("check", c.name).Str("outcome", res.Outcome).Str("reason", res.Reason).
			Str("type", res.Type).Bool("synapse_rejected", res.SynapseRej).Bool("our_rejected", res.OurRej).
			Strs("state_diff", res.StateDiff).Strs("push_diff", res.PushDiff).Int64("resolve_ms", res.ResolveMS).
			Msg("PDU shadow")
	}
}

// waitPersisted polls for the event until Synapse persists it or maxWait has
// passed since it was received. Synapse handles a PDU in the background after
// answering the transaction, so it is rarely there at once.
func (l *Live) waitPersisted(ctx context.Context, eventID string, received time.Time) (bool, error) {
	delay := 500 * time.Millisecond
	for {
		ok, err := l.st.EventExists(ctx, eventID)
		if err != nil {
			return false, err
		}
		if ok {
			liveWait.Observe(time.Since(received).Seconds())
			return true, nil
		}
		if time.Since(received)+delay > l.maxWait {
			return false, nil
		}
		t := time.NewTimer(delay)
		select {
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			return false, ctx.Err()
		}
		if delay < 30*time.Second {
			delay *= 2
		}
	}
}

// notPersisted handles a PDU Synapse did not persist in time. Synapse drops a
// PDU it cannot verify; if ours fails too, we agree. Otherwise it may still
// be on its way (missing prev events), or Synapse dropped it for a reason not
// reproduced here -- not a disagreement either way.
func (l *Live) notPersisted(ctx context.Context, raw []byte, rv *pdu.RoomVersion, eventID string, log zerolog.Logger) {
	ev, err := pdu.ParseEvent(raw, eventID, rv, false)
	if err != nil {
		l.record("received", OutcomeMatch, "malformed, not persisted")
		return
	}
	lookup := func(server string, keyIDs []string) (map[string]pdu.VerifyKey, error) {
		return l.st.VerifyKeys(ctx, server, keyIDs)
	}
	switch err := pdu.CheckSignatures(ev, raw, lookup); {
	case err == nil:
		l.record("received", OutcomeSkipped, "not persisted")
		log.Debug().Msg("PDU shadow: Synapse has not persisted a PDU whose signatures verify")
	case errors.Is(err, pdu.ErrKeyUnknown):
		l.record("received", OutcomeSkipped, "not persisted, key unknown")
	default:
		var se *pdu.SignatureError
		if errors.As(err, &se) {
			l.record("received", OutcomeMatch, "bad signature, not persisted")
			return
		}
		l.record("received", OutcomeRaise, "signatures")
	}
}

// reasonLabel folds a free-text reason into a bounded metric label.
func reasonLabel(outcome, reason string) string {
	if outcome == OutcomeMatch && reason == "" {
		return "ok"
	}
	for _, known := range []string{
		"no room_id", "unknown room", "unsupported room version", "event id not computable", "no event id",
		"room version lookup", "waiting for persistence", "malformed, not persisted", "not persisted, key unknown",
		"not persisted", "bad signature, not persisted", "signatures",
		"outlier", "create event", "prev event without state group", "a prev's state was computed after the event's",
		"no state group for the event", "state resolution v1", "signing key not held", "signing key replaced",
		"rejected", "partial state room", "snapshot taken after the event", "backfilled", "missing prevs", "race",
		"no snapshot", "soft fail",
		"push not configured", "invite", "min depth", "no state before", "pruned", "redacted", "push",
		"unparseable", "event id", "content hash", "state resolution", "auth",
	} {
		if strings.HasPrefix(reason, known) {
			return known
		}
	}
	return "other"
}

func (l *Live) record(check, outcome, reason string) {
	l.recordResult(check, &Result{Outcome: outcome, Reason: reason})
}

func (l *Live) recordResult(check string, r *Result) {
	liveChecks.WithLabelValues(check, r.Outcome, reasonLabel(r.Outcome, r.Reason)).Inc()
	if l.onRes != nil {
		l.onRes(check, r)
	}
}

var (
	liveChecks = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "goinbound_pdu_shadow_total",
		Help: "PDU shadow checks by check (received, signatures, state_auth, soft_fail, push), outcome and reason.",
	}, []string{"check", "outcome", "reason"})
	liveDropped = promauto.NewCounter(prometheus.CounterOpts{
		Name: "goinbound_pdu_shadow_dropped_total",
		Help: "PDUs not checked because the shadow queue was full.",
	})
	liveWait = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "goinbound_pdu_shadow_persist_wait_seconds",
		Help:    "Time from receiving a PDU to seeing Synapse persist it.",
		Buckets: []float64{.1, .25, .5, 1, 2.5, 5, 10, 30, 60, 120, 300},
	})
)
