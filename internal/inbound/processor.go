package inbound

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pduverify"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/replication"
)

// Deciding is what the processor needs from the PDU checker.
type Deciding interface {
	Decide(ctx context.Context, in pduverify.DecideInput) (*pduverify.Decision, error)
}

// Persisting sends events to the room's persister (fed_send_events), and
// asks the device list writer to resync a remote user's devices.
type Persisting interface {
	SendEvents(ctx context.Context, roomID string, entries []json.RawMessage, backfilled bool) error
	ResyncDevices(ctx context.Context, userID string) error
}

// Reading is the state the processor reads outside its own tables.
type Reading interface {
	RoomVersion(ctx context.Context, roomID string) (string, error)
	StateForGroup(ctx context.Context, group int64) (pdu.StateMap, error)
}

// Processor drains rooms' staging queues, as
// FederationServer._process_incoming_pdus_in_room_inner does
// (federation_server.py:1469).
type Processor struct {
	db      *DB
	locks   *Locks
	decide  Deciding
	persist Persisting
	read    Reading
	cache   *pduverify.StateCache
	missing *MissingDeps
	server  string
	log     zerolog.Logger

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu sync.Mutex
	// deferred is, per room, the staged event left for Synapse's worker,
	// so we do not take the room back from it every minute.
	deferred map[string]deferral
	// noFallback is write.fallback: none. There is no Synapse worker to
	// leave an event to, so a deferred event is retried at the next sweep,
	// and after fallbackAttempts dropped (attempts, by event ID).
	noFallback bool
	attempts   map[string]attempt
	spacing    time.Duration
	// onDefer is told whenever an event is left to Synapse.
	onDefer func()
	// after checks what the missing events path persists, once written.
	after *pduverify.AfterWrite
}

type attempt struct {
	n    int
	last time.Time
}

type deferral struct {
	origin, eventID string
	at              time.Time
}

// deferralTTL is how long a deferred room is left alone: Synapse's worker
// sweeps its staging every minute, and should have taken it by then.
const deferralTTL = 5 * time.Minute

// fallbackAttempts is how many times, with write.fallback: none, an event is
// tried before it is dropped. The retries are for what may pass (a database
// or persister error); what is certain to be deferred again (a case not
// ported) is dropped on the last one, as Synapse drops an event it fails to
// handle.
const fallbackAttempts = 3

// fallbackSpacing is the least time between two counted attempts: a room's
// head is retried whenever an event arrives, and a persister restart must
// not use up an event's attempts in seconds.
const fallbackSpacing = 2 * time.Minute

// NewProcessor builds a processor. Start begins the one-minute sweep.
func NewProcessor(db *DB, d Deciding, p Persisting, r Reading, server string, log zerolog.Logger) *Processor {
	ctx, cancel := context.WithCancel(context.Background())
	return &Processor{
		db: db, locks: NewLocks(db), decide: d, persist: p, read: r,
		cache: pduverify.NewStateCache(), server: server, log: log,
		ctx: ctx, cancel: cancel, deferred: map[string]deferral{}, attempts: map[string]attempt{}, spacing: fallbackSpacing,
	}
}

// VerifyAfterWrite has what the missing events path persists checked
// once written (pulled events, outliers).
func (p *Processor) VerifyAfterWrite(a *pduverify.AfterWrite) { p.after = a }

// OnDefer sets what is called whenever an event is left staged for Synapse
// (write.fallback: synapse): the sweep nudge, so that some Synapse process is
// sweeping staged events.
func (p *Processor) OnDefer(f func()) { p.onDefer = f }

// WithoutFallback is write.fallback: none: no Synapse worker takes events
// this processor defers.
func (p *Processor) WithoutFallback() { p.noFallback = true }

// giveUp counts a deferral of eventID, saying whether to drop the event now.
func (p *Processor) giveUp(eventID string) bool {
	if !p.noFallback {
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	a := p.attempts[eventID]
	if a.n > 0 && now.Sub(a.last) < p.spacing {
		return false
	}
	a.n++
	a.last = now
	if a.n < fallbackAttempts {
		p.attempts[eventID] = a
		return false
	}
	delete(p.attempts, eventID)
	return true
}

// handledEvent forgets an event's earlier deferrals.
func (p *Processor) handledEvent(eventID string) {
	if !p.noFallback {
		return
	}
	p.mu.Lock()
	delete(p.attempts, eventID)
	p.mu.Unlock()
}

// EnableMissingEvents lets the processor fetch missing prev events itself,
// rather than leave such events to Synapse.
func (p *Processor) EnableMissingEvents(m *MissingDeps) { p.missing = m }

// Start runs _handle_old_staged_events now and every minute.
func (p *Processor) Start() {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		t := time.NewTicker(time.Minute)
		defer t.Stop()
		for {
			p.sweep()
			select {
			case <-p.ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

// Close stops the sweep and waits for rooms being processed.
func (p *Processor) Close() {
	p.cancel()
	p.wg.Wait()
}

// Received is the tail of _handle_received_pdu: the event is staged, then
// the room's lock tried; with it, the room's queue is drained in the
// background.
func (p *Processor) Received(ctx context.Context, origin, roomID, eventID string, staged, metadata []byte) error {
	if err := p.db.Stage(ctx, origin, roomID, eventID, staged, metadata); err != nil {
		return err
	}
	lock, err := p.locks.TryAcquire(ctx, LockInboundPDU, roomID)
	if err != nil {
		return err
	}
	if lock != nil {
		p.startRoom(roomID, lock, origin, eventID)
	}
	return nil
}

// sweep is _handle_old_staged_events.
func (p *Processor) sweep() {
	if n, oldest, err := p.db.StagingAge(p.ctx); err == nil {
		stagedEvents.Set(float64(n))
		if oldest > 0 {
			stagedOldest.Set(time.Since(time.UnixMilli(oldest)).Seconds())
		} else {
			stagedOldest.Set(0)
		}
	}
	if n, oldest, err := p.db.StagingUnattended(p.ctx); err == nil {
		unattendedEvents.Set(float64(n))
		if oldest > 0 {
			unattendedOldest.Set(time.Since(time.UnixMilli(oldest)).Seconds())
		} else {
			unattendedOldest.Set(0)
		}
	}
	rooms, err := p.db.StagedRooms(p.ctx)
	if err != nil {
		if p.ctx.Err() == nil {
			p.log.Warn().Err(err).Msg("Write mode: could not list staged rooms")
		}
		return
	}
	rand.Shuffle(len(rooms), func(i, j int) { rooms[i], rooms[j] = rooms[j], rooms[i] })
	for _, room := range rooms {
		if p.isDeferred(room) {
			continue
		}
		lock, err := p.locks.TryAcquire(p.ctx, LockInboundPDU, room)
		if err != nil {
			if p.ctx.Err() == nil {
				p.log.Warn().Err(err).Str("room_id", room).Msg("Write mode: could not take a room's lock")
			}
			continue
		}
		if lock != nil {
			p.log.Info().Str("room_id", room).Msg("Handling old staged inbound events")
			p.startRoom(room, lock, "", "")
		}
		select {
		case <-p.ctx.Done():
			return
		case <-time.After(time.Duration(rand.Float64() * float64(100*time.Millisecond))):
		}
	}
}

// isDeferred says the room's head is an event left for Synapse, and it is
// still there.
func (p *Processor) isDeferred(room string) bool {
	p.mu.Lock()
	d, ok := p.deferred[room]
	p.mu.Unlock()
	if !ok {
		return false
	}
	ttl := deferralTTL
	if p.noFallback {
		// Nobody else will take it: try again at the next sweep.
		ttl = 0
	}
	if time.Since(d.at) > ttl {
		p.mu.Lock()
		delete(p.deferred, room)
		p.mu.Unlock()
		return false
	}
	origin, id, ok, err := p.db.NextStagedID(p.ctx, room)
	if err == nil && ok && origin == d.origin && id == d.eventID {
		return true
	}
	p.mu.Lock()
	delete(p.deferred, room)
	p.mu.Unlock()
	return false
}

func (p *Processor) startRoom(room string, lock *Lock, origin, eventID string) {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.processRoom(room, lock, origin, eventID)
	}()
}

// processRoom drains the room's queue while it can hold the lock.
func (p *Processor) processRoom(room string, lock *Lock, latestOrigin, latestID string) {
	ctx := p.ctx
	release := func(l *Lock) {
		rctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_ = l.Release(rctx)
		cancel()
	}
	rvID, err := p.read.RoomVersion(ctx, room)
	if err != nil {
		p.log.Warn().Err(err).Str("room_id", room).Msg("Write mode: room version")
		release(lock)
		return
	}
	rv, ok := pdu.LookupRoomVersion(rvID)
	if !ok {
		release(lock)
		return
	}

	next, err := p.db.NextStaged(ctx, room)
	if err != nil || next == nil {
		release(lock)
		return
	}
	for {
		id, err := stagedEventID(next, rv)
		if err != nil {
			// make_event_from_dict would raise; leave it to Synapse.
			p.deferRoom(room, next.Origin, "")
			release(lock)
			return
		}
		next.EventID = id

		outcome := p.handle(ctx, room, rv, next)
		if outcome == outcomeDefer && ctx.Err() == nil && p.giveUp(id) {
			// _process_incoming_pdus_in_room_inner: an event that fails is
			// logged and unstaged.
			p.log.Error().Str("event_id", id).Str("room_id", room).Str("origin", next.Origin).Int("attempts", fallbackAttempts).
				Msg("Write mode: dropping an event it could not handle, as Synapse drops an event it fails to handle (write.fallback: none)")
			handled.WithLabelValues("given_up").Inc()
			outcome = outcomeDone
		}
		if outcome == outcomeDefer {
			p.deferRoom(room, next.Origin, id)
			release(lock)
			return
		}
		p.handledEvent(id)
		if ts, ok, err := p.db.Unstage(ctx, next.Origin, id); err == nil && ok {
			processTime.Observe(time.Since(time.UnixMilli(ts)).Seconds())
		}
		// `async with lock` ends here, every event.
		release(lock)

		next, err = p.db.NextStaged(ctx, room)
		if err != nil || next == nil {
			return
		}
		if n, err := p.db.PruneStaged(ctx, room, rv.EventFormat == pdu.FormatV1V2); err == nil && n > 0 {
			pruned.Add(float64(n))
			p.log.Info().Int("pruned", n).Str("room_id", room).Msg("Pruning events from federation queue")
			if next, err = p.db.NextStaged(ctx, room); err != nil || next == nil {
				return
			}
		}
		if lock, err = p.locks.TryAcquire(ctx, LockInboundPDU, room); err != nil || lock == nil {
			return
		}
	}
}

// resync is _resync_device, in the background: mark the user's devices
// stale, then ask the device list writer to resync them.
func (p *Processor) resync(user string) {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		ctx, cancel := context.WithTimeout(p.ctx, time.Minute)
		defer cancel()
		resyncs.Inc()
		if err := p.db.MarkDevicesStale(ctx, user); err != nil {
			p.log.Warn().Err(err).Str("user_id", user).Msg("Failed to resync device")
			return
		}
		if err := p.persist.ResyncDevices(ctx, user); err != nil {
			p.log.Warn().Err(err).Str("user_id", user).Msg("Failed to resync device")
		}
	}()
}

func (p *Processor) deferRoom(room, origin, eventID string) {
	p.mu.Lock()
	p.deferred[room] = deferral{origin: origin, eventID: eventID, at: time.Now()}
	p.mu.Unlock()
	if p.onDefer != nil && !p.noFallback {
		p.onDefer()
	}
}

// stagedEventID is the event ID make_event_from_dict gives the staged JSON.
func stagedEventID(s *Staged, rv *pdu.RoomVersion) (string, error) {
	if rv.EventFormat == pdu.FormatV1V2 {
		var v struct {
			EventID string `json:"event_id"`
		}
		if err := json.Unmarshal(s.EventJSON, &v); err != nil || v.EventID == "" {
			return "", fmt.Errorf("no event_id")
		}
		return v.EventID, nil
	}
	return pdu.CalculateEventID(s.EventJSON, rv)
}

type outcome int

const (
	outcomeDone outcome = iota
	outcomeDefer
)

// handle is on_receive_pdu for one staged event, under the room's purge read
// lock. Everything but outcomeDefer unstages the event.
func (p *Processor) handle(ctx context.Context, room string, rv *pdu.RoomVersion, s *Staged) outcome {
	log := p.log.With().Str("event_id", s.EventID).Str("room_id", room).Logger()
	rw, err := p.locks.AcquireReadWrite(ctx, LockPurge, room, false)
	if err != nil {
		return outcomeDefer
	}
	defer func() {
		rctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_ = rw.Release(rctx)
		cancel()
	}()

	start := time.Now()
	in := pduverify.DecideInput{
		Origin: s.Origin, EventJSON: s.EventJSON, Metadata: s.InternalMetadata, EventID: s.EventID,
		Room: rv, OurServer: p.server, Cache: p.cache,
	}
	d, err := p.decide.Decide(ctx, in)
	if err == nil && d.Defer == "missing prevs" && p.missing != nil {
		drop, still, merr := p.missingPrevs(ctx, s.Origin, rv, d.Event)
		switch {
		case errors.Is(merr, errFailed):
			// A pulled prev raised: on_receive_pdu's "Error fetching
			// missing prev_events", and this event fails with it.
			log.Error().Err(merr).Msg("Failed to handle PDU")
			handled.WithLabelValues("failed").Inc()
			return outcomeDone
		case merr != nil:
			log.Info().Err(merr).Msg("Write mode: leaving an event with missing prevs to Synapse")
			handled.WithLabelValues("deferred").Inc()
			return outcomeDefer
		case drop != "":
			// Synapse's "Rejecting: failed to fetch %d prev events: %s", with
			// the origin asked.
			log.Warn().Str("origin", s.Origin).Int("count", len(still)).Str("prev_events", shortstr(still)).
				Str("why", drop).Msg("Rejecting: failed to fetch prev events")
			handled.WithLabelValues("dropped").Inc()
			return outcomeDone
		}
		d, err = p.decide.Decide(ctx, in)
	}
	retried := false
decided:
	if err == nil && d.Defer == pduverify.DeferMissingAuth && p.missing != nil {
		if aerr := p.remoteAuthChain(ctx, s.Origin, rv, d.Event); aerr != nil {
			log.Info().Err(aerr).Msg("Write mode: leaving an event with missing auth events to Synapse")
			handled.WithLabelValues("deferred").Inc()
			return outcomeDefer
		}
		if d, err = p.decide.Decide(ctx, in); err == nil && d.Defer == pduverify.DeferMissingAuth {
			// "Missing auth events": an AuthError, made a FederationError,
			// after the event's state groups were stored.
			if _, _, err := p.storeGroups(ctx, room, s.EventID, d); err != nil {
				log.Warn().Err(err).Msg("Write mode: storing state groups failed; leaving the event to Synapse")
				handled.WithLabelValues("error").Inc()
				return outcomeDefer
			}
			log.Warn().Str("why", authNotFound).Msg("Error handling PDU")
			handled.WithLabelValues("dropped").Inc()
			return outcomeDone
		}
	}
	switch {
	case err != nil:
		log.Warn().Err(err).Msg("Write mode: deciding failed; leaving the event to Synapse")
		handled.WithLabelValues("error").Inc()
		return outcomeDefer
	case d.Defer != "":
		log.Info().Str("why", d.Defer).Msg("Write mode: leaving the event to Synapse")
		handled.WithLabelValues("deferred").Inc()
		return outcomeDefer
	case d.Ignore != "":
		log.Info().Str("why", d.Ignore).Msg("Ignoring received event")
		handled.WithLabelValues("ignored").Inc()
		return outcomeDone
	case d.Drop != "":
		// FederationError: logged, and the event is not persisted.
		log.Warn().Str("why", d.Drop).Msg("Error handling PDU")
		handled.WithLabelValues("dropped").Inc()
		return outcomeDone
	case d.Raise != "":
		// Any other exception: logged, the event not persisted, but what
		// compute_event_context wrote before it raised stays.
		if _, _, err := p.storeGroups(ctx, room, s.EventID, d); err != nil {
			log.Warn().Err(err).Msg("Write mode: storing state groups failed; leaving the event to Synapse")
			handled.WithLabelValues("error").Inc()
			return outcomeDefer
		}
		log.Error().Str("why", d.Raise).Msg("Failed to handle PDU")
		handled.WithLabelValues("failed").Inc()
		return outcomeDone
	}

	if err := p.write(ctx, room, s, d); err != nil {
		if errors.Is(err, replication.ErrPartialStateConflict) {
			if !retried {
				// on_receive_pdu's PartialStateConflictError: the room was
				// un-partial stated meanwhile; the context is computed
				// again, and the event handled once more.
				log.Info().Msg("Room was un-partial stated while processing the PDU, trying again.")
				retried = true
				d, err = p.decide.Decide(ctx, in)
				goto decided
			}
			// A second conflict escapes: "Failed to handle PDU".
			log.Error().Err(err).Msg("Failed to handle PDU")
			handled.WithLabelValues("failed").Inc()
			return outcomeDone
		}
		log.Warn().Err(err).Msg("Write mode: persisting failed; leaving the event to Synapse")
		handled.WithLabelValues("error").Inc()
		return outcomeDefer
	}
	if d.ResyncDevices != "" && d.Rejected == "" {
		p.resync(d.ResyncDevices)
	}
	handleTime.Observe(time.Since(start).Seconds())
	switch {
	case d.Rejected != "":
		log.Warn().Str("reason", d.RejectedWhy).Bool("partial_state", d.PartialState).Msg("Rejected: failed auth")
		handled.WithLabelValues("rejected").Inc()
	case d.SoftFailed:
		handled.WithLabelValues("soft_failed").Inc()
	default:
		handled.WithLabelValues("persisted").Inc()
	}
	return outcomeDone
}

// write stores the event's state groups and push rows and sends it to the
// persister: calculate_context_info, UnpersistedEventContext.persist,
// _run_push_actions_and_persist_event.
func (p *Processor) write(ctx context.Context, room string, s *Staged, d *pduverify.Decision) error {
	before, after, err := p.storeGroups(ctx, room, s.EventID, d)
	if err != nil {
		return err
	}

	rows := make([]PushRow, len(d.Push))
	for i, r := range d.Push {
		rows[i] = PushRow(r)
	}
	if err := p.db.StagePush(ctx, s.EventID, rows); err != nil {
		return err
	}
	entry, err := d.SendEntry(s.EventJSON, before, after)
	if err != nil {
		_ = p.db.UnstagePush(ctx, s.EventID)
		return err
	}
	if err := p.persist.SendEvents(ctx, room, []json.RawMessage{entry}, false); err != nil {
		if uerr := p.db.UnstagePush(ctx, s.EventID); uerr != nil {
			p.log.Warn().Err(uerr).Msg("Error removing push actions after event persistence failure")
		}
		return err
	}
	return nil
}

// storeGroups is compute_event_context's writes: the deletion bumps, then
// the state groups before and after the event (none without an Entry).
func (p *Processor) storeGroups(ctx context.Context, room, eventID string, d *pduverify.Decision) (before, after int64, err error) {
	for _, groups := range d.Bump {
		missing, err := p.db.BumpDeletion(ctx, groups)
		if err != nil {
			return 0, 0, err
		}
		if len(missing) > 0 {
			p.cache.Pop(d.Groups)
			return 0, 0, fmt.Errorf("%w: %v", ErrMissingGroup, missing)
		}
	}
	if d.Entry == nil {
		// State resolution raised: the bumps were all it did.
		return 0, 0, nil
	}
	load := func(g int64) (pdu.StateMap, error) { return p.read.StateForGroup(ctx, g) }

	before = d.Entry.Group()
	if before == 0 {
		prev, delta := d.Entry.PrevGroup()
		g, err := p.db.StoreStateGroup(ctx, eventID, room, prev, delta, d.Entry.State(), load)
		if err != nil {
			return 0, 0, err
		}
		d.Entry.SetGroup(g)
		before = g
	}
	after = before
	if d.Event.IsState() {
		g, err := p.db.StoreStateGroup(ctx, eventID, room, before, pdu.StateMap{d.Event.Key(): d.Event.ID}, nil, load)
		if err != nil {
			return 0, 0, err
		}
		after = g
	}
	return before, after, nil
}

var (
	handled = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "goinbound_write_events_total",
		Help: "Staged events handled by write mode, by outcome.",
	}, []string{"outcome"})
	handleTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "goinbound_write_event_seconds",
		Help:    "Time to decide and persist one staged event.",
		Buckets: prometheus.ExponentialBuckets(0.005, 2, 14),
	})
	processTime = promauto.NewHistogram(prometheus.HistogramOpts{
		Name:    "goinbound_write_pdu_process_seconds",
		Help:    "Time from staging to unstaging, as Synapse's pdu_process_time.",
		Buckets: prometheus.ExponentialBuckets(0.01, 2, 16),
	})
	resyncs = promauto.NewCounter(prometheus.CounterOpts{
		Name: "goinbound_write_device_resyncs_total",
		Help: "Device resyncs asked for, for encrypted events from unknown devices or keys.",
	})
	pulledEvents = promauto.NewCounter(prometheus.CounterOpts{
		Name: "goinbound_write_pulled_events_total",
		Help: "Missing prev events pulled from the origin and persisted.",
	})
	outliersPersisted = promauto.NewCounter(prometheus.CounterOpts{
		Name: "goinbound_write_outliers_total",
		Help: "State and auth events fetched for missing prevs, persisted as outliers.",
	})
	stagedEvents = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "goinbound_staging_events",
		Help: "Events in federation_inbound_events_staging, ours and Synapse's, at the last minute's sweep.",
	})
	stagedOldest = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "goinbound_staging_oldest_seconds",
		Help: "Age of the oldest staged event at the last minute's sweep, 0 with none. Minutes means nobody is processing its room.",
	})
	unattendedEvents = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "goinbound_staging_unattended_events",
		Help: "Staged events in rooms whose inbound lock no process holds (free, or not renewed for 2 minutes), at the last minute's sweep.",
	})
	unattendedOldest = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "goinbound_staging_unattended_oldest_seconds",
		Help: "Age of the oldest staged event in a room no process holds, 0 with none. The alert signal: nobody is going to process it.",
	})
	pruned = promauto.NewCounter(prometheus.CounterOpts{
		Name: "goinbound_write_pruned_total",
		Help: "Staged events pruned from rooms with over 100 queued.",
	})
)
