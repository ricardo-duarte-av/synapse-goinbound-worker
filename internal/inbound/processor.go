package inbound

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/rs/zerolog"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pduverify"
)

// Deciding is what the processor needs from the PDU checker.
type Deciding interface {
	Decide(ctx context.Context, in pduverify.DecideInput) (*pduverify.Decision, error)
}

// Persisting sends events to the room's persister (fed_send_events), and
// asks the device list writer to resync a remote user's devices.
type Persisting interface {
	SendEvents(ctx context.Context, roomID string, entries []json.RawMessage) error
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
	server  string
	log     zerolog.Logger

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	mu sync.Mutex
	// deferred is, per room, the staged event left for Synapse's worker,
	// so we do not take the room back from it every minute.
	deferred map[string]deferral
}

type deferral struct {
	origin, eventID string
	at              time.Time
}

// deferralTTL is how long a deferred room is left alone: Synapse's worker
// sweeps its staging every minute, and should have taken it by then.
const deferralTTL = 5 * time.Minute

// NewProcessor builds a processor. Start begins the one-minute sweep.
func NewProcessor(db *DB, d Deciding, p Persisting, r Reading, server string, log zerolog.Logger) *Processor {
	ctx, cancel := context.WithCancel(context.Background())
	return &Processor{
		db: db, locks: NewLocks(db), decide: d, persist: p, read: r,
		cache: pduverify.NewStateCache(), server: server, log: log,
		ctx: ctx, cancel: cancel, deferred: map[string]deferral{},
	}
}

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
	if time.Since(d.at) > deferralTTL {
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
		if outcome == outcomeDefer {
			p.deferRoom(room, next.Origin, id)
			release(lock)
			return
		}
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
	d, err := p.decide.Decide(ctx, pduverify.DecideInput{
		Origin: s.Origin, EventJSON: s.EventJSON, Metadata: s.InternalMetadata, EventID: s.EventID,
		Room: rv, OurServer: p.server, Cache: p.cache,
	})
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
	}

	if err := p.write(ctx, room, s, d); err != nil {
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
	for _, groups := range d.Bump {
		missing, err := p.db.BumpDeletion(ctx, groups)
		if err != nil {
			return err
		}
		if len(missing) > 0 {
			p.cache.Pop(d.Groups)
			return fmt.Errorf("%w: %v", ErrMissingGroup, missing)
		}
	}
	load := func(g int64) (pdu.StateMap, error) { return p.read.StateForGroup(ctx, g) }

	before := d.Entry.Group()
	if before == 0 {
		prev, delta := d.Entry.PrevGroup()
		g, err := p.db.StoreStateGroup(ctx, s.EventID, room, prev, delta, d.Entry.State(), load)
		if err != nil {
			return err
		}
		d.Entry.SetGroup(g)
		before = g
	}
	after := before
	if d.Event.IsState() {
		g, err := p.db.StoreStateGroup(ctx, s.EventID, room, before, pdu.StateMap{d.Event.Key(): d.Event.ID}, nil, load)
		if err != nil {
			return err
		}
		after = g
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
	if err := p.persist.SendEvents(ctx, room, []json.RawMessage{entry}); err != nil {
		if uerr := p.db.UnstagePush(ctx, s.EventID); uerr != nil {
			p.log.Warn().Err(uerr).Msg("Error removing push actions after event persistence failure")
		}
		return err
	}
	return nil
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
	pruned = promauto.NewCounter(prometheus.CounterOpts{
		Name: "goinbound_write_pruned_total",
		Help: "Staged events pruned from rooms with over 100 queued.",
	})
)
