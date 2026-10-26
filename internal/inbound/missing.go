package inbound

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/fedfetch"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdustore"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pduverify"
)

// The missing prev events path of on_receive_pdu
// (handlers/federation_event.py): _get_missing_events_for_pdu,
// _process_pulled_events, _compute_event_context_with_maybe_missing_prevs,
// _get_state_ids_after_missing_prev_event and _auth_and_persist_outliers.
//
// What it cannot do as Synapse does returns errUncertain, and the staged
// event it was for is left to Synapse's worker: whatever we persisted on the
// way (outliers, pulled events) is what Synapse would have persisted too.

var errUncertain = errors.New("inbound: missing events path not reproducible")

// errFailed is a pulled event whose auth raised, as Synapse's would: the
// exception escapes _get_missing_events_for_pdu, and the event that pulled
// it fails too.
var errFailed = errors.New("inbound: a pulled event failed")

// Fetching pulls events from remote servers.
type Fetching interface {
	MissingEvents(ctx context.Context, origin, roomID string, rv *pdu.RoomVersion, earliest, latest []string, limit, minDepth int) ([]*fedfetch.Pulled, error)
	StateIDs(ctx context.Context, dest, roomID, eventID string) (state, auth []string, err error)
	Event(ctx context.Context, dest, eventID, roomID string, rv *pdu.RoomVersion) (*fedfetch.Pulled, error)
	State(ctx context.Context, dest, roomID, eventID string, rv *pdu.RoomVersion) (auth, state []*fedfetch.Pulled, err error)
	EventAuth(ctx context.Context, dest, roomID, eventID string, rv *pdu.RoomVersion) ([]*fedfetch.Pulled, error)
}

// MissingDeps enables the missing events path. Without it, an event with
// missing prevs is left to Synapse.
type MissingDeps struct {
	Fetch    Fetching
	Store    *pdustore.Store
	Verifier *pduverify.Verifier
}

// notDivulging is on_receive_pdu's FederationError for prevs still missing.
const notDivulging = "Your server isn't divulging details about prev_events referenced in this event."

// missingPrevs fetches what on_receive_pdu fetches for an event whose prevs
// are missing. drop is set when the event must then be dropped, with the
// prevs still missing; otherwise the prevs are in the timeline and the event
// can be decided again.
func (p *Processor) missingPrevs(ctx context.Context, origin string, rv *pdu.RoomVersion, ev *pdu.Event) (drop string, still []string, err error) {
	m := p.missing
	md, err := m.Store.MinDepth(ctx, ev.RoomID)
	if err != nil {
		return "", nil, err
	}
	if md != nil && ev.Depth > *md {
		if err := p.getMissingEvents(ctx, origin, rv, ev, *md); err != nil {
			return "", nil, err
		}
	}
	seen, err := m.Store.InTimeline(ctx, ev.PrevEvents)
	if err != nil {
		return "", nil, err
	}
	for _, prev := range uniqueStrings(ev.PrevEvents) {
		if !seen[prev] {
			still = append(still, prev)
		}
	}
	if len(still) > 0 {
		return notDivulging, still, nil
	}
	return "", nil, nil
}

// shortstr is like Synapse's shortstr, for a log line: at most five
// items, then "...".
func shortstr(items []string) string {
	const maxItems = 5
	if len(items) <= maxItems {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:maxItems], ", ") + ", ..."
}

// getMissingEvents is _get_missing_events_for_pdu.
func (p *Processor) getMissingEvents(ctx context.Context, origin string, rv *pdu.RoomVersion, ev *pdu.Event, minDepth int64) error {
	m := p.missing
	seen, err := m.Store.InTimeline(ctx, ev.PrevEvents)
	if err != nil {
		return err
	}
	missing := false
	for _, prev := range ev.PrevEvents {
		if !seen[prev] {
			missing = true
		}
	}
	if !missing {
		return nil
	}
	snap, err := m.Store.TakeSnapshot(ctx, ev.RoomID, ev.ID, ev.PrevEvents, nil)
	if err != nil {
		return err
	}
	latest := map[string]bool{}
	for id := range seen {
		latest[id] = true
	}
	for _, x := range snap.Extremities {
		latest[x] = true
	}
	earliest := make([]string, 0, len(latest))
	for id := range latest {
		earliest = append(earliest, id)
	}
	sort.Strings(earliest)
	events, err := m.Fetch.MissingEvents(ctx, origin, ev.RoomID, rv, earliest, []string{ev.ID}, 10, int(minDepth))
	if errors.Is(err, fedfetch.ErrUncertain) {
		return fmt.Errorf("%w: %v", errUncertain, err)
	}
	if err != nil {
		// RequestSendFailed, HttpResponseException, NotRetryingDestination:
		// "Failed to get prev_events", and on.
		p.log.Warn().Err(err).Str("event_id", ev.ID).Msg("Failed to get prev_events")
		return nil
	}
	p.log.Info().Int("count", len(events)).Str("event_id", ev.ID).Msg("Got prev_events")
	return p.processPulledEvents(ctx, origin, rv, events)
}

// processPulledEvents is _process_pulled_events (backfilled false).
func (p *Processor) processPulledEvents(ctx context.Context, origin string, rv *pdu.RoomVersion, events []*fedfetch.Pulled) error {
	m := p.missing
	ids := make([]string, len(events))
	for i, e := range events {
		ids[i] = e.ID
	}
	existing, _, err := m.Store.GetStoredEvents(ctx, ids)
	if err != nil {
		return err
	}
	var fresh []*fedfetch.Pulled
	for _, e := range events {
		if se := existing[e.ID]; se != nil && !se.Outlier {
			continue
		}
		// An outlier is de-outliered: processed as new.
		fresh = append(fresh, e)
	}
	freshIDs := make([]string, len(fresh))
	for i, e := range fresh {
		freshIDs[i] = e.ID
	}
	failed, err := p.db.FailedPulls(ctx, freshIDs)
	if err != nil {
		return err
	}
	var retried, first []*fedfetch.Pulled
	for _, e := range fresh {
		if failed[e.ID] {
			retried = append(retried, e)
		} else {
			first = append(first, e)
		}
	}
	byDepth := func(es []*fedfetch.Pulled) {
		sort.SliceStable(es, func(i, j int) bool { return es[i].Event.Depth < es[j].Event.Depth })
	}
	if len(retried) > 0 {
		// "Process previously failed backfill events in the background to
		// not waste time on something that is likely to fail again": not
		// awaited, and holding nothing, as Synapse's background process.
		byDepth(retried)
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			for _, e := range retried {
				if err := p.processPulledEvent(p.ctx, origin, rv, e); err != nil {
					p.log.Info().Err(err).Str("event_id", e.ID).Msg("Write mode: retrying a pulled event failed")
					return
				}
			}
		}()
	}
	byDepth(first)
	for _, e := range first {
		if err := p.processPulledEvent(ctx, origin, rv, e); err != nil {
			return err
		}
	}
	return nil
}

// processPulledEvent is _process_pulled_event.
func (p *Processor) processPulledEvent(ctx context.Context, origin string, rv *pdu.RoomVersion, pe *fedfetch.Pulled) error {
	m := p.missing
	ev := pe.Event
	room := ev.RoomID
	log := p.log.With().Str("event_id", pe.ID).Str("room_id", room).Logger()
	if len(ev.PrevEvents) > 20 || len(ev.AuthEvents) > 10 {
		cause := fmt.Sprintf("too many prev_events or auth_events (%d, %d)", len(ev.PrevEvents), len(ev.AuthEvents))
		log.Warn().Str("why", cause).Msg("Pulled event failed sanity check")
		return p.db.RecordFailedPull(ctx, room, pe.ID, cause)
	}

	seen, err := m.Store.InTimeline(ctx, ev.PrevEvents)
	if err != nil {
		return err
	}
	var missing []string
	for _, prev := range uniqueStrings(ev.PrevEvents) {
		if !seen[prev] {
			missing = append(missing, prev)
		}
	}
	if len(missing) > 0 {
		backoff, err := p.db.PullBackoff(ctx, missing)
		if err != nil {
			return err
		}
		if len(backoff) > 0 {
			// FederationPullAttemptBackoffError: logged, nothing recorded.
			log.Warn().Msg("Not pulling missing prev_events again yet (backing off)")
			return nil
		}
	}

	var stateBefore pdu.StateMap
	if len(missing) > 0 {
		st, err := p.stateAcrossMissingPrevs(ctx, origin, rv, ev, seen, missing)
		if errors.Is(err, errUncertain) {
			return err
		}
		if err != nil {
			// FederationError 403 "We can't get valid state history.":
			// recorded, and the event is not persisted.
			log.Warn().Err(err).Msg("Pulled event failed history check")
			return p.db.RecordFailedPull(ctx, room, pe.ID, "ERROR 403: We can't get valid state history.")
		}
		stateBefore = st
	}

	meta, err := json.Marshal(pe.Metadata)
	if err != nil {
		return err
	}
	in := pduverify.DecideInput{
		Origin: origin, EventJSON: pe.Raw, Metadata: meta, EventID: pe.ID,
		Room: rv, OurServer: p.server, Cache: p.cache, StateBefore: stateBefore,
	}
	d, err := m.Verifier.Decide(ctx, in)
	if err == nil && d.Defer == pduverify.DeferMissingAuth {
		if err := p.remoteAuthChain(ctx, origin, rv, ev); err != nil {
			return err
		}
		d, err = m.Verifier.Decide(ctx, in)
	}
	switch {
	case err != nil:
		return err
	case d.Defer == pduverify.DeferMissingAuth:
		// _process_received_pdu's AuthError, as a FederationError:
		// recorded, and the event not persisted. Its groups were stored.
		if _, _, err := p.storeGroups(ctx, room, pe.ID, d); err != nil {
			return fmt.Errorf("%w: storing state groups for pulled %s: %v", errUncertain, pe.ID, err)
		}
		log.Warn().Msg("Pulled event failed history check")
		return p.db.RecordFailedPull(ctx, room, pe.ID, authNotFound)
	case d.Defer != "":
		return fmt.Errorf("%w: pulled %s: %s", errUncertain, pe.ID, d.Defer)
	case d.Raise != "":
		// Not the FederationError _process_pulled_event catches: it
		// escapes, ending the batch and failing the event that pulled it.
		// Nothing is recorded; the state groups were stored.
		if _, _, err := p.storeGroups(ctx, room, pe.ID, d); err != nil {
			return fmt.Errorf("%w: storing state groups for pulled %s: %v", errUncertain, pe.ID, err)
		}
		return fmt.Errorf("%w: pulled %s: %s", errFailed, pe.ID, d.Raise)
	case d.Ignore != "" || d.Drop != "":
		return nil
	}
	s := &Staged{Origin: origin, EventID: pe.ID, EventJSON: pe.Raw, InternalMetadata: meta}
	if err := p.write(ctx, room, s, d); err != nil {
		return fmt.Errorf("%w: persisting pulled %s: %v", errUncertain, pe.ID, err)
	}
	pulledEvents.Inc()
	if d.ResyncDevices != "" && d.Rejected == "" {
		p.resync(d.ResyncDevices)
	}
	return nil
}

// authNotFound is the FederationError _process_received_pdu makes of
// _load_or_fetch_auth_events_for_event's AuthError, as str() gives it.
const authNotFound = "ERROR 403: Auth events could not be found"

// remoteAuthChain is the fetch in _load_or_fetch_auth_events_for_event:
// _get_remote_auth_chain_for_event, whose every exception is logged and
// swallowed ("Failed to get auth chain"). Errors of ours, not Synapse's,
// are errUncertain.
func (p *Processor) remoteAuthChain(ctx context.Context, dest string, rv *pdu.RoomVersion, ev *pdu.Event) error {
	p.log.Info().Str("event_id", ev.ID).Msg("Event refers to unknown auth events: fetching auth chain")
	events, err := p.missing.Fetch.EventAuth(ctx, dest, ev.RoomID, ev.ID, rv)
	if errors.Is(err, fedfetch.ErrUncertain) {
		return fmt.Errorf("%w: %v", errUncertain, err)
	}
	if err != nil {
		p.log.Warn().Err(err).Str("event_id", ev.ID).Msg("Failed to get auth chain")
		return nil
	}
	p.log.Info().Int("count", len(events)).Msg("/event_auth returned events")
	// The event itself may be returned, but is not processed yet.
	var auth []*fedfetch.Pulled
	for _, e := range events {
		if e.ID != ev.ID {
			auth = append(auth, e)
		}
	}
	err = p.authAndPersistOutliers(ctx, ev.RoomID, auth)
	var re *pdu.RaiseError
	if err != nil && !errors.Is(err, errUncertain) && errors.As(err, &re) {
		p.log.Warn().Err(err).Str("event_id", ev.ID).Msg("Failed to get auth chain")
		return nil
	}
	if err != nil && !errors.Is(err, errUncertain) {
		return fmt.Errorf("%w: auth chain: %v", errUncertain, err)
	}
	return err
}

// stateAcrossMissingPrevs is the missing-prevs half of
// _compute_event_context_with_maybe_missing_prevs: the remote's state after
// each missing prev, our state after the others, resolved.
func (p *Processor) stateAcrossMissingPrevs(ctx context.Context, dest string, rv *pdu.RoomVersion, ev *pdu.Event, seen map[string]bool, missing []string) (pdu.StateMap, error) {
	m := p.missing
	var sets []pdu.StateMap
	for _, prev := range missing {
		sm, err := p.stateIDsAfterMissingPrev(ctx, dest, rv, ev.RoomID, prev)
		if err != nil {
			return nil, err
		}
		sets = append(sets, sm)
	}
	// get_state_groups_ids: our state after the prevs we have, by group.
	groups := map[int64]bool{}
	var ordered []int64
	for _, prev := range ev.PrevEvents {
		if !seen[prev] {
			continue
		}
		g, err := m.Store.StateGroupForEvent(ctx, prev)
		if err != nil {
			return nil, fmt.Errorf("%w: our prev %s: %v", errUncertain, prev, err)
		}
		if !groups[g] {
			groups[g] = true
			ordered = append(ordered, g)
		}
	}
	for _, g := range ordered {
		st, err := m.Store.StateForGroup(ctx, g)
		if err != nil {
			return nil, err
		}
		sets = append(sets, st)
	}
	resolved, err := m.Verifier.ResolveStates(ctx, ev.RoomID, rv, sets)
	if err != nil {
		var re *pdu.RaiseError
		if errors.As(err, &re) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: resolution: %v", errUncertain, err)
	}
	return resolved, nil
}

// stateIDsAfterMissingPrev is _get_state_ids_after_missing_prev_event.
func (p *Processor) stateIDsAfterMissingPrev(ctx context.Context, dest string, rv *pdu.RoomVersion, room, eventID string) (pdu.StateMap, error) {
	m := p.missing
	state, auth, err := m.Fetch.StateIDs(ctx, dest, room, eventID)
	if errors.Is(err, fedfetch.ErrUncertain) {
		return nil, fmt.Errorf("%w: %v", errUncertain, err)
	}
	if err != nil {
		return nil, err
	}
	desired := uniqueStrings(append(append([]string{}, state...), eventID))
	have, err := m.Store.SeenEvents(ctx, room, desired)
	if err != nil {
		return nil, err
	}
	missing := map[string]bool{}
	for _, id := range desired {
		if !have[id] {
			missing[id] = true
		}
	}
	var authLeft []string
	for _, id := range uniqueStrings(auth) {
		if !have[id] {
			authLeft = append(authLeft, id)
		}
	}
	haveAuth, err := m.Store.SeenEvents(ctx, room, authLeft)
	if err != nil {
		return nil, err
	}
	for _, id := range authLeft {
		if !haveAuth[id] {
			missing[id] = true
		}
	}
	if len(missing)*10 >= len(auth)+len(state) {
		if err := p.stateAndPersist(ctx, dest, rv, room, eventID); err != nil {
			return nil, err
		}
	} else {
		ids := make([]string, 0, len(missing))
		for id := range missing {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		if err := p.eventsAndPersist(ctx, dest, rv, room, ids); err != nil {
			return nil, err
		}
	}

	meta, err := m.Store.EventsMetadata(ctx, state)
	if err != nil {
		return nil, err
	}
	out := pdu.StateMap{}
	for _, id := range state {
		md, ok := meta[id]
		if !ok || md.RoomID != room || md.StateKey == nil {
			continue
		}
		out[pdu.StateKey{Type: md.Type, StateKey: *md.StateKey}] = id
	}
	got, _, err := m.Store.GetStoredEvents(ctx, []string{eventID})
	if err != nil {
		return nil, err
	}
	remote := got[eventID]
	if remote == nil {
		return nil, fmt.Errorf("unable to get missing prev_event %s", eventID)
	}
	if remote.Event.IsState() && !remote.Event.Rejected {
		out[remote.Event.Key()] = eventID
	}
	return out, nil
}

// stateAndPersist is _get_state_and_persist.
func (p *Processor) stateAndPersist(ctx context.Context, dest string, rv *pdu.RoomVersion, room, eventID string) error {
	auth, state, err := p.missing.Fetch.State(ctx, dest, room, eventID, rv)
	if errors.Is(err, fedfetch.ErrUncertain) {
		return fmt.Errorf("%w: %v", errUncertain, err)
	}
	if err != nil {
		return err
	}
	if err := p.authAndPersistOutliers(ctx, room, append(auth, state...)); err != nil {
		return err
	}
	seen, err := p.missing.Store.SeenEvents(ctx, room, []string{eventID})
	if err != nil {
		return err
	}
	if !seen[eventID] {
		return p.eventsAndPersist(ctx, dest, rv, room, []string{eventID})
	}
	return nil
}

// eventsAndPersist is _get_events_and_persist: each event from dest, five
// at a time, then persisted as outliers.
func (p *Processor) eventsAndPersist(ctx context.Context, dest string, rv *pdu.RoomVersion, room string, ids []string) error {
	var mu sync.Mutex
	var events []*fedfetch.Pulled
	var uncertain error
	sem := make(chan struct{}, 5)
	var wg sync.WaitGroup
	for _, id := range ids {
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			e, err := p.missing.Fetch.Event(ctx, dest, id, room, rv)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case errors.Is(err, fedfetch.ErrUncertain):
				uncertain = fmt.Errorf("%w: %v", errUncertain, err)
			case err != nil:
				p.log.Warn().Err(err).Str("event_id", id).Msg("Error fetching missing state/auth event")
			case e == nil:
				p.log.Warn().Str("event_id", id).Str("server", dest).Msg("Server didn't return event")
			default:
				events = append(events, e)
			}
		}()
	}
	wg.Wait()
	if uncertain != nil {
		return uncertain
	}
	return p.authAndPersistOutliers(ctx, room, events)
}

// authAndPersistOutliers is _auth_and_persist_outliers.
func (p *Processor) authAndPersistOutliers(ctx context.Context, room string, pulled []*fedfetch.Pulled) error {
	m := p.missing
	byID := map[string]*fedfetch.Pulled{}
	for _, e := range pulled {
		if e.Event.RoomID != room {
			// Synapse would persist it in the batch for this room.
			return fmt.Errorf("%w: pulled %s is in room %s", errUncertain, e.ID, e.Event.RoomID)
		}
		byID[e.ID] = e
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	seen, err := m.Store.SeenEvents(ctx, room, ids)
	if err != nil {
		return err
	}
	for id := range seen {
		delete(byID, id)
	}
	graph := map[string][]string{}
	for id, e := range byID {
		for _, a := range e.Event.AuthEvents {
			if _, ok := byID[a]; ok {
				graph[id] = append(graph[id], a)
			}
		}
	}
	keys := make([]string, 0, len(byID))
	for id := range byID {
		keys = append(keys, id)
	}
	order := sortedTopologically(keys, graph)

	authIDs := map[string]bool{}
	for _, id := range order {
		for _, a := range byID[id].Event.AuthEvents {
			authIDs[a] = true
		}
	}
	authMap := map[string]*pdu.Event{}
	var fromDB []string
	for a := range authIDs {
		if e, ok := byID[a]; ok {
			authMap[a] = e.Event
		} else {
			fromDB = append(fromDB, a)
		}
	}
	if len(fromDB) > 0 {
		held, err := m.Store.GetEvents(ctx, fromDB)
		if err != nil {
			return err
		}
		for id, e := range held {
			authMap[id] = e
		}
	}

	var entries []json.RawMessage
	for _, id := range order {
		e := byID[id]
		rej, drop, err := pduverify.OutlierVerdict(e.Event, authMap)
		if err != nil {
			// The batch fails, nothing of it persisted. For missing prevs
			// that is "We can't get valid state history."
			return fmt.Errorf("outlier %s: %w", id, err)
		}
		if drop {
			p.log.Warn().Str("event_id", id).Msg("Dropping event which relies on an auth_event which could not be found")
			delete(authMap, id)
			continue
		}
		entry, err := pduverify.OutlierEntry(e.Raw, e.Event, e.Metadata, rej)
		if err != nil {
			return err
		}
		entries = append(entries, entry)
	}
	for i := 0; i < len(entries); i += 1000 {
		batch := entries[i:min(i+1000, len(entries))]
		if err := p.persist.SendEvents(ctx, room, batch, true); err != nil {
			return fmt.Errorf("%w: persisting outliers: %v", errUncertain, err)
		}
		outliersPersisted.Add(float64(len(batch)))
	}
	return nil
}

// sortedTopologically is sorted_topologically: Kahn's algorithm, ties by a
// min-heap of the IDs. Nodes in a cycle are never yielded.
func sortedTopologically(nodes []string, graph map[string][]string) []string {
	degree := map[string]int{}
	for _, n := range nodes {
		degree[n] = 0
	}
	reverse := map[string]map[string]bool{}
	for node, edges := range graph {
		if _, ok := degree[node]; !ok {
			continue
		}
		for _, e := range uniqueStrings(edges) {
			if _, ok := degree[e]; ok {
				degree[node]++
			}
			if reverse[e] == nil {
				reverse[e] = map[string]bool{}
			}
			reverse[e][node] = true
		}
	}
	var zero []string
	for n, d := range degree {
		if d == 0 {
			zero = append(zero, n)
		}
	}
	sort.Strings(zero)
	var out []string
	for len(zero) > 0 {
		n := zero[0]
		zero = zero[1:]
		out = append(out, n)
		for e := range reverse[n] {
			if _, ok := degree[e]; ok {
				degree[e]--
				if degree[e] == 0 {
					i := sort.SearchStrings(zero, e)
					zero = append(zero, "")
					copy(zero[i+1:], zero[i:])
					zero[i] = e
				}
			}
		}
	}
	return out
}

func uniqueStrings(s []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range s {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}
