// Package pdustore reads what PDU verification needs from Synapse's database:
// events as Synapse stored them (rejections included), auth edges, and state
// groups.
//
// Read-only, like package store. It is separate because its tables are many
// and its queries heavier -- a state group walk can read thousands of rows --
// and because the offline replay (cmd/pdusweep) uses it on its own.
package pdustore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
)

// Tables is every table this package reads.
var Tables = []string{
	"events", "event_json", "rooms", "rejections", "event_auth",
	"event_to_state_groups", "state_groups_state", "state_group_edges", "event_edges",
	"event_auth_chains", "event_auth_chain_links", "server_signature_keys", "redactions",
	"event_forward_extremities", "current_state_events", "partial_state_rooms",
	"federation_inbound_events_staging", "state_groups",
	// The push check.
	"local_current_membership", "room_memberships", "push_rules", "push_rules_enable",
	"ignored_users", "event_relations", "thread_subscriptions", "room_depth", "event_push_actions", "receipts_linearized",
}

// Store reads PDUs and state.
type Store struct {
	pool *pgxpool.Pool
}

// Open connects. The DSN's role needs SELECT on Tables.
func Open(ctx context.Context, dsn string, maxConns int32) (*Store, error) {
	return OpenAs(ctx, dsn, "", "", maxConns)
}

// OpenAs connects as user (replacing any the DSN names) with password (used
// only when the DSN has none), as package store does for the managed role.
func OpenAs(ctx context.Context, dsn, user, password string, maxConns int32) (*Store, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("pdustore: parse dsn: %w", err)
	}
	if maxConns > 0 {
		cfg.MaxConns = maxConns
	}
	if user != "" {
		cfg.ConnConfig.User = user
	}
	if cfg.ConnConfig.Password == "" && password != "" {
		cfg.ConnConfig.Password = password
	}
	// See package store: pgcat in transaction mode.
	cfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeExec
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("pdustore: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("pdustore: ping: %w", err)
	}
	return &Store{pool: pool}, nil
}

// Close releases the pool.
func (s *Store) Close() { s.pool.Close() }

// StoredEvent is an event with the bookkeeping Synapse keeps beside it.
type StoredEvent struct {
	*pdu.Event
	Outlier        bool
	StreamOrdering int64
	ReceivedTS     int64
	// Reason is the rejection reason, empty when accepted.
	Reason string
}

const qEvents = `
	SELECT e.event_id, ej.json, r.room_version,
	       COALESCE(e.rejection_reason, rej.reason), e.outlier, e.stream_ordering,
	       COALESCE(e.received_ts, 0)
	FROM events e
	JOIN event_json ej USING (event_id)
	JOIN rooms r ON r.room_id = e.room_id
	LEFT JOIN rejections rej USING (event_id)
	WHERE e.event_id = ANY($1)`

// ErrUnparseable marks events that could not be turned into a pdu.Event:
// an unknown room version, or JSON in a shape pdu does not handle.
var ErrUnparseable = errors.New("pdustore: event could not be parsed")

// GetStoredEvents loads events by ID. Events that exist but cannot be parsed
// are reported in bad rather than failing the whole call.
func (s *Store) GetStoredEvents(ctx context.Context, ids []string) (map[string]*StoredEvent, map[string]error, error) {
	out := map[string]*StoredEvent{}
	bad := map[string]error{}
	if len(ids) == 0 {
		return out, bad, nil
	}
	rows, err := s.pool.Query(ctx, qEvents, ids)
	if err != nil {
		return nil, nil, fmt.Errorf("pdustore: events: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			id, rvID string
			raw      []byte
			reason   *string
			se       StoredEvent
		)
		if err := rows.Scan(&id, &raw, &rvID, &reason, &se.Outlier, &se.StreamOrdering, &se.ReceivedTS); err != nil {
			return nil, nil, fmt.Errorf("pdustore: scan event: %w", err)
		}
		rv, ok := pdu.LookupRoomVersion(rvID)
		if !ok {
			bad[id] = fmt.Errorf("%w: room version %q", ErrUnparseable, rvID)
			continue
		}
		if reason != nil {
			se.Reason = *reason
		}
		ev, err := pdu.ParseEvent(raw, id, rv, reason != nil)
		if err != nil {
			bad[id] = fmt.Errorf("%w: %v", ErrUnparseable, err)
			continue
		}
		if ev.ID != id {
			bad[id] = fmt.Errorf("%w: stored under %s but its JSON says %s", ErrUnparseable, id, ev.ID)
			continue
		}
		se.Event = ev
		out[id] = &se
	}
	return out, bad, rows.Err()
}

// GetEvents satisfies stateres.Store.
func (s *Store) GetEvents(ctx context.Context, ids []string) (map[string]*pdu.Event, error) {
	got, bad, err := s.GetStoredEvents(ctx, ids)
	if err != nil {
		return nil, err
	}
	if len(bad) > 0 {
		for id, e := range bad {
			return nil, &pdu.RaiseError{Msg: fmt.Sprintf("event %s: %v", id, e)}
		}
	}
	out := make(map[string]*pdu.Event, len(got))
	for id, se := range got {
		out[id] = se.Event
	}
	return out, nil
}

const qAuthEdges = `SELECT event_id, auth_id FROM event_auth WHERE event_id = ANY($1)`

// AuthEdges satisfies stateres.Store.
func (s *Store) AuthEdges(ctx context.Context, ids []string) (map[string][]string, error) {
	out := map[string][]string{}
	for start := 0; start < len(ids); start += 5000 {
		end := min(start+5000, len(ids))
		rows, err := s.pool.Query(ctx, qAuthEdges, ids[start:end])
		if err != nil {
			return nil, fmt.Errorf("pdustore: auth edges: %w", err)
		}
		for rows.Next() {
			var id, aid string
			if err := rows.Scan(&id, &aid); err != nil {
				rows.Close()
				return nil, fmt.Errorf("pdustore: scan auth edge: %w", err)
			}
			out[id] = append(out[id], aid)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, fmt.Errorf("pdustore: auth edges: %w", err)
		}
	}
	return out, nil
}

// ErrNoStateGroup is an event without a state group: an outlier, or one whose
// group has since been deleted.
var ErrNoStateGroup = errors.New("pdustore: event has no state group")

const qStateGroup = `SELECT state_group FROM event_to_state_groups WHERE event_id = $1`

// StateGroupForEvent returns the state group Synapse stored for an event:
// the state AFTER it, or for a rejected or non-state event the state before.
func (s *Store) StateGroupForEvent(ctx context.Context, id string) (int64, error) {
	var g int64
	err := s.pool.QueryRow(ctx, qStateGroup, id).Scan(&g)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, ErrNoStateGroup
	}
	if err != nil {
		return 0, fmt.Errorf("pdustore: state group: %w", err)
	}
	return g, nil
}

// qStateForGroup walks the delta chain and keeps the newest row per key, as
// Synapse's _get_state_groups_from_groups_txn does.
const qStateForGroup = `
	WITH RECURSIVE sgs(state_group) AS (
		VALUES($1::bigint)
	  UNION ALL
		SELECT prev_state_group FROM state_group_edges e, sgs s
		WHERE s.state_group = e.state_group
	)
	SELECT DISTINCT ON (type, state_key) type, state_key, event_id
	FROM state_groups_state
	INNER JOIN sgs USING (state_group)
	ORDER BY type, state_key, state_group DESC`

// StateForGroup resolves a state group to its full state map.
//
// Synapse turns off sequential scans for this query, because the planner
// otherwise reads state_groups_state -- the largest table by far -- end to
// end. SET LOCAL needs a transaction, which also keeps the setting from
// leaking to other users of a pooled connection.
func (s *Store) StateForGroup(ctx context.Context, group int64) (pdu.StateMap, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return nil, fmt.Errorf("pdustore: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, qDisableSeqscan); err != nil {
		return nil, fmt.Errorf("pdustore: disable seqscan: %w", err)
	}
	rows, err := tx.Query(ctx, qStateForGroup, group)
	if err != nil {
		return nil, fmt.Errorf("pdustore: state for group: %w", err)
	}
	defer rows.Close()
	out := pdu.StateMap{}
	for rows.Next() {
		var k pdu.StateKey
		var id string
		if err := rows.Scan(&k.Type, &k.StateKey, &id); err != nil {
			return nil, fmt.Errorf("pdustore: scan state: %w", err)
		}
		out[k] = id
	}
	return out, rows.Err()
}

const qDisableSeqscan = `SET LOCAL enable_seqscan = off`

const qStateEdge = `SELECT prev_state_group FROM state_group_edges WHERE state_group = $1`

const qStateDeltaRows = `SELECT type, state_key, event_id FROM state_groups_state WHERE state_group = $1`

const qStateGroupEvent = `SELECT event_id FROM state_groups WHERE id = $1`

// StateGroupEvent is the event a state group was stored for: Synapse
// stores a new group under the event whose context needed it.
func (s *Store) StateGroupEvent(ctx context.Context, group int64) (string, error) {
	var id string
	if err := s.pool.QueryRow(ctx, qStateGroupEvent, group).Scan(&id); err != nil {
		return "", fmt.Errorf("pdustore: state group event: %w", err)
	}
	return id, nil
}

// qStateHops is _count_state_group_hops_txn's query: the group and every
// group its delta chain builds on.
const qStateHops = `WITH RECURSIVE state(state_group) AS (
		VALUES($1::bigint)
		UNION ALL
		SELECT prev_state_group FROM state_group_edges e, state s
		WHERE s.state_group = e.state_group
	)
	SELECT count(*) FROM state`

// StateHops is the length of a group's delta chain, the group included, as
// Synapse counts it. A group built on one with 100 or more is stored in full.
func (s *Store) StateHops(ctx context.Context, group int64) (int, error) {
	var n int
	if err := s.pool.QueryRow(ctx, qStateHops, group).Scan(&n); err != nil {
		return 0, fmt.Errorf("pdustore: state hops: %w", err)
	}
	return n, nil
}

// StateDelta is one link of a group's delta chain: the group it builds on
// (hasPrev false for a group stored in full) and its own rows, which override
// the prev group's. Synapse keeps chains short (it stores a full group every
// 100 deltas), and a delta is usually a single row.
func (s *Store) StateDelta(ctx context.Context, group int64) (prev int64, hasPrev bool, delta pdu.StateMap, err error) {
	err = s.pool.QueryRow(ctx, qStateEdge, group).Scan(&prev)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return 0, false, nil, nil
	case err != nil:
		return 0, false, nil, fmt.Errorf("pdustore: state edge: %w", err)
	}
	rows, err := s.pool.Query(ctx, qStateDeltaRows, group)
	if err != nil {
		return 0, false, nil, fmt.Errorf("pdustore: state delta: %w", err)
	}
	defer rows.Close()
	delta = pdu.StateMap{}
	for rows.Next() {
		var k pdu.StateKey
		var id string
		if err := rows.Scan(&k.Type, &k.StateKey, &id); err != nil {
			return 0, false, nil, fmt.Errorf("pdustore: scan delta: %w", err)
		}
		delta[k] = id
	}
	return prev, true, delta, rows.Err()
}

// qSample samples every room version in one pass over the window, rather
// than one sorted scan per version. The window is read through the
// stream_ordering index; anything costlier per event (counting edges for
// forks) is done afterwards, on the sample only.
const qSample = `
	SELECT room_version, event_id FROM (
		SELECT r.room_version, e.event_id,
		       row_number() OVER (PARTITION BY r.room_version ORDER BY random()) AS n
		FROM events e
		JOIN rooms r USING (room_id)
		LEFT JOIN rejections rej USING (event_id)
		WHERE e.stream_ordering > (SELECT max(stream_ordering) FROM events) - $3
		  AND r.room_version = ANY($1)
		  AND NOT e.outlier
		  AND e.type <> 'm.room.create'
		  AND (NOT $4 OR e.rejection_reason IS NOT NULL OR rej.reason IS NOT NULL)
	) s
	WHERE n <= $2`

const qForks = `
	SELECT event_id FROM event_edges
	WHERE event_id = ANY($1)
	GROUP BY event_id HAVING count(*) >= 2`

// forkOversample is how many events are sampled per fork wanted: about one
// event in twenty has several prevs.
const forkOversample = 40

// SampleEvents picks up to n random non-outlier events of each room version
// from the most recent window stream orderings, optionally only those with
// several prev events (where state resolution runs) or only rejected ones.
func (s *Store) SampleEvents(ctx context.Context, roomVersions []string, n int, window int64, forks, rejected bool) (map[string][]string, error) {
	want := n
	if forks {
		want = n * forkOversample
	}
	rows, err := s.pool.Query(ctx, qSample, roomVersions, want, window, rejected)
	if err != nil {
		return nil, fmt.Errorf("pdustore: sample: %w", err)
	}
	out := map[string][]string{}
	var all []string
	for rows.Next() {
		var v, id string
		if err := rows.Scan(&v, &id); err != nil {
			rows.Close()
			return nil, err
		}
		out[v] = append(out[v], id)
		all = append(all, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("pdustore: sample: %w", err)
	}
	if !forks {
		return out, nil
	}

	isFork := map[string]bool{}
	for start := 0; start < len(all); start += 1000 {
		end := min(start+1000, len(all))
		frows, err := s.pool.Query(ctx, qForks, all[start:end])
		if err != nil {
			return nil, fmt.Errorf("pdustore: sample forks: %w", err)
		}
		for frows.Next() {
			var id string
			if err := frows.Scan(&id); err != nil {
				frows.Close()
				return nil, err
			}
			isFork[id] = true
		}
		frows.Close()
		if err := frows.Err(); err != nil {
			return nil, fmt.Errorf("pdustore: sample forks: %w", err)
		}
	}
	for v, ids := range out {
		var kept []string
		for _, id := range ids {
			if isFork[id] && len(kept) < n {
				kept = append(kept, id)
			}
		}
		out[v] = kept
	}
	return out, nil
}

const qVerifyKeys = `
	SELECT key_id, verify_key, ts_valid_until_ms, ts_added_ms
	FROM server_signature_keys
	WHERE server_name = $1 AND key_id = ANY($2)`

// VerifyKeys returns the keys Synapse holds for a server, by key ID. An old
// key is valid until the time it expired. When several notaries vouched for
// the same key, the longest validity wins.
func (s *Store) VerifyKeys(ctx context.Context, server string, keyIDs []string) (map[string]pdu.VerifyKey, error) {
	rows, err := s.pool.Query(ctx, qVerifyKeys, server, keyIDs)
	if err != nil {
		return nil, fmt.Errorf("pdustore: verify keys: %w", err)
	}
	defer rows.Close()
	out := map[string]pdu.VerifyKey{}
	for rows.Next() {
		var kid string
		var key []byte
		var until, added *int64
		if err := rows.Scan(&kid, &key, &until, &added); err != nil {
			return nil, err
		}
		if len(key) != 32 {
			continue
		}
		v := pdu.VerifyKey{Key: key}
		if until != nil {
			v.ValidUntilMS = *until
		}
		if added != nil {
			v.AddedMS = *added
		}
		if cur, ok := out[kid]; !ok || v.ValidUntilMS > cur.ValidUntilMS {
			out[kid] = v
		}
	}
	return out, rows.Err()
}

const qRedacted = `SELECT EXISTS (SELECT 1 FROM redactions WHERE redacts = $1)`

// IsRedacted reports whether a redaction of the event exists, in which case
// Synapse may have replaced its stored JSON with the redacted form.
func (s *Store) IsRedacted(ctx context.Context, id string) (bool, error) {
	var r bool
	err := s.pool.QueryRow(ctx, qRedacted, id).Scan(&r)
	return r, err
}

// ErrUnknownRoom is a room this homeserver does not know.
var ErrUnknownRoom = errors.New("pdustore: unknown room")

const qRoomVersion = `SELECT room_version FROM rooms WHERE room_id = $1`

// RoomVersion returns the room's version.
func (s *Store) RoomVersion(ctx context.Context, roomID string) (string, error) {
	var v *string
	err := s.pool.QueryRow(ctx, qRoomVersion, roomID).Scan(&v)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && v == nil) {
		return "", ErrUnknownRoom
	}
	if err != nil {
		return "", fmt.Errorf("pdustore: room version: %w", err)
	}
	return *v, nil
}

const qEventExists = `SELECT EXISTS (SELECT 1 FROM events WHERE event_id = $1)`

// EventExists reports whether Synapse has persisted the event.
func (s *Store) EventExists(ctx context.Context, id string) (bool, error) {
	var ok bool
	if err := s.pool.QueryRow(ctx, qEventExists, id).Scan(&ok); err != nil {
		return false, fmt.Errorf("pdustore: event exists: %w", err)
	}
	return ok, nil
}

const qHostJoined = `SELECT state_key FROM current_state_events
	WHERE membership = 'join' AND type = 'm.room.member' AND room_id = $1 AND state_key LIKE $2
	LIMIT 1`

// HostJoined reports whether a user of host is joined to the room, as
// Synapse's is_host_joined (roommember.py:1191) does. A PDU for a room the
// receiving server is not in is ignored (federation_event.py:252). ok is
// false when host is one Synapse refuses to look up, raising instead.
func (s *Store) HostJoined(ctx context.Context, roomID, host string) (joined, ok bool, err error) {
	if strings.ContainsAny(host, "%_") {
		return false, false, nil
	}
	var userID string
	switch err := s.pool.QueryRow(ctx, qHostJoined, roomID, "%:"+host).Scan(&userID); {
	case errors.Is(err, pgx.ErrNoRows):
		return false, true, nil
	case err != nil:
		return false, false, fmt.Errorf("pdustore: host joined: %w", err)
	}
	// Synapse raises when the match is not the host's own user.
	if _, domain, found := strings.Cut(userID, ":"); !found || domain != host {
		return false, false, nil
	}
	return true, true, nil
}

const qStaged = `SELECT EXISTS (SELECT 1 FROM federation_inbound_events_staging WHERE event_id = $1)`

// Staged reports whether the event is still in Synapse's inbound staging
// queue: received, and not yet processed.
func (s *Store) Staged(ctx context.Context, id string) (bool, error) {
	var ok bool
	if err := s.pool.QueryRow(ctx, qStaged, id).Scan(&ok); err != nil {
		return false, fmt.Errorf("pdustore: staged: %w", err)
	}
	return ok, nil
}

// Snapshot is what Synapse's soft-fail check reads about a room
// (federation_event.py _check_for_soft_fail), captured as close as possible
// to the moment Synapse reads it.
type Snapshot struct {
	Extremities []string
	// Current is the current state for the requested keys.
	Current pdu.StateMap
	// PrevsInTimeline is have_events_in_timeline: every prev event is held,
	// and not as an outlier.
	PrevsInTimeline bool
	// MaxStream is the room's newest stream ordering when taken.
	MaxStream int64
	// EventPresent means the event was already persisted when the snapshot
	// was taken, so it describes the room after the event, not before.
	EventPresent bool
	PartialState bool
}

const qExtremities = `SELECT event_id FROM event_forward_extremities WHERE room_id = $1`

const qCurrentState = `
	SELECT c.type, c.state_key, c.event_id
	FROM current_state_events c
	JOIN unnest($2::text[], $3::text[]) AS k(type, state_key)
	  ON c.type = k.type AND c.state_key = k.state_key
	WHERE c.room_id = $1`

const qPrevsInTimeline = `
	SELECT count(*) FROM events WHERE event_id = ANY($1) AND NOT outlier`

const qPrevsReady = `
	SELECT (SELECT count(*) FROM events WHERE event_id = ANY($1) AND NOT outlier),
	       EXISTS (SELECT 1 FROM events WHERE event_id = $2)`

// PrevsReady reports whether every prev event is in the timeline, and
// whether the event itself has been persisted.
func (s *Store) PrevsReady(ctx context.Context, eventID string, prevs []string) (ready, present bool, err error) {
	u := uniqueIDs(prevs)
	var n int
	if err := s.pool.QueryRow(ctx, qPrevsReady, u, eventID).Scan(&n, &present); err != nil {
		return false, false, fmt.Errorf("pdustore: prevs ready: %w", err)
	}
	return n == len(u), present, nil
}

const qRoomMaxStream = `SELECT COALESCE(max(stream_ordering), 0) FROM events WHERE room_id = $1`

const qPartialState = `SELECT EXISTS (SELECT 1 FROM partial_state_rooms WHERE room_id = $1)`

// TakeSnapshot reads the room as the soft-fail check would see it.
func (s *Store) TakeSnapshot(ctx context.Context, roomID, eventID string, prevs []string, keys []pdu.StateKey) (*Snapshot, error) {
	snap := &Snapshot{Current: pdu.StateMap{}}
	var err error
	// Stream position first, and presence last: if the event is absent at
	// the end, it was absent throughout.
	if err = s.pool.QueryRow(ctx, qRoomMaxStream, roomID).Scan(&snap.MaxStream); err != nil {
		return nil, fmt.Errorf("pdustore: room max stream: %w", err)
	}
	rows, err := s.pool.Query(ctx, qExtremities, roomID)
	if err != nil {
		return nil, fmt.Errorf("pdustore: extremities: %w", err)
	}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		snap.Extremities = append(snap.Extremities, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	types, sks := make([]string, len(keys)), make([]string, len(keys))
	for i, k := range keys {
		types[i], sks[i] = k.Type, k.StateKey
	}
	rows, err = s.pool.Query(ctx, qCurrentState, roomID, types, sks)
	if err != nil {
		return nil, fmt.Errorf("pdustore: current state: %w", err)
	}
	for rows.Next() {
		var k pdu.StateKey
		var id string
		if err := rows.Scan(&k.Type, &k.StateKey, &id); err != nil {
			rows.Close()
			return nil, err
		}
		snap.Current[k] = id
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var n int
	if err := s.pool.QueryRow(ctx, qPrevsInTimeline, uniqueIDs(prevs)).Scan(&n); err != nil {
		return nil, fmt.Errorf("pdustore: prevs: %w", err)
	}
	snap.PrevsInTimeline = n == len(uniqueIDs(prevs))
	if err := s.pool.QueryRow(ctx, qPartialState, roomID).Scan(&snap.PartialState); err != nil {
		return nil, fmt.Errorf("pdustore: partial state: %w", err)
	}
	if snap.EventPresent, err = s.EventExists(ctx, eventID); err != nil {
		return nil, err
	}
	return snap, nil
}

func uniqueIDs(ids []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, id := range ids {
		if !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}

const qRoomEventsBetween = `
	SELECT count(*) FROM events
	WHERE room_id = $1 AND stream_ordering > $2 AND stream_ordering < $3 AND event_id <> $4`

// RoomEventsBetween counts the room's events persisted strictly between two
// stream orderings, other than the given event.
func (s *Store) RoomEventsBetween(ctx context.Context, roomID string, after, before int64, except string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, qRoomEventsBetween, roomID, after, before, except).Scan(&n)
	return n, err
}

const qInternalMetadata = `SELECT internal_metadata FROM event_json WHERE event_id = $1`

// SoftFailed reports Synapse's soft_failed flag for an event.
func (s *Store) SoftFailed(ctx context.Context, id string) (bool, error) {
	var meta string
	if err := s.pool.QueryRow(ctx, qInternalMetadata, id).Scan(&meta); err != nil {
		return false, fmt.Errorf("pdustore: internal metadata: %w", err)
	}
	var m struct {
		SoftFailed bool `json:"soft_failed"`
	}
	_ = json.Unmarshal([]byte(meta), &m)
	return m.SoftFailed, nil
}

// InternalMetadata is the event's stored internal metadata, decoded.
func (s *Store) InternalMetadata(ctx context.Context, id string) (map[string]any, error) {
	var meta string
	if err := s.pool.QueryRow(ctx, qInternalMetadata, id).Scan(&meta); err != nil {
		return nil, fmt.Errorf("pdustore: internal metadata: %w", err)
	}
	m := map[string]any{}
	if err := json.Unmarshal([]byte(meta), &m); err != nil {
		return nil, fmt.Errorf("pdustore: internal metadata: %w", err)
	}
	return m, nil
}

const qCurrentStateEvent = `
	SELECT c.event_id, ej.json,
	       EXISTS (SELECT 1 FROM redactions r WHERE r.redacts = c.event_id)
	FROM current_state_events c
	JOIN event_json ej USING (event_id)
	WHERE c.room_id = $1 AND c.type = $2 AND c.state_key = $3`

// CurrentStateEvent is the room's current state event of a type and state
// key: get_current_state_event. nil when there is none.
func (s *Store) CurrentStateEvent(ctx context.Context, roomID, typ, stateKey string) (*CurrentEvent, error) {
	var e CurrentEvent
	switch err := s.pool.QueryRow(ctx, qCurrentStateEvent, roomID, typ, stateKey).Scan(&e.EventID, &e.JSON, &e.Redacted); {
	case errors.Is(err, pgx.ErrNoRows):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("pdustore: current state event: %w", err)
	}
	return &e, nil
}

// CurrentEvent is a current state event as stored.
type CurrentEvent struct {
	EventID string
	JSON    []byte
	// Redacted: a redaction of it is stored, so Synapse may read it
	// pruned (whether it does depends on the redaction's validity).
	Redacted bool
}
