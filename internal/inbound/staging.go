package inbound

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tidwall/gjson"
)

// The staging area (storage/databases/main/event_federation.py:2287-2525).
// Synapse's inbound worker and we share it: whoever holds a room's
// LockInboundPDU drains everything staged for the room, whoever staged it.

// qStage is insert_received_event_to_staging's simple_upsert with no
// update values: the first copy of an event from an origin is kept.
const qStage = `
	INSERT INTO federation_inbound_events_staging (origin, event_id, room_id, received_ts, event_json, internal_metadata)
	VALUES ($1, $2, $3, $4, $5, $6)
	ON CONFLICT (origin, event_id) DO NOTHING`

const (
	qUnstage = `
		DELETE FROM federation_inbound_events_staging
		WHERE origin = $1 AND event_id = $2
		RETURNING received_ts`
	qNextStagedID = `
		SELECT origin, event_id
		FROM federation_inbound_events_staging
		WHERE room_id = $1
		ORDER BY received_ts ASC
		LIMIT 1`
	qNextStaged = `
		SELECT event_json, internal_metadata, origin
		FROM federation_inbound_events_staging
		WHERE room_id = $1
		ORDER BY received_ts ASC
		LIMIT 1`
	qStagedCount  = `SELECT COUNT(*) FROM federation_inbound_events_staging WHERE room_id = $1`
	qStagedEvents = `SELECT event_id, event_json FROM federation_inbound_events_staging WHERE room_id = $1`
	qPruneStaged  = `DELETE FROM federation_inbound_events_staging WHERE room_id = $1 AND event_id = ANY($2)`
	qStagedRooms  = `SELECT DISTINCT room_id FROM federation_inbound_events_staging`
	qStagingAge   = `SELECT count(*), COALESCE(min(received_ts), 0) FROM federation_inbound_events_staging`
	// qStagingUnattended is qStagingAge for rooms whose inbound lock nobody
	// holds: no row, or one not renewed within the lock timeout.
	qStagingUnattended = `
	SELECT count(*), COALESCE(min(s.received_ts), 0)
	FROM federation_inbound_events_staging s
	WHERE NOT EXISTS (
		SELECT 1 FROM worker_locks l
		WHERE l.lock_name = $1 AND l.lock_key = s.room_id AND l.last_renewed_ts >= $2)`
)

// Staged is a staged event: event.get_dict() and its internal metadata, as
// Synapse stored them.
type Staged struct {
	Origin           string
	EventID          string
	EventJSON        []byte
	InternalMetadata []byte
}

// Stage is insert_received_event_to_staging. eventJSON is event.get_dict()
// (after _check_sigs_and_hash: pruned on a bad hash, with any policy server
// signature added) and metadata internal_metadata.get_dict().
func (d *DB) Stage(ctx context.Context, origin, roomID, eventID string, eventJSON, metadata []byte) error {
	_, err := d.pool.Exec(ctx, qStage, origin, eventID, roomID, d.nowMS(), string(eventJSON), string(metadata))
	if err != nil {
		return fmt.Errorf("inbound: stage %s: %w", eventID, err)
	}
	return nil
}

// Unstage is remove_received_event_from_staging: the row's received_ts, or
// ok false if it was not there.
func (d *DB) Unstage(ctx context.Context, origin, eventID string) (receivedTS int64, ok bool, err error) {
	err = d.pool.QueryRow(ctx, qUnstage, origin, eventID).Scan(&receivedTS)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, fmt.Errorf("inbound: unstage %s: %w", eventID, err)
	}
	return receivedTS, true, nil
}

// NextStagedID is get_next_staged_event_id_for_room.
func (d *DB) NextStagedID(ctx context.Context, roomID string) (origin, eventID string, ok bool, err error) {
	err = d.pool.QueryRow(ctx, qNextStagedID, roomID).Scan(&origin, &eventID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, fmt.Errorf("inbound: next staged id: %w", err)
	}
	return origin, eventID, true, nil
}

// NextStaged is get_next_staged_event_for_room. The event ID is the caller's
// to compute: the stored JSON has none for v3+ rooms.
func (d *DB) NextStaged(ctx context.Context, roomID string) (*Staged, error) {
	var ev, meta string
	s := &Staged{}
	err := d.pool.QueryRow(ctx, qNextStaged, roomID).Scan(&ev, &meta, &s.Origin)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inbound: next staged: %w", err)
	}
	s.EventJSON, s.InternalMetadata = []byte(ev), []byte(meta)
	return s, nil
}

// PruneStaged is prune_staged_events_in_room: below 100 staged events
// nothing; otherwise every staged event another staged event names as a
// prev event is dropped, keeping the queue's extremities. v1v2 says the room
// uses [event_id, hashes] pairs for prev events.
func (d *DB) PruneStaged(ctx context.Context, roomID string, v1v2 bool) (int, error) {
	var count int
	if err := d.pool.QueryRow(ctx, qStagedCount, roomID).Scan(&count); err != nil {
		return 0, fmt.Errorf("inbound: staged count: %w", err)
	}
	if count < 100 {
		return 0, nil
	}
	rows, err := d.pool.Query(ctx, qStagedEvents, roomID)
	if err != nil {
		return 0, fmt.Errorf("inbound: staged events: %w", err)
	}
	referenced, seen := map[string]bool{}, map[string]bool{}
	for rows.Next() {
		var id, js string
		if err := rows.Scan(&id, &js); err != nil {
			rows.Close()
			return 0, err
		}
		seen[id] = true
		for _, p := range stagedPrevs(js, v1v2) {
			referenced[p] = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	var drop []string
	for id := range referenced {
		if seen[id] {
			drop = append(drop, id)
		}
	}
	if len(drop) == 0 {
		return 0, nil
	}
	if _, err := d.pool.Exec(ctx, qPruneStaged, roomID, drop); err != nil {
		return 0, fmt.Errorf("inbound: prune staged: %w", err)
	}
	return len(drop), nil
}

// stagedPrevs is the prev event IDs prune_staged_events_in_room reads from a
// staged event's JSON, stopping at the first malformed entry as it does
// (after taking the ones before it).
func stagedPrevs(js string, v1v2 bool) []string {
	prevs := gjson.Get(js, "prev_events")
	if !prevs.Exists() {
		return nil
	}
	if !prevs.IsArray() {
		return nil
	}
	var out []string
	for _, p := range prevs.Array() {
		if v1v2 {
			if !p.IsArray() || len(p.Array()) != 2 || p.Array()[0].Type != gjson.String {
				break
			}
			out = append(out, p.Array()[0].Str)
		} else {
			if p.Type != gjson.String {
				break
			}
			out = append(out, p.Str)
		}
	}
	return out
}

// StagingAge counts every staged event, ours or Synapse's, and gives the
// oldest's received_ts (0 with none).
func (d *DB) StagingAge(ctx context.Context) (n int64, oldestMS int64, err error) {
	if err := d.pool.QueryRow(ctx, qStagingAge).Scan(&n, &oldestMS); err != nil {
		return 0, 0, fmt.Errorf("inbound: staging age: %w", err)
	}
	return n, oldestMS, nil
}

// StagingUnattended is StagingAge for the events no process is handling:
// their room's inbound lock is free or dead (not renewed for lockTimeout, as
// Synapse judges it).
func (d *DB) StagingUnattended(ctx context.Context) (n int64, oldestMS int64, err error) {
	alive := time.Now().Add(-lockTimeout).UnixMilli()
	if err := d.pool.QueryRow(ctx, qStagingUnattended, LockInboundPDU, alive).Scan(&n, &oldestMS); err != nil {
		return 0, 0, fmt.Errorf("inbound: unattended staging: %w", err)
	}
	return n, oldestMS, nil
}

// StagedRooms is get_all_rooms_with_staged_incoming_events.
func (d *DB) StagedRooms(ctx context.Context) ([]string, error) {
	rows, err := d.pool.Query(ctx, qStagedRooms)
	if err != nil {
		return nil, fmt.Errorf("inbound: staged rooms: %w", err)
	}
	return pgx.CollectRows(rows, pgx.RowTo[string])
}
