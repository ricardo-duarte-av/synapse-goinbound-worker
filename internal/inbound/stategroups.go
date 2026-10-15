package inbound

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
)

// State groups, as the inbound worker stores them
// (storage/databases/state/store.py store_state_group, and
// state/deletion.py's bump).

// maxStateDeltaHops is MAX_STATE_DELTA_HOPS (state/bg_updates.py): a delta
// chain this long is ended with a full group.
const maxStateDeltaHops = 100

const (
	// qLockGroups is _get_existing_groups_with_lock.
	qLockGroups = `SELECT id FROM state_groups WHERE id = ANY($1) FOR KEY SHARE`
	// qBumpDeletion is _bump_deletion_txn.
	qBumpDeletion = `
		UPDATE state_groups_pending_deletion
		SET sequence_number = DEFAULT, insertion_ts = $1
		WHERE state_group = ANY($2)`
	// qStateHops is _count_state_group_hops_txn.
	qStateHops = `
		WITH RECURSIVE state(state_group) AS (
			VALUES($1::bigint)
			UNION ALL
			SELECT prev_state_group FROM state_group_edges e, state s
			WHERE s.state_group = e.state_group
		)
		SELECT count(*) FROM state`
	qNextStateGroup   = `SELECT nextval('state_group_id_seq')`
	qInsertStateGroup = `INSERT INTO state_groups (id, room_id, event_id) VALUES ($1, $2, $3)`
	qInsertEdge       = `INSERT INTO state_group_edges (state_group, prev_state_group) VALUES ($1, $2)`
	qInsertState      = `
		INSERT INTO state_groups_state (state_group, room_id, type, state_key, event_id)
		SELECT $1, $2, k.type, k.state_key, k.event_id
		FROM unnest($3::text[], $4::text[], $5::text[]) AS k(type, state_key, event_id)`
)

// ErrMissingGroup is a state group that has been deleted.
var ErrMissingGroup = errors.New("inbound: state group deleted")

// BumpDeletion is check_state_groups_and_bump_deletion: locks the groups
// that exist, delays any pending deletion of them, and reports those that
// are gone.
func (d *DB) BumpDeletion(ctx context.Context, groups []int64) (missing []int64, err error) {
	err = pgx.BeginFunc(ctx, d.pool, func(tx pgx.Tx) error {
		var e error
		missing, e = d.bumpTx(ctx, tx, groups)
		return e
	})
	return missing, err
}

func (d *DB) bumpTx(ctx context.Context, tx pgx.Tx, groups []int64) ([]int64, error) {
	if len(groups) == 0 {
		return nil, nil
	}
	rows, err := tx.Query(ctx, qLockGroups, groups)
	if err != nil {
		return nil, fmt.Errorf("inbound: lock groups: %w", err)
	}
	have, err := pgx.CollectRows(rows, pgx.RowTo[int64])
	if err != nil {
		return nil, fmt.Errorf("inbound: lock groups: %w", err)
	}
	if len(have) > 0 {
		if _, err := tx.Exec(ctx, qBumpDeletion, d.nowMS(), have); err != nil {
			return nil, fmt.Errorf("inbound: bump deletion: %w", err)
		}
	}
	held := map[int64]bool{}
	for _, g := range have {
		held[g] = true
	}
	var missing []int64
	for _, g := range groups {
		if !held[g] {
			missing = append(missing, g)
		}
	}
	return missing, nil
}

// StoreStateGroup is store_state_group: a delta on prev when prev is set and
// its chain is short enough, otherwise in full. full is the whole state when
// there is no prev; with a prev it may be nil, and is then loaded with
// load(prev) plus the delta when a full group is needed.
func (d *DB) StoreStateGroup(ctx context.Context, eventID, roomID string, prev int64, delta, full pdu.StateMap, load func(int64) (pdu.StateMap, error)) (int64, error) {
	if prev == 0 && full == nil {
		return 0, errors.New("inbound: a state group needs a prev group or the full state")
	}
	if prev != 0 {
		var group int64
		err := pgx.BeginFunc(ctx, d.pool, func(tx pgx.Tx) error {
			missing, err := d.bumpTx(ctx, tx, []int64{prev})
			if err != nil {
				return err
			}
			if len(missing) > 0 {
				return fmt.Errorf("%w: trying to persist state with unpersisted prev_group %d", ErrMissingGroup, prev)
			}
			var hops int
			if err := tx.QueryRow(ctx, qStateHops, prev).Scan(&hops); err != nil {
				return fmt.Errorf("inbound: state hops: %w", err)
			}
			if hops >= maxStateDeltaHops {
				return nil
			}
			if group, err = d.insertGroupTx(ctx, tx, roomID, eventID, delta); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, qInsertEdge, group, prev); err != nil {
				return fmt.Errorf("inbound: state group edge: %w", err)
			}
			return nil
		})
		if err != nil || group != 0 {
			return group, err
		}
		if full == nil {
			base, err := load(prev)
			if err != nil {
				return 0, err
			}
			full = make(pdu.StateMap, len(base)+len(delta))
			for k, v := range base {
				full[k] = v
			}
			for k, v := range delta {
				full[k] = v
			}
		}
	}
	var group int64
	err := pgx.BeginFunc(ctx, d.pool, func(tx pgx.Tx) error {
		var err error
		group, err = d.insertGroupTx(ctx, tx, roomID, eventID, full)
		return err
	})
	return group, err
}

// insertGroupTx allocates a group and stores its rows.
func (d *DB) insertGroupTx(ctx context.Context, tx pgx.Tx, roomID, eventID string, rows pdu.StateMap) (int64, error) {
	var group int64
	if err := tx.QueryRow(ctx, qNextStateGroup).Scan(&group); err != nil {
		return 0, fmt.Errorf("inbound: state group id: %w", err)
	}
	if _, err := tx.Exec(ctx, qInsertStateGroup, group, roomID, eventID); err != nil {
		return 0, fmt.Errorf("inbound: state group: %w", err)
	}
	types := make([]string, 0, len(rows))
	keys := make([]string, 0, len(rows))
	ids := make([]string, 0, len(rows))
	for k, v := range rows {
		types, keys, ids = append(types, k.Type), append(keys, k.StateKey), append(ids, v)
	}
	if len(ids) > 0 {
		if _, err := tx.Exec(ctx, qInsertState, group, roomID, types, keys, ids); err != nil {
			return 0, fmt.Errorf("inbound: state group rows: %w", err)
		}
	}
	return group, nil
}
