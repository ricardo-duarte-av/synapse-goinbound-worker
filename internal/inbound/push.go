package inbound

import (
	"context"
	"encoding/json"
	"fmt"
)

// PushRow is a row for event_push_actions_staging; Actions is the column as
// _serialize_action writes it.
type PushRow struct {
	UserID    string
	Actions   string
	Notif     bool
	Highlight bool
	Unread    bool
	ThreadID  string
}

const (
	// qStagePush is add_push_actions_to_staging's simple_insert_many.
	qStagePush = `
		INSERT INTO event_push_actions_staging (event_id, user_id, actions, notif, highlight, unread, thread_id, inserted_ts)
		SELECT $1, k.user_id, k.actions, k.notif, k.highlight, k.unread, k.thread_id, $2
		FROM unnest($3::text[], $4::text[], $5::smallint[], $6::smallint[], $7::smallint[], $8::text[])
			AS k(user_id, actions, notif, highlight, unread, thread_id)`
	qUnstagePush = `DELETE FROM event_push_actions_staging WHERE event_id = $1`
)

// StagePush is add_push_actions_to_staging. Nothing is written for no rows.
func (d *DB) StagePush(ctx context.Context, eventID string, rows []PushRow) error {
	if len(rows) == 0 {
		return nil
	}
	n := len(rows)
	users, actions, threads := make([]string, n), make([]string, n), make([]string, n)
	notif, highlight, unread := make([]int16, n), make([]int16, n), make([]int16, n)
	for i, r := range rows {
		users[i], actions[i], threads[i] = r.UserID, r.Actions, r.ThreadID
		notif[i], highlight[i], unread[i] = b2i(r.Notif), b2i(r.Highlight), b2i(r.Unread)
	}
	if _, err := d.pool.Exec(ctx, qStagePush, eventID, d.nowMS(), users, actions, notif, highlight, unread, threads); err != nil {
		return fmt.Errorf("inbound: stage push actions: %w", err)
	}
	return nil
}

// UnstagePush is remove_push_actions_from_staging, after persisting failed.
func (d *DB) UnstagePush(ctx context.Context, eventID string) error {
	if _, err := d.pool.Exec(ctx, qUnstagePush, eventID); err != nil {
		return fmt.Errorf("inbound: unstage push actions: %w", err)
	}
	return nil
}

func b2i(b bool) int16 {
	if b {
		return 1
	}
	return 0
}

// qSetTxnResponse is set_received_txn_response: the first answer stays.
const qSetTxnResponse = `
	INSERT INTO received_transactions (transaction_id, origin, response_code, response_json, ts)
	VALUES ($1, $2, $3, $4, $5)
	ON CONFLICT (transaction_id, origin) DO NOTHING`

// SetTxnResponse stores the answer given to a transaction, as
// encode_canonical_json of it, so a retry is answered the same.
func (d *DB) SetTxnResponse(ctx context.Context, origin, txnID string, code int, canonicalJSON []byte) error {
	if !json.Valid(canonicalJSON) {
		return fmt.Errorf("inbound: transaction response is not JSON")
	}
	if _, err := d.pool.Exec(ctx, qSetTxnResponse, txnID, origin, code, canonicalJSON, d.nowMS()); err != nil {
		return fmt.Errorf("inbound: transaction response: %w", err)
	}
	return nil
}

// qMarkDevicesStale is mark_remote_users_device_caches_as_stale's upsert,
// insertion values only.
const qMarkDevicesStale = `
	INSERT INTO device_lists_remote_resync (user_id, added_ts) VALUES ($1, $2)
	ON CONFLICT (user_id) DO NOTHING`

// MarkDevicesStale records that a remote user's cached devices may be out
// of date.
func (d *DB) MarkDevicesStale(ctx context.Context, userID string) error {
	if _, err := d.pool.Exec(ctx, qMarkDevicesStale, userID, d.nowMS()); err != nil {
		return fmt.Errorf("inbound: mark devices stale: %w", err)
	}
	return nil
}
