package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// ServerKeyJSON is one row of Synapse's server_keys_json: a server's published
// key response as Synapse fetched it, signatures included.
type ServerKeyJSON struct {
	KeyID        string
	FromServer   string
	ValidUntilMS int64
	JSON         []byte
}

const qServerKeys = `
	SELECT key_id, from_server, ts_valid_until_ms, key_json
	FROM server_keys_json
	WHERE server_name = $1 AND ts_valid_until_ms > $2
	ORDER BY ts_valid_until_ms DESC`

// GetServerKeys returns the key responses Synapse has cached for a server that
// are still valid at validAtMS, newest expiry first.
func (s *Store) GetServerKeys(ctx context.Context, serverName string, validAtMS int64) ([]ServerKeyJSON, error) {
	ctx, cancel := s.withTimeout(ctx)
	defer cancel()

	start := time.Now()
	rows, err := s.pool.Query(ctx, qServerKeys, serverName, validAtMS)
	if err != nil {
		observe("server_keys", start, err)
		return nil, fmt.Errorf("store: get server keys: %w", err)
	}
	defer rows.Close()

	var out []ServerKeyJSON
	for rows.Next() {
		var k ServerKeyJSON
		if err := rows.Scan(&k.KeyID, &k.FromServer, &k.ValidUntilMS, &k.JSON); err != nil {
			observe("server_keys", start, err)
			return nil, fmt.Errorf("store: scan server key: %w", err)
		}
		out = append(out, k)
	}
	err = rows.Err()
	observe("server_keys", start, err)
	if err != nil {
		return nil, fmt.Errorf("store: server key rows: %w", err)
	}
	return out, nil
}

// ServerACLEvent is a room's current m.room.server_acl event.
type ServerACLEvent struct {
	EventID string
	JSON    []byte
	// Redacted reports that a redaction of this event exists. Synapse would
	// then evaluate the REDACTED event, whose content is empty -- which
	// bans every server. Whether the redaction applies depends on room
	// version rules this worker does not implement, so callers treat it as
	// "ask Synapse" rather than guess.
	Redacted bool
}

const qCurrentServerACL = `
	SELECT c.event_id, j.json,
	       EXISTS (SELECT 1 FROM redactions r WHERE r.redacts = c.event_id)
	FROM current_state_events c
	JOIN event_json j USING (event_id)
	WHERE c.room_id = $1 AND c.type = 'm.room.server_acl' AND c.state_key = ''`

// CurrentServerACL returns the room's current server ACL event, or nil when the
// room has none -- or is not a room we know, which Synapse treats the same way
// (get_current_state_event returns None, so no ACL applies).
func (s *Store) CurrentServerACL(ctx context.Context, roomID string) (*ServerACLEvent, error) {
	var ev ServerACLEvent
	err := s.queryRow(ctx, "current_server_acl", qCurrentServerACL, roomID).
		Scan(&ev.EventID, &ev.JSON, &ev.Redacted)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("store: current server acl: %w", err)
	}
	return &ev, nil
}

// StoredResponse is Synapse's persisted answer to a transaction it already
// processed, from received_transactions.
type StoredResponse struct {
	Code int
	JSON []byte
}

// TxnState is what decides whether we may answer a transaction ourselves.
type TxnState struct {
	// RetryLastTS is destinations.retry_last_ts for the origin, zero when
	// there is no row or no backoff.
	//
	// Non-zero means Synapse, had it received this request, would reset the
	// origin's backoff and broadcast REMOTE_SERVER_UP
	// (transport/server/_base.py:143). That needs a write to destinations and
	// a cache invalidation streamed to every worker, which only Synapse can do
	// correctly -- so such a transaction is proxied, and Synapse does it.
	RetryLastTS int64
	// Previous is Synapse's stored response when it has already answered
	// this (origin, transaction id), as checked by have_responded
	// (federation_server.py:400). Nil when it has not.
	Previous *StoredResponse
}

// One round trip for both, since this runs once per native transaction.
const qTxnState = `
	SELECT
		(SELECT retry_last_ts FROM destinations WHERE destination = $1),
		r.response_code, r.response_json
	FROM (SELECT 1) AS one
	LEFT JOIN received_transactions r
		ON r.transaction_id = $2 AND r.origin = $1`

// GetTxnState reads the origin's retry state and any stored response for the
// transaction.
func (s *Store) GetTxnState(ctx context.Context, origin, txnID string) (TxnState, error) {
	var (
		retry *int64
		code  *int32
		body  []byte
	)
	err := s.queryRow(ctx, "txn_state", qTxnState, origin, txnID).Scan(&retry, &code, &body)
	if err != nil {
		return TxnState{}, fmt.Errorf("store: txn state: %w", err)
	}
	var st TxnState
	if retry != nil {
		st.RetryLastTS = *retry
	}
	if code != nil {
		st.Previous = &StoredResponse{Code: int(*code), JSON: body}
	}
	return st, nil
}
