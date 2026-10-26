package pdustore

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// What the push check (pduverify.Push) reads: who is in the room, their push
// rules, and the push actions Synapse stored. Most of it is current state, so
// the check guards each read against membership changes since the event.

// PushRuleRow is a push_rules row.
type PushRuleRow struct {
	RuleID        string
	PriorityClass int
	Priority      int
	Conditions    string
	Actions       string
}

// PushActionRow is an event_push_actions row.
type PushActionRow struct {
	UserID    string
	Actions   string
	Notif     bool
	Highlight bool
	Unread    bool
	ThreadID  string
}

const qLocalJoined = `
	SELECT user_id FROM local_current_membership WHERE room_id = $1 AND membership = 'join'`

// LocalJoined is get_local_users_in_room.
func (s *Store) LocalJoined(ctx context.Context, roomID string) ([]string, error) {
	return s.strings(ctx, "local members", qLocalJoined, roomID)
}

const qJoinedCount = `
	SELECT count(*) FROM current_state_events WHERE room_id = $1 AND membership = 'join'`

// JoinedCount is get_number_joined_users_in_room.
func (s *Store) JoinedCount(ctx context.Context, roomID string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, qJoinedCount, roomID).Scan(&n)
	return n, err
}

const qProfiles = `
	SELECT c.state_key, m.display_name FROM room_memberships m
	JOIN current_state_events c
	  ON m.event_id = c.event_id AND m.room_id = c.room_id AND m.user_id = c.state_key
	WHERE c.type = 'm.room.member' AND c.room_id = $1 AND m.membership = 'join'
	  AND c.state_key = ANY($2)`

// Profiles is get_subset_users_in_room_with_profiles: each joined user's
// display name in the room, nil when the member event sets none.
func (s *Store) Profiles(ctx context.Context, roomID string, users []string) (map[string]*string, error) {
	rows, err := s.pool.Query(ctx, qProfiles, roomID, users)
	if err != nil {
		return nil, fmt.Errorf("pdustore: profiles: %w", err)
	}
	out := map[string]*string{}
	for rows.Next() {
		var u string
		var dn *string
		if err := rows.Scan(&u, &dn); err != nil {
			rows.Close()
			return nil, err
		}
		out[u] = dn
	}
	return out, rows.Err()
}

const qMemberDisplayName = `SELECT display_name FROM room_memberships WHERE event_id = $1`

// MemberDisplayName is the display name room_memberships holds for a member
// event; nil when it sets none or is not stored.
func (s *Store) MemberDisplayName(ctx context.Context, eventID string) (*string, error) {
	var dn *string
	err := s.pool.QueryRow(ctx, qMemberDisplayName, eventID).Scan(&dn)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return dn, err
}

const qPushRules = `
	SELECT user_name, rule_id, priority_class, priority, conditions, actions
	FROM push_rules WHERE user_name = ANY($1)`

// PushRules is bulk_get_push_rules' rows, per user, in the database's order:
// the caller sorts, as Synapse does, stably.
func (s *Store) PushRules(ctx context.Context, users []string) (map[string][]PushRuleRow, error) {
	rows, err := s.pool.Query(ctx, qPushRules, users)
	if err != nil {
		return nil, fmt.Errorf("pdustore: push rules: %w", err)
	}
	out := map[string][]PushRuleRow{}
	for rows.Next() {
		var u string
		var r PushRuleRow
		if err := rows.Scan(&u, &r.RuleID, &r.PriorityClass, &r.Priority, &r.Conditions, &r.Actions); err != nil {
			rows.Close()
			return nil, err
		}
		out[u] = append(out[u], r)
	}
	return out, rows.Err()
}

const qPushRulesEnabled = `
	SELECT user_name, rule_id, enabled FROM push_rules_enable WHERE user_name = ANY($1)`

// PushRulesEnabled is bulk_get_push_rules_enabled: bool(enabled), so a NULL
// is disabled.
func (s *Store) PushRulesEnabled(ctx context.Context, users []string) (map[string]map[string]bool, error) {
	rows, err := s.pool.Query(ctx, qPushRulesEnabled, users)
	if err != nil {
		return nil, fmt.Errorf("pdustore: push rules enabled: %w", err)
	}
	out := map[string]map[string]bool{}
	for rows.Next() {
		var u, id string
		var en *int16
		if err := rows.Scan(&u, &id, &en); err != nil {
			rows.Close()
			return nil, err
		}
		if out[u] == nil {
			out[u] = map[string]bool{}
		}
		out[u][id] = en != nil && *en != 0
	}
	return out, rows.Err()
}

const qIgnoredBy = `SELECT ignorer_user_id FROM ignored_users WHERE ignored_user_id = $1`

// IgnoredBy is ignored_by: the users who ignore userID.
func (s *Store) IgnoredBy(ctx context.Context, userID string) (map[string]bool, error) {
	ids, err := s.strings(ctx, "ignored by", qIgnoredBy, userID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out, nil
}

// qThreadID is get_thread_id's query (relations.py:1034).
const qThreadID = `
	WITH RECURSIVE related_events AS (
		SELECT event_id, relates_to_id, relation_type, 0 AS depth
		FROM event_relations
		WHERE event_id = $1
		UNION SELECT e.event_id, e.relates_to_id, e.relation_type, depth + 1
		FROM event_relations e
		INNER JOIN related_events r ON r.relates_to_id = e.event_id
		WHERE depth <= 3
	)
	SELECT relates_to_id FROM related_events
	WHERE relation_type = 'm.thread'
	ORDER BY depth DESC
	LIMIT 1`

// ThreadID is get_thread_id: the root of the thread eventID is in, or "main".
func (s *Store) ThreadID(ctx context.Context, eventID string) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx, qThreadID, eventID).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "main", nil
	}
	return id, err
}

const qThreadSubscribers = `
	SELECT user_id FROM thread_subscriptions WHERE room_id = $1 AND event_id = $2 AND subscribed`

// ThreadSubscribers is get_subscribers_to_thread.
func (s *Store) ThreadSubscribers(ctx context.Context, roomID, root string) (map[string]bool, error) {
	ids, err := s.strings(ctx, "thread subscribers", qThreadSubscribers, roomID, root)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(ids))
	for _, id := range ids {
		out[id] = true
	}
	return out, nil
}

const qMinDepth = `SELECT min_depth FROM room_depth WHERE room_id = $1`

// MinDepth is get_min_depth; nil when the room has none.
func (s *Store) MinDepth(ctx context.Context, roomID string) (*int64, error) {
	var d *int64
	err := s.pool.QueryRow(ctx, qMinDepth, roomID).Scan(&d)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return d, err
}

const qMemberEventsAfter = `
	SELECT count(*) FROM events
	WHERE room_id = $1 AND type = 'm.room.member' AND stream_ordering > $2 AND event_id <> $3`

// MemberEventsAfter counts the room's member events persisted after a stream
// ordering, other than the given event: each may have changed who the push
// check's current-state reads return.
func (s *Store) MemberEventsAfter(ctx context.Context, roomID string, after int64, except string) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, qMemberEventsAfter, roomID, after, except).Scan(&n)
	return n, err
}

const qPushActions = `
	SELECT user_id, actions, COALESCE(notif, 0), COALESCE(highlight, 0), COALESCE(unread, 0),
	       COALESCE(thread_id, '')
	FROM event_push_actions WHERE event_id = $1`

// PushActions is what Synapse stored for an event in event_push_actions.
func (s *Store) PushActions(ctx context.Context, eventID string) ([]PushActionRow, error) {
	rows, err := s.pool.Query(ctx, qPushActions, eventID)
	if err != nil {
		return nil, fmt.Errorf("pdustore: push actions: %w", err)
	}
	var out []PushActionRow
	for rows.Next() {
		var r PushActionRow
		var n, h, u int16
		if err := rows.Scan(&r.UserID, &r.Actions, &n, &h, &u, &r.ThreadID); err != nil {
			rows.Close()
			return nil, err
		}
		r.Notif, r.Highlight, r.Unread = n != 0, h != 0, u != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) strings(ctx context.Context, what, q string, args ...any) ([]string, error) {
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("pdustore: %s: %w", what, err)
	}
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// Receipt is a receipts_linearized position.
type Receipt struct {
	ThreadID       *string
	StreamOrdering int64
}

const qReceipts = `
	SELECT user_id, thread_id, event_stream_ordering FROM receipts_linearized
	WHERE room_id = $1 AND user_id = ANY($2) AND event_stream_ordering IS NOT NULL`

// Receipts is each user's latest receipts in the room, of every type: each
// deletes the user's non-highlight push actions up to it
// (_handle_new_receipts_for_notifs_txn).
func (s *Store) Receipts(ctx context.Context, roomID string, users []string) (map[string][]Receipt, error) {
	rows, err := s.pool.Query(ctx, qReceipts, roomID, users)
	if err != nil {
		return nil, fmt.Errorf("pdustore: receipts: %w", err)
	}
	out := map[string][]Receipt{}
	for rows.Next() {
		var u string
		var r Receipt
		if err := rows.Scan(&u, &r.ThreadID, &r.StreamOrdering); err != nil {
			rows.Close()
			return nil, err
		}
		out[u] = append(out[u], r)
	}
	return out, rows.Err()
}

const qRetryTimings = `SELECT failure_ts, retry_last_ts, retry_interval FROM destinations WHERE destination = $1`

// RetryTimings is get_destination_retry_timings: none (all zero) without a
// row or with retry_last_ts null or zero.
func (s *Store) RetryTimings(ctx context.Context, dest string) (failureTS *int64, lastTS, interval int64, err error) {
	var last, iv *int64
	err = s.pool.QueryRow(ctx, qRetryTimings, dest).Scan(&failureTS, &last, &iv)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, 0, 0, nil
	}
	if err != nil || last == nil || *last == 0 {
		return nil, 0, 0, err
	}
	if iv != nil {
		interval = *iv
	}
	return failureTS, *last, interval, nil
}
