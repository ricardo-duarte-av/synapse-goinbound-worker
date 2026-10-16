package pdustore

import (
	"context"
	"fmt"
	"strings"

	"github.com/tidwall/gjson"
)

// Which events Synapse returns in redacted form when it loads them
// (EventsWorkerStore._fetch_event_rows and _maybe_redact_event_row,
// events_worker.py): an event Synapse loads is pruned when a redaction of it
// is honoured, whether its stored JSON has been pruned yet or not (that
// happens only after redaction_retention_period).

const qRedactLoadInfo = `
	SELECT event_id, room_id, sender, type, COALESCE(stream_ordering, 0)
	FROM events WHERE event_id = ANY($1)`

const qRedactionsOf = `SELECT redacts, event_id, recheck FROM redactions WHERE redacts = ANY($1)`

// qBanRedactions is MSC4293: a kick or ban asking for the user's events in
// the room to be redacted, up to redact_end_ordering when set.
const qBanRedactions = `
	SELECT b.room_id, b.user_id, b.redacting_event_id, b.redact_end_ordering
	FROM room_ban_redactions b
	JOIN unnest($1::text[], $2::text[]) AS k(room_id, user_id)
	  ON b.room_id = k.room_id AND b.user_id = k.user_id`

const qRedactingEvents = `
	SELECT e.event_id, e.room_id, e.sender,
	       EXISTS (SELECT 1 FROM rejections r WHERE r.event_id = e.event_id),
	       COALESCE(j.internal_metadata, '{}')
	FROM events e LEFT JOIN event_json j ON j.event_id = e.event_id
	WHERE e.event_id = ANY($1)`

type redactTarget struct {
	room, sender, typ string
	stream            int64
	confirmed         bool
	unconfirmed       []string
}

// RedactedOnLoad says which of ids Synapse would load in redacted form.
func (s *Store) RedactedOnLoad(ctx context.Context, ids []string) (map[string]bool, error) {
	out := map[string]bool{}
	if len(ids) == 0 {
		return out, nil
	}
	targets := map[string]*redactTarget{}
	rows, err := s.pool.Query(ctx, qRedactLoadInfo, ids)
	if err != nil {
		return nil, fmt.Errorf("pdustore: redaction targets: %w", err)
	}
	for rows.Next() {
		var id string
		t := &redactTarget{}
		if err := rows.Scan(&id, &t.room, &t.sender, &t.typ, &t.stream); err != nil {
			rows.Close()
			return nil, err
		}
		targets[id] = t
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// The redactions table: recheck false is confirmed.
	rows, err = s.pool.Query(ctx, qRedactionsOf, ids)
	if err != nil {
		return nil, fmt.Errorf("pdustore: redactions: %w", err)
	}
	for rows.Next() {
		var redacts, by string
		var recheck bool
		if err := rows.Scan(&redacts, &by, &recheck); err != nil {
			rows.Close()
			return nil, err
		}
		if t := targets[redacts]; t != nil {
			if recheck {
				t.unconfirmed = append(t.unconfirmed, by)
			} else {
				t.confirmed = true
			}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// MSC4293 redactions, always unconfirmed.
	var bRooms, bUsers []string
	for _, t := range targets {
		bRooms, bUsers = append(bRooms, t.room), append(bUsers, t.sender)
	}
	rows, err = s.pool.Query(ctx, qBanRedactions, bRooms, bUsers)
	if err != nil {
		return nil, fmt.Errorf("pdustore: ban redactions: %w", err)
	}
	for rows.Next() {
		var room, user, by string
		var end *int64
		if err := rows.Scan(&room, &user, &by, &end); err != nil {
			rows.Close()
			return nil, err
		}
		for _, t := range targets {
			if t.room != room || t.sender != user {
				continue
			}
			// "if redact_end_ordering:" -- unset or 0 ends nothing.
			if end != nil && *end != 0 && t.stream >= *end {
				continue
			}
			t.unconfirmed = append(t.unconfirmed, by)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// The redacting events, fetched only for events with no confirmed
	// redaction.
	var need []string
	for _, t := range targets {
		if !t.confirmed {
			need = append(need, t.unconfirmed...)
		}
	}
	type redacting struct {
		room, sender string
		rejected     bool
		recheck      bool
	}
	by := map[string]redacting{}
	if len(need) > 0 {
		rows, err = s.pool.Query(ctx, qRedactingEvents, need)
		if err != nil {
			return nil, fmt.Errorf("pdustore: redacting events: %w", err)
		}
		for rows.Next() {
			var id, meta string
			var r redacting
			if err := rows.Scan(&id, &r.room, &r.sender, &r.rejected, &meta); err != nil {
				rows.Close()
				return nil, err
			}
			r.recheck = gjson.Get(meta, "recheck_redaction").Bool()
			by[id] = r
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}

	for id, t := range targets {
		out[id] = honoured(t, func(rid string) (string, string, bool, bool, bool) {
			r, ok := by[rid]
			return r.room, r.sender, r.rejected, r.recheck, ok
		})
	}
	return out, nil
}

// honoured is _maybe_redact_event_row's verdict.
func honoured(t *redactTarget, lookup func(id string) (room, sender string, rejected, recheck, found bool)) bool {
	if t.typ == "m.room.create" {
		return false
	}
	if t.confirmed {
		return true
	}
	for _, rid := range t.unconfirmed {
		room, sender, rejected, recheck, found := lookup(rid)
		if !found || rejected {
			continue
		}
		if room != t.room {
			continue
		}
		// need_to_check_redaction: the redacter's server must be the
		// original sender's.
		if recheck && domainOf(sender) != domainOf(t.sender) {
			continue
		}
		return true
	}
	return false
}

// domainOf is get_domain_from_id: what follows the first colon.
func domainOf(id string) string {
	_, d, ok := strings.Cut(id, ":")
	if !ok {
		return ""
	}
	return d
}
