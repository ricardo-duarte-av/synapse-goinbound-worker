package pdustore

import (
	"context"
	"testing"
)

// RedactedOnLoad is _maybe_redact_event_row: confirmed redactions apply;
// unconfirmed ones only when the redacting event is held, not rejected, in
// the room and, if it still needs rechecking, from the sender's server; MSC4293
// ban redactions are unconfirmed ones, up to their end ordering; the create
// event is never redacted.
func TestRedactedOnLoad(t *testing.T) {
	st, c := throwawayStore(t)
	ctx := context.Background()
	const room = "!redact:test"
	for _, q := range []string{
		`DELETE FROM events WHERE room_id = '` + room + `' OR event_id LIKE '$rl_%'`,
		`DELETE FROM event_json WHERE event_id LIKE '$rl_%'`,
		`DELETE FROM redactions WHERE event_id LIKE '$rl_%' OR redacts LIKE '$rl_%'`,
		`DELETE FROM rejections WHERE event_id LIKE '$rl_%'`,
		`DELETE FROM room_ban_redactions WHERE room_id = '` + room + `'`,
	} {
		if _, err := c.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	n := int64(970_000_000)
	event := func(id, typ, sender, roomID, meta string) {
		t.Helper()
		n++
		if _, err := c.Exec(ctx, `INSERT INTO events (event_id, type, room_id, sender, topological_ordering, stream_ordering, processed, outlier, depth)
			VALUES ($1, $2, $3, $4, $5, $5, true, false, $5)`, id, typ, roomID, sender, n); err != nil {
			t.Fatal(err)
		}
		if _, err := c.Exec(ctx, `INSERT INTO event_json (event_id, room_id, internal_metadata, json, format_version) VALUES ($1, $2, $3, '{}', 3)`,
			id, roomID, meta); err != nil {
			t.Fatal(err)
		}
	}
	redaction := func(by, redacts string, recheck bool) {
		t.Helper()
		if _, err := c.Exec(ctx, `INSERT INTO redactions (event_id, redacts, recheck) VALUES ($1, $2, $3)`, by, redacts, recheck); err != nil {
			t.Fatal(err)
		}
	}

	event("$rl_create", "m.room.create", "@a:one.example", room, `{}`)
	event("$rl_confirmed", "m.room.message", "@a:one.example", room, `{}`)
	event("$rl_same", "m.room.message", "@a:one.example", room, `{}`)
	event("$rl_other", "m.room.message", "@a:one.example", room, `{}`)
	event("$rl_rejected", "m.room.message", "@a:one.example", room, `{}`)
	event("$rl_missing", "m.room.message", "@a:one.example", room, `{}`)
	event("$rl_elsewhere", "m.room.message", "@a:one.example", room, `{}`)
	event("$rl_plain", "m.room.message", "@a:one.example", room, `{}`)
	// Redactions needing the recheck, from the same and another server.
	event("$rl_r_same", "m.room.redaction", "@b:one.example", room, `{"recheck_redaction":true}`)
	event("$rl_r_other", "m.room.redaction", "@b:two.example", room, `{"recheck_redaction":true}`)
	event("$rl_r_rejected", "m.room.redaction", "@b:one.example", room, `{}`)
	event("$rl_r_elsewhere", "m.room.redaction", "@b:one.example", "!other:test", `{}`)
	if _, err := c.Exec(ctx, `INSERT INTO rejections (event_id, reason, last_check) VALUES ('$rl_r_rejected', 'auth', '0')`); err != nil {
		t.Fatal(err)
	}
	redaction("$rl_r_any1", "$rl_create", false)
	redaction("$rl_r_any2", "$rl_confirmed", false)
	redaction("$rl_r_same", "$rl_same", true)
	redaction("$rl_r_other", "$rl_other", true)
	redaction("$rl_r_rejected", "$rl_rejected", true)
	redaction("$rl_r_gone", "$rl_missing", true)
	redaction("$rl_r_elsewhere", "$rl_elsewhere", true)

	// MSC4293: a kick of @k with its events redacted, up to an end.
	event("$rl_k1", "m.room.message", "@k:three.example", room, `{}`)
	event("$rl_kick", "m.room.member", "@mod:four.example", room, `{}`)
	event("$rl_k2", "m.room.message", "@k:three.example", room, `{}`)
	var end int64
	if err := c.QueryRow(ctx, `SELECT stream_ordering FROM events WHERE event_id = '$rl_k2'`).Scan(&end); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(ctx, `INSERT INTO room_ban_redactions (room_id, user_id, redacting_event_id, redact_end_ordering) VALUES ($1, '@k:three.example', '$rl_kick', $2)`, room, end); err != nil {
		t.Fatal(err)
	}

	ids := []string{"$rl_create", "$rl_confirmed", "$rl_same", "$rl_other", "$rl_rejected", "$rl_missing", "$rl_elsewhere", "$rl_plain", "$rl_k1", "$rl_k2"}
	got, err := st.RedactedOnLoad(ctx, ids)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"$rl_create": false, "$rl_confirmed": true, "$rl_same": true, "$rl_other": false,
		"$rl_rejected": false, "$rl_missing": false, "$rl_elsewhere": false, "$rl_plain": false,
		"$rl_k1": true, "$rl_k2": false,
	}
	for _, id := range ids {
		if got[id] != want[id] {
			t.Errorf("%s: redacted %v, want %v", id, got[id], want[id])
		}
	}
}
