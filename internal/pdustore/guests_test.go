package pdustore

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// Run against a throwaway PostgreSQL holding Synapse's schema, as the write
// mode tests are (see internal/inbound):
//
//	INBOUND_TEST_ADMIN_DSN="host=127.0.0.1 port=55432 user=synapse password=test dbname=synapse" go test ./internal/pdustore/
func throwawayStore(t *testing.T) (*Store, *pgx.Conn) {
	t.Helper()
	dsn := os.Getenv("INBOUND_TEST_ADMIN_DSN")
	if dsn == "" {
		t.Skip("INBOUND_TEST_ADMIN_DSN not set")
	}
	if strings.Contains(dsn, "/var/sockets") {
		t.Fatal("INBOUND_TEST_ADMIN_DSN must be a throwaway database, not the live one")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close(context.Background()) })
	st, err := Open(ctx, dsn, 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(st.Close)
	return st, conn
}

func TestLocalGuestMembers(t *testing.T) {
	st, conn := throwawayStore(t)
	ctx := context.Background()
	const room, server = "!guests:test", "our.example"
	for _, q := range []string{
		`DELETE FROM current_state_events WHERE room_id = '` + room + `'`,
		`DELETE FROM event_json WHERE room_id = '` + room + `'`,
	} {
		if _, err := conn.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	member := func(i int, user string, content map[string]any) {
		id := fmt.Sprintf("$m%d", i)
		ev, _ := json.Marshal(map[string]any{"type": "m.room.member", "state_key": user, "room_id": room, "content": content})
		membership, _ := content["membership"].(string)
		if _, err := conn.Exec(ctx, `INSERT INTO event_json (event_id, room_id, internal_metadata, json, format_version) VALUES ($1, $2, '{}', $3, 3)`,
			id, room, string(ev)); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Exec(ctx, `INSERT INTO current_state_events (event_id, room_id, type, state_key, membership) VALUES ($1, $2, 'm.room.member', $3, $4)`,
			id, room, user, membership); err != nil {
			t.Fatal(err)
		}
	}

	count := func() int {
		t.Helper()
		n, ok, err := st.LocalGuestMembers(ctx, room, server)
		if err != nil || !ok {
			t.Fatalf("n %d, ok %v, err %v", n, ok, err)
		}
		return n
	}

	// Not kicked: a local user who is not a guest, a remote guest, a local
	// guest who left, a "guest" kind that is not a string, and a user of a
	// server whose name ends like ours.
	member(1, "@alice:our.example", map[string]any{"membership": "join"})
	member(2, "@g:remote.example", map[string]any{"membership": "join", "kind": "guest"})
	member(3, "@left:our.example", map[string]any{"membership": "leave", "kind": "guest"})
	member(4, "@odd:our.example", map[string]any{"membership": "join", "kind": []string{"guest"}})
	member(5, "@x:notour.example", map[string]any{"membership": "join", "kind": "guest"})
	if n := count(); n != 0 {
		t.Fatalf("%d guests to kick, want 0", n)
	}

	// Kicked: local guests joined or invited.
	member(6, "@g1:our.example", map[string]any{"membership": "join", "kind": "guest"})
	member(7, "@g2:our.example", map[string]any{"membership": "invite", "kind": "guest"})
	if n := count(); n != 2 {
		t.Fatalf("%d guests to kick, want 2", n)
	}

	if _, ok, _ := st.LocalGuestMembers(ctx, room, "our_server"); ok {
		t.Error("a server name LIKE cannot match exactly was accepted")
	}
}
