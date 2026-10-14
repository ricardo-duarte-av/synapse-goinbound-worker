package dbrole

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/store"
)

// TestLiveEnsure creates a throwaway role on a real PostgreSQL, logs in as it
// over TCP with the derived password -- which proves PostgreSQL accepts our
// SCRAM verifier -- checks its grants, runs Ensure again to show it is
// idempotent, and drops the role.
//
//	DBROLE_ADMIN_DSN="host=/var/sockets user=synapse dbname=synapse-db" \
//	DBROLE_TCP_DSN="host=172.20.0.38 port=5432 dbname=synapse-db sslmode=disable" \
//	go test -run LiveEnsure ./internal/dbrole/
//
// DBROLE_TCP_DSN must reach PostgreSQL through a pg_hba rule that requires a
// password; over a trusted unix socket the password would not be checked.
func TestLiveEnsure(t *testing.T) {
	admin, tcp := os.Getenv("DBROLE_ADMIN_DSN"), os.Getenv("DBROLE_TCP_DSN")
	if admin == "" || tcp == "" {
		t.Skip("DBROLE_ADMIN_DSN and DBROLE_TCP_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	suffix := make([]byte, 4)
	_, _ = rand.Read(suffix)
	role := "goinbound_selftest_" + hex.EncodeToString(suffix)
	password := Password("test-admin-password", role)
	spec := Spec{Role: role, Password: password, Tables: store.Tables}

	t.Cleanup(func() {
		conn, err := pgx.Connect(context.Background(), admin)
		if err != nil {
			t.Errorf("cleanup: %v", err)
			return
		}
		defer conn.Close(context.Background())
		ident := pgx.Identifier{role}.Sanitize()
		for _, q := range []string{"DROP OWNED BY " + ident, "DROP ROLE " + ident} {
			if _, err := conn.Exec(context.Background(), q); err != nil {
				t.Errorf("cleanup %q: %v", q, err)
			}
		}
	})

	check := func(stage string) {
		t.Helper()
		db, err := store.Open(ctx, store.Config{DSN: tcp, User: role, Password: password, MaxConns: 1})
		if err != nil {
			t.Fatalf("%s: logging in as %s over TCP with the derived password: %v", stage, role, err)
		}
		defer db.Close()
		missing, err := db.MissingPrivileges(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if len(missing) > 0 {
			t.Fatalf("%s: role lacks %v", stage, missing)
		}
		if _, err := db.GetTxnState(ctx, "no-such-origin.invalid", "x"); err != nil {
			t.Fatalf("%s: a real query as the role: %v", stage, err)
		}
	}

	if err := Ensure(ctx, admin, spec); err != nil {
		t.Fatalf("create: %v", err)
	}
	check("after create")

	if err := Ensure(ctx, admin, spec); err != nil {
		t.Fatalf("second run on an existing role: %v", err)
	}
	check("after repair")

	// A wrong password must not get in, or the test proves nothing.
	if db, err := store.Open(ctx, store.Config{DSN: tcp, User: role, Password: "wrong", MaxConns: 1}); err == nil {
		db.Close()
		t.Fatal("logged in with the wrong password; this DSN is not checking passwords")
	}
}
