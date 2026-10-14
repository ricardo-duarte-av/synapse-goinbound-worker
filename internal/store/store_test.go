package store

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdustore"
)

// TestEveryQueryIsASelect keeps this package read-only by construction.
//
// Every write this worker causes goes through Synapse's stream writers, which
// is what makes it safe to run beside Synapse at all. A query that wrote --
// even to a table that looks like ours to write -- would skip the caches and
// streams Synapse keeps in step with its tables, and the result would be
// silently stale everywhere else. So: every SQL constant (named q...) must be a
// SELECT, and nothing may call the pool's write paths.
func TestEveryQueryIsASelect(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}

	queries := 0
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.ValueSpec:
					for i, id := range n.Names {
						if !strings.HasPrefix(id.Name, "q") || i >= len(n.Values) {
							continue
						}
						lit, ok := n.Values[i].(*ast.BasicLit)
						if !ok || lit.Kind != token.STRING {
							continue
						}
						sql, err := strconv.Unquote(lit.Value)
						if err != nil {
							t.Fatalf("%s: %v", name, err)
						}
						queries++
						if !strings.HasPrefix(strings.ToUpper(strings.TrimSpace(sql)), "SELECT") {
							t.Errorf("%s: %s is not a SELECT:\n%s", name, id.Name, sql)
						}
					}
				case *ast.SelectorExpr:
					switch n.Sel.Name {
					case "Exec", "Begin", "BeginTx", "CopyFrom", "SendBatch":
						t.Errorf("%s: calls %s, a write path", fset.Position(n.Pos()), n.Sel.Name)
					}
				}
				return true
			})
		}
	}
	if queries == 0 {
		t.Fatal("found no queries; the test is not looking where they are")
	}
}

// Live tests against Synapse's real database.
//
//	SYNAPSE_DSN="host=/var/sockets user=synapse dbname=synapse-db" go test ./internal/store/
func liveStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("SYNAPSE_DSN")
	if dsn == "" {
		t.Skip("SYNAPSE_DSN not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s, err := Open(ctx, Config{DSN: dsn, MaxConns: 2, QueryTimeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func TestLiveTxnState(t *testing.T) {
	s := liveStore(t)
	ctx := context.Background()

	// A transaction Synapse answered recently must come back as stored.
	var origin, txnID string
	err := s.pool.QueryRow(ctx,
		`SELECT origin, transaction_id FROM received_transactions ORDER BY ts DESC LIMIT 1`).Scan(&origin, &txnID)
	if err != nil {
		t.Fatal(err)
	}
	st, err := s.GetTxnState(ctx, origin, txnID)
	if err != nil {
		t.Fatal(err)
	}
	if st.Previous == nil || st.Previous.Code == 0 || len(st.Previous.JSON) == 0 {
		t.Errorf("txn %s from %s: stored response = %+v", txnID, origin, st.Previous)
	}
	t.Logf("%s: retry_last_ts=%d previous=%d %s", origin, st.RetryLastTS, st.Previous.Code, st.Previous.JSON)

	// One that never existed.
	st, err = s.GetTxnState(ctx, "no-such-origin.invalid", "no-such-txn")
	if err != nil {
		t.Fatal(err)
	}
	if st.Previous != nil || st.RetryLastTS != 0 {
		t.Errorf("unknown origin and txn: %+v", st)
	}
}

func TestLiveCurrentServerACL(t *testing.T) {
	s := liveStore(t)
	ctx := context.Background()

	var roomID string
	err := s.pool.QueryRow(ctx,
		`SELECT room_id FROM current_state_events WHERE type = 'm.room.server_acl' AND state_key = '' LIMIT 1`).Scan(&roomID)
	if err != nil {
		t.Skipf("no room with a server ACL: %v", err)
	}
	ev, err := s.CurrentServerACL(ctx, roomID)
	if err != nil {
		t.Fatal(err)
	}
	if ev == nil || ev.EventID == "" || !strings.Contains(string(ev.JSON), "m.room.server_acl") {
		t.Errorf("%s: acl = %+v", roomID, ev)
	}

	ev, err = s.CurrentServerACL(ctx, "!no-such-room:invalid")
	if err != nil || ev != nil {
		t.Errorf("unknown room: %+v, %v; want no ACL", ev, err)
	}
}

func TestLiveServerKeys(t *testing.T) {
	s := liveStore(t)
	keys, err := s.GetServerKeys(context.Background(), "matrix.org", time.Now().UnixMilli())
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) == 0 {
		t.Skip("no cached keys for matrix.org")
	}
	if len(keys[0].JSON) == 0 {
		t.Error("key row without JSON")
	}
}

// TestQueriesReadOnlyListedTables keeps Tables -- what the read-only role is
// granted -- in step with what the queries actually read. A table missing from
// the list would make every start find the role "incomplete" and the first
// query fail; a table in the list but unused is a grant nobody needs.
func TestQueriesReadOnlyListedTables(t *testing.T) {
	listed := map[string]bool{}
	for _, tbl := range Tables {
		listed[tbl] = true
	}
	used := map[string]bool{}

	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}
	ref := regexp.MustCompile(`(?i)\b(?:FROM|JOIN)\s+([a-z_][a-z0-9_]*)`)
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				vs, ok := n.(*ast.ValueSpec)
				if !ok {
					return true
				}
				for i, id := range vs.Names {
					if !strings.HasPrefix(id.Name, "q") || i >= len(vs.Values) {
						continue
					}
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					sql, _ := strconv.Unquote(lit.Value)
					for _, m := range ref.FindAllStringSubmatch(sql, -1) {
						tbl := strings.ToLower(m[1])
						if tbl == "select" { // FROM (SELECT ...)
							continue
						}
						used[tbl] = true
						if !listed[tbl] {
							t.Errorf("%s reads %s, which is not in Tables", id.Name, tbl)
						}
					}
				}
				return true
			})
		}
	}
	for tbl := range listed {
		if !used[tbl] {
			t.Errorf("Tables grants %s, which no query reads", tbl)
		}
	}

	// The hand-run SQL must grant exactly the same.
	b, err := os.ReadFile("../../deploy/readonly-role.sql")
	if err != nil {
		t.Fatal(err)
	}
	grant := regexp.MustCompile(`(?s)GRANT SELECT ON\s+(.*?)\s+TO goinbound_ro;`).FindSubmatch(b)
	if grant == nil {
		t.Fatal("deploy/readonly-role.sql has no GRANT SELECT ... TO goinbound_ro")
	}
	var inSQL []string
	for _, f := range strings.Split(string(grant[1]), ",") {
		inSQL = append(inSQL, strings.TrimSpace(f))
	}
	slices.Sort(inSQL)
	want := slices.Clone(Tables)
	for _, t := range pdustore.Tables {
		if !slices.Contains(want, t) {
			want = append(want, t)
		}
	}
	slices.Sort(want)
	if !slices.Equal(inSQL, want) {
		t.Errorf("deploy/readonly-role.sql grants %v, store and pdustore read %v", inSQL, want)
	}
}
