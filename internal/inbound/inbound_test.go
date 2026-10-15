package inbound

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/dbrole"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
)

// Tests that write run against a throwaway PostgreSQL holding Synapse's
// schema (pg_dump --schema-only of the live database, no rows), never the
// live one:
//
//	INBOUND_TEST_ADMIN_DSN="host=127.0.0.1 port=55432 user=synapse password=test dbname=synapse" go test ./internal/inbound/
//
// They create the write role from Grants and connect as it, so a missing
// grant fails here, not in production.
const testRole = "goinbound_rw_test"

func testDB(t *testing.T, instance string) *DB {
	t.Helper()
	admin := os.Getenv("INBOUND_TEST_ADMIN_DSN")
	if admin == "" {
		t.Skip("INBOUND_TEST_ADMIN_DSN not set")
	}
	if strings.Contains(admin, "/var/sockets") {
		t.Fatal("INBOUND_TEST_ADMIN_DSN must be a throwaway database, not the live one")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := dbrole.Ensure(ctx, admin, dbrole.Spec{Role: testRole, Password: "test", Writes: Grants, Sequences: Sequences}); err != nil {
		t.Fatal(err)
	}
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	for _, g := range Grants {
		if _, err := conn.Exec(ctx, "TRUNCATE "+g.Table+" CASCADE"); err != nil {
			t.Fatal(err)
		}
	}
	conn.Close(ctx)
	cfg, _ := pgx.ParseConfig(admin)
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=test dbname=%s", cfg.Host, cfg.Port, testRole, cfg.Database)
	d, err := Open(ctx, dsn, instance)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	return d
}

// A second process on the same database, under another instance name.
func otherInstance(t *testing.T, d *DB, instance string) *DB {
	t.Helper()
	o := *d
	o.instance = instance
	return &o
}

func TestRoomLockExcludesOtherInstances(t *testing.T) {
	ctx := context.Background()
	d := testDB(t, "goinbound-test")
	py := NewLocks(otherInstance(t, d, "av-inbound-federation-worker-1"))
	us := NewLocks(d)

	l1, err := py.TryAcquire(ctx, LockInboundPDU, "!room:x")
	if err != nil || l1 == nil {
		t.Fatalf("first acquire: %v %v", l1, err)
	}
	if l2, err := us.TryAcquire(ctx, LockInboundPDU, "!room:x"); err != nil || l2 != nil {
		t.Fatalf("another instance took a held lock: %v %v", l2, err)
	}
	if l, err := us.TryAcquire(ctx, LockInboundPDU, "!other:x"); err != nil || l == nil {
		t.Fatalf("another room's lock: %v %v", l, err)
	}
	// Held by ourselves: not taken twice in one process.
	if l, err := py.TryAcquire(ctx, LockInboundPDU, "!room:x"); err != nil || l != nil {
		t.Fatalf("taken twice by its holder: %v %v", l, err)
	}
	if ok, err := l1.StillValid(ctx); err != nil || !ok {
		t.Fatalf("held lock not valid: %v %v", ok, err)
	}
	if err := l1.Release(ctx); err != nil {
		t.Fatal(err)
	}
	if ok, _ := l1.StillValid(ctx); ok {
		t.Error("a released lock is still valid")
	}
	l3, err := us.TryAcquire(ctx, LockInboundPDU, "!room:x")
	if err != nil || l3 == nil {
		t.Fatalf("acquire after release: %v %v", l3, err)
	}
	l3.Release(ctx)
}

// A holder that stopped renewing (a process that died) loses the lock after
// two minutes.
func TestRoomLockTimesOut(t *testing.T) {
	ctx := context.Background()
	d := testDB(t, "goinbound-test")
	dead := otherInstance(t, d, "dead-worker")
	past := time.Now().Add(-3 * time.Minute)
	dead.now = func() time.Time { return past }
	if l, err := NewLocks(dead).TryAcquire(ctx, LockInboundPDU, "!room:x"); err != nil || l == nil {
		t.Fatalf("acquire: %v %v", l, err)
	}
	if l, err := NewLocks(d).TryAcquire(ctx, LockInboundPDU, "!room:x"); err != nil || l == nil {
		t.Fatalf("a timed-out lock was not taken over: %v %v", l, err)
	}
}

func TestPurgeLockReadersShareWritersExclude(t *testing.T) {
	ctx := context.Background()
	d := testDB(t, "goinbound-test")
	us := NewLocks(d)
	main := NewLocks(otherInstance(t, d, "master"))

	r1, err := us.TryAcquireReadWrite(ctx, LockPurge, "!room:x", false)
	if err != nil || r1 == nil {
		t.Fatalf("read lock: %v %v", r1, err)
	}
	r2, err := main.TryAcquireReadWrite(ctx, LockPurge, "!room:x", false)
	if err != nil || r2 == nil {
		t.Fatalf("second read lock: %v %v", r2, err)
	}
	if w, err := main.TryAcquireReadWrite(ctx, LockPurge, "!room:x", true); err != nil || w != nil {
		t.Fatalf("write lock while read-locked: %v %v", w, err)
	}
	r1.Release(ctx)
	r2.Release(ctx)
	w, err := main.TryAcquireReadWrite(ctx, LockPurge, "!room:x", true)
	if err != nil || w == nil {
		t.Fatalf("write lock once free: %v %v", w, err)
	}
	// A reader now waits for the purge.
	waitCtx, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
	defer cancel()
	if r, err := us.AcquireReadWrite(waitCtx, LockPurge, "!room:x", false); err == nil || r != nil {
		t.Fatalf("read lock during a purge: %v %v", r, err)
	}
	w.Release(ctx)
	if r, err := us.AcquireReadWrite(ctx, LockPurge, "!room:x", false); err != nil || r == nil {
		t.Fatalf("read lock after the purge: %v %v", r, err)
	}
}

func TestStaging(t *testing.T) {
	ctx := context.Background()
	d := testDB(t, "goinbound-test")
	tick := int64(1000)
	d.now = func() time.Time { tick++; return time.UnixMilli(tick) }

	if err := d.Stage(ctx, "a.example", "!r:x", "$1", []byte(`{"prev_events":[]}`), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	// The same event from the same origin again keeps the first copy.
	if err := d.Stage(ctx, "a.example", "!r:x", "$1", []byte(`{"second":true}`), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	// From another origin it is staged again.
	if err := d.Stage(ctx, "b.example", "!r:x", "$1", []byte(`{"prev_events":[]}`), []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	origin, id, ok, err := d.NextStagedID(ctx, "!r:x")
	if err != nil || !ok || origin != "a.example" || id != "$1" {
		t.Fatalf("next id: %s %s %v %v", origin, id, ok, err)
	}
	s, err := d.NextStaged(ctx, "!r:x")
	if err != nil || s == nil || string(s.EventJSON) != `{"prev_events":[]}` {
		t.Fatalf("next: %+v %v", s, err)
	}
	ts, ok, err := d.Unstage(ctx, "a.example", "$1")
	if err != nil || !ok || ts != 1001 {
		t.Fatalf("unstage: %d %v %v", ts, ok, err)
	}
	if _, ok, _ := d.Unstage(ctx, "a.example", "$1"); ok {
		t.Error("unstaged twice")
	}
	if origin, _, _, _ := d.NextStagedID(ctx, "!r:x"); origin != "b.example" {
		t.Errorf("next after unstage: %s", origin)
	}
	rooms, err := d.StagedRooms(ctx)
	if err != nil || len(rooms) != 1 || rooms[0] != "!r:x" {
		t.Errorf("rooms: %v %v", rooms, err)
	}
	if s, _ := d.NextStaged(ctx, "!empty:x"); s != nil {
		t.Error("an empty room has a next event")
	}
}

// Past 100 staged events, everything another staged event points at goes.
func TestPruneStaged(t *testing.T) {
	ctx := context.Background()
	d := testDB(t, "goinbound-test")
	for i := 0; i < 120; i++ {
		prev := ""
		if i > 0 {
			prev = fmt.Sprintf(`"$%d"`, i-1)
		}
		js := fmt.Sprintf(`{"prev_events":[%s]}`, prev)
		if err := d.Stage(ctx, "a.example", "!r:x", fmt.Sprintf("$%d", i), []byte(js), []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	n, err := d.PruneStaged(ctx, "!r:x", false)
	if err != nil || n != 119 {
		t.Fatalf("pruned %d, %v", n, err)
	}
	s, _ := d.NextStaged(ctx, "!r:x")
	if s == nil || !strings.Contains(string(s.EventJSON), `"$118"`) {
		t.Errorf("kept %+v, want the chain's tip", s)
	}
	if n, _ := d.PruneStaged(ctx, "!r:x", false); n != 0 {
		t.Errorf("pruned a short queue: %d", n)
	}
}

func TestStagedPrevs(t *testing.T) {
	for _, c := range []struct {
		js   string
		v1v2 bool
		want string
	}{
		{`{"prev_events":["$a","$b"]}`, false, "$a $b"},
		{`{"prev_events":["$a",1,"$b"]}`, false, "$a"},
		{`{"prev_events":"$a"}`, false, ""},
		{`{}`, false, ""},
		{`{"prev_events":[["$a",{}],["$b",{}]]}`, true, "$a $b"},
		{`{"prev_events":[["$a",{}],["$b"]]}`, true, "$a"},
	} {
		if got := strings.Join(stagedPrevs(c.js, c.v1v2), " "); got != c.want {
			t.Errorf("%s: %q, want %q", c.js, got, c.want)
		}
	}
}

// Every query names only tables in Grants, and only with a granted
// privilege.
func TestQueriesUseOnlyGrants(t *testing.T) {
	granted := map[string]string{}
	for _, g := range Grants {
		granted[g.Table] = g.Privileges
	}
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi os.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }, 0)
	if err != nil {
		t.Fatal(err)
	}
	uses := []struct {
		re   *regexp.Regexp
		priv string
	}{
		{regexp.MustCompile(`(?i)\bINSERT\s+INTO\s+(\w+)`), "INSERT"},
		{regexp.MustCompile(`(?i)\bUPDATE\s+(\w+)\s+SET`), "UPDATE"},
		{regexp.MustCompile(`(?i)\bDELETE\s+FROM\s+(\w+)`), "DELETE"},
		{regexp.MustCompile(`(?i)\bFROM\s+(\w+)`), "SELECT"},
		{regexp.MustCompile(`(?i)\bJOIN\s+(\w+)`), "SELECT"},
	}
	// Names that follow FROM without being tables: functions, and the
	// recursive CTE of qStateHops.
	notTables := map[string]bool{"unnest": true, "state": true}
	queries := 0
	for _, pkg := range pkgs {
		for _, f := range pkg.Files {
			ast.Inspect(f, func(n ast.Node) bool {
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
					queries++
					for _, u := range uses {
						for _, m := range u.re.FindAllStringSubmatch(sql, -1) {
							if notTables[m[1]] {
								continue
							}
							privs, ok := granted[m[1]]
							if !ok {
								t.Errorf("%s uses %s, which is not in Grants", id.Name, m[1])
								continue
							}
							if !strings.Contains(privs, u.priv) {
								t.Errorf("%s needs %s on %s, granted %q", id.Name, u.priv, m[1], privs)
							}
						}
					}
				}
				return true
			})
		}
	}
	if queries == 0 {
		t.Fatal("found no queries")
	}
}

// The role has nothing beyond Grants: Synapse's other tables are refused.
func TestWriteRoleIsExact(t *testing.T) {
	ctx := context.Background()
	d := testDB(t, "goinbound-test")
	for _, q := range []string{
		`SELECT 1 FROM events LIMIT 1`,
		`INSERT INTO rejections (event_id, reason, last_check) VALUES ('$x', 'x', 'x')`,
		`UPDATE state_groups SET room_id = 'x' WHERE id = 0`,
		`SELECT nextval('events_stream_seq')`,
	} {
		if _, err := d.pool.Exec(ctx, q); err == nil || !strings.Contains(err.Error(), "permission denied") {
			t.Errorf("%s: %v, want permission denied", q, err)
		}
	}
}

func adminConn(t *testing.T) *pgx.Conn {
	t.Helper()
	c, err := pgx.Connect(context.Background(), os.Getenv("INBOUND_TEST_ADMIN_DSN"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(context.Background()) })
	return c
}

func groupRows(t *testing.T, c *pgx.Conn, g int64) (prev int64, rows map[string]string) {
	t.Helper()
	ctx := context.Background()
	_ = c.QueryRow(ctx, `SELECT prev_state_group FROM state_group_edges WHERE state_group = $1`, g).Scan(&prev)
	rows = map[string]string{}
	r, err := c.Query(ctx, `SELECT type || '/' || state_key, event_id FROM state_groups_state WHERE state_group = $1`, g)
	if err != nil {
		t.Fatal(err)
	}
	for r.Next() {
		var k, v string
		r.Scan(&k, &v)
		rows[k] = v
	}
	return prev, rows
}

func TestStoreStateGroup(t *testing.T) {
	ctx := context.Background()
	d := testDB(t, "goinbound-test")
	c := adminConn(t)
	create := pdu.StateKey{Type: "m.room.create"}
	topic := pdu.StateKey{Type: "m.room.topic"}

	full, err := d.StoreStateGroup(ctx, "$create", "!r:x", 0, nil, pdu.StateMap{create: "$create"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if prev, rows := groupRows(t, c, full); prev != 0 || rows["m.room.create/"] != "$create" || len(rows) != 1 {
		t.Fatalf("full group: prev %d rows %v", prev, rows)
	}
	delta, err := d.StoreStateGroup(ctx, "$topic", "!r:x", full, pdu.StateMap{topic: "$topic"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if prev, rows := groupRows(t, c, delta); prev != full || len(rows) != 1 || rows["m.room.topic/"] != "$topic" {
		t.Fatalf("delta group: prev %d rows %v", prev, rows)
	}

	// _count_state_group_hops_txn counts the group itself: the full group
	// is 1, so after 98 more deltas the chain is 100 long, and the next
	// group is stored in full.
	last := delta
	for i := 0; i < 98; i++ {
		if last, err = d.StoreStateGroup(ctx, fmt.Sprintf("$e%d", i), "!r:x", last, pdu.StateMap{topic: fmt.Sprintf("$e%d", i)}, nil, nil); err != nil {
			t.Fatal(err)
		}
	}
	loaded := 0
	load := func(g int64) (pdu.StateMap, error) {
		loaded++
		return pdu.StateMap{create: "$create", topic: "$e98"}, nil
	}
	end, err := d.StoreStateGroup(ctx, "$end", "!r:x", last, pdu.StateMap{topic: "$end"}, nil, load)
	if err != nil {
		t.Fatal(err)
	}
	if prev, rows := groupRows(t, c, end); prev != 0 || len(rows) != 2 || rows["m.room.topic/"] != "$end" || loaded != 1 {
		t.Fatalf("after 100 hops: prev %d rows %v loaded %d", prev, rows, loaded)
	}

	// A deleted prev group is refused.
	if _, err := d.StoreStateGroup(ctx, "$x", "!r:x", 999999999, pdu.StateMap{topic: "$x"}, nil, nil); !errors.Is(err, ErrMissingGroup) {
		t.Fatalf("missing prev: %v", err)
	}
}

func TestBumpDeletion(t *testing.T) {
	ctx := context.Background()
	d := testDB(t, "goinbound-test")
	c := adminConn(t)
	g, err := d.StoreStateGroup(ctx, "$e", "!r:x", 0, nil, pdu.StateMap{{Type: "m.room.create"}: "$e"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Exec(ctx, `INSERT INTO state_groups_pending_deletion (state_group, insertion_ts) VALUES ($1, 5)`, g); err != nil {
		t.Fatal(err)
	}
	var seq0 int64
	c.QueryRow(ctx, `SELECT sequence_number FROM state_groups_pending_deletion WHERE state_group = $1`, g).Scan(&seq0)
	missing, err := d.BumpDeletion(ctx, []int64{g, 888888888})
	if err != nil || len(missing) != 1 || missing[0] != 888888888 {
		t.Fatalf("missing %v, %v", missing, err)
	}
	var seq, ts int64
	c.QueryRow(ctx, `SELECT sequence_number, insertion_ts FROM state_groups_pending_deletion WHERE state_group = $1`, g).Scan(&seq, &ts)
	if seq == seq0 || ts == 5 {
		t.Errorf("not bumped: sequence %d -> %d, ts %d", seq0, seq, ts)
	}
}

func TestStagePushAndTxnResponse(t *testing.T) {
	ctx := context.Background()
	d := testDB(t, "goinbound-test")
	c := adminConn(t)
	rows := []PushRow{{UserID: "@a:x", Actions: "", Notif: true}, {UserID: "@b:x", Actions: `["notify"]`, Notif: true, Highlight: true, Unread: true, ThreadID: "main"}}
	if err := d.StagePush(ctx, "$e", rows); err != nil {
		t.Fatal(err)
	}
	var n, hl int
	c.QueryRow(ctx, `SELECT count(*), sum(highlight) FROM event_push_actions_staging WHERE event_id = '$e'`).Scan(&n, &hl)
	if n != 2 || hl != 1 {
		t.Fatalf("staged %d rows, %d highlights", n, hl)
	}
	if err := d.UnstagePush(ctx, "$e"); err != nil {
		t.Fatal(err)
	}
	c.QueryRow(ctx, `SELECT count(*) FROM event_push_actions_staging`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d rows left", n)
	}

	if err := d.SetTxnResponse(ctx, "a.example", "t1", 200, []byte(`{"pdus":{}}`)); err != nil {
		t.Fatal(err)
	}
	if err := d.SetTxnResponse(ctx, "a.example", "t1", 200, []byte(`{"pdus":{"$x":{}}}`)); err != nil {
		t.Fatal(err)
	}
	var body string
	c.QueryRow(ctx, `SELECT convert_from(response_json, 'UTF8') FROM received_transactions WHERE origin = 'a.example' AND transaction_id = 't1'`).Scan(&body)
	if body != `{"pdus":{}}` {
		t.Errorf("stored %s, want the first answer", body)
	}
}
