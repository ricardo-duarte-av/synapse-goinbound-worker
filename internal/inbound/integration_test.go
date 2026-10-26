package inbound

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/rs/zerolog"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/acl"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/fedclient"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/fedfetch"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdustore"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pduverify"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/stateres"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/store"
)

// An end-to-end run of write mode over a small real room on the throwaway
// database: a PDU whose prev event is missing is staged, the prev fetched
// from the origin with /get_missing_events, both decided and sent to the
// persister (a fake that stores what the real one would need), in order,
// with their state groups.

type signer struct {
	server string
	keyID  string
	priv   ed25519.PrivateKey
}

// event builds a signed v10 event, returning its ID and JSON.
func (s signer) event(t *testing.T, rv *pdu.RoomVersion, fields map[string]any) (string, []byte) {
	t.Helper()
	fields["hashes"] = map[string]any{}
	b, _ := json.Marshal(fields)
	b, _ = sjson.DeleteBytes(b, "hashes")
	sum, err := pdu.ContentHash(b)
	if err != nil {
		t.Fatal(err)
	}
	b, _ = sjson.SetBytes(b, "hashes", map[string]string{"sha256": base64.RawStdEncoding.EncodeToString(sum[:])})
	red, err := pdu.Redact(b, rv)
	if err != nil {
		t.Fatal(err)
	}
	red, _ = sjson.DeleteBytes(red, "signatures")
	red, _ = sjson.DeleteBytes(red, "unsigned")
	canon, err := pdu.Canonical(red)
	if err != nil {
		t.Fatal(err)
	}
	sig := base64.RawStdEncoding.EncodeToString(ed25519.Sign(s.priv, canon))
	b, _ = sjson.SetBytes(b, "signatures", map[string]any{s.server: map[string]string{s.keyID: sig}})
	id, err := pdu.CalculateEventID(b, rv)
	if err != nil {
		t.Fatal(err)
	}
	return id, b
}

// fakePersister stores events as the real persister would for what the
// processor reads back: events, event_json, event_to_state_groups.
type fakePersister struct {
	t      *testing.T
	c      *pgx.Conn
	mu     sync.Mutex
	order  []string
	stream int64
	sent   []json.RawMessage
}

func (f *fakePersister) SendEvents(ctx context.Context, room string, entries []json.RawMessage, backfilled bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	rv, _ := pdu.LookupRoomVersion("10")
	for _, e := range entries {
		f.sent = append(f.sent, e)
		ev := gjson.GetBytes(e, "event").Raw
		id, err := pdu.CalculateEventID([]byte(ev), rv)
		if err != nil {
			return err
		}
		f.order = append(f.order, id)
		outlier := gjson.GetBytes(e, "outlier").Bool()
		f.stream++
		var sk *string
		if v := gjson.Get(ev, "state_key"); v.Exists() {
			sk = &v.Str
		}
		if _, err := f.c.Exec(ctx, `INSERT INTO events (topological_ordering, event_id, type, room_id, processed, outlier, depth, origin_server_ts, received_ts, sender, stream_ordering, state_key, instance_name)
			VALUES ($1, $2, $3, $4, true, $5, $1, $6, $6, $7, $8, $9, 'persister')`,
			gjson.Get(ev, "depth").Int(), id, gjson.Get(ev, "type").Str, room, outlier, gjson.Get(ev, "origin_server_ts").Int(),
			gjson.Get(ev, "sender").Str, f.stream, sk); err != nil {
			return err
		}
		if _, err := f.c.Exec(ctx, `INSERT INTO event_json (event_id, room_id, internal_metadata, json, format_version) VALUES ($1, $2, $3, $4, 3)`,
			id, room, gjson.GetBytes(e, "internal_metadata").Raw, ev); err != nil {
			return err
		}
		if !outlier {
			g := gjson.GetBytes(e, "context.state_group").Int()
			if _, err := f.c.Exec(ctx, `INSERT INTO event_to_state_groups (event_id, state_group) VALUES ($1, $2)`, id, g); err != nil {
				return err
			}
			if _, err := f.c.Exec(ctx, `DELETE FROM event_forward_extremities WHERE room_id = $1`, room); err != nil {
				return err
			}
			if _, err := f.c.Exec(ctx, `INSERT INTO event_forward_extremities (event_id, room_id) VALUES ($1, $2)`, id, room); err != nil {
				return err
			}
		}
	}
	return nil
}

func (f *fakePersister) ResyncDevices(context.Context, string) error { return nil }

type rewriteTo struct{ to *url.URL }

func (r rewriteTo) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.URL.Scheme, req.URL.Host = r.to.Scheme, r.to.Host
	return http.DefaultTransport.RoundTrip(req)
}

func TestWriteModeFetchesMissingPrevs(t *testing.T) {
	t.Run("origin has it", func(t *testing.T) { runMissingPrevs(t, true, false) })
	// "Your server isn't divulging details about prev_events": dropped.
	t.Run("origin does not", func(t *testing.T) { runMissingPrevs(t, false, false) })
	// The pulled prev's own prev is missing: its state comes from the
	// origin's /state_ids and /state, the prev from /event as an outlier.
	t.Run("gap behind the prev", func(t *testing.T) { runMissingPrevs(t, true, true) })
	// The pulled prev is power levels with a string notification level, as
	// $oBePoe… in !bdbbTYhctZTWzoTzn9:federated.nexus: its auth raises a
	// SynapseError, which fails M3 as well. Nothing is persisted or
	// recorded; M2's state group is stored.
	t.Run("pulled prev raises", func(t *testing.T) {
		raiseAt = "pulled"
		defer func() { raiseAt = "" }()
		runMissingPrevs(t, true, false)
	})
	// The same event, as the outlier behind M2: "We can't get valid state
	// history." recorded for M2, and M3 dropped, its prev still missing.
	t.Run("outlier raises", func(t *testing.T) {
		raiseAt = "outlier"
		defer func() { raiseAt = "" }()
		runMissingPrevs(t, true, true)
	})
	// Carol's join is in the room's state but not held: a PDU she sends
	// refers to an unknown auth event, fetched with /event_auth.
	t.Run("auth event fetched", func(t *testing.T) {
		authGap = "served"
		defer func() { authGap = "" }()
		runMissingPrevs(t, true, false)
	})
	// The origin has no /event_auth: "Auth events could not be found",
	// and the PDU is dropped.
	t.Run("auth event not found", func(t *testing.T) {
		authGap = "unserved"
		defer func() { authGap = "" }()
		runMissingPrevs(t, true, false)
	})
	// The pulled prev is hers: the failure is recorded for it, and M3 is
	// dropped, its prev still missing.
	t.Run("pulled prev's auth event not found", func(t *testing.T) {
		authGap = "pulled"
		defer func() { authGap = "" }()
		runMissingPrevs(t, true, false)
	})
	// Through the front door, beside a PDU with a forged signature.
	t.Run("front door", func(t *testing.T) {
		frontDoor = true
		defer func() { frontDoor = false }()
		runMissingPrevs(t, true, false)
	})
}

var frontDoor bool

// authGap gives Carol, whose join we do not hold, a PDU: the one received
// ("served": the origin has /event_auth, "unserved": it does not) or the
// pulled prev ("pulled").
var authGap string

// raiseAt makes the pulled prev ("pulled") or the outlier behind it
// ("outlier") a power levels event whose auth raises.
var raiseAt string

func runMissingPrevs(t *testing.T, originHasIt, gap bool) {
	ctx := context.Background()
	d := testDB(t, "goinbound-test")
	c := adminConn(t)
	rv, _ := pdu.LookupRoomVersion("10")
	room := fmt.Sprintf("!e2e%d:local.test", time.Now().UnixNano())
	_, lpriv, _ := ed25519.GenerateKey(nil)
	_, rpriv, _ := ed25519.GenerateKey(nil)
	local := signer{"local.test", "ed25519:l", lpriv}
	remote := signer{"remote.test", "ed25519:r", rpriv}
	alice, bob, carol := "@alice:local.test", "@bob:remote.test", "@carol:remote.test"
	ts := int64(1_700_000_000_000)

	ev := func(s signer, typ, sender string, sk *string, content map[string]any, depth int, prevs, auth []string) (string, []byte) {
		ts++
		f := map[string]any{"type": typ, "room_id": room, "sender": sender, "content": content, "depth": depth,
			"origin_server_ts": ts, "prev_events": prevs, "auth_events": auth, "unsigned": map[string]any{}}
		if sk != nil {
			f["state_key"] = *sk
		}
		return s.event(t, rv, f)
	}
	empty, aliceKey, bobKey, carolKey := "", alice, bob, carol
	createID, create := ev(local, "m.room.create", alice, &empty, map[string]any{"creator": alice, "room_version": "10"}, 1, []string{}, []string{})
	aJoinID, aJoin := ev(local, "m.room.member", alice, &aliceKey, map[string]any{"membership": "join"}, 2, []string{createID}, []string{createID})
	plID, pl := ev(local, "m.room.power_levels", alice, &empty, map[string]any{"users": map[string]any{alice: 100, bob: 100}}, 3, []string{aJoinID}, []string{createID, aJoinID})
	jrID, jr := ev(local, "m.room.join_rules", alice, &empty, map[string]any{"join_rule": "public"}, 4, []string{plID}, []string{createID, aJoinID, plID})
	bJoinID, bJoin := ev(remote, "m.room.member", bob, &bobKey, map[string]any{"membership": "join"}, 5, []string{jrID}, []string{createID, plID, jrID})
	cJoinID, cJoin := ev(remote, "m.room.member", carol, &carolKey, map[string]any{"membership": "join"}, 5, []string{jrID}, []string{createID, plID, jrID})
	m1ID, m1 := ev(remote, "m.room.message", bob, nil, map[string]any{"msgtype": "m.text", "body": "one"}, 6, []string{bJoinID}, []string{createID, plID, bJoinID})
	// With a gap, M2's prev is X, which nobody sends us but /event.
	m2Prev := m1ID
	badPL := map[string]any{"users": map[string]any{alice: 100, bob: 100}, "notifications": map[string]any{"room": "50"}}
	xType, xKey, xContent := "m.room.message", (*string)(nil), map[string]any{"msgtype": "m.text", "body": "x"}
	if raiseAt == "outlier" {
		xType, xKey, xContent = "m.room.power_levels", &empty, badPL
	}
	xID, x := ev(remote, xType, bob, xKey, xContent, 7, []string{m1ID}, []string{createID, plID, bJoinID})
	if gap {
		m2Prev = xID
	}
	m2Type, m2Key, m2Content := "m.room.message", (*string)(nil), map[string]any{"msgtype": "m.text", "body": "two"}
	if raiseAt == "pulled" {
		m2Type, m2Key, m2Content = "m.room.power_levels", &empty, badPL
	}
	m2Sender, m2Auth := bob, []string{createID, plID, bJoinID}
	if authGap == "pulled" {
		m2Sender, m2Auth = carol, []string{createID, plID, cJoinID}
	}
	m2ID, m2 := ev(remote, m2Type, m2Sender, m2Key, m2Content, 8, []string{m2Prev}, m2Auth)
	mcID, mc := ev(remote, "m.room.message", carol, nil, map[string]any{"msgtype": "m.text", "body": "carol"}, 7, []string{m1ID}, []string{createID, plID, cJoinID})
	m3ID, m3 := ev(remote, "m.room.message", bob, nil, map[string]any{"msgtype": "m.text", "body": "three"}, 9, []string{m2ID}, []string{createID, plID, bJoinID})

	// The room as Synapse holds it once M1 is persisted.
	must := func(q string, args ...any) {
		t.Helper()
		if _, err := c.Exec(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	must(`DELETE FROM server_signature_keys WHERE server_name IN ('remote.test', 'local.test')`)
	must(`TRUNCATE events, event_json, event_to_state_groups, current_state_events, event_forward_extremities,
		room_depth, local_current_membership, rooms CASCADE`)
	must(`INSERT INTO rooms (room_id, is_public, creator, room_version, has_auth_chain_index) VALUES ($1, false, $2, '10', false)`, room, alice)
	roomState := pdu.StateMap{
		{Type: "m.room.create"}: createID, {Type: "m.room.member", StateKey: alice}: aJoinID,
		{Type: "m.room.power_levels"}: plID, {Type: "m.room.join_rules"}: jrID, {Type: "m.room.member", StateKey: bob}: bJoinID,
	}
	if authGap != "" {
		roomState[pdu.StateKey{Type: "m.room.member", StateKey: carol}] = cJoinID
	}
	group, err := d.StoreStateGroup(ctx, bJoinID, room, 0, nil, roomState, nil)
	if err != nil {
		t.Fatal(err)
	}
	type held struct {
		id  string
		raw []byte
	}
	for i, e := range []held{{createID, create}, {aJoinID, aJoin}, {plID, pl}, {jrID, jr}, {bJoinID, bJoin}, {m1ID, m1}} {
		j := gjson.ParseBytes(e.raw)
		var sk *string
		if v := j.Get("state_key"); v.Exists() {
			sk = &v.Str
		}
		must(`INSERT INTO events (topological_ordering, event_id, type, room_id, processed, outlier, depth, origin_server_ts, received_ts, sender, stream_ordering, state_key, instance_name)
			VALUES ($1, $2, $3, $4, true, false, $1, $5, $5, $6, $7, $8, 'master')`,
			j.Get("depth").Int(), e.id, j.Get("type").Str, room, j.Get("origin_server_ts").Int(), j.Get("sender").Str, int64(i+1), sk)
		must(`INSERT INTO event_json (event_id, room_id, internal_metadata, json, format_version) VALUES ($1, $2, '{}', $3, 3)`, e.id, room, string(e.raw))
		must(`INSERT INTO event_to_state_groups (event_id, state_group) VALUES ($1, $2)`, e.id, group)
		if sk != nil {
			mem := j.Get("content.membership").Str
			var m *string
			if mem != "" {
				m = &mem
			}
			must(`INSERT INTO current_state_events (event_id, room_id, type, state_key, membership) VALUES ($1, $2, $3, $4, $5)`, e.id, room, j.Get("type").Str, *sk, m)
		}
	}
	must(`INSERT INTO event_forward_extremities (event_id, room_id) VALUES ($1, $2)`, m1ID, room)
	must(`INSERT INTO room_depth (room_id, min_depth) VALUES ($1, 1)`, room)
	must(`INSERT INTO local_current_membership (room_id, user_id, event_id, membership) VALUES ($1, $2, $3, 'join')`, room, alice, aJoinID)
	must(`INSERT INTO server_signature_keys (server_name, key_id, from_server, ts_added_ms, verify_key, ts_valid_until_ms)
		VALUES ('remote.test', 'ed25519:r', 'remote.test', 1, $1, 9000000000000)`, []byte(rpriv.Public().(ed25519.PublicKey)))
	must(`INSERT INTO server_signature_keys (server_name, key_id, from_server, ts_added_ms, verify_key, ts_valid_until_ms)
		VALUES ('local.test', 'ed25519:l', 'local.test', 1, $1, 9000000000000)`, []byte(lpriv.Public().(ed25519.PublicKey)))

	// The origin, which has M2.
	var asked []string
	var amu sync.Mutex
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		amu.Lock()
		asked = append(asked, r.Method+" "+r.URL.Path)
		amu.Unlock()
		switch {
		case strings.HasPrefix(r.URL.Path, "/_matrix/federation/v1/get_missing_events/") && originHasIt:
			w.Write([]byte(`{"events":[` + string(m2) + `]}`))
			return
		case strings.HasPrefix(r.URL.Path, "/_matrix/federation/v1/state_ids/") && r.URL.Query().Get("event_id") == xID:
			ids, _ := json.Marshal(map[string]any{"pdu_ids": []string{createID, aJoinID, plID, jrID, bJoinID}, "auth_chain_ids": []string{createID, aJoinID, plID}})
			w.Write(ids)
			return
		case strings.HasPrefix(r.URL.Path, "/_matrix/federation/v1/state/") && r.URL.Query().Get("event_id") == xID:
			w.Write([]byte(`{"auth_chain":[` + string(create) + `,` + string(aJoin) + `,` + string(pl) + `],"pdus":[` +
				string(create) + `,` + string(aJoin) + `,` + string(pl) + `,` + string(jr) + `,` + string(bJoin) + `]}`))
			return
		case strings.HasPrefix(r.URL.Path, "/_matrix/federation/v1/event_auth/") && authGap == "served":
			w.Write([]byte(`{"auth_chain":[` + string(create) + `,` + string(aJoin) + `,` + string(pl) + `,` + string(jr) + `,` + string(cJoin) + `]}`))
			return
		case r.URL.Path == "/_matrix/federation/v1/event/"+xID:
			w.Write([]byte(`{"origin":"remote.test","origin_server_ts":1,"pdus":[` + string(x) + `]}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer origin.Close()
	to, _ := url.Parse(origin.URL)

	pst, err := pdustore.Open(ctx, os.Getenv("INBOUND_TEST_ADMIN_DSN"), 4)
	if err != nil {
		t.Fatal(err)
	}
	defer pst.Close()
	v := pduverify.New(pst, stateres.Options{})
	v.EnablePush(pduverify.PushConfig{ServerName: "local.test"})
	fc, err := fedclient.New("local.test", "ed25519 l "+base64.RawStdEncoding.EncodeToString(lpriv.Seed()), nil, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	fc.HTTP.Transport.(*fedclient.JSONContentType).Next = rewriteTo{to}
	per := &fakePersister{t: t, c: c, stream: 100}
	p := NewProcessor(d, v, per, pst, "local.test", zerolog.New(zerolog.NewTestWriter(t)))
	p.EnableMissingEvents(&MissingDeps{Fetch: fedfetch.New(fc, pst, v, nil, "local.test", nil), Store: pst, Verifier: v})
	defer p.Close()

	if frontDoor {
		forgedID, forged := ev(remote, "m.room.message", bob, nil, map[string]any{"msgtype": "m.text", "body": "forged"}, 7, []string{m1ID}, []string{createID, plID, bJoinID})
		forged, _ = sjson.SetBytes(forged, "signatures.remote\\.test.ed25519:r", base64.RawStdEncoding.EncodeToString(make([]byte, 64)))
		if forgedID, err = pdu.CalculateEventID(forged, rv); err != nil {
			t.Fatal(err)
		}
		edb, err := store.Open(ctx, store.Config{DSN: os.Getenv("INBOUND_TEST_ADMIN_DSN"), MaxConns: 2, QueryTimeout: 5 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		defer edb.Close()
		fd := NewFrontDoor(FrontDoorDeps{Store: pst, Verifier: v, ACL: acl.NewChecker(edb, 0), Processor: p, Server: "local.test"})
		plan, why := fd.PlanPDUs(ctx, "remote.test", []json.RawMessage{m3, forged}, time.Now())
		if why != "" {
			t.Fatalf("left to Synapse: %s", why)
		}
		res := plan.Run(ctx)
		if string(res[m3ID]) != `{}` {
			t.Errorf("M3's entry %s", res[m3ID])
		}
		want := `{"error":"ERROR 403: unable to verify signature for sender domain remote.test: 401: Invalid signature for server remote.test with key ed25519:r: Unable to verify signature for remote.test: <class 'nacl.exceptions.BadSignatureError'> Signature was forged or corrupt"}`
		if string(res[forgedID]) != want {
			t.Errorf("forged entry %s", res[forgedID])
		}
		if staged, _ := pst.Staged(ctx, forgedID); staged {
			t.Error("the forged PDU was staged")
		}
	} else {
		recvID, recv := m3ID, m3
		if authGap == "served" || authGap == "unserved" {
			recvID, recv = mcID, mc
		}
		staged, err := pduverify.StagedEvent(recv, time.Now(), "", nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Received(ctx, "remote.test", room, recvID, staged, []byte(`{}`)); err != nil {
			t.Fatal(err)
		}
	}
	failedPulls := func() []string {
		var causes []string
		rows, err := c.Query(ctx, `SELECT event_id || ' ' || last_cause FROM event_failed_pull_attempts WHERE room_id = $1`, room)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var r string
			rows.Scan(&r)
			causes = append(causes, r)
		}
		return causes
	}
	if authGap != "" {
		waitFor(t, "unstaged", func() bool { s, _ := d.NextStaged(ctx, room); return s == nil })
		per.mu.Lock()
		defer per.mu.Unlock()
		if p.isDeferred(room) {
			t.Error("deferred")
		}
		switch authGap {
		case "served":
			if len(per.order) != 2 || per.order[0] != cJoinID || per.order[1] != mcID {
				t.Fatalf("persisted %v, want Carol's join then her message", per.order)
			}
			if !gjson.GetBytes(per.sent[0], "outlier").Bool() {
				t.Errorf("Carol's join not an outlier: %s", per.sent[0])
			}
			if r := gjson.GetBytes(per.sent[1], "rejected_reason"); r.Type != gjson.Null {
				t.Errorf("message rejected: %s", r.Raw)
			}
		case "unserved":
			if len(per.sent) != 0 {
				t.Errorf("persisted %v", per.order)
			}
		case "pulled":
			if len(per.sent) != 0 {
				t.Errorf("persisted %v", per.order)
			}
			if want := m2ID + " " + authNotFound; len(failedPulls()) != 1 || failedPulls()[0] != want {
				t.Errorf("failed pulls %v, want [%s]", failedPulls(), want)
			}
		}
		return
	}
	if raiseAt != "" {
		waitFor(t, "M3 unstaged", func() bool { s, _ := d.NextStaged(ctx, room); return s == nil })
		per.mu.Lock()
		defer per.mu.Unlock()
		if len(per.sent) != 0 {
			t.Errorf("persisted %v; Synapse persists nothing when auth raises", per.order)
		}
		if p.isDeferred(room) {
			t.Error("deferred")
		}
		causes := failedPulls()
		var groups int
		c.QueryRow(ctx, `SELECT count(*) FROM state_groups WHERE event_id = $1`, m2ID).Scan(&groups)
		switch raiseAt {
		case "pulled":
			if len(causes) != 0 {
				t.Errorf("failed pulls %v; the exception escapes before any is recorded", causes)
			}
			if groups != 1 {
				t.Errorf("%d state groups for M2, want its group after", groups)
			}
		case "outlier":
			if want := m2ID + " ERROR 403: We can't get valid state history."; len(causes) != 1 || causes[0] != want {
				t.Errorf("failed pulls %v, want [%s]", causes, want)
			}
			if groups != 0 {
				t.Errorf("%d state groups for M2; its context was never computed", groups)
			}
		}
		return
	}
	if !originHasIt {
		waitFor(t, "M3 dropped", func() bool { s, _ := d.NextStaged(ctx, room); return s == nil })
		per.mu.Lock()
		defer per.mu.Unlock()
		if len(per.sent) != 0 {
			t.Errorf("persisted %v; Synapse drops an event whose prevs it cannot get", per.order)
		}
		return
	}
	want := []string{m2ID, m3ID}
	if gap {
		want = []string{xID, m2ID, m3ID}
	}
	waitFor(t, "all persisted", func() bool { per.mu.Lock(); defer per.mu.Unlock(); return len(per.sent) == len(want) })

	per.mu.Lock()
	defer per.mu.Unlock()
	for i := range want {
		if per.order[i] != want[i] {
			t.Fatalf("persisted %v, want %v", per.order, want)
		}
	}
	if gap {
		// X is an outlier, persisted backfilled; M2's state came from the
		// origin and is stored in full, a new group with the room's state.
		x := per.sent[0]
		if !gjson.GetBytes(x, "outlier").Bool() || gjson.GetBytes(x, "context.state_group").Type != gjson.Null {
			t.Errorf("X: %s", x)
		}
		m2g := gjson.GetBytes(per.sent[1], "context.state_group").Int()
		if m2g == group || len(gjson.GetBytes(per.sent[1], "context.state_group_deltas").Array()) != 1 {
			t.Errorf("M2's context %s, want a new full group", gjson.GetBytes(per.sent[1], "context").Raw)
		}
		if st, err := pst.StateForGroup(ctx, m2g); err != nil || len(st) != 5 {
			t.Errorf("M2's group %d: %v %v", m2g, st, err)
		}
		amu.Lock()
		t.Logf("asked: %v", asked)
		amu.Unlock()
		return
	}
	for i, e := range per.sent {
		if gjson.GetBytes(e, "outlier").Bool() || gjson.GetBytes(e, "rejected_reason").Type != gjson.Null {
			t.Errorf("entry %d: outlier or rejected: %s", i, e)
		}
		if g := gjson.GetBytes(e, "context.state_group").Int(); g != group {
			t.Errorf("entry %d: state group %d, want the room's %d (no state changed)", i, g, group)
		}
	}
	amu.Lock()
	if len(asked) != 1 {
		t.Errorf("asked the origin %v", asked)
	}
	amu.Unlock()
	if s, _ := d.NextStaged(ctx, room); s != nil {
		t.Error("M3 left staged")
	}
}
