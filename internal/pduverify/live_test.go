package pduverify

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdustore"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/stateres"
)

// TestLiveOnStoredEvents feeds the live shadow a transaction rebuilt from
// recently persisted events, as their senders would have sent them, and
// expects no disagreement: each must be found persisted, its event ID
// recomputed (v3+), and its signatures, auth and state match.
//
//	SYNAPSE_DSN="host=/var/sockets user=synapse dbname=synapse-db" go test -run TestLiveOnStoredEvents ./internal/pduverify/
func TestLiveOnStoredEvents(t *testing.T) {
	dsn := os.Getenv("SYNAPSE_DSN")
	if dsn == "" {
		t.Skip("SYNAPSE_DSN not set")
	}
	ctx := context.Background()
	st, err := pdustore.Open(ctx, dsn, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	var pdus []json.RawMessage
	sampled, err := st.SampleEvents(ctx, []string{"5", "10", "11", "12"}, 5, 200000, false, false)
	if err != nil {
		t.Fatal(err)
	}
	for _, ids := range sampled {
		got, _, err := st.GetStoredEvents(ctx, ids)
		if err != nil {
			t.Fatal(err)
		}
		for _, se := range got {
			pdus = append(pdus, json.RawMessage(se.JSON))
		}
	}
	if len(pdus) == 0 {
		t.Skip("no events sampled")
	}
	body, _ := json.Marshal(map[string]any{"pdus": pdus})

	var mu sync.Mutex
	results := map[string][]*Result{}
	done := make(chan struct{}, 8*len(pdus))
	live := NewLive(New(st, stateres.Options{}), st, LiveOptions{
		MaxWait: 5 * time.Second,
		OnResult: func(check string, r *Result) {
			mu.Lock()
			results[check] = append(results[check], r)
			mu.Unlock()
			done <- struct{}{}
		},
	}, zerolog.Nop())
	defer live.Close()

	live.Prepare("", body, time.Now()).Commit()
	// Four checks (signatures, state_auth, soft_fail, push) per persisted PDU.
	deadline := time.After(2 * time.Minute)
	for n := 0; n < 4*len(pdus); n++ {
		select {
		case <-done:
		case <-deadline:
			t.Fatalf("only %d of %d results arrived", n, 4*len(pdus))
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if r := results["received"]; len(r) > 0 {
		t.Errorf("%d PDUs did not get past receipt, e.g. %+v", len(r), r[0])
	}
	// soft_fail and push are skipped throughout here: these events were
	// persisted before the snapshot.
	for _, check := range []string{"signatures", "state_auth", "soft_fail", "push"} {
		counts := map[string]int{}
		for _, r := range results[check] {
			counts[r.Outcome]++
			if r.Outcome == OutcomeMismatch || r.Outcome == OutcomeError {
				t.Errorf("%s %s: %s %s %v", check, r.EventID, r.Outcome, r.Reason, r.StateDiff)
			}
		}
		t.Logf("%s: %v", check, counts)
	}
}

func TestRescindsInvite(t *testing.T) {
	rv, _ := pdu.LookupRoomVersion("10")
	ev := func(sender, stateKey, membership string) *pdu.Event {
		raw := `{"type":"m.room.member","room_id":"!r:x","sender":"` + sender + `","state_key":"` + stateKey +
			`","content":{"membership":"` + membership + `"},"auth_events":[],"prev_events":[],"depth":1,"origin_server_ts":1}`
		e, err := pdu.ParseEvent([]byte(raw), "$e", rv, false)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	for _, c := range []struct {
		e    *pdu.Event
		want bool
	}{
		{ev("@a:remote", "@b:us", "leave"), true},
		{ev("@b:us", "@b:us", "leave"), false},         // our own leave
		{ev("@a:remote", "@c:remote", "leave"), false}, // not ours
		{ev("@a:remote", "@b:us", "ban"), false},
		{ev("@a:remote", "@b:usx", "leave"), false},
	} {
		if got := rescindsInvite(c.e, "us"); got != c.want {
			t.Errorf("%s -> %s: got %v", c.e.Sender, *c.e.StateKey, got)
		}
	}
}

// A label that an earlier one is a prefix of could never be reported.
func TestReasonLabelsAreReachable(t *testing.T) {
	for _, l := range reasonLabels {
		if got := reasonLabel(OutcomeMismatch, l); got != l {
			t.Errorf("%q is reported as %q", l, got)
		}
	}
}
