package pduverify

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

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
	for _, v := range []string{"5", "10", "11", "12"} {
		ids, err := st.SampleEvents(ctx, v, 5, 200000, false, false)
		if err != nil {
			t.Fatal(err)
		}
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
	done := make(chan struct{}, 4*len(pdus))
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

	live.Submit(body)
	// Two checks (signatures, state_auth) per persisted PDU.
	deadline := time.After(2 * time.Minute)
	for n := 0; n < 2*len(pdus); n++ {
		select {
		case <-done:
		case <-deadline:
			t.Fatalf("only %d of %d results arrived", n, 2*len(pdus))
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if r := results["received"]; len(r) > 0 {
		t.Errorf("%d PDUs did not get past receipt, e.g. %+v", len(r), r[0])
	}
	for _, check := range []string{"signatures", "state_auth"} {
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
