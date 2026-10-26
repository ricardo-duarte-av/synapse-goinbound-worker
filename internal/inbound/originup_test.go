package inbound

import (
	"context"
	"testing"
)

// The reset is Synapse's upsert: a backed-off row is cleared, an unknown
// origin gets a cleared row, and each reset streams one invalidation under
// our name, with increasing IDs.
func TestResetDestination(t *testing.T) {
	ctx := context.Background()
	d := testDB(t, "goinbound-test")
	c := adminConn(t)
	if _, err := c.Exec(ctx, `INSERT INTO destinations (destination, failure_ts, retry_last_ts, retry_interval)
		VALUES ('down.example', 111, 222, 600000)`); err != nil {
		t.Fatal(err)
	}

	first, err := d.ResetDestination(ctx, "down.example")
	if err != nil {
		t.Fatal(err)
	}
	var failure *int64
	var last, interval int64
	if err := c.QueryRow(ctx, `SELECT failure_ts, retry_last_ts, retry_interval FROM destinations
		WHERE destination = 'down.example'`).Scan(&failure, &last, &interval); err != nil {
		t.Fatal(err)
	}
	if failure != nil || last != 0 || interval != 0 {
		t.Errorf("after reset: failure_ts %v, retry_last_ts %d, retry_interval %d; want NULL, 0, 0", failure, last, interval)
	}

	second, err := d.ResetDestination(ctx, "new.example")
	if err != nil {
		t.Fatal(err)
	}
	if second.StreamID <= first.StreamID {
		t.Errorf("stream IDs %d then %d; want increasing", first.StreamID, second.StreamID)
	}

	var inst, fn string
	var keys []string
	var ts int64
	if err := c.QueryRow(ctx, `SELECT instance_name, cache_func, keys, invalidation_ts
		FROM cache_invalidation_stream_by_instance WHERE stream_id = $1`, first.StreamID).Scan(&inst, &fn, &keys, &ts); err != nil {
		t.Fatal(err)
	}
	if inst != "goinbound-test" || fn != "get_destination_retry_timings" || len(keys) != 1 || keys[0] != "down.example" || ts != first.InvalidationTS {
		t.Errorf("invalidation row = %s %s %v %d", inst, fn, keys, ts)
	}
	var n int
	_ = c.QueryRow(ctx, `SELECT count(*) FROM destinations WHERE destination = 'new.example' AND retry_last_ts = 0`).Scan(&n)
	if n != 1 {
		t.Error("an unknown origin did not get a cleared row")
	}
}

// A backoff is stored only when it is longer or later than the stored one,
// as _set_destination_retry_timings_txn's WHERE has it; a clear always is.
func TestSetRetryTimings(t *testing.T) {
	ctx := context.Background()
	d := testDB(t, "goinbound-test")
	c := adminConn(t)
	c.Exec(ctx, `DELETE FROM destinations WHERE destination = 'flaky.example'`)
	read := func() (failure *int64, last, interval int64) {
		t.Helper()
		if err := c.QueryRow(ctx, `SELECT failure_ts, retry_last_ts, retry_interval FROM destinations WHERE destination = 'flaky.example'`).
			Scan(&failure, &last, &interval); err != nil {
			t.Fatal(err)
		}
		return
	}
	f := int64(1000)
	if _, err := d.SetRetryTimings(ctx, "flaky.example", &f, 1000, 600000); err != nil {
		t.Fatal(err)
	}
	if got, last, iv := read(); got == nil || *got != 1000 || last != 1000 || iv != 600000 {
		t.Errorf("first backoff: %v %d %d", got, last, iv)
	}
	// Older and shorter: kept as it was.
	if _, err := d.SetRetryTimings(ctx, "flaky.example", &f, 500, 300000); err != nil {
		t.Fatal(err)
	}
	if _, last, iv := read(); last != 1000 || iv != 600000 {
		t.Errorf("older backoff applied: %d %d", last, iv)
	}
	inv, err := d.SetRetryTimings(ctx, "flaky.example", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got, last, iv := read(); got != nil || last != 0 || iv != 0 {
		t.Errorf("cleared: %v %d %d", got, last, iv)
	}
	if inv.CacheFunc != CacheRetryTimings || len(inv.Keys) != 1 || inv.Keys[0] != "flaky.example" {
		t.Errorf("invalidation %+v", inv)
	}
}
