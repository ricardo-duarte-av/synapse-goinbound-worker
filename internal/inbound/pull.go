package inbound

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Failed pull attempts (event_federation.py record_event_failed_pull_attempt
// and get_event_ids_to_not_pull_from_backoff). The persister clears an
// event's row when it persists the event.

const (
	qRecordFailedPull = `
		INSERT INTO event_failed_pull_attempts (room_id, event_id, num_attempts, last_attempt_ts, last_cause)
		VALUES ($1, $2, 1, $3, $4)
		ON CONFLICT (room_id, event_id) DO UPDATE SET
			num_attempts = event_failed_pull_attempts.num_attempts + 1,
			last_attempt_ts = EXCLUDED.last_attempt_ts,
			last_cause = EXCLUDED.last_cause`
	// Not filtered by room, as Synapse does not filter it either.
	qFailedPulls = `
		SELECT event_id, last_attempt_ts, num_attempts
		FROM event_failed_pull_attempts WHERE event_id = ANY($1)`
)

// The backoff: 2^attempts hours, the exponent at most 8.
const (
	pullBackoffStep     = time.Hour
	pullBackoffDoubling = 8
)

// RecordFailedPull is record_event_failed_pull_attempt.
func (d *DB) RecordFailedPull(ctx context.Context, roomID, eventID, cause string) error {
	if _, err := d.pool.Exec(ctx, qRecordFailedPull, roomID, eventID, d.nowMS(), cause); err != nil {
		return fmt.Errorf("inbound: record failed pull: %w", err)
	}
	return nil
}

// FailedPulls is get_event_ids_with_failed_pull_attempts.
func (d *DB) FailedPulls(ctx context.Context, eventIDs []string) (map[string]bool, error) {
	rows, err := d.failedPullRows(ctx, eventIDs)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, r := range rows {
		out[r.id] = true
	}
	return out, nil
}

// PullBackoff is get_event_ids_to_not_pull_from_backoff: events not to pull
// again yet, with the time they may be.
func (d *DB) PullBackoff(ctx context.Context, eventIDs []string) (map[string]int64, error) {
	rows, err := d.failedPullRows(ctx, eventIDs)
	if err != nil {
		return nil, err
	}
	now := d.nowMS()
	out := map[string]int64{}
	for _, r := range rows {
		end := r.last + (int64(1)<<min(r.attempts, pullBackoffDoubling))*pullBackoffStep.Milliseconds()
		if now < end {
			out[r.id] = end
		}
	}
	return out, nil
}

type failedPull struct {
	id       string
	last     int64
	attempts int
}

func (d *DB) failedPullRows(ctx context.Context, eventIDs []string) ([]failedPull, error) {
	if len(eventIDs) == 0 {
		return nil, nil
	}
	rows, err := d.pool.Query(ctx, qFailedPulls, eventIDs)
	if err != nil {
		return nil, fmt.Errorf("inbound: failed pulls: %w", err)
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (failedPull, error) {
		var f failedPull
		err := r.Scan(&f.id, &f.last, &f.attempts)
		return f, err
	})
}
