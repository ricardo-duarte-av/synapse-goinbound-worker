// Package inbound is write mode: what Synapse's inbound federation worker
// writes itself, written the same way (docs/write-mode.md). Everything here
// goes through a role granted exactly Grants and Sequences; everything else
// reaches Synapse over replication.
package inbound

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/dbrole"
)

// Grants is every table write mode touches, and how. TestQueriesUseOnlyGrants
// keeps it and the queries in step.
var Grants = []dbrole.Grant{
	{Table: "received_transactions", Privileges: "SELECT, INSERT"},
	{Table: "federation_inbound_events_staging", Privileges: "SELECT, INSERT, DELETE"},
	{Table: "worker_locks", Privileges: "SELECT, INSERT, UPDATE, DELETE"},
	{Table: "worker_read_write_locks", Privileges: "SELECT, INSERT, UPDATE, DELETE"},
	// Written by worker_read_write_locks' triggers, which run as the caller.
	{Table: "worker_read_write_locks_mode", Privileges: "SELECT, INSERT, UPDATE, DELETE"},
	// UPDATE only so the prev group can be locked FOR KEY SHARE, as
	// _get_existing_groups_with_lock does; nothing updates it.
	{Table: "state_groups", Privileges: "SELECT, INSERT, UPDATE (id)"},
	{Table: "state_group_edges", Privileges: "SELECT, INSERT"},
	{Table: "state_groups_state", Privileges: "SELECT, INSERT"},
	{Table: "state_groups_pending_deletion", Privileges: "SELECT, UPDATE"},
	{Table: "event_push_actions_staging", Privileges: "SELECT, INSERT, DELETE"},
	{Table: "event_failed_pull_attempts", Privileges: "SELECT, INSERT, UPDATE, DELETE"},
}

// Sequences are granted USAGE: new state group IDs, and the pending
// deletion bump's sequence_number = DEFAULT.
var Sequences = []string{"state_group_id_seq", "state_groups_pending_deletion_sequence_number_seq"}

// DB is the write connection.
type DB struct {
	pool *pgxpool.Pool
	// instance is our instance_name in lock rows. It must be no Synapse
	// process's: try_acquire_lock lets an instance take a lock it holds
	// under its own name.
	instance string
	now      func() time.Time
}

// Open connects as the write role.
func Open(ctx context.Context, dsn, instance string) (*DB, error) {
	if instance == "" {
		return nil, fmt.Errorf("inbound: no instance name")
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("inbound: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("inbound: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("inbound: %w", err)
	}
	return &DB{pool: pool, instance: instance, now: time.Now}, nil
}

// Close closes the pool.
func (d *DB) Close() { d.pool.Close() }

func (d *DB) nowMS() int64 { return d.now().UnixMilli() }

// randomString is random_string: letters only, from a secure source.
func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, n)
	for i := range b {
		k, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			panic(err)
		}
		b[i] = letters[k.Int64()]
	}
	return string(b)
}
