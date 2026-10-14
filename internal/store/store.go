// Package store reads Synapse's PostgreSQL database.
//
// It only reads. Native EDU handling hands every write to Synapse's own stream
// writers over replication, so this worker has nothing to write: the queries
// here are all SELECTs, and TestEveryQueryIsASelect keeps it that way.
//
// Every query has a name, used as the label on its latency histogram. An
// unnamed query is one nobody can find on a dashboard.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Config describes the connection.
type Config struct {
	DSN string
	// User, when set, replaces any user the DSN names.
	User string
	// Password is used when the DSN carries none. It is how the derived
	// password of a managed role (package dbrole) reaches the connection
	// without being written into any config file.
	Password       string
	MaxConns       int32
	ConnectTimeout time.Duration
	// QueryTimeout bounds each query. Zero means no bound beyond the
	// caller's context.
	QueryTimeout time.Duration
}

// Store is a read-only handle on Synapse's database.
type Store struct {
	pool         *pgxpool.Pool
	queryTimeout time.Duration
}

// Open connects to the database.
func Open(ctx context.Context, cfg Config) (*Store, error) {
	pcfg, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("store: parse dsn: %w", err)
	}
	if cfg.MaxConns > 0 {
		pcfg.MaxConns = cfg.MaxConns
	}
	if cfg.User != "" {
		pcfg.ConnConfig.User = cfg.User
	}
	if pcfg.ConnConfig.Password == "" && cfg.Password != "" {
		pcfg.ConnConfig.Password = cfg.Password
	}
	// The database sits behind pgcat in transaction pooling mode. Any mode
	// that prepares a statement on one round trip and executes it on the next
	// can land the two on different server connections, and fails with
	// "unnamed prepared statement does not exist" (SQLSTATE 26000). Exec mode
	// sends each query in one go.
	pcfg.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeExec
	if cfg.ConnectTimeout > 0 {
		pcfg.ConnConfig.ConnectTimeout = cfg.ConnectTimeout
	}

	pool, err := pgxpool.NewWithConfig(ctx, pcfg)
	if err != nil {
		return nil, fmt.Errorf("store: connect: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("store: ping: %w", err)
	}
	return &Store{pool: pool, queryTimeout: cfg.QueryTimeout}, nil
}

// Close releases the pool.
func (s *Store) Close() {
	if s != nil && s.pool != nil {
		s.pool.Close()
	}
}

// IsReadOnly reports whether the connected role defaults to read-only
// transactions. Checked at startup and reported: this worker never writes, and
// a role that cannot is the structural guarantee of that.
func (s *Store) IsReadOnly(ctx context.Context) (bool, error) {
	var v string
	if err := s.queryRow(ctx, "is_read_only", qIsReadOnly).Scan(&v); err != nil {
		return false, fmt.Errorf("store: check read-only: %w", err)
	}
	return v == "on", nil
}

const qIsReadOnly = `SELECT current_setting('default_transaction_read_only')`

// row defers the query's context cancellation and timing until Scan, since a
// pgx.Row is only read then.
type row struct {
	row    pgx.Row
	cancel context.CancelFunc
	name   string
	start  time.Time
}

func (r row) Scan(dest ...any) error {
	defer r.cancel()
	err := r.row.Scan(dest...)
	observe(r.name, r.start, err)
	return err
}

func (s *Store) queryRow(ctx context.Context, name, sql string, args ...any) row {
	ctx, cancel := s.withTimeout(ctx)
	return row{row: s.pool.QueryRow(ctx, sql, args...), cancel: cancel, name: name, start: time.Now()}
}

func (s *Store) withTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if s.queryTimeout > 0 {
		return context.WithTimeout(ctx, s.queryTimeout)
	}
	return context.WithCancel(ctx)
}

func observe(name string, start time.Time, err error) {
	result := "ok"
	switch {
	case err == nil, errors.Is(err, pgx.ErrNoRows):
	case errors.Is(err, context.DeadlineExceeded):
		result = "timeout"
	default:
		result = "error"
	}
	queryDuration.WithLabelValues(name, result).Observe(time.Since(start).Seconds())
}

var queryDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
	Name:    "goinbound_db_query_duration_seconds",
	Help:    "Time spent on each named database query.",
	Buckets: []float64{.0005, .001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2.5, 5},
}, []string{"query", "result"})
