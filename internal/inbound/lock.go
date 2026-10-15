package inbound

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Synapse's lock names.
const (
	// LockInboundPDU is _INBOUND_EVENT_HANDLING_LOCK_NAME
	// (federation_server.py:138), keyed by room: one process drains a
	// room's staging queue at a time.
	LockInboundPDU = "federation_inbound_pdu"
	// LockPurge is NEW_EVENT_DURING_PURGE_LOCK_NAME (handlers/worker_lock.py:55):
	// a read lock per room while an event is handled, so a purge (the
	// write lock) waits.
	LockPurge = "new_event_during_purge_lock"
)

// The lock timings (storage/databases/main/lock.py).
const (
	lockRenewal = 30 * time.Second
	lockTimeout = 2 * time.Minute
	// maxLockWait is WORKER_LOCK_MAX_RETRY_INTERVAL.
	maxLockWait = 5 * time.Second
)

// qTryAcquireLock is _try_acquire_lock_txn. A lock not renewed within the
// timeout can be taken, and so can one held under our own instance name.
const qTryAcquireLock = `
	INSERT INTO worker_locks (lock_name, lock_key, instance_name, token, last_renewed_ts)
	VALUES ($1, $2, $3, $4, $5)
	ON CONFLICT (lock_name, lock_key)
	DO UPDATE
		SET
			token = EXCLUDED.token,
			instance_name = EXCLUDED.instance_name,
			last_renewed_ts = EXCLUDED.last_renewed_ts
		WHERE
			worker_locks.last_renewed_ts < $6
			OR worker_locks.instance_name = EXCLUDED.instance_name`

// qTryAcquireRWLock is _try_acquire_read_write_lock_txn. A conflicting lock
// makes the triggers' insert into worker_read_write_locks_mode fail.
const qTryAcquireRWLock = `
	INSERT INTO worker_read_write_locks (lock_name, lock_key, write_lock, instance_name, token, last_renewed_ts)
	VALUES ($1, $2, $3, $4, $5, $6)`

const (
	qRenewLock       = `UPDATE worker_locks SET last_renewed_ts = $4 WHERE lock_name = $1 AND lock_key = $2 AND token = $3`
	qRenewRWLock     = `UPDATE worker_read_write_locks SET last_renewed_ts = $4 WHERE lock_name = $1 AND lock_key = $2 AND token = $3`
	qDropLock        = `DELETE FROM worker_locks WHERE lock_name = $1 AND lock_key = $2 AND token = $3`
	qDropRWLock      = `DELETE FROM worker_read_write_locks WHERE lock_name = $1 AND lock_key = $2 AND token = $3`
	qLockRenewedTS   = `SELECT last_renewed_ts FROM worker_locks WHERE lock_name = $1 AND lock_key = $2 AND token = $3`
	qRWLockRenewedTS = `SELECT last_renewed_ts FROM worker_read_write_locks WHERE lock_name = $1 AND lock_key = $2 AND token = $3`
)

// Lock is a held lock, renewed until released.
type Lock struct {
	d         *DB
	readWrite bool
	name, key string
	token     string

	once sync.Once
	stop chan struct{}
	done chan struct{}
}

// Locks remembers which locks this process holds, as LockStore's
// _live_lock_tokens and _acquiring_locks do: a lock we hold is not taken
// again under our own name.
type Locks struct {
	d    *DB
	mu   sync.Mutex
	held map[[2]string]*Lock
	busy map[[2]string]bool
}

// NewLocks is the lock store over d.
func NewLocks(d *DB) *Locks {
	return &Locks{d: d, held: map[[2]string]*Lock{}, busy: map[[2]string]bool{}}
}

// TryAcquire is try_acquire_lock: the lock, or nil when someone holds it.
func (l *Locks) TryAcquire(ctx context.Context, name, key string) (*Lock, error) {
	k := [2]string{name, key}
	l.mu.Lock()
	if l.busy[k] {
		l.mu.Unlock()
		return nil, nil
	}
	l.busy[k] = true
	held := l.held[k]
	l.mu.Unlock()
	defer func() {
		l.mu.Lock()
		delete(l.busy, k)
		l.mu.Unlock()
	}()

	if held != nil {
		ok, err := held.StillValid(ctx)
		if err != nil {
			return nil, err
		}
		if ok {
			return nil, nil
		}
	}
	now := l.d.nowMS()
	token := randomString(6)
	tag, err := l.d.pool.Exec(ctx, qTryAcquireLock, name, key, l.d.instance, token, now, now-lockTimeout.Milliseconds())
	if err != nil {
		return nil, fmt.Errorf("inbound: acquire %s %s: %w", name, key, err)
	}
	if tag.RowsAffected() == 0 {
		return nil, nil
	}
	lock := l.d.newLock(false, name, key, token, func() {
		l.mu.Lock()
		if l.held[k] != nil && l.held[k].token == token {
			delete(l.held, k)
		}
		l.mu.Unlock()
	})
	l.mu.Lock()
	l.held[k] = lock
	l.mu.Unlock()
	return lock, nil
}

// TryAcquireReadWrite is try_acquire_read_write_lock: nil when a
// conflicting lock is held.
func (l *Locks) TryAcquireReadWrite(ctx context.Context, name, key string, write bool) (*Lock, error) {
	token := randomString(6)
	_, err := l.d.pool.Exec(ctx, qTryAcquireRWLock, name, key, write, l.d.instance, token, l.d.nowMS())
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code[:2] == "23" {
		// IntegrityError: someone holds it in the other mode.
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("inbound: acquire %s %s: %w", name, key, err)
	}
	return l.d.newLock(true, name, key, token, nil), nil
}

// AcquireReadWrite waits for a read/write lock, as WaitingLock does:
// retrying from 100ms, doubling, at most every 5s. Synapse also wakes
// waiters when a lock is released, over replication; we only poll.
func (l *Locks) AcquireReadWrite(ctx context.Context, name, key string, write bool) (*Lock, error) {
	wait := 100 * time.Millisecond
	for {
		lock, err := l.TryAcquireReadWrite(ctx, name, key, write)
		if err != nil || lock != nil {
			return lock, err
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(wait):
		}
		wait = min(wait*2, maxLockWait)
	}
}

func (d *DB) newLock(readWrite bool, name, key, token string, onRelease func()) *Lock {
	lk := &Lock{d: d, readWrite: readWrite, name: name, key: key, token: token,
		stop: make(chan struct{}), done: make(chan struct{})}
	go lk.renew(onRelease)
	return lk
}

// renew is Lock._renew every 30s, until released.
func (lk *Lock) renew(onRelease func()) {
	defer close(lk.done)
	if onRelease != nil {
		defer onRelease()
	}
	q := qRenewLock
	if lk.readWrite {
		q = qRenewRWLock
	}
	t := time.NewTicker(lockRenewal)
	defer t.Stop()
	for {
		select {
		case <-lk.stop:
			return
		case <-t.C:
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			_, _ = lk.d.pool.Exec(ctx, q, lk.name, lk.key, lk.token, lk.d.nowMS())
			cancel()
		}
	}
}

// StillValid is is_still_valid: our row is there and was renewed in time.
func (lk *Lock) StillValid(ctx context.Context) (bool, error) {
	q := qLockRenewedTS
	if lk.readWrite {
		q = qRWLockRenewedTS
	}
	var ts int64
	err := lk.d.pool.QueryRow(ctx, q, lk.name, lk.key, lk.token).Scan(&ts)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, fmt.Errorf("inbound: lock valid: %w", err)
	}
	return lk.d.nowMS()-lockTimeout.Milliseconds() < ts, nil
}

// Release stops renewing and deletes our row. Safe to call more than once.
func (lk *Lock) Release(ctx context.Context) error {
	var err error
	lk.once.Do(func() {
		close(lk.stop)
		<-lk.done
		q := qDropLock
		if lk.readWrite {
			q = qDropRWLock
		}
		_, err = lk.d.pool.Exec(ctx, q, lk.name, lk.key, lk.token)
	})
	return err
}
