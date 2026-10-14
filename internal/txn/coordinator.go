package txn

import (
	"sync"
	"time"
)

// answer is a response we gave, kept so a retry gets the same one.
type answer struct {
	status int
	body   []byte
}

// flight is the transaction currently being handled for one origin.
type flight struct {
	txnID string
	done  chan struct{}
}

type cacheKey struct{ origin, txnID string }

type cached struct {
	answer
	expires time.Time
}

// coordinator reproduces the two guarantees Synapse makes about concurrent
// transactions (federation_server.py:341-369):
//
//   - One transaction per origin at a time. A different transaction from an
//     origin that already has one in progress is refused with a 429, and the
//     refusal is not remembered, so the same transaction can be retried.
//   - A retry of a transaction gets the answer the first attempt got. A
//     retry that arrives while the first attempt is still running waits for
//     it; one that arrives within 30 seconds after gets its answer from cache
//     (Synapse's ResponseCache timeout).
//
// It covers proxied transactions too. Synapse's own copy of the first rule
// only sees the transactions that reach it, so without this a native
// transaction and a proxied one from the same origin could run at once -- which
// is exactly the reordering the rule exists to prevent.
type coordinator struct {
	ttl time.Duration
	now func() time.Time

	mu     sync.Mutex
	active map[string]*flight
	cache  map[cacheKey]cached
}

func newCoordinator(ttl time.Duration) *coordinator {
	return &coordinator{
		ttl:    ttl,
		now:    time.Now,
		active: make(map[string]*flight),
		cache:  make(map[cacheKey]cached),
	}
}

// begin claims the origin for txnID.
//
// Exactly one of the results is meaningful: own is the caller's claim, to be
// passed to end; wait is a flight for the SAME transaction to wait on before
// calling begin again; busy means the origin is handling a different
// transaction.
func (c *coordinator) begin(origin, txnID string) (own *flight, wait *flight, busy bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if f, ok := c.active[origin]; ok {
		if f.txnID == txnID {
			return nil, f, false
		}
		return nil, nil, true
	}
	f := &flight{txnID: txnID, done: make(chan struct{})}
	c.active[origin] = f
	return f, nil, false
}

// lookup returns the cached answer for a transaction, if any.
func (c *coordinator) lookup(origin, txnID string) (answer, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.cache[cacheKey{origin, txnID}]
	if !ok || c.now().After(e.expires) {
		return answer{}, false
	}
	return e.answer, true
}

// end releases the claim. A non-nil ans is remembered for retries.
//
// Only answers we produced ourselves are remembered. For a proxied
// transaction Synapse keeps its own ResponseCache and received_transactions
// row, so a retry proxied again gets Synapse's answer from Synapse.
func (c *coordinator) end(origin string, f *flight, ans *answer) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.active[origin] == f {
		delete(c.active, origin)
	}
	if ans != nil {
		now := c.now()
		if len(c.cache) >= 1024 {
			for k, e := range c.cache {
				if now.After(e.expires) {
					delete(c.cache, k)
				}
			}
		}
		c.cache[cacheKey{origin, f.txnID}] = cached{answer: *ans, expires: now.Add(c.ttl)}
	}
	close(f.done)
}
