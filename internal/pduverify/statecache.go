package pduverify

import (
	"container/list"
	"context"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdustore"
)

// DefaultStateCacheEntries bounds the state group cache. An entry costs about
// 210 bytes (measured on a 149k-entry group: 31MB), so this is ~85MB.
const DefaultStateCacheEntries = 400_000

// groupCache holds resolved state groups, least recently used first out,
// bounded by their total number of entries: the rooms worth caching are
// the big ones, where one group is 150k entries, so a bound on the number
// of groups bounds nothing. A group's contents never change.
type groupCache struct {
	mu      sync.Mutex
	budget  int
	entries int
	lru     *list.List // of *cached, most recent at the front
	byGroup map[int64]*list.Element
}

type cached struct {
	group int64
	state pdu.StateMap
}

func newGroupCache(budget int) *groupCache {
	if budget <= 0 {
		budget = DefaultStateCacheEntries
	}
	return &groupCache{budget: budget, lru: list.New(), byGroup: map[int64]*list.Element{}}
}

// SetStateCacheEntries changes the state cache's bound, emptying it.
func (s *Verifier) SetStateCacheEntries(n int) { s.groups = newGroupCache(n) }

func (c *groupCache) peek(g int64) (pdu.StateMap, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.byGroup[g]
	if !ok {
		return nil, false
	}
	c.lru.MoveToFront(e)
	return e.Value.(*cached).state, true
}

func (c *groupCache) put(g int64, m pdu.StateMap) {
	if len(m) > c.budget {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.byGroup[g]; ok {
		return
	}
	c.byGroup[g] = c.lru.PushFront(&cached{group: g, state: m})
	c.entries += len(m)
	for c.entries > c.budget {
		old := c.lru.Back()
		v := old.Value.(*cached)
		c.lru.Remove(old)
		delete(c.byGroup, v.group)
		c.entries -= len(v.state)
	}
	stateCacheEntries.Set(float64(c.entries))
}

// get returns a group's state. When the group it was stored as a delta of
// is cached -- in a room, the next event's group usually builds on the last
// one's -- it is rebuilt from that and its delta rows, rather than read in
// full: one row instead of 150k in a big room.
func (c *groupCache) get(ctx context.Context, st *pdustore.Store, g int64) (pdu.StateMap, error) {
	if m, ok := c.peek(g); ok {
		stateCacheLoads.WithLabelValues("hit").Inc()
		return m, nil
	}
	prev, hasPrev, delta, err := st.StateDelta(ctx, g)
	if err != nil {
		return nil, err
	}
	if hasPrev {
		if base, ok := c.peek(prev); ok {
			m := make(pdu.StateMap, len(base)+len(delta))
			for k, v := range base {
				m[k] = v
			}
			for k, v := range delta {
				m[k] = v
			}
			stateCacheLoads.WithLabelValues("delta").Inc()
			c.put(g, m)
			return m, nil
		}
	}
	m, err := st.StateForGroup(ctx, g)
	if err != nil {
		return nil, err
	}
	stateCacheLoads.WithLabelValues("full").Inc()
	c.put(g, m)
	return m, nil
}

var (
	stateCacheEntries = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "goinbound_pdu_state_cache_entries",
		Help: "State map entries held by the PDU checker's state group cache.",
	})
	stateCacheLoads = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "goinbound_pdu_state_cache_loads_total",
		Help: "State groups the PDU checker needed, by how they were got: hit (cached), delta (rebuilt from a cached prev group) or full (read from the database).",
	}, []string{"how"})
)
