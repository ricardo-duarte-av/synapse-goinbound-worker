package stateres

import (
	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
)

// authChainDifference is _get_auth_chain_difference (v2.py:446) for events
// that are all persisted, computed by walking the auth DAG rather than through
// Synapse's chain cover index. The two give the same sets; the walk is simply
// slower, which an offline replay can afford.
//
// Definitions, as Synapse implements them:
//
//   - A state set's auth chain INCLUDES the set's own events
//     (event_federation.py _get_auth_chain_difference_txn marks each event as
//     present in the sets that hold it directly). The difference is every
//     event in some chain but not in all of them.
//   - For v2.1 the conflicted subgraph is added: events that are an ancestor of
//     some conflicted event AND a descendant of some conflicted event, plus the
//     conflicted events themselves (the chain cover version takes the
//     intersection of backwards- and forwards-reachable positions).
func (r *resolver) authChainDifference(stateSets []pdu.StateMap, conflicted map[string]bool) (map[string]bool, error) {
	closures := make([]map[string]bool, len(stateSets))
	for i, s := range stateSets {
		var start []string
		for _, id := range s {
			start = append(start, id)
		}
		c, err := r.closure(start)
		if err != nil {
			return nil, err
		}
		closures[i] = c
	}

	diff := map[string]bool{}
	for i, c := range closures {
		for id := range c {
			if diff[id] {
				continue
			}
			for j, other := range closures {
				if j != i && !other[id] {
					diff[id] = true
					break
				}
			}
		}
	}

	if r.rv.StateRes != pdu.StateResV21 {
		return diff, nil
	}

	sub, err := r.conflictedSubgraph(conflicted)
	if err != nil {
		return nil, err
	}
	for id := range sub {
		diff[id] = true
	}
	return diff, nil
}

// closure returns the events and all their auth ancestors.
func (r *resolver) closure(start []string) (map[string]bool, error) {
	seen := map[string]bool{}
	frontier := start
	for len(frontier) > 0 {
		var next []string
		for _, id := range frontier {
			if !seen[id] {
				seen[id] = true
				next = append(next, id)
			}
		}
		if len(next) == 0 {
			break
		}
		edges, err := r.authEdges(next)
		if err != nil {
			return nil, err
		}
		frontier = frontier[:0]
		for _, id := range next {
			for _, aid := range edges[id] {
				if !seen[aid] {
					frontier = append(frontier, aid)
				}
			}
		}
	}
	return seen, nil
}

// authEdges fetches auth edges, caching them for the life of the resolver.
func (r *resolver) authEdges(ids []string) (map[string][]string, error) {
	if r.edges == nil {
		r.edges = map[string][]string{}
	}
	var missing []string
	for _, id := range ids {
		if _, ok := r.edges[id]; !ok {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		got, err := r.store.AuthEdges(r.ctx, missing)
		if err != nil {
			return nil, err
		}
		for _, id := range missing {
			// An event with no rows still gets an entry, so it is not
			// fetched again.
			r.edges[id] = got[id]
		}
	}
	out := make(map[string][]string, len(ids))
	for _, id := range ids {
		out[id] = r.edges[id]
	}
	return out, nil
}

// conflictedSubgraph is the v2.1 conflicted subgraph: the conflicted events,
// and every event that lies on an auth path between two of them.
func (r *resolver) conflictedSubgraph(conflicted map[string]bool) (map[string]bool, error) {
	var start []string
	for id := range conflicted {
		start = append(start, id)
	}
	// Ancestors of the conflicted events, themselves included. Every path
	// from a conflicted event down to another lies inside this set.
	back, err := r.closure(start)
	if err != nil {
		return nil, err
	}

	// reaches[x]: x has a conflicted event among its strict ancestors, so x
	// is forwards-reachable from one.
	reaches := map[string]bool{}
	state := map[string]int{} // 0 unvisited, 1 in progress, 2 done
	var visit func(id string) bool
	visit = func(id string) bool {
		switch state[id] {
		case 2:
			return reaches[id]
		case 1:
			return false // the auth graph is acyclic; never revisit a frame
		}
		state[id] = 1
		res := false
		for _, aid := range r.edges[id] {
			if !back[aid] {
				continue
			}
			if conflicted[aid] || visit(aid) {
				res = true
			}
		}
		reaches[id], state[id] = res, 2
		return res
	}

	sub := map[string]bool{}
	for id := range back {
		if conflicted[id] || visit(id) {
			sub[id] = true
		}
	}
	return sub, nil
}
