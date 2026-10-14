package pdustore

import (
	"context"
	"fmt"
	"sort"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/stateres"
)

// The auth chain difference through Synapse's chain cover index, ported from
// _get_auth_chain_difference_using_cover_index_txn
// (storage/databases/main/event_federation.py:557, see also
// docs/auth_chain_difference_algorithm.md).
//
// Every event in the auth DAG sits at a (chain, sequence number) position;
// within a chain, a later event reaches every earlier one, and links record
// where a chain reaches into another. Reachability is answered from the links
// without ever walking the events themselves, which is what makes state
// resolution in a room with a hundred thousand members cheap.

// An event the chain cover index does not cover is reported as
// stateres.ErrNoChainCover. Synapse patches such sets up from
// event_auth_chain_to_calculate; that path is not ported, so state resolution
// falls back to walking the DAG.

// maxChainLength is MAX_CHAIN_LENGTH (event_federation.py:116).
const maxChainLength = (1 << 53) - 1

// chainBatch is how many origin chains _get_chain_links fetches per query.
// Only used to report how many batches Synapse would have needed.
const chainBatch = 1000

type position struct{ chain, seq int64 }

type link struct {
	originSeq    int64
	targetChain  int64
	targetSeqNum int64
}

const qChainInfo = `SELECT event_id, chain_id, sequence_number FROM event_auth_chains WHERE event_id = ANY($1)`

// qChainLinks fetches the links out of the given chains. Called breadth-first
// until no new chain turns up, it returns the same links as Synapse's
// recursive _get_chain_links query -- every link out of every chain reachable
// from the start -- in a few round trips instead of one recursive query per
// thousand chains. That difference is not small: in a room with 67k member
// chains Synapse's form takes 67 queries and 18 seconds.
const qChainLinks = `
	SELECT origin_chain_id, origin_sequence_number, target_chain_id, target_sequence_number
	FROM event_auth_chain_links WHERE origin_chain_id = ANY($1)`

// qChainGaps is _fetch_event_ids_from_chains_txn's Postgres form: every event
// in (min, max] of each chain, in one query.
const qChainGaps = `
	SELECT c.event_id
	FROM event_auth_chains AS c,
	     unnest($1::bigint[], $2::bigint[], $3::bigint[]) AS l(chain_id, min_seq, max_seq)
	WHERE c.chain_id = l.chain_id
	  AND l.min_seq < c.sequence_number AND c.sequence_number <= l.max_seq`

// AuthChainDifference computes the difference of the state sets' auth chains,
// each including its own events, and with conflicted set the v2.1 conflicted
// subgraph (nil otherwise). conflicted must be a subset of the state sets'
// events. It satisfies stateres.ChainCover.
func (s *Store) AuthChainDifference(ctx context.Context, stateSets []map[string]bool, conflicted map[string]bool) (map[string]bool, map[string]bool, error) {
	initial := map[string]bool{}
	for _, set := range stateSets {
		for id := range set {
			initial[id] = true
		}
	}

	info := map[string]position{}
	chainToEvent := map[int64]map[int64]string{}
	seenChains := map[int64]bool{}
	ids := make([]string, 0, len(initial))
	for id := range initial {
		ids = append(ids, id)
	}
	for start := 0; start < len(ids); start += 1000 {
		end := min(start+1000, len(ids))
		rows, err := s.pool.Query(ctx, qChainInfo, ids[start:end])
		if err != nil {
			return nil, nil, fmt.Errorf("pdustore: chain info: %w", err)
		}
		for rows.Next() {
			var id string
			var p position
			if err := rows.Scan(&id, &p.chain, &p.seq); err != nil {
				rows.Close()
				return nil, nil, err
			}
			info[id] = p
			seenChains[p.chain] = true
			if chainToEvent[p.chain] == nil {
				chainToEvent[p.chain] = map[int64]string{}
			}
			chainToEvent[p.chain][p.seq] = id
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return nil, nil, err
		}
	}
	for id := range initial {
		if _, ok := info[id]; !ok {
			return nil, nil, fmt.Errorf("%w: %s", stateres.ErrNoChainCover, id)
		}
	}

	v21 := conflicted != nil
	var conflictedPositions []position
	if v21 {
		for id := range conflicted {
			conflictedPositions = append(conflictedPositions, info[id])
		}
		sortPositions(conflictedPositions)
	}
	backReach := map[int64]int64{}
	fwdReach := map[int64]int64{}

	// For each state set: chain -> highest sequence number reachable.
	setToChain := make([]map[int64]int64, len(stateSets))
	for i, set := range stateSets {
		chains := map[int64]int64{}
		for id := range set {
			p := info[id]
			if p.seq > chains[p.chain] {
				chains[p.chain] = p.seq
			}
		}
		setToChain[i] = chains
	}

	// All links reachable from the chains seen. Synapse fetches these in
	// batches of a thousand origin chains, each answered with everything
	// reachable from it. For the auth difference the batching changes
	// nothing. For v2.1's forwards reachability it can: Synapse walks each
	// batch's links separately, so a path needing links from two batches
	// is missed -- and which links share a batch depends on Python set
	// order, so Synapse's own answer is not reproducible then. Using every
	// link at once gives true reachability; the batches metric says how
	// often Synapse would have needed more than one.
	links, err := s.allChainLinks(ctx, sortedChains(seenChains))
	if err != nil {
		return nil, nil, err
	}
	batches := (len(seenChains) + chainBatch - 1) / chainBatch

	for _, chains := range setToChain {
		for _, c := range sortedKeys(links) {
			if seq, ok := chains[c]; ok {
				materialize(c, seq, links, chains, true)
			}
		}
		for c := range chains {
			seenChains[c] = true
		}
	}

	if v21 {
		// accumulate_forwards_reachable_events, then the backwards walk.
		fwd := forwardLinks(links)
		for _, p := range conflictedPositions {
			if cur, ok := fwdReach[p.chain]; !ok || p.seq < cur {
				fwdReach[p.chain] = p.seq
			}
			materialize(p.chain, p.seq, fwd, fwdReach, false)
		}
		for _, p := range conflictedPositions {
			if _, ok := links[p.chain]; !ok {
				// Not on a path to the root.
				continue
			}
			if p.seq > backReach[p.chain] {
				backReach[p.chain] = p.seq
			}
			materialize(p.chain, p.seq, links, backReach, true)
		}
	}
	chainBatches.Observe(float64(batches))

	// The difference: on each chain, positions reachable from some set but
	// not from all of them.
	diff := map[string]bool{}
	gaps := map[int64][2]int64{}
	for _, c := range sortedChains(seenChains) {
		minSeq, maxSeq := int64(-1), int64(0)
		for _, chains := range setToChain {
			v := chains[c]
			if minSeq < 0 || v < minSeq {
				minSeq = v
			}
			if v > maxSeq {
				maxSeq = v
			}
		}
		if minSeq < maxSeq {
			for seq := minSeq + 1; seq <= maxSeq; seq++ {
				if id, ok := chainToEvent[c][seq]; ok {
					diff[id] = true
				} else {
					gaps[c] = [2]int64{minSeq, maxSeq}
					break
				}
			}
		}
	}

	var subgraph map[string]bool
	subGaps := map[int64][2]int64{}
	if v21 {
		subgraph = map[string]bool{}
		for c, b := range backReach {
			f, ok := fwdReach[c]
			if !ok || f > b {
				continue
			}
			for seq := f; seq <= b; seq++ {
				if id, ok := chainToEvent[c][seq]; ok {
					subgraph[id] = true
				} else {
					// _fetch_event_ids_from_chains_txn is exclusive of the
					// lower bound.
					subGaps[c] = [2]int64{f - 1, b}
					break
				}
			}
		}
	}

	if err := s.fillGaps(ctx, gaps, diff); err != nil {
		return nil, nil, err
	}
	if err := s.fillGaps(ctx, subGaps, subgraph); err != nil {
		return nil, nil, err
	}
	return diff, subgraph, nil
}

// allChainLinks returns every link out of every chain reachable from start,
// keyed by origin chain. Chains with no links have no entry, as in Synapse.
func (s *Store) allChainLinks(ctx context.Context, start []int64) (map[int64][]link, error) {
	out := map[int64][]link{}
	queried := map[int64]bool{}
	frontier := start
	for len(frontier) > 0 {
		for _, c := range frontier {
			queried[c] = true
		}
		var next []int64
		for i := 0; i < len(frontier); i += 50000 {
			batch := frontier[i:min(i+50000, len(frontier))]
			rows, err := s.pool.Query(ctx, qChainLinks, batch)
			if err != nil {
				return nil, fmt.Errorf("pdustore: chain links: %w", err)
			}
			for rows.Next() {
				var origin int64
				var l link
				if err := rows.Scan(&origin, &l.originSeq, &l.targetChain, &l.targetSeqNum); err != nil {
					rows.Close()
					return nil, err
				}
				out[origin] = append(out[origin], l)
				if !queried[l.targetChain] {
					queried[l.targetChain] = true
					next = append(next, l.targetChain)
				}
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return nil, fmt.Errorf("pdustore: chain links: %w", err)
			}
		}
		frontier = next
	}
	return out, nil
}

// fillGaps fetches the events in (lo, hi] of each chain into out.
func (s *Store) fillGaps(ctx context.Context, gaps map[int64][2]int64, out map[string]bool) error {
	if len(gaps) == 0 {
		return nil
	}
	var chains, lo, hi []int64
	for c, g := range gaps {
		chains, lo, hi = append(chains, c), append(lo, g[0]), append(hi, g[1])
	}
	rows, err := s.pool.Query(ctx, qChainGaps, chains, lo, hi)
	if err != nil {
		return fmt.Errorf("pdustore: chain gaps: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return err
		}
		out[id] = true
	}
	return rows.Err()
}

// materialize is _materialize (event_federation.py:2641).
func materialize(origin, seq int64, links map[int64][]link, materialized map[int64]int64, backwards bool) {
	stack := []position{{origin, seq}}
	for len(stack) > 0 {
		p := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, l := range links[p.chain] {
			if backwards {
				if l.originSeq > p.seq {
					continue
				}
				if materialized[l.targetChain] < l.targetSeqNum {
					stack = append(stack, position{l.targetChain, l.targetSeqNum})
					materialized[l.targetChain] = l.targetSeqNum
				}
			} else {
				if l.originSeq < p.seq {
					continue
				}
				cur, ok := materialized[l.targetChain]
				if !ok {
					cur = maxChainLength
				}
				if cur > l.targetSeqNum {
					stack = append(stack, position{l.targetChain, l.targetSeqNum})
					materialized[l.targetChain] = l.targetSeqNum
				}
			}
		}
	}
}

// forwardLinks is _generate_forward_links: the same links, reversed.
func forwardLinks(links map[int64][]link) map[int64][]link {
	out := map[int64][]link{}
	for origin, ls := range links {
		for _, l := range ls {
			out[l.targetChain] = append(out[l.targetChain], link{originSeq: l.targetSeqNum, targetChain: origin, targetSeqNum: l.originSeq})
		}
	}
	return out
}

func sortedChains(m map[int64]bool) []int64 {
	out := make([]int64, 0, len(m))
	for c := range m {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortedKeys(m map[int64][]link) []int64 {
	out := make([]int64, 0, len(m))
	for c := range m {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

func sortPositions(ps []position) {
	sort.Slice(ps, func(i, j int) bool {
		if ps[i].chain != ps[j].chain {
			return ps[i].chain < ps[j].chain
		}
		return ps[i].seq < ps[j].seq
	})
}

// chainBatches counts how many _get_chain_links batches a difference needed.
// Above one, Synapse's own answer for v2.1 depends on set iteration order, so
// a disagreement there is not necessarily ours.
var chainBatches = promauto.NewHistogram(prometheus.HistogramOpts{
	Name:    "goinbound_pdu_chain_link_batches",
	Help:    "Chain link batches per auth chain difference.",
	Buckets: []float64{1, 2, 3, 5, 10},
})
