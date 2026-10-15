package pdustore

import (
	"encoding/json"
	"maps"
	"os"
	"testing"
)

// testdata/forward_cases.json is printed by Synapse 1.162's own
// accumulate_forwards_reachable_events, fed batch by batch by a copy of
// _get_chain_links' loop over a CPython set (the recursive query done in
// memory), on random chain graphs of more than one batch.
func TestBatchedForwardReachMatchesSynapse(t *testing.T) {
	b, err := os.ReadFile("testdata/forward_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []struct {
		Insertion  []int64    `json:"insertion"`
		Links      [][4]int64 `json:"links"`
		Conflicted [][2]int64 `json:"conflicted"`
		Fwd        [][2]int64 `json:"fwd"`
	}
	if err := json.Unmarshal(b, &cases); err != nil {
		t.Fatal(err)
	}
	differs := 0
	for i, c := range cases {
		links := map[int64][]link{}
		for _, l := range c.Links {
			links[l[0]] = append(links[l[0]], link{originSeq: l[1], targetChain: l[2], targetSeqNum: l[3]})
		}
		var conflicted []position
		for _, p := range c.Conflicted {
			conflicted = append(conflicted, position{p[0], p[1]})
		}
		want := map[int64]int64{}
		for _, f := range c.Fwd {
			want[f[0]] = f[1]
		}
		if got := batchedForwardReach(c.Insertion, links, conflicted); !maps.Equal(got, want) {
			t.Errorf("case %d: %d chains reached, Synapse %d", i, len(got), len(want))
		}
		all := map[int64]int64{}
		accumulateForwards(all, links, conflicted)
		if !maps.Equal(all, want) {
			differs++
		}
	}
	// Otherwise the cases would not test the batching.
	if differs == 0 {
		t.Error("no case where batching changes Synapse's answer")
	}
	t.Logf("%d of %d cases differ from walking every link at once", differs, len(cases))
}
