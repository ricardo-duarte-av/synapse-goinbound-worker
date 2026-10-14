package pduverify

import (
	"maps"
	"testing"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
)

func sk(t, k string) pdu.StateKey { return pdu.StateKey{Type: t, StateKey: k} }

func TestPlanBefore(t *testing.T) {
	a := pdu.StateMap{sk("m.room.create", ""): "$c", sk("m.room.member", "@a:x"): "$a1"}
	b := pdu.StateMap{sk("m.room.create", ""): "$c", sk("m.room.member", "@a:x"): "$a2"}
	ab := pdu.StateMap{sk("m.room.create", ""): "$c", sk("m.room.member", "@a:x"): "$a2", sk("m.room.member", "@b:x"): "$b1"}
	extra := pdu.StateMap{sk("m.room.create", ""): "$c", sk("m.room.topic", ""): "$t"}

	cases := []struct {
		name     string
		groups   []int64
		sets     []pdu.StateMap
		resolved pdu.StateMap
		want     string
		tie      bool
	}{
		{"one group", []int64{5}, []pdu.StateMap{a}, a, "reuse 5", false},
		{"exact match", []int64{5, 6}, []pdu.StateMap{a, b}, b, "reuse 6", false},
		{"two exact matches", []int64{5, 6}, []pdu.StateMap{a, a}, a, "reuse 5", true},
		{"smallest delta", []int64{5, 6}, []pdu.StateMap{a, b}, ab, "new from 6 +1", false},
		{"equal deltas", []int64{5, 6}, []pdu.StateMap{b, maps.Clone(b)}, ab, "new from 5 +1", true},
		{"a group with a key the result lacks is no base", []int64{5, 7}, []pdu.StateMap{extra, a}, ab, "new from 7 +2", false},
		{"no base at all", []int64{7, 8}, []pdu.StateMap{extra, maps.Clone(extra)}, a, "new_full", false},
	}
	for _, c := range cases {
		got := planBefore(c.groups, c.sets, c.resolved)
		if got.String() != c.want || got.tie != c.tie {
			t.Errorf("%s: got %s (tie %v), want %s (tie %v)", c.name, got, got.tie, c.want, c.tie)
		}
	}
}

// Groups 8 and 16 share slot 0 of an 8-slot table, so which one Synapse
// iterates first depends on insertion order: a real tie. 9 and 16 do not.
func TestPlanOrderedResolvesTiesBySetOrder(t *testing.T) {
	b := pdu.StateMap{sk("m.room.create", ""): "$c", sk("m.room.member", "@a:x"): "$a2"}
	ab := pdu.StateMap{sk("m.room.create", ""): "$c", sk("m.room.member", "@a:x"): "$a2", sk("m.room.member", "@b:x"): "$b1"}
	if p := planOrdered([]int64{16, 9}, []pdu.StateMap{b, maps.Clone(b)}, ab); p.tie || p.prev != 16 {
		t.Errorf("16, 9: got %s tie %v, want new from 16 (slot 0 before slot 1)", p, p.tie)
	}
	if p := planOrdered([]int64{16, 8}, []pdu.StateMap{b, maps.Clone(b)}, ab); !p.tie {
		t.Errorf("16, 8: got %s, want a tie", p)
	}
}
