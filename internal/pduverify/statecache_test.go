package pduverify

import (
	"testing"

	"github.com/ricardo-duarte-av/synapse-goinbound-worker/internal/pdu"
)

func TestDiffAfterOverlay(t *testing.T) {
	k := func(t, s string) pdu.StateKey { return pdu.StateKey{Type: t, StateKey: s} }
	before := pdu.StateMap{k("m.room.create", ""): "$c", k("m.room.member", "@a"): "$a1"}
	own := k("m.room.member", "@a")
	stored := pdu.StateMap{k("m.room.create", ""): "$c", k("m.room.member", "@a"): "$a2"}
	if d := diffAfter(before, &own, "$a2", stored); len(d) != 0 {
		t.Errorf("the event replacing a key: %v", d)
	}
	newKey := k("m.room.member", "@b")
	stored2 := pdu.StateMap{k("m.room.create", ""): "$c", k("m.room.member", "@a"): "$a1", newKey: "$b"}
	if d := diffAfter(before, &newKey, "$b", stored2); len(d) != 0 {
		t.Errorf("the event adding a key: %v", d)
	}
	if d := diffAfter(before, nil, "", stored2); len(d) != 1 {
		t.Errorf("a stored key we lack was not reported: %v", d)
	}
	if len(before) != 2 || before[own] != "$a1" {
		t.Error("diffAfter changed the state before")
	}
}

func TestGroupCacheBoundByEntries(t *testing.T) {
	big := func(n int) pdu.StateMap {
		m := pdu.StateMap{}
		for i := 0; i < n; i++ {
			m[pdu.StateKey{Type: "t", StateKey: string(rune(i + 1))}] = "$e"
		}
		return m
	}
	c := newGroupCache(250)
	c.put(1, big(100))
	c.put(2, big(100))
	c.peek(1) // 1 is now more recent than 2
	c.put(3, big(100))
	if _, ok := c.peek(2); ok {
		t.Error("the least recently used group was kept over the bound")
	}
	if _, ok := c.peek(1); !ok {
		t.Error("a recently used group was evicted")
	}
	if c.entries > 250 {
		t.Errorf("entries %d over the bound", c.entries)
	}
	c.put(4, big(300))
	if _, ok := c.peek(4); ok {
		t.Error("a group larger than the whole bound was cached")
	}
}
