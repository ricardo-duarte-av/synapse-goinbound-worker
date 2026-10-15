package inbound

import (
	"slices"
	"testing"
)

// sorted_topologically: auth events first, ties by the smallest ID, cycles
// never yielded.
func TestSortedTopologically(t *testing.T) {
	got := sortedTopologically([]string{"$c", "$a", "$b", "$d"}, map[string][]string{
		"$c": {"$a"}, "$b": {"$a", "$a"}, "$d": {"$c", "$b"},
	})
	if want := []string{"$a", "$b", "$c", "$d"}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	got = sortedTopologically([]string{"$x", "$y", "$z"}, map[string][]string{"$x": {"$y"}, "$y": {"$x"}})
	if want := []string{"$z"}; !slices.Equal(got, want) {
		t.Errorf("cycle: got %v, want %v", got, want)
	}
	// Edges to events outside the batch do not count.
	got = sortedTopologically([]string{"$b", "$a"}, map[string][]string{"$a": {"$elsewhere"}})
	if want := []string{"$a", "$b"}; !slices.Equal(got, want) {
		t.Errorf("outside edges: got %v", got)
	}
}
