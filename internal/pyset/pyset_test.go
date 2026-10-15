package pyset

import (
	"encoding/json"
	"os"
	"slices"
	"testing"
)

// testdata/pyset_cases.json is [ids, list(set(set(ids)))] pairs printed by
// the Python 3.13 in the Synapse image.
func TestPySetOrderMatchesCPython(t *testing.T) {
	b, err := os.ReadFile("testdata/pyset_cases.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases [][2][]int64
	if err := json.Unmarshal(b, &cases); err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		if got := Order(c[0]); !slices.Equal(got, c[1]) {
			t.Errorf("set(set(%v)) = %v, want %v", c[0], got, c[1])
		}
	}
}
