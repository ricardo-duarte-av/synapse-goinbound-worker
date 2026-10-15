// Package pyset reproduces the iteration order of CPython 3.13 sets of
// ints, where Synapse's answer depends on it.
package pyset

// Order is the order CPython 3.13 iterates set(set(ids)), the ids added in
// the order given. Synapse iterates such sets in, for example,
// state_group_ids_set (state/__init__.py resolve_state_groups_for_events,
// copied again by _get_state_for_groups_using_cache, whose dict order
// decides which group _make_state_cache_entry picks on a tie) and
// _get_chain_links' chains_to_fetch (which chains share a link batch).
//
// Small ints hash to themselves, so the order is the hash table's slot
// order, which depends on insertion order only when ids collide. This is
// Objects/setobject.c: set_add_entry, set_insert_clean, set_table_resize
// and set_merge. ids must be distinct and positive.
func Order(ids []int64) []int64 {
	s := newPySet()
	for _, id := range ids {
		s.add(id)
	}
	return s.copySet().slots()
}

const (
	pySetMinSize      = 8
	pySetLinearProbes = 9
	pySetPerturbShift = 5
)

type pySet struct {
	table []int64 // 0 is an empty slot
	used  int
}

func newPySet() *pySet { return &pySet{table: make([]int64, pySetMinSize)} }

func (s *pySet) mask() int { return len(s.table) - 1 }

// insertClean is set_insert_clean: place a key known to be absent.
func insertClean(table []int64, id int64) {
	mask := uint64(len(table) - 1)
	perturb := uint64(id)
	i := uint64(id) & mask
	for {
		if table[i] == 0 {
			table[i] = id
			return
		}
		if i+pySetLinearProbes <= mask {
			for j := uint64(1); j <= pySetLinearProbes; j++ {
				if table[i+j] == 0 {
					table[i+j] = id
					return
				}
			}
		}
		perturb >>= pySetPerturbShift
		i = (i*5 + 1 + perturb) & mask
	}
}

// add is set_add_entry for a key not yet present (no dummies: nothing is
// ever removed), then the resize check.
func (s *pySet) add(id int64) {
	insertClean(s.table, id)
	s.used++
	if s.used*5 >= s.mask()*3 {
		minused := s.used * 4
		if s.used > 50000 {
			minused = s.used * 2
		}
		s.resize(minused)
	}
}

// resize is set_table_resize: re-place every key, in table order.
func (s *pySet) resize(minused int) {
	size := pySetMinSize
	for size <= minused {
		size <<= 1
	}
	old := s.table
	s.table = make([]int64, size)
	for _, id := range old {
		if id != 0 {
			insertClean(s.table, id)
		}
	}
}

// copySet is set(s): set_merge into a new, empty set.
func (s *pySet) copySet() *pySet {
	c := newPySet()
	if s.used*5 >= c.mask()*3 {
		c.resize(s.used * 2)
	}
	if len(c.table) == len(s.table) {
		copy(c.table, s.table)
	} else {
		for _, id := range s.table {
			if id != 0 {
				insertClean(c.table, id)
			}
		}
	}
	c.used = s.used
	return c
}

func (s *pySet) slots() []int64 {
	out := make([]int64, 0, s.used)
	for _, id := range s.table {
		if id != 0 {
			out = append(out, id)
		}
	}
	return out
}
