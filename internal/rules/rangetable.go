package rules

import (
	"container/heap"
	"math"
	"sort"
)

// u128 is an unsigned 128-bit value, used for IPv6 prefixes.
type u128 struct{ hi, lo uint64 }

func cmpU128(a, b u128) int {
	switch {
	case a.hi < b.hi:
		return -1
	case a.hi > b.hi:
		return 1
	case a.lo < b.lo:
		return -1
	case a.lo > b.lo:
		return 1
	}
	return 0
}

// incU128 adds one and reports whether the result wrapped around.
func incU128(v u128) (u128, bool) {
	if v.lo != math.MaxUint64 {
		return u128{hi: v.hi, lo: v.lo + 1}, false
	}
	if v.hi == math.MaxUint64 {
		return u128{}, true
	}
	return u128{hi: v.hi + 1}, false
}

// decU128 subtracts one. The caller guarantees the value is not zero.
func decU128(v u128) u128 {
	if v.lo != 0 {
		return u128{hi: v.hi, lo: v.lo - 1}
	}
	return u128{hi: v.hi - 1, lo: math.MaxUint64}
}

func cmpU32(a, b uint32) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// bound is a position on the address line. past marks one past the largest
// address and sorts after every real position, which keeps interval maths free
// of wrap-around special cases.
type bound struct {
	v    u128
	past bool
}

func boundOf(v u128) bound      { return bound{v: v} }
func boundPast() bound          { return bound{past: true} }
func boundOfU32(v uint32) bound { return bound{v: u128{lo: uint64(v)}} }

func cmpBound(a, b bound) int {
	switch {
	case a.past && b.past:
		return 0
	case a.past:
		return 1
	case b.past:
		return -1
	}
	return cmpU128(a.v, b.v)
}

// prev returns the position one below b, treating the position as an exclusive
// upper boundary.
func (b bound) prev() bound {
	if b.past {
		return boundOf(u128{hi: math.MaxUint64, lo: math.MaxUint64})
	}
	return boundOf(decU128(b.v))
}

// next returns the position one above b.
func (b bound) next() bound {
	if b.past {
		return b
	}
	v, wrapped := incU128(b.v)
	if wrapped {
		return boundPast()
	}
	return boundOf(v)
}

// block is one prefix in the address line, [start, end).
type block struct {
	start bound
	end   bound
	idx   int32
}

// builtRange is a disjoint, sorted range that resolves to a single rule index.
type builtRange struct {
	start bound
	end   bound // inclusive
	idx   int32
}

// buildRanges turns a set of prefixes into sorted, disjoint ranges. Prefixes
// are either disjoint or nested, but the sweep handles arbitrary overlap too:
// every elementary interval keeps the lowest rule index covering it, which is
// the first-match-wins semantics of the rule list.
func buildRanges(blocks []block) []builtRange {
	if len(blocks) == 0 {
		return nil
	}
	events := make([]event, 0, 2*len(blocks))
	for _, b := range blocks {
		events = append(events, event{pos: b.start, open: true, idx: b.idx})
		events = append(events, event{pos: b.end, open: false, idx: b.idx})
	}
	sort.Slice(events, func(i, j int) bool {
		if c := cmpBound(events[i].pos, events[j].pos); c != 0 {
			return c < 0
		}
		return !events[i].open && events[j].open
	})

	out := make([]builtRange, 0, len(blocks))
	active := make(map[int32]int, 8)
	h := &idxHeap{}
	var prev bound
	have := false

	for i := 0; i < len(events); {
		pos := events[i].pos
		if have {
			if idx, ok := activeMin(h, active); ok {
				out = appendRange(out, prev, pos.prev(), idx)
			}
		}
		for i < len(events) && cmpBound(events[i].pos, pos) == 0 {
			e := events[i]
			if e.open {
				if active[e.idx] == 0 {
					heap.Push(h, e.idx)
				}
				active[e.idx]++
			} else {
				active[e.idx]--
			}
			i++
		}
		prev = pos
		have = true
	}
	return out
}

type event struct {
	pos  bound
	open bool
	idx  int32
}

// activeMin returns the lowest index that still has open blocks.
func activeMin(h *idxHeap, active map[int32]int) (int32, bool) {
	for h.Len() > 0 && active[(*h)[0]] == 0 {
		heap.Pop(h)
	}
	if h.Len() == 0 {
		return 0, false
	}
	return (*h)[0], true
}

// appendRange adds a range, merging it into the previous one when they are
// adjacent and share a rule index.
func appendRange(out []builtRange, start, end bound, idx int32) []builtRange {
	if cmpBound(start, end) > 0 {
		return out
	}
	if n := len(out); n > 0 {
		last := &out[n-1]
		if last.idx == idx && cmpBound(last.end.next(), start) == 0 {
			last.end = end
			return out
		}
	}
	return append(out, builtRange{start: start, end: end, idx: idx})
}

// idxHeap is a min-heap of rule indices.
type idxHeap []int32

func (h idxHeap) Len() int            { return len(h) }
func (h idxHeap) Less(i, j int) bool  { return h[i] < h[j] }
func (h idxHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *idxHeap) Push(x interface{}) { *h = append(*h, x.(int32)) }
func (h *idxHeap) Pop() interface{} {
	old := *h
	n := len(old)
	v := old[n-1]
	*h = old[:n-1]
	return v
}

// rangeTable answers "which rule covers this value" over sorted disjoint
// ranges. It is immutable after construction and safe for concurrent reads.
type rangeTable[A comparable] struct {
	starts []A
	ends   []A // inclusive
	idxs   []int32
	cmp    func(a, b A) int
}

func (t *rangeTable[A]) len() int { return len(t.starts) }

// lookup returns the index of the rule covering v.
func (t *rangeTable[A]) lookup(v A) (int32, bool) {
	lo, hi := 0, len(t.starts)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if t.cmp(t.starts[mid], v) <= 0 {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo == 0 {
		return 0, false
	}
	i := lo - 1
	if t.cmp(v, t.ends[i]) <= 0 {
		return t.idxs[i], true
	}
	return 0, false
}

// newRangeTable4 builds a table over the IPv4 address line.
func newRangeTable4(ranges []builtRange) *rangeTable[uint32] {
	t := &rangeTable[uint32]{cmp: cmpU32}
	for _, r := range ranges {
		start := uint32(r.start.v.lo)
		end := uint32(math.MaxUint32)
		if !r.end.past {
			end = uint32(r.end.v.lo)
		}
		t.starts = append(t.starts, start)
		t.ends = append(t.ends, end)
		t.idxs = append(t.idxs, r.idx)
	}
	return t
}

// newRangeTable6 builds a table over the IPv6 address line.
func newRangeTable6(ranges []builtRange) *rangeTable[u128] {
	t := &rangeTable[u128]{cmp: cmpU128}
	for _, r := range ranges {
		end := u128{hi: math.MaxUint64, lo: math.MaxUint64}
		if !r.end.past {
			end = r.end.v
		}
		t.starts = append(t.starts, r.start.v)
		t.ends = append(t.ends, end)
		t.idxs = append(t.idxs, r.idx)
	}
	return t
}

// newRangeTablePorts builds a table over the port number line.
func newRangeTablePorts(ranges []builtRange) *rangeTable[uint32] {
	return newRangeTable4(ranges)
}
