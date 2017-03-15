package corefile

import (
	"fmt"
	"sort"
)

// dataSegment describes a segment of a Program's virtual memory.
type dataSegment struct {
	addr uint64
	data []byte // points to mmap’d files

	// writable is true if the memory range was writable by the program
	// and the core file was mapped in writable mode.
	writable bool

	// readable is true if the memory range was readable by the program.
	// e.g., this is false for stack guards.
	readable bool
}

func (s dataSegment) String() string {
	mode := ""
	if s.readable {
		mode += "R"
	}
	if s.writable {
		mode += "W"
	}
	return fmt.Sprintf("dataSegment{addr:0x%x, size:0x%x, mode:%v}", s.addr, s.size(), mode)
}

// contains reports whether the segment contains the given address.
func (s dataSegment) contains(addr uint64) bool {
	return s.addr <= addr && addr < s.addr+s.size()
}

// containsRange reports whether the segment contains the range [addr, addr+size).
func (s dataSegment) containsRange(addr, size uint64) bool {
	return s.contains(addr) && (size == 0 || s.contains(addr+size-1))
}

// size reports the size of the segment in bytes.
func (s dataSegment) size() uint64 {
	return uint64(len(s.data))
}

// slice takes a slice of the given segment. addr is an absolute address.
// Returns false if [addr,addr+size) is out-of-bounds of s.
func (s dataSegment) slice(addr, size uint64) (dataSegment, bool) {
	offset := addr - s.addr
	if offset > s.size() || offset+size > s.size() {
		return dataSegment{}, false
	}
	return dataSegment{
		addr:     addr,
		data:     s.data[offset : offset+size : offset+size],
		writable: s.writable,
		readable: s.readable,
	}, true
}

// suffix is a shorthand for taking a slice of the given segment from
// addr to the end of the segment.
func (s dataSegment) suffix(addr uint64) (dataSegment, bool) {
	return s.slice(addr, s.size()-(addr-s.addr))
}

// dataSegments is a list of virtual memory segments.
type dataSegments []dataSegment

func (ss dataSegments) Len() int           { return len(ss) }
func (ss dataSegments) Swap(i, k int)      { ss[i], ss[k] = ss[k], ss[i] }
func (ss dataSegments) Less(i, k int) bool { return ss[i].addr < ss[k].addr }

// findSegment finds the segment that contains the given address.
func (ss dataSegments) findSegment(addr uint64) (dataSegment, bool) {
	// Binary search for an upper-bound segment, then check
	// if the previous segment contains addr.
	k := sort.Search(len(ss), func(k int) bool {
		return addr < ss[k].addr
	})
	k--
	if k >= 0 && ss[k].contains(addr) {
		return ss[k], true
	}
	return dataSegment{}, false
}

// slice takes a slice at the given address. Fails if the slice is not
// contained within a single segment.
func (ss dataSegments) slice(addr, size uint64) (dataSegment, bool) {
	s, ok := ss.findSegment(addr)
	if !ok {
		return dataSegment{}, false
	}
	return s.slice(addr, size)
}

// insert inserts a range [addr, addr+size) into ss. We maintain an invariant
// that ss is sorted and contains only non-overlapping segments. If the given
// range overlaps an existing segment, the range is split into a set subranges
// that do not overlap any existing segments. If new dataSegments are needed,
// they are created with makeSegment.
func (ss *dataSegments) insert(addr, size uint64, makeSegment func(addr, size uint64) (dataSegment, error)) error {
	if size == 0 {
		return nil
	}

	if sanityChecks {
		defer func() {
			if !sort.IsSorted(*ss) {
				for k, s := range *ss {
					printf("dataSegments[%v] = %s", k, s)
				}
				panic(fmt.Sprintf("dataSegments are not sorted after insert(0x%x, 0x%x)", addr, size))
			}
		}()
	}

	// Binary search for the first segment where s.addr+s.size > addr.
	k := sort.Search(len(*ss), func(k int) bool {
		s := (*ss)[k]
		return s.addr+s.size() > addr
	})

	// (*ss)[k-1] is fully below [addr, addr+size).
	// Starting from k, walk forward and split the range at all overlapping segments.
	for {
		if k == len(*ss) {
			s, err := makeSegment(addr, size)
			if err != nil {
				return err
			}
			logf("loading %s", s)
			*ss = append(*ss, s)
			return nil
		}
		// If any part of the current range lies to the left of segment k,
		// insert a new segment before k.
		if addr < (*ss)[k].addr {
			slen := (*ss)[k].addr - addr
			if slen > size {
				slen = size
			}
			s, err := makeSegment(addr, slen)
			if err != nil {
				return err
			}
			logf("loading %s", s)
			*ss = append((*ss)[:k], append(dataSegments{s}, (*ss)[k:]...)...)
			k++
		}
		// If any part of the current range lies to the right of the current
		// segment, preserve that part of the range and advance to the next segment.
		segEnd := (*ss)[k].addr + (*ss)[k].size()
		rangeEnd := addr + size
		if segEnd < rangeEnd {
			if addr < segEnd {
				addr = segEnd
				size = rangeEnd - segEnd
			}
			k++
			continue
		}
		// No part of the current range lies to the right of the current
		// segment, so we're done.
		return nil
	}
}
