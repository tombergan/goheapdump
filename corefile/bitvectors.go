package corefile

import (
	"bytes"
	"fmt"
	"sort"
)

func min(x, y uint64) uint64 {
	if x < y {
		return x
	}
	return y
}

func max(x, y uint64) uint64 {
	if x > y {
		return x
	}
	return y
}

func roundDown(x, align uint64) uint64 {
	return x - x%align
}

func roundUp(x, align uint64) uint64 {
	return align * ((x + align - 1) / align)
}

// bitvector has one bit for each pointer-aligned word in a Program's
// virtual memory space.
//
// TODO: support very large heaps
// TODO: support concurrent updates
type bitvector struct {
	chunks  []bitvectorChunk
	ptrSize uint64 // in bytes
}

// XXX revisit uint64
type bitvectorChunk struct {
	addr uint64 // must be pointer-aligned
	size uint64 // size in bytes
	bits []uint64
}

func newBitvector(p *Program) *bitvector {
	bv := &bitvector{
		ptrSize: uint64(p.RuntimeLibrary.Arch.PointerSize),
	}
	for _, s := range p.dataSegments {
		start := roundDown(s.addr, bv.ptrSize)
		end := roundUp(s.addr+s.size(), bv.ptrSize)
		chunk := bitvectorChunk{
			addr: start,
			size: end - start,
			bits: make([]uint64, (end-start)/bv.ptrSize/8),
		}
		bv.chunks = append(bv.chunks, chunk)
	}
	return bv
}

// acquireRange sets all bits in the range [addr, addr+size) to 1, then
// reports whether any of the bits were previously 0.
func (bv *bitvector) acquireRange(addr, size uint64) bool {
	if size == 0 {
		return false
	}
	k := sort.Search(len(bv.chunks), func(k int) bool {
		return addr < bv.chunks[k].addr
	})
	if k > 0 {
		k--
		if bv.chunks[k].addr+bv.chunks[k].size <= addr {
			k++
		}
	}
	end := addr + size - 1
	changed := false
	for ; k < len(bv.chunks) && bv.chunks[k].addr <= end; k++ {
		if bv.chunks[k].acquireRange(addr, size, bv.ptrSize) {
			changed = true
		}
	}
	return changed
}

func (chunk *bitvectorChunk) acquireRange(addrStart, size, ptrSize uint64) bool {
	addrStart = max(addrStart, chunk.addr)
	addrEnd := min(addrStart+size, chunk.addr+chunk.size)

	offsetStart := addrStart - chunk.addr
	offsetEnd := addrEnd - chunk.addr

	bit := offsetStart / ptrSize
	bitEnd := roundUp(offsetEnd, ptrSize) / ptrSize

	changed := false
	for ; bit < bitEnd; bit++ {
		mask := uint64(1) << (bit % 8)
		if chunk.bits[bit/8]&mask == 0 {
			chunk.bits[bit/8] |= mask
			changed = true
		}
	}
	return changed
}

// gcBitvector is an immutable bitvector that represents a GC bitmap
// loaded from the core file.
type gcBitvector struct {
	bits    []byte
	nbits   uint64
	seg     dataSegment // the bitvector covers addresses in this segment
	ptrSize uint64
}

var gcEmptyBitvector = &gcBitvector{
	bits: make([]byte, 0),
}

func newGCBitvector(p *Program, seg dataSegment, bitsAddr, nbits uint64) (*gcBitvector, error) {
	ptrSize := uint64(p.RuntimeLibrary.Arch.PointerSize)
	size := (nbits + 7) / 8
	if sanityChecks && size > seg.size() {
		panic(fmt.Sprintf("nbits=%d, size=%d, seg.size=%d", nbits, size, seg))
	}
	if seg.addr%ptrSize != 0 {
		panic(fmt.Sprintf("seg.addr=0x%x not aligned to ptrSize=%d", seg.addr, ptrSize))
	}
	bits, ok := p.dataSegments.slice(bitsAddr, size)
	if !ok {
		return nil, fmt.Errorf("error loading bitvector at 0x%x (nbits=%d, size=%d)", bitsAddr, nbits, size)
	}
	return &gcBitvector{
		bits:    bits.data,
		nbits:   nbits,
		seg:     seg,
		ptrSize: ptrSize,
	}, nil
}

// has reports whether addr contains a pointer.
// Returns false if addr is outside the range of this bitvector.
func (bv *gcBitvector) has(addr uint64) bool {
	bit := (addr - bv.seg.addr) / bv.ptrSize
	if bit >= bv.nbits {
		return false
	}
	mask := uint8(1) << (bit % 8)
	return uint8(bv.bits[bit/8])&mask != 0
}

// isStackVarLive checks the given type against the GC bitmap.
// There are three cases:
//
//   1. Pointers in the type exactly match the bitvector. The variable is live.
//   2. The type has pointers but the bitvector is empty. The variable is not live.
//   3. The type has pointers that only partially match the bitvector.
//      There is a type-mismatch failure and a likely bug.
//
func (bv *gcBitvector) isStackVarLive(addr uint64, t Type) (bool, error) {
	ptrsHave, ptrsMissing, err := bv.analyzeType(addr, t)
	if err != nil {
		return false, err
	}
	if ptrsMissing == 0 {
		return true, nil
	}
	if ptrsHave == 0 {
		return false, nil
	}
	return false, fmt.Errorf("mismatched types for %t at 0x%x: missing %d pointers of %d", t, addr, ptrsMissing, ptrsMissing+ptrsHave)
}

// checkPreciseType checks if a type at the given address has exactly the
// pointers described by bv. Returns an error if not.
func (bv *gcBitvector) checkPreciseType(addr uint64, t Type) error {
	ptrsHave, ptrsMissing, err := bv.analyzeType(addr, t)
	if err != nil {
		return err
	}
	if ptrsMissing == 0 {
		return nil
	}
	return fmt.Errorf("mismatched types for %t at 0x%x: missing %d pointers of %d", t, addr, ptrsMissing, ptrsMissing+ptrsHave)
}

func (bv *gcBitvector) analyzeType(baseAddr uint64, t Type) (ptrsHave int, ptrsMissing int, err error) {
	var visit func(addr uint64, t Type, path string) error
	visit = func(addr uint64, t Type, path string) error {
		if rep := t.InternalRepresentation(); rep != nil {
			t = rep
		}
		if !t.containsPointers() {
			end := addr + t.Size()
			for addr = roundDown(addr, bv.ptrSize); addr < end; addr += bv.ptrSize {
				if bv.has(addr) {
					return fmt.Errorf("(0x%x)%s has type %s, but gcBitvector expects a pointer", baseAddr, path, t)
				}
			}
			return nil
		}

		switch t := t.(type) {
		case *ArrayType:
			for k := uint64(0); k < t.Len; k++ {
				if err := visit(addr+k*t.Elem.Size(), t.Elem, fmt.Sprintf("[%d]", k)); err != nil {
					return err
				}
			}
			return nil

		case *PtrType, *FuncType:
			if bv.has(addr) {
				ptrsHave++
			} else {
				ptrsMissing++
			}
			return nil

		case *StructType:
			for _, f := range t.Fields {
				fname := f.Name
				if fname == "" {
					fname = fmt.Sprintf("$offset_%d", f.Offset)
				}
				if err := visit(addr+f.Offset, f.Type, fmt.Sprintf("%s.%s", path, fname)); err != nil {
					return err
				}
			}
			return nil

		default:
			panic(fmt.Sprintf("unexpected type %s %T at addr 0x%x", t, t, addr))
		}
	}

	err = visit(baseAddr, t, "")
	return ptrsHave, ptrsMissing, err
}

func (bv *gcBitvector) String() string {
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "gcBitvector{seg:%s nbits:%d bits:", bv.seg, bv.nbits)
	writeBitvector(buf, bv.bits, int(bv.nbits))
	buf.WriteString("}")
	return buf.String()
}

func writeBitvector(buf *bytes.Buffer, bits []byte, nbits int) {
	for k := range bits {
		b := bits[k]
		for i := 0; i < 8 && i < nbits; i++ {
			if b&1 != 0 {
				buf.WriteString("1")
			} else {
				buf.WriteString("0")
			}
			b >>= 1
		}
		if nbits < 8 {
			return
		}
		nbits -= 8
	}
}
