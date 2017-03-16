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

// programBitvector has one bit for each pointer-aligned word in a
// Program's virtual memory space. This is used by Query for graph
// reachability queries.
//
// TODO: support very large heaps
// TODO: support concurrent updates
type programBitvector struct {
	chunks  []programBitvectorChunk
	ptrSize uint64 // in bytes
}

type programBitvectorChunk struct {
	addr uint64   // must be pointer-aligned
	size uint64   // size in bytes
	bits []uint64 // bits is uint64 instead of uint8 so eventually we can atomic CAS
}

func newProgramBitvector(p *Program) *programBitvector {
	bv := &programBitvector{
		ptrSize: uint64(p.RuntimeLibrary.Arch.PointerSize),
	}
	for _, s := range p.dataSegments {
		start := roundDown(s.addr, bv.ptrSize)
		end := roundUp(s.addr+s.size(), bv.ptrSize)
		chunk := programBitvectorChunk{
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
func (bv *programBitvector) acquireRange(addr, size uint64) bool {
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

func (chunk *programBitvectorChunk) acquireRange(addrStart, size, ptrSize uint64) bool {
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
// loaded from the core file. gcBitmap covers bitmaps for global and
// stack data. For heap data, use gcHeapBitvector.
type gcBitvector struct {
	bits    []byte
	nbits   uint64
	ptrSize uint64
	seg     dataSegment // the bitvector covers addresses in this segment
}

var gcEmptyBitvector = &gcBitvector{
	bits: make([]byte, 0),
}

func newGCBitvector(p *Program, seg dataSegment, bits []byte, nbits uint64) *gcBitvector {
	ptrSize := uint64(p.RuntimeLibrary.Arch.PointerSize)
	// Sanity checks.
	if size := (nbits + 7) / 8; size > seg.size() {
		panic(fmt.Sprintf("nbits=%d, size=%d, seg.size=%d", nbits, size, seg))
	}
	if seg.addr%ptrSize != 0 {
		panic(fmt.Sprintf("seg.addr=0x%x not aligned to ptrSize=%d", seg.addr, ptrSize))
	}
	return &gcBitvector{
		bits:    bits,
		nbits:   nbits,
		ptrSize: ptrSize,
		seg:     seg,
	}
}

// contains reports whether bv covers the given address.
func (bv *gcBitvector) contains(addr uint64) bool {
	return bv.seg.contains(addr)
}

// isPointer reports whether addr contains a pointer.
// Returns false if addr is outside the range of this bitvector.
func (bv *gcBitvector) isPointer(addr uint64) bool {
	bit := (addr - bv.seg.addr) / bv.ptrSize
	if bit >= bv.nbits {
		return false
	}
	return ((uint8(bv.bits[bit/8]) >> (bit % 8)) & 1) != 0
}

// foreachPointer calls fn for each pointer in the range [addr, addr+size).
// addr must be pointer-aligned.
func (bv *gcBitvector) foreachPointer(addr, size uint64, fn func(ptrValue uint64)) {
	for end := addr + size; addr < end; addr += bv.ptrSize {
		if bv.isPointer(addr) {
			fn(addr)
		}
	}
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
	ptrsHave, ptrsMissing, err := compareGCBitvectorAndType(addr, bv.ptrSize, t, bv.isPointer)
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
	ptrsHave, ptrsMissing, err := compareGCBitvectorAndType(addr, bv.ptrSize, t, bv.isPointer)
	if err != nil {
		return err
	}
	if ptrsMissing == 0 {
		return nil
	}
	return fmt.Errorf("mismatched types for %t at 0x%x: missing %d pointers of %d", t, addr, ptrsMissing, ptrsMissing+ptrsHave)
}

func (bv *gcBitvector) String() string {
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "gcBitvector{seg:%s nbits:%d bits:", bv.seg, bv.nbits)
	writeBitvector(buf, bv.seg.addr, bv.seg.size(), bv.ptrSize, bv.isPointer)
	buf.WriteString("}")
	return buf.String()
}

// gcHeapBitvector describes a bitvector for a single heap object.
// See runtime/mbitmap.go.
type gcHeapBitvector struct {
	baseAddr uint64 // base address of the heap arena
	objAddr  uint64 // base address of the object
	objSize  uint64
	ptrSize  uint64
	bitmap   []byte // the entire heap bitmap
}

func makeGCHeapBitvector(baseAddr, objAddr, objSize, ptrSize uint64, bitmap []byte) gcHeapBitvector {
	if objAddr%ptrSize != 0 {
		panic(fmt.Sprintf("object addr 0x%x is not aligned to pointer size %d", objAddr, ptrSize))
	}
	return gcHeapBitvector{baseAddr, objAddr, objSize, ptrSize, bitmap}
}

// test reports whether addr is a pointer. If addr is not a pointer
// and there are no more pointers after addr, then mightHaveMore is false.
//
// test panics if addr is out-of-range or not pointer-aligned.
// Panicking on bad addrs is necessary because certain offsets within a
// bitvector have special meaning; see the "checkmarking" comment below.
func (bv gcHeapBitvector) test(addr uint64) (isPointer bool, mightHaveMore bool) {
	if addr%bv.ptrSize != 0 {
		panic(fmt.Sprintf("addr 0x%x is not aligned to pointer size %d", addr, bv.ptrSize))
	}
	if addr >= bv.objAddr+bv.objSize {
		panic(fmt.Sprintf("addr 0x%x is not inside object [0x%x, 0x%x)", addr, bv.objAddr, bv.objAddr+bv.objSize))
	}
	// See runtime/mbitmap.go:heapBitsForAddr.
	// and runtime/mbitmap.go:heapBits.isPointer.
	off := (addr - bv.baseAddr) / bv.ptrSize
	byteVal := bv.bitmap[uint64(len(bv.bitmap))-off/4-1] >> (off & 3)
	isPointer = (byteVal & 1) != 0
	// See runtime/mbitmap.go:hbits.morePointers.
	// If the high bit is zero, there are no more pointers, except
	// for the second word, where the high bit is used for checkmarking.
	if addr == bv.objAddr+bv.ptrSize {
		mightHaveMore = true
	} else {
		mightHaveMore = (byteVal & (1 << 4)) != 0
	}
	return isPointer, mightHaveMore
}

// foreachPointer calls fn for each pointer in the range [addr, addr+size).
// addr must be pointer-aligned.
func (bv gcHeapBitvector) foreachPointer(addr, size uint64, fn func(ptrValue uint64)) {
	for end := addr + size; addr < end; addr += bv.ptrSize {
		isPointer, mightHaveMore := bv.test(addr)
		if isPointer {
			fn(addr)
		}
		if !mightHaveMore {
			return
		}
	}
}

// checkPreciseType checks if a type at the given address has exactly the
// pointers described by bv. Returns an error if not.
func (bv gcHeapBitvector) checkPreciseType(addr uint64, t Type) error {
	ptrsHave, ptrsMissing, err := compareGCBitvectorAndType(addr, bv.ptrSize, t, func(addr uint64) (isPtr bool) {
		if addr%bv.ptrSize == 0 {
			isPtr, _ = bv.test(addr)
		}
		return isPtr
	})
	if err != nil {
		return err
	}
	if ptrsMissing == 0 {
		return nil
	}
	return fmt.Errorf("mismatched types for %t at 0x%x: missing %d pointers of %d", t, addr, ptrsMissing, ptrsMissing+ptrsHave)
}

func (bv gcHeapBitvector) String() string {
	buf := &bytes.Buffer{}
	fmt.Fprintf(buf, "gcHeapBitvector{addr:0x%x bits:", bv.baseAddr)
	writeBitvector(buf, bv.objAddr, bv.objSize, bv.ptrSize, func(addr uint64) bool {
		isPtr, _ := bv.test(addr)
		return isPtr
	})
	buf.WriteString("}")
	return buf.String()
}

// compareGCBitvectorAndType is compares an object at baseAddr of type t
// with the GC bitvector abstracted by gcIsPtr. The return values are:
//
//   - ptrsHave counts the number of pointers that match in t and the bitvector
//   - ptrsMissing counts the number of points in t missing from the bitvector
//   - err is non-nil if any pointer in the bitvector is missing from t
//
func compareGCBitvectorAndType(baseAddr, ptrSize uint64, t Type, gcIsPtr func(addr uint64) bool) (ptrsHave int, ptrsMissing int, err error) {
	var visit func(addr uint64, t Type, path string) error
	visit = func(addr uint64, t Type, path string) error {
		if rep := t.InternalRepresentation(); rep != nil {
			t = rep
		}
		if !t.containsPointers() {
			end := addr + t.Size()
			for addr = roundDown(addr, ptrSize); addr < end; addr += ptrSize {
				if gcIsPtr(addr) {
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

		case *PtrType, *UnsafePtrType, *FuncType:
			if gcIsPtr(addr) {
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

func writeBitvector(buf *bytes.Buffer, startAddr, size, ptrSize uint64, isPtr func(addr uint64) bool) {
	for addr := startAddr; addr < startAddr+size; addr += ptrSize {
		if isPtr(addr) {
			buf.WriteString("1")
		} else {
			buf.WriteString("0")
		}
	}
}
