package corefile

import (
	"bytes"
	"testing"

	"golang.org/x/debug/arch"
)

func TestRoundUpDown(t *testing.T) {
	const ptrSize = 8
	tests := []struct {
		n        uint64
		wantDown uint64
		wantUp   uint64
	}{
		{0, 0, 0},
		{1, 0, 8},
		{4, 0, 8},
		{7, 0, 8},
		{8, 8, 8},
		{9, 8, 16},
		{15, 8, 16},
		{16, 16, 16},
	}

	for _, test := range tests {
		if got := roundUp(test.n, ptrSize); got != test.wantUp {
			t.Errorf("roundUp(%v, %v)=%v, want %v", test.n, ptrSize, got, test.wantUp)
		}
		if got := roundDown(test.n, ptrSize); got != test.wantDown {
			t.Errorf("roundDown(%v, %v)=%v, want %v", test.n, ptrSize, got, test.wantDown)
		}
	}
}

func TestProgramBitvector(t *testing.T) {
	p := &Program{
		RuntimeLibrary: &RuntimeLibrary{
			Arch: arch.Architecture{PointerSize: 4},
		},
		dataSegments: dataSegments{
			dataSegment{addr: 100, data: make([]byte, 32)},
			dataSegment{addr: 200, data: make([]byte, 64)},
			dataSegment{addr: 300, data: make([]byte, 64)},
		},
	}
	bv := newProgramBitvector(p)

	tests := []struct {
		addr, size uint64
		want       bool
	}{
		{100, 0, false}, // nop
		{100, 2, true},
		{100, 4, false}, // covered by prior
		{104, 4, true},
		{104, 8, true},
		{100, 28, true},
		{130, 2, true}, // first segment all covered
		{100, 32, false},
		{116, 16, false},
		{180, 100, true}, // second segment all covered
		{200, 64, false},
		{331, 2, true},
		{328, 4, false}, // covered by prior
		{332, 4, false}, // covered by prior
		{324, 4, true},
		{336, 4, true},
	}

	for _, test := range tests {
		if got := bv.acquireRange(test.addr, test.size); got != test.want {
			t.Errorf("acquireRange(%v, %v)=%v, want %v", test.addr, test.size, got, test.want)
		}
	}
}

func TestGCHeapBitvector(t *testing.T) {
	const arenaAddr = 200
	const ptrSize = 8
	const objSize = 64

	bitmap := make([]byte, 100)
	// Object at addr 200 = {ptr, noptr, noptr, ptr, ptr, ptr, ptr, noptr}.
	bitmap[99] = 0 |
		/* addr 200 */ (1 << 0) | (1 << 4) |
		/* addr 208 */ (0 << 1) | (0 << 5) | // checkmarking bit; not all done
		/* addr 216 */ (0 << 2) | (1 << 6) |
		/* addr 224 */ (1 << 3) | (1 << 7)
	bitmap[98] = 0 |
		/* addr 232 */ (1 << 0) | (1 << 4) |
		/* addr 240 */ (1 << 1) | (1 << 5) |
		/* addr 248 */ (1 << 2) | (1 << 6) |
		/* addr 256 */ (0 << 3) | (0 << 7) // no more

	// Object at addr 328 = {ptr, ptr, noptr, noptr, ptr, noptr, noptr, noptr}.
	bitmap[95] = 0 |
		/* addr 328 */ (1 << 0) | (1 << 4) |
		/* addr 336 */ (1 << 1) | (1 << 5) |
		/* addr 344 */ (0 << 2) | (1 << 6) |
		/* addr 352 */ (0 << 3) | (1 << 7)
	bitmap[94] = 0 |
		/* addr 360 */ (1 << 0) | (1 << 4) |
		/* addr 368 */ (0 << 1) | (0 << 5) | // no more
		/* addr 376 */ (0 << 2) | (0 << 6) |
		/* addr 386 */ (0 << 3) | (0 << 7)

	tests := []struct {
		objAddr  uint64
		addr     uint64
		wantPtr  bool
		wantMore bool
	}{
		// First object.
		{200, 200, true, true},
		{200, 208, false, true},
		{200, 216, false, true},
		{200, 224, true, true},
		{200, 232, true, true},
		{200, 240, true, true},
		{200, 248, true, true},
		{200, 256, false, false},
		// Second object.
		{328, 328, true, true},
		{328, 336, true, true},
		{328, 344, false, true},
		{328, 352, false, true},
		{328, 360, true, true},
		{328, 368, false, false},
		{328, 376, false, false},
		{328, 384, false, false},
	}

	for _, test := range tests {
		bv := makeGCHeapBitvector(arenaAddr, test.objAddr, objSize, ptrSize, bitmap)
		if gotPtr, gotMore := bv.test(test.addr); gotPtr != test.wantPtr || gotMore != test.wantMore {
			t.Errorf("test(%v)=%v,%v want %v,%v", test.addr, gotPtr, gotMore, test.wantPtr, test.wantMore)
		}
	}
}

func TestWriteBitvector(t *testing.T) {
	tests := []struct {
		bits  []byte
		nbits uint64
		want  string
	}{
		{[]byte{0x1}, 1, "1"},
		{[]byte{0x5}, 4, "1010"},
		{[]byte{0x63, 0x80, 0x1}, 20, "11000110000000011000"},
	}

	for _, test := range tests {
		bv := gcBitvector{
			bits:    test.bits,
			nbits:   test.nbits,
			ptrSize: 8,
			seg: dataSegment{
				addr: 100,
				data: make([]byte, test.nbits*8),
			},
		}
		buf := &bytes.Buffer{}
		writeBitvector(buf, bv.seg.addr, bv.seg.size(), bv.ptrSize, bv.isPointer)
		if got := buf.String(); got != test.want {
			t.Errorf("writeBitvector(%v, %v)=%s, want %s", test.bits, test.nbits, got, test.want)
		}
	}
}
