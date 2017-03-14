package corefile

import (
	"bytes"
	"testing"

	"golang.org/x/debug/arch"
)

func TestBitvector(t *testing.T) {
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
	bv := newBitvector(p)

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

func TestWriteBitvector(t *testing.T) {
	tests := []struct {
		bits  []byte
		nbits int
		want  string
	}{
		{[]byte{0x1}, 1, "1"},
		{[]byte{0x5}, 4, "1010"},
		{[]byte{0x63, 0x80, 0x1}, 20, "11000110000000011000"},
	}

	for _, test := range tests {
		buf := &bytes.Buffer{}
		writeBitvector(buf, test.bits, test.nbits)
		if got := buf.String(); got != test.want {
			t.Errorf("writeBitvector(%v, %v)=%s, want %s", test.bits, test.nbits, got, test.want)
		}
	}
}
