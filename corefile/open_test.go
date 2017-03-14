package corefile

import (
	"fmt"
	"reflect"
	"testing"
)

func TestSplitPkgPath(t *testing.T) {
	tests := []struct {
		fullname    string
		wantPkgPath string
		wantName    string
	}{
		{"uint", "", "uint"},
		{"net.Conn", "net", "Conn"},
		{"net/http.Response", "net/http", "Response"},
		{"github.com/foo/bar.name", "github.com/foo/bar", "name"},
	}

	for _, test := range tests {
		if gotPkgPath, gotName := splitPkgPathName(test.fullname); gotPkgPath != test.wantPkgPath || gotName != test.wantName {
			t.Errorf("splitPkgPathName(%q)=%q,%q want %q,%q", test.fullname, gotPkgPath, gotName, test.wantPkgPath, test.wantName)
		}
	}
}

func fmtDataSegment(s dataSegment) string {
	return fmt.Sprintf("{addr:%d,size:%d}", s.addr, s.size())
}

func TestDataSegmentsInsert(t *testing.T) {
	makeSegment := func(addr, size uint64) (dataSegment, error) {
		return dataSegment{addr: addr, data: make([]byte, size)}, nil
	}
	mustMakeSegment := func(addr, size uint64) dataSegment {
		s, _ := makeSegment(addr, size)
		return s
	}

	var ss dataSegments
	ss.insert(10, 5, makeSegment)
	ss.insert(20, 5, makeSegment)  // no overlap
	ss.insert(30, 5, makeSegment)  // no overlap
	ss.insert(0, 12, makeSegment)  // overlaps [10, 15)
	ss.insert(0, 15, makeSegment)  // overlaps [0, 10) and [10, 15)
	ss.insert(18, 8, makeSegment)  // overlaps [20, 25)
	ss.insert(29, 20, makeSegment) // overlaps [30, 35)

	expected := []dataSegment{
		mustMakeSegment(0, 10),
		mustMakeSegment(10, 5),
		mustMakeSegment(18, 2),
		mustMakeSegment(20, 5),
		mustMakeSegment(25, 1),
		mustMakeSegment(29, 1),
		mustMakeSegment(30, 5),
		mustMakeSegment(35, 14),
	}
	for k := range expected {
		if k > len(ss) {
			t.Errorf("missing %d segments at end", k-len(ss))
		}
		if expected[k].addr != ss[k].addr || expected[k].size() != ss[k].size() {
			t.Errorf("segments[%v]=%s, want %s", k, fmtDataSegment(ss[k]), fmtDataSegment(expected[k]))
		}
	}
	for k := len(expected); k < len(ss); k++ {
		t.Errorf("extra segment at end: %q", fmtDataSegment(ss[k]))
	}
}

func TestDataSegmentsFind(t *testing.T) {
	makeSegment := func(addr, size uint64) (dataSegment, error) {
		return dataSegment{addr: addr, data: make([]byte, size)}, nil
	}

	var ss dataSegments
	ss.insert(10, 5, makeSegment)
	ss.insert(20, 5, makeSegment)
	ss.insert(30, 5, makeSegment)

	tests := []struct {
		addr        uint64
		want        bool
		wantSegment dataSegment
	}{
		{9, false, dataSegment{}},
		{10, true, ss[0]},
		{14, true, ss[0]},
		{15, false, dataSegment{}},
		{19, false, dataSegment{}},
		{20, true, ss[1]},
		{25, false, dataSegment{}},
		{30, true, ss[2]},
		{35, false, dataSegment{}},
	}

	for _, test := range tests {
		gotSegment, got := ss.findSegment(test.addr)
		if got != test.want || (got && !reflect.DeepEqual(gotSegment, test.wantSegment)) {
			t.Errorf("findSegment(%d)=%s,%v want %s,%v", test.addr, fmtDataSegment(gotSegment), got, fmtDataSegment(test.wantSegment), test.want)
		}
	}
}

func TestDataSegmentsSlice(t *testing.T) {
	makeSegment := func(addr, size uint64) (dataSegment, error) {
		return dataSegment{addr: addr, data: make([]byte, size)}, nil
	}

	var ss dataSegments
	ss.insert(10, 5, makeSegment)
	ss.insert(20, 5, makeSegment)
	ss.insert(30, 5, makeSegment)

	tests := []struct {
		addr, size  uint64
		want        bool
		wantSegment dataSegment
	}{
		{9, 5, false, dataSegment{}},
		{10, 0, true, dataSegment{addr: 10, data: ss[0].data[:0]}},
		{10, 1, true, dataSegment{addr: 10, data: ss[0].data[:1]}},
		{10, 5, true, dataSegment{addr: 10, data: ss[0].data[:5]}},
		{10, 6, false, dataSegment{}},
		{11, 2, true, dataSegment{addr: 11, data: ss[0].data[1:3]}},
		{19, 5, false, dataSegment{}},
		{21, 3, true, dataSegment{addr: 21, data: ss[0].data[1:4]}},
		{29, 5, false, dataSegment{}},
		{31, 3, true, dataSegment{addr: 31, data: ss[0].data[1:4]}},
		{35, 0, false, dataSegment{}},
	}

	for _, test := range tests {
		gotSegment, got := ss.slice(test.addr, test.size)
		if got != test.want || (got && !reflect.DeepEqual(gotSegment, test.wantSegment)) {
			t.Errorf("slice(%d, %d)=%s,%v want %s,%v", test.addr, test.size, fmtDataSegment(gotSegment), got, fmtDataSegment(test.wantSegment), test.want)
		}
	}
}
