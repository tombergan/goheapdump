package corefile

import (
	"testing"
)

func TestVarSet(t *testing.T) {
	inserts := []struct {
		pkgPath, name string
		addr, size    uint64
		want          bool
	}{
		{"p", "a", 20, 8, true},
		{"p", "b", 30, 8, true},
		{"p", "c", 10, 8, true},
		{"p", "d", 8, 2, true},
		{"p", "e", 6, 3, false},
		{"p", "f", 12, 4, false},
		{"p", "g", 17, 2, false},
		{"p", "h", 22, 4, false},
		{"p", "i", 32, 4, false},
		{"p", "a", 50, 4, false},
		{"q", "a", 50, 4, true},
	}

	var vs VarSet
	for _, test := range inserts {
		v := Var{
			Name:    test.name,
			PkgPath: test.pkgPath,
			Value: Value{
				Type:  &NumericType{baseType: baseType{size: test.size}},
				Addr:  test.addr,
				Bytes: make([]byte, test.size),
			},
		}
		got := vs.insert(v) == nil
		if got != test.want {
			t.Errorf("insert(addr=%v, size=%v)=%v want %v", test.addr, test.size, got, test.want)
		}
	}

	nameLookups := []struct {
		fullname string
		want     bool
		wantAddr uint64
	}{
		{"p.a", true, 20},
		{"p.c", true, 10},
		{"p.x", false, 0},
		{"z.a", false, 0},
	}

	for _, test := range nameLookups {
		gotV, got := vs.FindName(test.fullname)
		if got != test.want || (got && gotV.Value.Addr != test.wantAddr) {
			t.Errorf("FindName(%q)=%v,%v want %v,%v", test.fullname, gotV.Value.Addr, got, test.wantAddr, test.want)
		}
	}

	addrLookups := []struct {
		addr     uint64
		want     bool
		wantAddr uint64
	}{
		{20, true, 20},
		{24, true, 20},
		{27, true, 20},
		{28, false, 9},
		{8, true, 8},
		{5, false, 0},
		{49, false, 0},
		{53, true, 50},
		{54, false, 0},
	}

	for _, test := range addrLookups {
		gotV, got := vs.FindAddr(test.addr)
		if got != test.want || (got && gotV.Value.Addr != test.wantAddr) {
			t.Errorf("FindAddr(%v)=%v,%v want %v,%v", test.addr, gotV.Value.Addr, got, test.wantAddr, test.want)
		}
	}
}
