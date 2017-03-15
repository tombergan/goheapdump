package corefile

import (
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
