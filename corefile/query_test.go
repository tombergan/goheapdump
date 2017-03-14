package corefile

import (
	"fmt"
	"reflect"
	"testing"
)

// TODO: closures passed to Run calls must be concurrent safe
func TestQuery(t *testing.T) {
	vs := &VarSet{}
	var addr uint64
	makeVar := func(pkgPath, name string) Var {
		addr++
		return Var{
			Name:    name,
			PkgPath: pkgPath,
			Value: Value{
				Type:  &NumericType{baseType: baseType{size: 1}},
				Addr:  addr,
				Bytes: make([]byte, 1),
			},
		}
	}

	vs.insert(makeVar("path1", "x1"))
	vs.insert(makeVar("path2", "x2"))
	vs.insert(makeVar("path2", "y2"))
	vs.insert(makeVar("path3", "x3"))
	vs.insert(makeVar("path3", "y3"))
	vs.insert(makeVar("path3", "z3"))

	mapTests := []struct {
		label string
		query *Query
		want  map[string]bool
	}{
		{
			label: "Map",
			query: NewQuery(vs).
				Map(func(v Var) string { return v.FullName() }),
			want: map[string]bool{
				"path1.x1": true,
				"path2.x2": true,
				"path2.y2": true,
				"path3.x3": true,
				"path3.y3": true,
				"path3.z3": true,
			},
		},
		{
			label: "Flatten.Map",
			query: NewQuery(vs).
				Flatten(NewQuery(makeVar("path4", "z4"))).
				Map(func(v Var) string { return v.FullName() }),
			want: map[string]bool{
				"path1.x1": true,
				"path2.x2": true,
				"path2.y2": true,
				"path3.x3": true,
				"path3.y3": true,
				"path3.z3": true,
				"path4.z4": true,
			},
		},
		{
			label: "Where.Map",
			query: NewQuery(vs).
				Where(func(v Var) bool { return v.Name == "x2" || v.Name == "x3" }).
				Map(func(v Var) string { return v.FullName() }),
			want: map[string]bool{
				"path2.x2": true,
				"path3.x3": true,
			},
		},
		{
			label: "GroupBy.Map",
			query: NewQuery(vs).
				GroupBy(func(v Var) string { return v.PkgPath }).
				Map(func(g QueryGrouping) string {
					count := g.Elems.
						Map(func(v Var) int { return 1 }).
						Reduce(func(x, y int) int { return x + y }).
						RunAndReturn().(int)
					return fmt.Sprintf("%s:%v", g.Key, count)
				}),
			want: map[string]bool{
				"path1:1": true,
				"path2:2": true,
				"path3:3": true,
			},
		},
		{
			label: "GroupByAndReduce",
			query: NewQuery(vs).
				GroupByAndReduce(
					func(v Var) (string, int) { return v.PkgPath, 1 },
					func(x, y int) int { return x + y }).
				Map(func(g QueryGrouping) string {
					return fmt.Sprintf("%s:%v", g.Key, g.Elems.RunAndReturn().(int))
				}),
			want: map[string]bool{
				"path1:1": true,
				"path2:2": true,
				"path3:3": true,
			},
		},
	}
	for _, test := range mapTests {
		t.Run(test.label, func(t *testing.T) {
			output := make(map[string]bool)
			test.query.Run(func(x string) {
				output[x] = true
			})
			if !reflect.DeepEqual(output, test.want) {
				t.Errorf("\ngot:  %v\nwant: %v", output, test.want)
			}
		})
	}

	reduceTests := []struct {
		label string
		query *Query
		want  int
	}{
		{
			label: "Map.Reduce",
			query: NewQuery(vs).
				Map(func(v Var) int { return 1 }).
				Reduce(func(x, y int) int { return x + y }),
			want: 6,
		},
		{
			label: "Where.Map.Reduce",
			query: NewQuery(vs).
				Where(func(v Var) bool { return v.Name == "x2" || v.Name == "x3" }).
				Map(func(v Var) int { return 1 }).
				Reduce(func(x, y int) int { return x + y }),
			want: 2,
		},
		{
			label: "Map + Reduce on empty",
			query: NewQuery(&VarSet{}).
				Map(func(v Var) int { return 1 }).
				Reduce(func(x, y int) int { return x + y }),
			want: 0,
		},
	}
	for _, test := range reduceTests {
		t.Run(test.label+" (Run)", func(t *testing.T) {
			var output int
			var noutput int
			test.query.Run(func(x int) {
				noutput++
				output = x
			})
			if noutput != 1 {
				t.Errorf("got %d outputs, want 1", noutput)
			}
			if output != test.want {
				t.Errorf("got output %v, want %v", output, test.want)
			}
		})
		t.Run(test.label+" (RunAndReturn)", func(t *testing.T) {
			output := test.query.RunAndReturn().(int)
			if output != test.want {
				t.Errorf("got %v, want %v", output, test.want)
			}
		})
	}

	existsTests := []struct {
		label string
		query *Query
		want  bool
	}{
		{
			label: "Exists true",
			query: NewQuery(vs).
				Exists(func(v Var) bool { return v.PkgPath == "path2" }),
			want: true,
		},
		{
			label: "Exists false",
			query: NewQuery(vs).
				Exists(func(v Var) bool { return v.PkgPath == "badpath" }),
			want: false,
		},
	}
	for _, test := range existsTests {
		t.Run(test.label+" (Run)", func(t *testing.T) {
			var output bool
			var noutput int
			test.query.Run(func(x bool) {
				noutput++
				output = x
			})
			if noutput != 1 {
				t.Errorf("got %d outputs, want 1", noutput)
			}
			if output != test.want {
				t.Errorf("got output %v, want %v", output, test.want)
			}
		})
		t.Run(test.label+" (RunAndReturn)", func(t *testing.T) {
			output := test.query.RunAndReturn().(bool)
			if output != test.want {
				t.Errorf("got %v, want %v", output, test.want)
			}
		})
	}
}
