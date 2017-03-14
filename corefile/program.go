package corefile

import (
	"fmt"
	"sort"
	"unicode"
	"unicode/utf8"

	"golang.org/x/debug/dwarf"
)

// Program describes the state of a program in a core file.
type Program struct {
	// Goroutines enumerates all goroutines spawned by application code,
	// including the main goroutine. This excludes runtime-internal goroutines
	// such as GC workers.
	Goroutines []*Goroutine

	// GlobalVars enumerates global variables in the program. This includes
	// both exported and unexported variables, but does not include variables
	// from the runtime package.
	GlobalVars *VarSet

	// RuntimeLibary describes the runtime library used by this program,
	// including exported and unexported variables from the runtime package.
	RuntimeLibrary *RuntimeLibrary

	// TODO?: CGo describes the state of the Program’s C code.
	//CGO *CGO

	// Internal info.
	typeCache    typeCache              // for canonicalizing types
	dwarfs       map[string]*dwarf.Data // maps filepath to the DWARF loaded from that path
	dataSegments dataSegments           // virtual memory mappings
	filemaps     []*mmapFile            // each dataSegment points into one of these mmaps
}

// Goroutine summarizes a single goroutine.
type Goroutine struct {
	G         Value       // the runtime library’s goroutine descriptor object
	CreatorPC uint64      // the go statement that created this goroutine
	Stack     *StackFrame // top of stack (the youngest frame)
	Program   *Program    // parent program

	// StatusString describes the current status of the goroutine as a
	// human-readable string.
	StatusString string

	// WaitingOn gives the address of all objects that the goroutine is
	// waiting on (*sync.Mutex, chan, etc.). Multiple values are possible
	// if the goroutine is in a multi-branch select statement. Empty if
	// the goroutine is not waiting on a value.
	WaitingOn []uint64
}

// StackFrame summarizes a single stack frame.
// TODO: what about deferred closures? `DeferredClosures []Value`?
type StackFrame struct {
	PC             uint64      // currently executing instruction
	Caller, Callee *StackFrame // stack frame links
	Goroutine      *Goroutine  // parent goroutine
	LocalVars      *VarSet     // live local variables
	Func           *FuncInfo   // function called for this frame

	argsArea   dataSegment
	argsBV     *gcBitvector
	localsArea dataSegment
	localsBV   *gcBitvector
}

// Var describes a global or local variable. A Var is simply a named value.
// For global variables, PkgPath names the parent package (can be empty).
// For local variables, Frame names the parent stack frame.
type Var struct {
	Name    string // short name of the variable, not including the package
	PkgPath string
	Frame   *StackFrame
	Value   Value
}

// IsGlobal returns true if v is a global variable.
func (v *Var) IsGlobal() bool {
	return v.Frame == nil
}

// IsExportedGlobal returns true if v is an exported global variable.
func (v *Var) IsExportedGlobal() bool {
	if !v.IsGlobal() {
		return false
	}
	r, _ := utf8.DecodeRuneInString(v.Name)
	return unicode.IsUpper(r)
}

// FullName returns the full name of v.
// For global variables, this includes PkgPath.
// For local variables, this is just v.Name.
func (v *Var) FullName() string {
	if v.PkgPath != "" {
		return v.PkgPath + "." + v.Name
	}
	return v.Name
}

type sortVarByAddr []*Var

func (a sortVarByAddr) Len() int           { return len(a) }
func (a sortVarByAddr) Swap(i, k int)      { a[i], a[k] = a[k], a[i] }
func (a sortVarByAddr) Less(i, k int) bool { return a[i].Value.Addr < a[k].Value.Addr }

// VarSet describes a set of variables.
type VarSet struct {
	list  sortVarByAddr   // kept sorted
	names map[string]*Var // indexed by full name (including the pkgPath)
}

// FindAddr looks up the variable that contains the given address.
func (vs *VarSet) FindAddr(addr uint64) (Var, bool) {
	// Binary search for an upper-bound, then check if the previous var contains addr.
	k := sort.Search(len(vs.list), func(k int) bool {
		return addr < vs.list[k].Value.Addr
	})
	k--
	if k >= 0 && vs.list[k].Value.ContainsAddress(addr) {
		return *vs.list[k], true
	}
	return Var{}, false
}

// FindName looks up the variable with the given name.
// For global variables, name must include the full package path.
func (vs *VarSet) FindName(fullname string) (Var, bool) {
	if v := vs.names[fullname]; v != nil {
		return *v, true
	}
	return Var{}, false
}

// insert adds v to the set.
// Returns an error if v overlaps any Var already in the set.
func (vs *VarSet) insert(v Var) error {
	reportConflict := func(old *Var) error {
		return fmt.Errorf("cannot insert %s (addr=0x%x, size=0x%x): conflicts with %s (addr=0x%x, size=0x%x)",
			v.FullName(), v.Value.Addr, v.Value.Size(),
			old.FullName(), old.Value.Addr, old.Value.Size())
	}

	if vs.names == nil {
		vs.names = make(map[string]*Var)
	}

	// Binary search for an upper-bound.
	k := sort.Search(len(vs.list), func(k int) bool {
		return v.Value.Addr < vs.list[k].Value.Addr
	})

	// Check for a conflict.
	if k < len(vs.list) && v.Value.Size() > 0 && vs.list[k].Value.ContainsAddress(v.Value.Addr+v.Value.Size()-1) {
		return reportConflict(vs.list[k])
	}
	if k > 0 && vs.list[k-1].Value.ContainsAddress(v.Value.Addr) {
		return reportConflict(vs.list[k-1])
	}
	if old, has := vs.names[v.FullName()]; has {
		return reportConflict(old)
	}

	// Insert before k.
	vs.list = append(vs.list[:k], append(sortVarByAddr{&v}, vs.list[k:]...)...)
	vs.names[v.FullName()] = &v

	if sanityChecks && !sort.IsSorted(vs.list) {
		for k, v := range vs.list {
			printf("vs.list[%v] = { addr:0x%x, size:0x%x }", k, v.Value.Addr, v.Value.Size())
		}
		panic(fmt.Sprintf("vars are not sorted after insert(0x%x, 0x%x)", v.Value.Addr, v.Value.Size()))
	}

	return nil
}
