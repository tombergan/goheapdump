// Package heapdump reads and processes heapdump files.
// XXX TODO say more
package heapdump

import (
	"errors"
	"fmt"
	"golang.org/x/debug/gosym"
	"log"
	"sort"
	"unsafe"
)

// ErrOutOfRange is returned when an address is out-of-range.
var ErrOutOfRange = errors.New("out of range")

// Dump represents a single heapdump. This is a wrapper around a RawDump
// that adds type annotations and other useful features for exploring heapdumps.
// Dump is not safe for concurrent use.
type Dump struct {
	// Raw provides a link to the raw heapdump structures. Most users
	// will find it easier to use Dump methods and fields rather than
	// accessing this raw object directly.
	Raw *RawDump

	// OSThreads is a list of allocated OS-level threads.
	OSThreads []*OSThread

	// Goroutines is a list of allocated goroutines.
	Goroutines []*Goroutine

	// GlobalVars is the set of known global variables.
	GlobalVars RootVarSet

	// Finalizers is a list of all registered finalizers.
	Finalizers []*Finalizer

	// OtherRoots lists any other GC roots not categorized above.
	OtherRoots []*RootVar

	// HeapObjects lists all objects on the heap. Sorted by Value.Addr().
	// HeapObjects[k] corresponds exactly to Raw.HeapObjects[k].
	HeapObjects []Value

	// XXX defers, panics, memprof samples?

	// Internal state.
	singlePtrField RawPtrFields    // has one pointer, at offset 0
	tc             *typeCache      // for creating types
	symtab         *gosym.Table    // only set if the dump was loaded with an execfile
	typeFromAddr   map[uint64]Type // for resolving interface values
	typeFromItab   map[uint64]Type // for resolving interface values

	// The list of incoming objects is split in two parts for efficiency.
	// If an object has <= 1 inbound edge, we store it in inbound1[x]. Otherwise,
	// it is stored in inboundN[x]. Since most objects have only one incoming
	// reference, inboundN ends up small. These fields are lazily-initialized
	// by PrecomputeInEdges.
	inbound1 []*Value
	inboundN map[*Value][]*Value
}

// Close closes a Dump.
func (d *Dump) Close() error {
	return d.Raw.Close()
}

// HasTypeInfo returns true if there is type information available in this Dump.
func (d *Dump) HasTypeInfo() bool {
	return d.symtab != nil
}

// LookupPC returns line information about the given program counter,
// or nil if the PC is unknown or if symbol information is not available.
func (d *Dump) LookupPC(pc uint64) *SymTabLine {
	if d.symtab == nil {
		return nil
	}
	f, l, fn := d.symtab.PCToLine(pc)
	if fn == nil {
		return nil
	}
	return &SymTabLine{f, l, fn}
}

// FindObject returns the object that contains addr, or nil if addr refers to unknown memory.
func (d *Dump) FindObject(addr uint64) *Value {
	if v := d.FindHeapObject(addr); v != nil {
		return v
	}
	if rv := d.FindStackOrGlobalObject(addr); rv != nil {
		return rv.Value
	}
	return nil
}

// FindHeapObject returns &d.HeapObjects[x], where heap object x contains addr.
// Returns nil if addr does not point to a known heap object.
func (d *Dump) FindHeapObject(addr uint64) *Value {
	// Binary search for an upper-bound value, then check if the previous value contains addr.
	k := sort.Search(len(d.HeapObjects), func(k int) bool {
		return addr < d.HeapObjects[k].Addr()
	})
	k--
	if k >= 0 && d.HeapObjects[k].ContainsAddress(addr) {
		return &d.HeapObjects[k]
	}
	return nil
}

// FindStackOrGlobalObject returns the RootVar containing addr, or nil
// if addr does not point to a stack variable or global variable.
func (d *Dump) FindStackOrGlobalObject(addr uint64) *RootVar {
	for k := range d.Raw.GlobalSegments {
		if d.Raw.GlobalSegments[k].Contains(addr) {
			return d.GlobalVars.FindAddr(addr)
		}
	}
	for _, g := range d.Goroutines {
		for sf := g.Stack; sf != nil; sf = sf.Caller {
			if !sf.Raw.Segment.Contains(addr) {
				continue
			}
			if lv := sf.LocalVars.FindAddr(addr); lv != nil {
				return lv
			}
		}
	}
	return nil
}

// ForeachRootVar iterates over all known RootVars.
func (d *Dump) ForeachRootVar(fn func(*RootVar)) {
	for _, gv := range d.GlobalVars.List {
		fn(gv)
	}
	for _, g := range d.Goroutines {
		for sf := g.Stack; sf != nil; sf = sf.Caller {
			for _, lv := range sf.LocalVars.List {
				fn(lv)
			}
		}
	}
	for _, f := range d.Finalizers {
		fn(f.Obj)
		fn(f.ObjType)
		fn(f.Fn)
		fn(f.FnArgType)
	}
	for _, ov := range d.OtherRoots {
		fn(ov)
	}
}

// ForeachRootPointer is a shorthand that iterates over all pointers in all RootVars.
func (d *Dump) ForeachRootPointer(fn func(*Value)) {
	d.ForeachRootVar(func(rv *RootVar) { rv.Value.ForeachPointer(fn) })
}

// value2heap converts a *Value to an index in d.HeapObjects.
func (d *Dump) value2heap(v *Value) (int, error) {
	if len(d.HeapObjects) == 0 {
		return -1, errors.New("heap is empty")
	}
	start := uintptr(unsafe.Pointer(&d.HeapObjects[0]))
	elemSz := uintptr(unsafe.Sizeof(d.HeapObjects[0]))
	if len(d.HeapObjects) > 1 {
		// In case there is padding between elements.
		elemSz = uintptr(unsafe.Pointer(&d.HeapObjects[1])) - start
	}
	end := start + elemSz*uintptr(len(d.HeapObjects))
	val := uintptr(unsafe.Pointer(v))
	if val < start || end <= val {
		return -1, fmt.Errorf("value %x (%s) not in d.HeapObjects (%x,%x)", val, v.Type, start, end)
	}
	return int((val - start) / elemSz), nil
}

// InEdges returns the set of values that point-to heap object v.
// v must point to a value in d.HeapObjects, otherwise this will panic.
// Caller should not mutate the returned slice.
func (d *Dump) InEdges(v *Value) []*Value {
	d.PrecomputeInEdges()

	if ptrs, ok := d.inboundN[v]; ok {
		return ptrs
	}

	idx, err := d.value2heap(v)
	if err != nil {
		panic(err)
	}
	if ptr := d.inbound1[idx]; ptr != nil {
		return []*Value{ptr}
	}

	return nil
}

// PrecomputeInEdges precomputes information needed by InEdges. If this is not
// called explicitly, it will be called automatically on the first call to InEdges.
func (d *Dump) PrecomputeInEdges() {
	if d.inboundN != nil {
		return
	}

	d.inbound1 = make([]*Value, len(d.HeapObjects))
	d.inboundN = make(map[*Value][]*Value)

	addPtr := func(ptr *Value) {
		if ptr.IsZero() {
			return
		}
		obj, _, err := ptr.DerefContainer()
		if err != nil {
			return
		}
		idx, err := d.value2heap(obj)
		if err != nil {
			return // skip pointers to non-heap objects
		}
		if d.inbound1[idx] == nil {
			d.inbound1[idx] = ptr
			return
		}
		if d.inboundN[obj] == nil {
			d.inboundN[obj] = []*Value{d.inbound1[idx], ptr}
			return
		}
		d.inboundN[obj] = append(d.inboundN[obj], ptr)
	}

	d.ForeachRootPointer(addPtr)
	for k := range d.HeapObjects {
		d.HeapObjects[k].ForeachPointer(addPtr)
	}
}

// FindRootsFor finds the set of GC roots from which heap address v is reachable.
// Always returns the empty list if v doesn't refer to a heap object.
// TODO: Also look in OtherRoots and Finalizers
func (d *Dump) FindRootsFor(v *Value) []*RootVar {
	visited := make([]bool, len(d.HeapObjects))
	roots := make(map[*RootVar]struct{})
	stack := []*Value{v}

	for len(stack) != 0 {
		v := stack[len(stack)-1]
		stack = stack[:len(stack)-1]

		// If v is a heap object, continue on incoming edges.
		if obj := d.FindHeapObject(v.Addr()); obj != nil {
			idx, err := d.value2heap(obj)
			if err != nil {
				panic(err) // should not happen
			}
			if !visited[idx] {
				visited[idx] = true
				for _, ptr := range d.InEdges(obj) {
					stack = append(stack, ptr)
				}
			}
			continue
		}

		// If v is a RootVar, add to the output set.
		if rv := d.FindStackOrGlobalObject(v.Addr()); rv != nil {
			roots[rv] = struct{}{}
			continue
		}

		// FIXME
		fmt.Printf("Warning: unhandled case in FindRootsFor (Finalizer or OtherRoot)\n")
	}

	out := make([]*RootVar, 0, len(roots))
	for rv := range roots {
		out = append(out, rv)
	}
	return out
}

// XXX TODO?
//  Add more wrapper methods to access fields from Raw{*} fields?

// SymTabLine describes a source code line from a symbol table.
type SymTabLine struct {
	File string      // file name
	Line int         // line number in File
	Func *gosym.Func // function containing the source line (if any)
}

// OSThread represents a single OS-level thread.
type OSThread struct {
	Raw        *RawOSThread
	M          *Value       // thread descriptor (may be nil if types aren't available)
	Goroutines []*Goroutine // goroutines attached to this thread
}

// Goroutine represents a single goroutine.
type Goroutine struct {
	Raw      *RawGoroutine
	G        *Value      // goroutine descriptor (may be nil if types aren't available)
	OSThread *OSThread   // link to the associated OSThread, if any
	Stack    *StackFrame // link to the youngest (currently-executing) stack frame
	// TODO: defer records
	// TODO: panic records
	// TODO: CtxtAddr?
}

// Status returns the goroutine status as a string.
// See gc/src/runtime/runtime2.go.
func (g *Goroutine) Status() string {
	const scan = 0x1000
	var s string
	switch status := g.Raw.Status &^ scan; status {
	case 0:
		s = "idle"
	case 1:
		s = "runnable"
	case 2:
		log.Println("Goroutine.Status: running goroutine in heapdump (should never happen)")
		s = "running"
	case 3:
		s = "syscall"
	case 4:
		s = g.Raw.WaitReason
	case 5:
		log.Println("Goroutine.Status: unexpected status 5 (unused)")
		s = "unused5"
	case 6:
		s = "dead"
	case 7:
		log.Println("Goroutine.Status: unexpected status 7 (unused)")
		s = "unused7"
	case 8:
		s = "copystack"
	default:
		panic(fmt.Errorf("unknown status %x", g.Raw.Status))
	}
	if g.Raw.Status&scan != 0 {
		s = "scan(" + s + ")"
	}
	return s
}

// StackFrame represents a single stack frame.
type StackFrame struct {
	Raw            *RawStackFrame
	Caller, Callee *StackFrame // link to the caller and callee frames, if any
	Goroutine      *Goroutine  // link to the parent goroutine
	LocalVars      RootVarSet  // includes parameters to this function
}

// Addr returns the base (lowest) address of the stack frame.
func (sf *StackFrame) Addr() uint64 {
	return sf.Raw.Segment.Addr
}

// Size returns the size of this stack frame in bytes.
func (sf *StackFrame) Size() uint64 {
	return sf.Raw.Segment.Size()
}

// Dpeth returns the stack depth of this frame. Depth 0 is the frame with no callee.
func (sf *StackFrame) Depth() uint64 {
	return sf.Raw.Depth
}

// PC returns the currently-executing PC of the stack frame.
func (sf *StackFrame) PC() uint64 {
	return sf.Raw.PC
}

// Finalizer represents a single registered finalizer.
type Finalizer struct {
	Raw       *RawFinalizer
	Obj       *RootVar // object to finalize
	ObjType   *RootVar // type descriptor for Obj
	Fn        *RootVar // finalizer function
	FnArgType *RootVar // type descriptor for Fn's arg
}

// RootVarSet is a set of RootVars.
type RootVarSet struct {
	List   []*RootVar          // sorted by RootVar.Value.Addr()
	ByName map[string]*RootVar // indexed by RootVar.Name
}

// FindAddr searches for a variable by its address.
func (l *RootVarSet) FindAddr(addr uint64) *RootVar {
	// Binary searches for an upper-bound root, then check if the previous root contains addr.
	k := sort.Search(len(l.List), func(k int) bool {
		return addr < l.List[k].Value.Addr()
	})
	k--
	if k >= 0 && l.List[k].Value.ContainsAddress(addr) {
		return l.List[k]
	}
	return nil
}

func (l *RootVarSet) init() {
	if l.ByName == nil {
		l.ByName = make(map[string]*RootVar)
	}
}

func (l *RootVarSet) add(rv *RootVar) {
	if old := l.ByName[rv.Name]; old != nil {
		LogPrintf("warning: dup vars %#v and %#v", *old, *rv)
	}
	l.List = append(l.List, rv)
	l.ByName[rv.Name] = rv
}

func (l *RootVarSet) sort() {
	sort.Sort(sortVarByAddr(l.List))
}

type sortVarByAddr []*RootVar

func (a sortVarByAddr) Len() int           { return len(a) }
func (a sortVarByAddr) Swap(i, k int)      { a[i], a[k] = a[k], a[i] }
func (a sortVarByAddr) Less(i, k int) bool { return a[i].Value.Addr() < a[k].Value.Addr() }

// RootVar is a variable that might act as a root for garbage collection.
// This covers all local and global variables (including non-pointers),
// plus other runtime-internal pointers that are GC roots.
//
// In some cases (Dump.Finalizers and Dump.OtherRoots), we don't know where
// the RootVar is actually located -- we only know what it points at. For
// these cases, RootVar.Value.Addr() is 0.
type RootVar struct {
	Kind  RootVarKind // describes where this root comes from
	Name  string      // fully-qualified package name, if known, otherwise "unknown{*}"
	Value *Value
}

// RootVarKind gives the various kinds of RootVars.
type RootVarKind string

const (
	RootVarGlobal        RootVarKind = "Global"
	RootVarLocal                     = "Local"
	RootVarFuncParameter             = "FuncParameter"
	RootVarFinalizer                 = "Finalizer"
	RootVarOther                     = "Other"
)
