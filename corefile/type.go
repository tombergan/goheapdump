package corefile

import (
	"bytes"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"

	"golang.org/x/debug/dwarf"
)

// Type is the interface implemented by all types.
//
// Type values defined in the same Program are comparable with the == and !=
// operators. Two Type values are equal iff they represent identical types.
//
// TODO: Add "Unnamed() Type" to return the unnamed version of a type?
type Type interface {
	// Program returns the program that defined this type.
	Program() *Program

	// String prints the type as a string.
	// For named types, this prints the full name of the type including the PkgPath.
	String() string

	// Name is the name of the type within its package, or "" for unnamed types.
	// See reflect.Type.Name.
	Name() string

	// PkgPath returns a named type's package path.
	// See reflect.Type.PkgPath.
	PkgPath() string

	// Size in bytes of values of this type.
	Size() uint64

	// InternalRepresentation returns the internal type used by the runtime library
	// to implement this type. Returns nil for NumericType, ArrayType, PtrType, StructType,
	// FuncType, and GCObjectType, which do not have a special internal representation.
	// For example, the InternalRepresentation of a SliceType is a StructType that
	// is equivalent to reflect.SliceHeader as defined in the core file’s version of
	// package reflect.
	InternalRepresentation() Type

	// directIface returns true if the type is pointer-shaped, meaning it can be
	// stored directly in the value of an iface or eface.
	directIface() bool

	// containsPointers returns true if values of this type might contain pointers.
	containsPointers() bool

	// base returns the shared type info.
	base() *baseType
}

type baseType struct {
	program       *Program
	name, pkgPath string // if named and known
	size          uint64
}

func (t *baseType) Program() *Program { return t.program }
func (t *baseType) Name() string      { return t.name }
func (t *baseType) PkgPath() string   { return t.pkgPath }
func (t *baseType) Size() uint64      { return t.size }
func (t *baseType) base() *baseType   { return t }

func (t *baseType) String() string {
	if t.pkgPath != "" {
		return t.pkgPath + "." + t.name
	}
	return t.name
}

// NumericKind gives the various kinds of numeric types.
type NumericKind string

const (
	NumericBool NumericKind = "bool"

	NumericUint8  = "uint8"
	NumericUint16 = "uint16"
	NumericUint32 = "uint32"
	NumericUint64 = "uint64"

	NumericInt8  = "int8"
	NumericInt16 = "int16"
	NumericInt32 = "int32"
	NumericInt64 = "int64"

	NumericFloat32    = "float32"
	NumericFloat64    = "float64"
	NumericComplex64  = "complex64"
	NumericComplex128 = "complex128"
)

// NumericType is the type of booleans and all numbers.
type NumericType struct {
	baseType
	Kind NumericKind
}

func (t *NumericType) String() string {
	if t.Name() != "" {
		return t.baseType.String()
	}
	return string(t.Kind)
}

func (t *NumericType) InternalRepresentation() Type {
	return nil
}

func (t *NumericType) directIface() bool {
	return false
}

func (t *NumericType) containsPointers() bool {
	return false
}

func numericKindToSize(k NumericKind) uint64 {
	switch k {
	case NumericBool, NumericUint8, NumericInt8:
		return 1 // Value.ReadScalar must change if this does
	case NumericUint16, NumericInt16:
		return 2
	case NumericUint32, NumericInt32, NumericFloat32:
		return 4
	case NumericUint64, NumericInt64, NumericFloat64, NumericComplex64:
		return 8
	case NumericComplex128:
		return 16
	default:
		panic(fmt.Errorf("bad NumericKind %d", k))
	}
}

// ArrayType is the type of arrays.
type ArrayType struct {
	baseType
	Elem Type
	Len  uint64 // number of elements
}

func (t *ArrayType) String() string {
	if t.Name() != "" {
		return t.baseType.String()
	}
	return fmt.Sprintf("[%d]", t.Len) + t.Elem.String()
}

func (t *ArrayType) InternalRepresentation() Type {
	return nil
}

func (t *ArrayType) directIface() bool {
	return t.Len == 1 && t.Elem.directIface()
}

func (t *ArrayType) containsPointers() bool {
	return t.Elem.containsPointers()
}

// PtrType is the type of pointers.
type PtrType struct {
	baseType
	Elem Type
}

func (t *PtrType) String() string {
	if t.Name() != "" {
		return t.baseType.String()
	}
	return "*" + t.Elem.String()
}

func (t *PtrType) InternalRepresentation() Type {
	return nil
}

func (t *PtrType) directIface() bool {
	return true
}

func (t *PtrType) containsPointers() bool {
	return true
}

// StructType is the type of structs.
type StructType struct {
	baseType
	hasPtrs bool
	Fields  []StructField // sorted by offset
}

func (t *StructType) String() string {
	if t.Name() != "" {
		return t.baseType.String()
	}
	var buf bytes.Buffer
	buf.WriteString("struct {")
	for k, f := range t.Fields {
		// TODO: for anonymous fields, don't print the type?
		buf.WriteString(f.Name)
		if k == 0 {
			buf.WriteString(" ")
		} else {
			buf.WriteString("; ")
		}
		buf.WriteString(f.Type.String())
	}
	if len(t.Fields) != 0 {
		buf.WriteString(" ")
	}
	buf.WriteString("}")
	return buf.String()
}

func (t *StructType) InternalRepresentation() Type {
	return nil
}

func (t *StructType) directIface() bool {
	return t.size == uint64(t.program.RuntimeLibrary.Arch.PointerSize) &&
		len(t.Fields) == 1 && t.Fields[0].Type.directIface()
}

func (t *StructType) containsPointers() bool {
	return t.hasPtrs
}

// FieldByName returns the field with the given name. Never returns an unnamed field.
// Returns false if not found.
// TODO: better than O(n) for large structs
func (t *StructType) FieldByName(name string) (StructField, bool) {
	if name == "" {
		return StructField{}, false
	}
	for k := range t.Fields {
		if t.Fields[k].Name == name {
			return t.Fields[k], true
		}
	}
	return StructField{}, false
}

// FieldContainingOffset returns the field that contains the given offset.
// The result is a pointer into t.Fields, or nil if not found.
// TODO: better than O(n) for large structs
func (t *StructType) FieldContainingOffset(offset uint64) (StructField, bool) {
	for k := range t.Fields {
		f := &t.Fields[k]
		if f.Offset <= offset && offset < f.Offset+f.Type.Size() {
			return *f, true
		}
	}
	return StructField{}, false
}

// StructField is a single field within a struct.
type StructField struct {
	Name   string
	Type   Type
	Offset uint64
}

type sortFieldByOffset []StructField

func (a sortFieldByOffset) Len() int           { return len(a) }
func (a sortFieldByOffset) Swap(i, k int)      { a[i], a[k] = a[k], a[i] }
func (a sortFieldByOffset) Less(i, k int) bool { return a[i].Offset < a[k].Offset }

type structFieldList []StructField

func (a structFieldList) String() string {
	var buf bytes.Buffer
	for _, f := range a {
		// TODO: UGLY: This is used to canonicalize struct types. It's an ugly way
		// to use a variable-length array as a map key. The %p assumes that Go does
		// not have a moving GC. A less ugly way to do this is to give each type a
		// unique ID, then print the unique ID instead of the f.Type pointer.
		fmt.Fprintf(&buf, "%d: %s %p, ", f.Offset, f.Name, f.Type)
	}
	return buf.String()
}

// InterfaceType represents an interface.
type InterfaceType struct {
	baseType
	Rep   *StructType // struct that represents this interface (e.g., runtime.iface or runtime.eface)
	EFace bool        // true if this is an eface (i.e., "interface{}")
}

func (t *InterfaceType) String() string {
	if t.EFace && t.Name() == "" {
		return "interface {}"
	}
	return t.baseType.String()
}

func (t *InterfaceType) InternalRepresentation() Type {
	return t.Rep
}

func (t *InterfaceType) directIface() bool {
	return t.Rep.directIface()
}

func (t *InterfaceType) containsPointers() bool {
	return true
}

const (
	efaceTypeField = 0 // Rep.Fields[0] is the *runtime._type pointer
	efaceDataField = 1 // Rep.Fields[1] is the data pointer
	ifaceTabField  = 0 // Rep.Fields[0] is the *runtime.itab pointer
	ifaceDataField = 1 // Rep.Fields[1] is the data pointer
)

// SliceType represents a slice.
type SliceType struct {
	baseType
	Rep  *StructType // struct that represents this slice (e.g., runtime.slice)
	Elem Type        // type of elements in this slice
}

func (t *SliceType) String() string {
	if t.Name() != "" {
		return t.baseType.String()
	}
	return "[]" + t.Elem.String()
}

func (t *SliceType) InternalRepresentation() Type {
	return t.Rep
}

func (t *SliceType) directIface() bool {
	return t.Rep.directIface()
}

func (t *SliceType) containsPointers() bool {
	return true
}

const (
	sliceArrayField = 0 // Rep.Fields[0] has the slice's base pointer (type *Elem)
	sliceLenField   = 1 // Rep.Fields[1] has the slice's len (type int)
	sliceCapField   = 2 // Rep.Fields[2] has the slice's cap (type int)
)

// StringType represents a string.
type StringType struct {
	baseType
	Rep *StructType // struct that represents this string (e.g., runtime.stringStruct)
}

func (t *StringType) String() string {
	if t.Name() != "" {
		return t.baseType.String()
	}
	return "string"
}

func (t *StringType) InternalRepresentation() Type {
	return t.Rep
}

func (t *StringType) directIface() bool {
	return t.Rep.directIface()
}

func (t *StringType) containsPointers() bool {
	return true
}

const (
	stringArrayField = 0 // Rep.Fields[0] has the strings's base pointer (type *uint8)
	stringLenField   = 1 // Rep.Fields[1] has the strings's len (type int)
)

// ChanType represents a channel.
type ChanType struct {
	baseType
	Rep  *PtrType        // ptr-to-struct that represents this chan (e.g., *runtime.hchan)
	Dir  reflect.ChanDir // channel direction
	Elem Type            // type of elements in this chan
}

func (t *ChanType) String() string {
	if t.Name() != "" {
		return t.baseType.String()
	}
	switch t.Dir {
	case reflect.BothDir:
		return "chan " + t.Elem.String()
	case reflect.RecvDir:
		return "<-chan " + t.Elem.String()
	case reflect.SendDir:
		return "chan<- " + t.Elem.String()
	default:
		panic(fmt.Sprintf("unknown chan dir %x", t.Dir))
	}
}

func (t *ChanType) InternalRepresentation() Type {
	return t.Rep
}

func (t *ChanType) directIface() bool {
	return t.Rep.directIface()
}

func (t *ChanType) containsPointers() bool {
	return true
}

const (
	chanLenField    = 0 // Rep.Fields[0] has the chan's len field (type uint)
	chanCapField    = 1 // Rep.Fields[1] has the chan's cap field (type uint)
	chanBufferField = 2 // Rep.Fields[2] has the chan's buffer pointer (type *Elem, effectively)
)

// MapType represents a map.
type MapType struct {
	baseType
	Rep  *PtrType // ptr-to-struct that represents this map (e.g., *runtime.hmap)
	Key  Type     // type of keys in this map
	Elem Type     // type of values in this map
}

func (t *MapType) String() string {
	if t.Name() != "" {
		return t.baseType.String()
	}
	return "map[" + t.Key.String() + "]" + t.Elem.String()
}

func (t *MapType) InternalRepresentation() Type {
	return t.Rep
}

func (t *MapType) directIface() bool {
	return t.Rep.directIface()
}

func (t *MapType) containsPointers() bool {
	return true
}

const (
	mapLenField = 0 // Rep.Fields[0] has the map's len field (type int)
)

// FuncType represents a function.
// Currently, we do not record the parameter or result types of the function.
// TODO: need to record param and result types so we can get types in closures?
// See: src/runtime/runtime2.go:funcval and src/cmd/compile/internal/gc/cgen.go:Ginscall
type FuncType struct {
	baseType
}

func (t *FuncType) String() string {
	if t.Name() != "" {
		return t.baseType.String()
	}
	return "func"
}

func (t *FuncType) InternalRepresentation() Type {
	return nil // TODO?
}

func (t *FuncType) directIface() bool {
	return t.Size() == uint64(t.Program().RuntimeLibrary.Arch.PointerSize)
}

func (t *FuncType) containsPointers() bool {
	return true // TODO?
}

// GCObjectType TODO: describe
type GCObjectType struct {
	baseType
}

func (t *GCObjectType) String() string {
	return fmt.Sprintf("$GCObject<%d>", t.baseType.size)
}

func (t *GCObjectType) InternalRepresentation() Type {
	return nil
}

func (t *GCObjectType) directIface() bool {
	panic("not implemented")
}

func (t *GCObjectType) containsPointers() bool {
	return true // conservative; we have to check the heap bitmap to know for sure
}

// typeCache is used to canonicalize types.
// When the core file is being loaded, we call addDWARF repeatedly to build
// a one-to-one mapping from each DWARF type to a Type. After the core file
// is loaded, we use Program.FooType methods to lookup types as needed, and
// we also translate types from the runtime library with convertRuntimeType.
type typeCache struct {
	program   *Program
	nameCache map[string]Type      // cache of named types
	anonCache map[interface{}]Type // cache of anonymous types

	// for runtime converstions
	runtimeCache map[uint64]Type // maps type descriptor address to type

	// for DWARF conversions
	dwarfCache map[dwarfCacheKey]Type // for addDWARF, findDWARF
	dwarfDone  bool                   // no addDWARF calls allowed after this

	// for verbosef debugging during conversions
	depth int
}

type dwarfCacheKey struct {
	dt       dwarf.Type
	typename string
}

func (tc *typeCache) initialize(p *Program) {
	tc.program = p
	tc.nameCache = make(map[string]Type)
	tc.anonCache = make(map[interface{}]Type)
	tc.runtimeCache = make(map[uint64]Type)
	tc.dwarfCache = make(map[dwarfCacheKey]Type)
}

func (tc *typeCache) verbosef(format string, args ...interface{}) {
	verbosef(strings.Repeat(" ", tc.depth)+format, args...)
}

// fullname != "" means add to nameCache.
// anonKey != nil means add to anonCache.
// Exactly one must be specified.
func (tc *typeCache) add(t Type, fullname string, anonKey interface{}) {
	if fullname != "" {
		if old := tc.nameCache[fullname]; old != nil {
			tc.verbosef("WARNING: named type %s already exists as %T; overriding", fullname, old)
		}
		tc.nameCache[fullname] = t
	} else if anonKey != nil {
		if old := tc.anonCache[anonKey]; old != nil {
			tc.verbosef("WARNING: anonymous type with key %v already exists as %s (%T); overriding", anonKey, old, old)
		}
		tc.anonCache[anonKey] = t
	} else {
		panic("fullname and anonKey both nil")
	}
}

// findDWARF looks up the Type for dt.
// Returns nil if not found.
func (tc *typeCache) findDWARF(dt dwarf.Type) Type {
	return tc.dwarfCache[dwarfCacheKey{dt, dt.Common().Name}]
}

// addDWARF builds a Type for dt if it does not yet exist.
func (tc *typeCache) addDWARF(dt dwarf.Type) (Type, error) {
	if tc.dwarfDone {
		panic("addDWARF called after dwarfDone")
	}
	tc.depth++
	defer func() { tc.depth-- }()
	t, err := tc.addDWARFWithTypedef(dt, "")
	if err != nil {
		return nil, err
	}
	tc.verbosef("converted (%s, %T) -> (%s, %T, sz=%d, p=%s, n=%s)", dt, dt, t, t, t.Size(), t.PkgPath(), t.Name())
	return t, nil
}

func (tc *typeCache) addDWARFWithTypedef(dt dwarf.Type, typename string) (Type, error) {
	// If not inside a typedef, then the typename comes from dt.
	if typename == "" {
		typename = dt.Common().Name
	}

	tc.verbosef("convert (%s, %T, name=%s, off=0x%x)", dt, dt, typename, dt.Common().Offset)

	key := dwarfCacheKey{dt, typename}
	if t := tc.dwarfCache[key]; t != nil {
		tc.verbosef("cached (%s, %T) -> (%s, %T, sz=%d, p=%s, n=%s)", dt, dt, t, t, t.Size(), t.PkgPath(), t.Name())
		return t, nil
	}

	add := func(t Type) Type {
		tc.dwarfCache[key] = t
		return t
	}
	addNumeric := func(k NumericKind) Type {
		if size, expected := dt.Common().ByteSize, numericKindToSize(k); uint64(size) != expected {
			panic(fmt.Errorf("wrong size %d for type %s, want %s", size, dt, expected))
		}
		t := &NumericType{}
		t.initialize(tc, typename, k)
		return add(t)
	}

	switch dt := dt.(type) {
	// NumericTypes.

	case *dwarf.BoolType:
		return addNumeric(NumericBool), nil
	case *dwarf.CharType:
		return addNumeric(NumericInt8), nil
	case *dwarf.UcharType:
		return addNumeric(NumericUint8), nil

	case *dwarf.IntType:
		switch dt.ByteSize {
		case 1:
			return addNumeric(NumericInt8), nil
		case 2:
			return addNumeric(NumericInt16), nil
		case 4:
			return addNumeric(NumericInt32), nil
		case 8:
			return addNumeric(NumericInt64), nil
		default:
			return nil, fmt.Errorf("unsupported IntType %s size=%d", dt.String(), dt.ByteSize)
		}

	case *dwarf.UintType:
		switch dt.ByteSize {
		case 1:
			return addNumeric(NumericUint8), nil
		case 2:
			return addNumeric(NumericUint16), nil
		case 4:
			return addNumeric(NumericUint32), nil
		case 8:
			return addNumeric(NumericUint64), nil
		default:
			return nil, fmt.Errorf("unsupported UintType %s size=%d", dt.String(), dt.ByteSize)
		}

	case *dwarf.FloatType:
		switch dt.ByteSize {
		case 4:
			return addNumeric(NumericFloat32), nil
		case 8:
			return addNumeric(NumericFloat64), nil
		default:
			return nil, fmt.Errorf("unsupported FloatType %s size=%d", dt.String(), dt.ByteSize)
		}

	case *dwarf.ComplexType:
		switch dt.ByteSize {
		case 8:
			return addNumeric(NumericComplex64), nil
		case 16:
			return addNumeric(NumericComplex128), nil
		default:
			return nil, fmt.Errorf("unsupported ComplexType %s size=%d", dt.String(), dt.ByteSize)
		}

	// Composites.
	// We allocate each FooType before parsing the subtypes so that
	// a subtype can have a circular reference back to the FooType.

	case *dwarf.ArrayType:
		t := add(new(ArrayType))
		elem, err := tc.addDWARF(dt.Type)
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(typename, "[") {
			typename = "" // anonymous type
		}
		if got, want := uint64(dt.ByteSize), uint64(dt.Count)*elem.Size(); got != want {
			return nil, fmt.Errorf("expected sizeof(ArrayType %s)=%d, but DWARF says %d", dt, want, got)
		}
		t.(*ArrayType).initialize(tc, typename, elem, uint64(dt.Count))
		return t, nil

	case *dwarf.PtrType:
		if typename == "unsafe.Pointer" {
			t := add(new(PtrType))
			t.(*PtrType).initialize(tc, typename, tc.program.MakeGCObjectType(0))
			return t, nil
		}
		t := add(new(PtrType))
		elem, err := tc.addDWARF(dt.Type)
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(typename, "*") {
			typename = "" // anonymous type
		}
		if got, want := uint64(dt.ByteSize), uint64(tc.program.RuntimeLibrary.Arch.PointerSize); got != want {
			return nil, fmt.Errorf("expected sizeof(PtrType %s)=%d, but DWARF says %d", dt, want, got)
		}
		t.(*PtrType).initialize(tc, typename, elem)
		return t, nil

	case *dwarf.StructType:
		if dt.Kind != "struct" {
			return nil, fmt.Errorf("unsupported DWARF struct kind %s (type is %s)", dt.Kind, dt)
		}
		if dt.Incomplete {
			return nil, fmt.Errorf("DWARF incomplete structs are not supported (type is %s)", dt)
		}
		t := add(new(StructType))
		var fields []StructField
		for _, df := range dt.Field {
			tc.verbosef("field %s", df.Name)
			if df.BitSize != 0 {
				return nil, fmt.Errorf("struct bit fields not supported %s.%s", dt, df.Name)
			}
			t, err := tc.addDWARF(df.Type)
			if err != nil {
				return nil, err
			}
			if uint64(dt.ByteSize) < uint64(df.ByteOffset)+t.Size() {
				// Allow size=0 fields just past the end of the struct.
				// This is used by the runtime library, which does the "0-length array" trick.
				if t.Size() > 0 || df.ByteOffset > df.ByteSize {
					return nil, fmt.Errorf("field %s (offset=%d, size=%d) is outside of %s (size %d)", df.Name, df.ByteOffset, df.ByteSize, dt, dt.ByteSize)
				}
			}
			fields = append(fields, StructField{
				Name:   df.Name,
				Type:   t,
				Offset: uint64(df.ByteOffset),
			})
		}
		if strings.HasPrefix(typename, "struct {") {
			typename = "" // anonymous type
		}
		t.(*StructType).initialize(tc, typename, fields, uint64(dt.ByteSize))
		return t, nil

	case *dwarf.InterfaceType:
		t := add(new(InterfaceType))
		// In the DWARF, interfaces are a typedef to their rep type.
		rep, err := tc.addDWARF(dt.TypedefType.Type)
		if err != nil {
			return nil, err
		}
		if _, ok := rep.(*StructType); !ok {
			return nil, fmt.Errorf("expected StructType for interface rep, got %s (%T), DWARF type is %s (%T)",
				rep, rep, dt, dt)
		}
		t.(*InterfaceType).initialize(tc, typename, rep.String() == "runtime.eface", rep.(*StructType))
		return t, nil

	case *dwarf.SliceType:
		t := add(new(SliceType))
		elem, err := tc.addDWARF(dt.ElemType)
		if err != nil {
			return nil, err
		}
		// The actual slice struct is named runtime.slice. However, in the DWARF,
		// each []foo is typedef'd to a struct type named "[]foo", where the array
		// field has type *foo. We rename that struct type so it has does not look
		// like "[]foo" when printed.
		dt.StructType.StructName = fmt.Sprintf("$sliceStruct<%s>", dt.StructType.Name[2:])
		rep, err := tc.addDWARF(&dt.StructType)
		if err != nil {
			return nil, err
		}
		if _, ok := rep.(*StructType); !ok {
			return nil, fmt.Errorf("expected StructType for slice rep, got %s (%T), DWARF type is %s (%T)",
				rep, rep, dt, dt)
		}
		if strings.HasPrefix(typename, "[") {
			typename = "" // anonymous type
		}
		t.(*SliceType).initialize(tc, typename, elem, rep.(*StructType))
		return t, nil

	case *dwarf.StringType:
		t := add(new(StringType))
		// Rename the rep type, otherwise the default name is "string",
		// which makes the rep type look like the actual string type.
		dt.StructType.StructName = "$stringStruct"
		rep, err := tc.addDWARF(&dt.StructType)
		if err != nil {
			return nil, err
		}
		if _, ok := rep.(*StructType); !ok {
			return nil, fmt.Errorf("expected StructType for string rep, got %s (%T), DWARF type is %s (%T)",
				rep, rep, dt, dt)
		}
		if typename == "string" {
			typename = "" // anonymous type
		}
		t.(*StringType).initialize(tc, typename, rep.(*StructType))
		return t, nil

	case *dwarf.ChanType:
		t := add(new(ChanType))
		elem, err := tc.addDWARF(dt.ElemType)
		if err != nil {
			return nil, err
		}
		// In the DWARF, chans are a typedef to their rep type.
		rep, err := tc.addDWARF(dt.TypedefType.Type)
		if err != nil {
			return nil, err
		}
		if !isPtrToStruct(rep) {
			return nil, fmt.Errorf("expected PtrType(StructType) for chan rep, got %s (%T), DWARF type is %s (%T)",
				rep, rep, dt, dt)
		}
		var dir reflect.ChanDir
		switch {
		case strings.HasPrefix(dt.Common().Name, "chan "):
			dir = reflect.BothDir
		case strings.HasPrefix(dt.Common().Name, "<-chan "):
			dir = reflect.RecvDir
		case strings.HasPrefix(dt.Common().Name, "chan<- "):
			dir = reflect.SendDir
		}
		if strings.HasPrefix(typename, "chan ") || strings.HasPrefix(typename, "<-chan ") || strings.HasPrefix(typename, "chan<- ") {
			typename = "" // anonymous type
		}
		t.(*ChanType).initialize(tc, typename, dir, elem, rep.(*PtrType))
		return t, nil

	case *dwarf.MapType:
		t := add(new(MapType))
		key, err := tc.addDWARF(dt.KeyType)
		if err != nil {
			return nil, err
		}
		elem, err := tc.addDWARF(dt.ElemType)
		if err != nil {
			return nil, err
		}
		// In the DWARF, maps are a typedef to their rep type.
		rep, err := tc.addDWARF(dt.TypedefType.Type)
		if err != nil {
			return nil, err
		}
		if !isPtrToStruct(rep) {
			return nil, fmt.Errorf("expected PtrType(StructType) for map rep, got %s (%T), DWARF type is %s (%T)",
				rep, rep, dt, dt)
		}
		if strings.HasPrefix(typename, "map[") {
			typename = "" // anonymous type
		}
		t.(*MapType).initialize(tc, typename, key, elem, rep.(*PtrType))
		return t, nil

	case *dwarf.FuncType:
		t := add(new(FuncType))
		t.(*FuncType).initialize(tc, typename, uint64(tc.program.RuntimeLibrary.Arch.PointerSize))
		return t, nil

	case *dwarf.TypedefType:
		// This could in theory be a typedef of a typedef. As of go 1.8, the go compiler
		// expands recursive typedefs in the DWARF so that each typedef refers directly
		// to a concrete type, however that may change. We support recursive typedefs by
		// unfolding the typedef chain here, then recursing on the concrete type once per
		// typedef name.
		typedefs := []*dwarf.TypedefType{dt}
		var concrete dwarf.Type
		for {
			if _, istypedef := dt.Type.(*dwarf.TypedefType); !istypedef {
				concrete = dt.Type
				break
			}
			dt = dt.Type.(*dwarf.TypedefType)
			typedefs = append(typedefs, dt)
		}
		var first Type
		for _, dt := range typedefs {
			t, err := tc.addDWARFWithTypedef(concrete, dt.Name)
			if err != nil {
				return nil, err
			}
			tc.verbosef("converted (%s, %T) -> (%s, %T, sz=%d, p=%s, n=%s)", dt, dt, t, t, t.Size(), t.PkgPath(), t.Name())
			tc.dwarfCache[dwarfCacheKey{dt, dt.Name}] = t
			if first == nil {
				first = t
			}
		}
		return first, nil

	case *dwarf.UnspecifiedType:
		// TODO: These are used for internal variables like $f64.* and go.itab.*.
		// Why can't these internal variables have real types?
		return add(tc.program.MakeGCObjectType(0)), nil

	// Unsupported types.

	default:
		return nil, fmt.Errorf("unsupported DWARF type %s (%T)", dt, dt)
	}
}

// convertRuntimeItab builds a Type that represents the type described by the given
// runtime itab descriptor (e.g., a *runtime.itab).
func (tc *typeCache) convertRuntimeItab(itabptr Value) (Type, error) {
	itab, err := itabptr.Deref()
	if err != nil {
		return nil, err
	}

	tc.depth++
	defer func() { tc.depth-- }()
	tc.verbosef("convert runtime itab (0x%x, %s)", itab.Addr, itab.Type)

	tptr, err := itab.Field(tc.program.RuntimeLibrary.itabTypeField)
	if err != nil {
		return nil, err
	}
	return tc.convertRuntimeType(tptr)
}

// convertRuntimeType builds a Type that represents the type described by the given
// runtime type descriptor (e.g., a *runtime._type).
func (tc *typeCache) convertRuntimeType(tptr Value) (Type, error) {
	tdesc, err := tptr.Deref()
	if err != nil {
		return nil, err
	}

	tc.depth++
	defer func() { tc.depth-- }()
	tc.verbosef("convert runtime type (0x%x, %s)", tdesc.Addr, tdesc.Type)

	t := tc.runtimeCache[tdesc.Addr]
	if t != nil {
		tc.verbosef("cached (0x%x, %s) -> (%s, %T, sz=%d, p=%s, n=%s)", tdesc.Addr, tdesc.Type, t, t, t.Size(), t.PkgPath(), t.Name())
	} else {
		// If this is a named type, lookup the full name and forward to tc.program.FindType().
		// Since Go programs cannot dynamically create named types via package reflect, any named
		// types must have already been created via DWARF. If the type is not named, we need to
		// walk the type descriptor to build the type.
		const tflagNamed = 1 << 2 // see runtime/type.go
		tflag, err := tdesc.ReadUintField(tc.program.RuntimeLibrary.typeTflagField)
		if err != nil {
			return nil, err
		}
		if (tflag & tflagNamed) != 0 {
			pkgPath, name, err := tc.runtimeTypePkgPathName(tdesc, tflag)
			if err != nil {
				return nil, err
			}
			var fullname string
			if pkgPath != "" {
				fullname = pkgPath + "." + name
			} else {
				fullname = name
			}
			t = tc.program.FindType(fullname)
			if t == nil {
				return nil, fmt.Errorf("could not find runtime type %q", fullname)
			}
		} else {
			t, err = tc.convertUnnamedRuntimeType(tdesc)
			if err != nil {
				return nil, err
			}
		}
	}

	tc.verbosef("converted (0x%x, %s) -> (%s, %T, sz=%d, p=%s, n=%s)", tdesc.Addr, tdesc.Type, t, t, t.Size(), t.PkgPath(), t.Name())

	if sanityChecks {
		size, err := tdesc.ReadUintField(tc.program.RuntimeLibrary.typeSizeField)
		if err != nil {
			panic(err)
		}
		if size != t.Size() {
			panic(fmt.Sprintf("at 0x%x, type size (%d) for %s does not match runtime._type.size (%d)", tdesc.Addr, t.Size(), t, size))
		}
		kind, err := tdesc.ReadUintField(tc.program.RuntimeLibrary.typeKindField)
		if err != nil {
			panic(err)
		}
		if got, want := t.directIface(), (kind&rttKindDirectIface) != 0; got != want {
			panic(fmt.Sprintf("at 0x%x, type directIface (%v) for %s does not match runtime._type (%v)", tdesc.Addr, got, t, want))
		}
	}

	return t, nil
}

// See reflect/type.go, runtime/type.go, and runtime/typekind.go.
const (
	rttKindBool = 1 + iota
	rttKindInt
	rttKindInt8
	rttKindInt16
	rttKindInt32
	rttKindInt64
	rttKindUint
	rttKindUint8
	rttKindUint16
	rttKindUint32
	rttKindUint64
	rttKindUintptr
	rttKindFloat32
	rttKindFloat64
	rttKindComplex64
	rttKindComplex128
	rttKindArray
	rttKindChan
	rttKindFunc
	rttKindInterface
	rttKindMap
	rttKindPtr
	rttKindSlice
	rttKindString
	rttKindStruct
	rttKindUnsafePointer

	rttKindDirectIface = 1 << 5
	rttKindMask        = (1 << 5) - 1
)

// runtimeTypePkgPathName returns the pkgPath and name for the given runtime type descriptor.
func (tc *typeCache) runtimeTypePkgPathName(tdesc Value, tflag uint64) (string, string, error) {
	name, err := tc.runtimeTypeName(tdesc)
	if err != nil {
		return "", "", err
	}
	pkgPath, err := tc.runtimeTypePkgPath(tdesc, tflag)
	if err != nil {
		return "", "", err
	}
	return pkgPath, name, nil
}

// implements reflect.rtype.Name().
func (tc *typeCache) runtimeTypeName(tdesc Value) (string, error) {
	strfield, err := tdesc.ReadUintField(tc.program.RuntimeLibrary.typeStrField)
	if err != nil {
		return "", err
	}
	str, err := tc.runtimeResolveNameOff(tdesc.Addr, strfield)
	if err != nil {
		return "", err
	}
	k := strings.LastIndex(str, ".")
	if k >= 0 {
		return str[k+1:], nil
	}
	return str, nil
}

// implements reflect.rtype.PkgPath().
func (tc *typeCache) runtimeTypePkgPath(tdesc Value, tflag uint64) (string, error) {
	rt := tc.program.RuntimeLibrary
	const tflagUncommon = 1 << 0
	if (tflag & tflagUncommon) == 0 {
		return "", nil
	}

	// runtime._type.uncommon()
	kind, err := tdesc.ReadUintField(rt.typeKindField)
	if err != nil {
		return "", err
	}
	var offset uint64
	switch kind & rttKindMask {
	case rttKindStruct:
		offset = rt.structtypeType.Size()
	case rttKindPtr:
		offset = rt.ptrtypeType.Size()
	case rttKindFunc:
		offset = rt.chantypeType.Size()
	case rttKindSlice:
		offset = rt.slicetypeType.Size()
	case rttKindArray:
		offset = rt.arraytypeType.Size()
	case rttKindChan:
		offset = rt.chantypeType.Size()
	case rttKindMap:
		offset = rt.maptypeType.Size()
	case rttKindInterface:
		offset = rt.interfacetypeType.Size()
	default:
		offset = rt.typeType.Size()
	}

	// TODO: ideally, we should lookup the rtype for typeof(runtime.uncommontype.pkgPath),
	// then use rtype.fieldalign to ensure that offset has appropriate alignment. That seems
	// tedious, so for now, we cheat by assuming offset is properly aligned.
	uct, err := tc.program.Value(tdesc.Addr+offset, rt.uncommontypeType)
	if err != nil {
		return "", err
	}
	ppfield, err := uct.ReadUintField(rt.uncommontypePkgPathField)
	if err != nil {
		return "", err
	}
	return tc.runtimeResolveNameOff(tdesc.Addr, ppfield)
}

// implements runtime.resolveNameOff() + runtime.name.name().
func (tc *typeCache) runtimeResolveNameOff(tptr, off uint64) (string, error) {
	if off == 0 {
		return "", nil
	}
	for _, md := range tc.program.RuntimeLibrary.moduledatas {
		if !md.types.contains(tptr) {
			continue
		}
		s, ok := md.types.suffix(md.types.addr + off)
		if !ok {
			return "", fmt.Errorf("error reading typename at off=0x%x from %s", off, md.types)
		}
		str, err := tc.runtimeName(s, 0)
		if err != nil {
			return "", fmt.Errorf("error reading typename at off=0x%x from %s: %v", off, md.types, err)
		}
		return str, nil
	}

	// Not in static data, so it should be a runtime name.
	printf("TODO: runtime names not implemented")
	return fmt.Sprintf("<unknown_type_name_%x_%x>", tptr, off), nil
	/*
		res, found := reflectOffs.m[int32(off)]
		if !found {
			return error
		}
		return name{(*byte)(res)}
	*/
}

// implements runtime.name.name().
// If dataAddr !=0, then s is looked up in tc.program via dataAddr.
func (tc *typeCache) runtimeName(s dataSegment, dataAddr uint64) (string, error) {
	if dataAddr != 0 {
		var ok bool
		s, ok = tc.program.dataSegments.findSegment(dataAddr)
		if !ok {
			return "", fmt.Errorf("name out-of-bounds at addr=0x%x", s.addr)
		}
		s, ok = s.suffix(dataAddr)
		if !ok {
			panic(fmt.Sprintf("suffix(0x%x) out-of-bounds for segment 0x%x, %v", dataAddr, s.addr, s.size()))
		}
	}
	// See comments in reflect/type.go at the definition of reflect.name:
	//   - first byte is a bitfield
	//   - next two bytes are the data length (data[1]<<8 | data[2])
	//   - next bytes are the name (data[3:3+len])
	strlen := uint64(s.data[1])<<8 | uint64(s.data[2])
	str, ok := s.slice(s.addr+3, strlen)
	if !ok {
		return "", fmt.Errorf("name out-of-bounds at addr=0x%x, length=%d", s.addr, strlen)
	}
	return string(str.data), nil
}

func (tc *typeCache) convertUnnamedRuntimeType(tdesc Value) (Type, error) {
	rt := tc.program.RuntimeLibrary

	kind, err := tdesc.ReadUintField(rt.typeKindField)
	if err != nil {
		return nil, err
	}

	switch kind & rttKindMask {
	case rttKindBool:
		return tc.program.MakeNumericType(NumericBool), nil

	case rttKindInt:
		switch rt.Arch.IntSize {
		case 4:
			return tc.program.MakeNumericType(NumericInt32), nil
		case 8:
			return tc.program.MakeNumericType(NumericInt64), nil
		default:
			panic(fmt.Sprintf("unexpected Arch.IntSize: %d", rt.Arch.IntSize))
		}
	case rttKindInt8:
		return tc.program.MakeNumericType(NumericInt8), nil
	case rttKindInt16:
		return tc.program.MakeNumericType(NumericInt16), nil
	case rttKindInt32:
		return tc.program.MakeNumericType(NumericInt32), nil
	case rttKindInt64:
		return tc.program.MakeNumericType(NumericInt64), nil

	case rttKindUint:
		switch rt.Arch.IntSize {
		case 4:
			return tc.program.MakeNumericType(NumericUint32), nil
		case 8:
			return tc.program.MakeNumericType(NumericUint64), nil
		default:
			panic(fmt.Sprintf("unexpected Arch.IntSize: %d", rt.Arch.IntSize))
		}
	case rttKindUint8:
		return tc.program.MakeNumericType(NumericUint8), nil
	case rttKindUint16:
		return tc.program.MakeNumericType(NumericUint16), nil
	case rttKindUint32:
		return tc.program.MakeNumericType(NumericUint32), nil
	case rttKindUint64:
		return tc.program.MakeNumericType(NumericUint64), nil

	case rttKindUintptr:
		switch rt.Arch.PointerSize {
		case 4:
			return tc.program.MakeNumericType(NumericUint32), nil
		case 8:
			return tc.program.MakeNumericType(NumericUint64), nil
		default:
			panic(fmt.Sprintf("unexpected Arch.PointerSize: %d", rt.Arch.PointerSize))
		}

	case rttKindFloat32:
		return tc.program.MakeNumericType(NumericFloat32), nil
	case rttKindFloat64:
		return tc.program.MakeNumericType(NumericFloat64), nil
	case rttKindComplex64:
		return tc.program.MakeNumericType(NumericComplex64), nil
	case rttKindComplex128:
		return tc.program.MakeNumericType(NumericComplex128), nil

	case rttKindArray:
		tdesc, err = tc.program.Value(tdesc.Addr, rt.arraytypeType)
		if err != nil {
			return nil, err
		}
		elemptr, err := tdesc.Field(rt.arraytypeElemField)
		if err != nil {
			return nil, err
		}
		elem, err := tc.convertRuntimeType(elemptr)
		if err != nil {
			return nil, err
		}
		count, err := tdesc.ReadUintField(rt.arraytypeLenField)
		if err != nil {
			return nil, err
		}
		return tc.program.MakeArrayType(elem, count), nil

	case rttKindPtr:
		tdesc, err = tc.program.Value(tdesc.Addr, rt.ptrtypeType)
		if err != nil {
			return nil, err
		}
		elemptr, err := tdesc.Field(rt.ptrtypeElemField)
		if err != nil {
			return nil, err
		}
		elem, err := tc.convertRuntimeType(elemptr)
		if err != nil {
			return nil, err
		}
		return tc.program.MakePtrType(elem), nil

	case rttKindStruct:
		size, err := tdesc.ReadUintField(tc.program.RuntimeLibrary.typeSizeField)
		if err != nil {
			return nil, err
		}
		tdesc, err = tc.program.Value(tdesc.Addr, rt.structtypeType)
		if err != nil {
			return nil, err
		}
		fields, err := tdesc.Field(rt.structtypeFieldsField)
		if err != nil {
			return nil, err
		}
		nfields, err := fields.Len()
		if err != nil {
			return nil, err
		}
		var outfields []StructField
		for k := uint64(0); k < nfields; k++ {
			field, err := fields.Index(k)
			if err != nil {
				return nil, err
			}
			// field.name.bytes
			name, err := field.Field(rt.structfieldNameField)
			if err != nil {
				return nil, err
			}
			namedataptr, err := name.ReadUintField(name.Type.(*StructType).Fields[0])
			if err != nil {
				return nil, err
			}
			fieldname, err := tc.runtimeName(dataSegment{}, namedataptr)
			if err != nil {
				return nil, err
			}
			tc.verbosef("field %s", fieldname)
			offset, err := field.ReadUintField(rt.structfieldOffsetField)
			if err != nil {
				return nil, err
			}
			ftptr, err := field.Field(rt.structfieldTypeField)
			if err != nil {
				return nil, err
			}
			ft, err := tc.convertRuntimeType(ftptr)
			if err != nil {
				return nil, err
			}
			outfields = append(outfields, StructField{
				Name:   fieldname,
				Type:   ft,
				Offset: offset,
			})
		}
		return tc.program.MakeStructType(outfields, size), nil

	case rttKindInterface:
		// All interface types are named internally, even interface types
		// that are anonymous in the original Go source code.
		// TODO: We should actually print the type as a string then lookup
		// that string as the "named" type.
		t := tc.program.FindType("interface {}")
		if t == nil {
			return nil, errors.New("could not find type interface {}")
		}
		return t, nil

	case rttKindSlice:
		tdesc, err = tc.program.Value(tdesc.Addr, rt.slicetypeType)
		if err != nil {
			return nil, err
		}
		elemptr, err := tdesc.Field(rt.slicetypeElemField)
		if err != nil {
			return nil, err
		}
		elem, err := tc.convertRuntimeType(elemptr)
		if err != nil {
			return nil, err
		}
		return tc.program.MakeSliceType(elem), nil

	case rttKindString:
		panic("type unnamed string type should be cached")

	case rttKindChan:
		tdesc, err = tc.program.Value(tdesc.Addr, rt.chantypeType)
		if err != nil {
			return nil, err
		}
		elemptr, err := tdesc.Field(rt.chantypeElemField)
		if err != nil {
			return nil, err
		}
		elem, err := tc.convertRuntimeType(elemptr)
		if err != nil {
			return nil, err
		}
		dir, err := tdesc.ReadUintField(rt.chantypeDirField)
		if err != nil {
			return nil, err
		}
		return tc.program.MakeChanType(reflect.ChanDir(dir), elem), nil

	case rttKindMap:
		tdesc, err = tc.program.Value(tdesc.Addr, rt.maptypeType)
		if err != nil {
			return nil, err
		}
		keyptr, err := tdesc.Field(rt.maptypeKeyField)
		if err != nil {
			return nil, err
		}
		key, err := tc.convertRuntimeType(keyptr)
		if err != nil {
			return nil, err
		}
		elemptr, err := tdesc.Field(rt.maptypeElemField)
		if err != nil {
			return nil, err
		}
		elem, err := tc.convertRuntimeType(elemptr)
		if err != nil {
			return nil, err
		}
		return tc.program.MakeMapType(key, elem), nil

	case rttKindFunc:
		t := tc.anonCache[[1]interface{}{"FuncType"}]
		if t == nil {
			return nil, errors.New("could not find cached FuncType")
		}
		return t, nil

	case rttKindUnsafePointer:
		t := tc.program.FindType("unsafe.Pointer")
		if t == nil {
			return nil, errors.New("could not find type unsafe.Pointer")
		}
		return t, nil

	default:
		return nil, fmt.Errorf("unexpected kind %d", kind)
	}
}

// FindType looks up the type with the given name.
// Returns nil if the name is not found.
func (p *Program) FindType(fullname string) Type {
	return p.typeCache.nameCache[fullname]
}

// Type constructors.

// MakeNumericType constructs an unnamed numeric type.
func (p *Program) MakeNumericType(k NumericKind) *NumericType {
	if t := p.typeCache.anonCache[[2]interface{}{"NumericType", k}]; t != nil {
		return t.(*NumericType)
	}
	t := &NumericType{}
	t.initialize(&p.typeCache, "", k)
	return t
}

// MakeArrayType constructs an unnamed array type.
func (p *Program) MakeArrayType(elem Type, n uint64) *ArrayType {
	if t := p.typeCache.anonCache[[3]interface{}{"ArrayType", elem, n}]; t != nil {
		return t.(*ArrayType)
	}
	t := &ArrayType{}
	t.initialize(&p.typeCache, "", elem, n)
	return t
}

// MakePtrType contructs an unnamed pointer type.
func (p *Program) MakePtrType(elem Type) *PtrType {
	if t := p.typeCache.anonCache[[2]interface{}{"PtrType", elem}]; t != nil {
		return t.(*PtrType)
	}
	t := &PtrType{}
	t.initialize(&p.typeCache, "", elem)
	return t
}

// MakeStructType contructs an unnamed struct type.
// If size==0, it is inferred automatically from fields (if any).
func (p *Program) MakeStructType(fields []StructField, size uint64) *StructType {
	if size == 0 {
		for _, f := range fields {
			if end := f.Offset + f.Type.Size(); end > size {
				size = end
			}
		}
	}
	sort.Sort(sortFieldByOffset(fields))
	if t := p.typeCache.anonCache[[3]interface{}{"StructType", size, structFieldList(fields).String()}]; t != nil {
		return t.(*StructType)
	}
	t := &StructType{}
	t.initialize(&p.typeCache, "", fields, size)
	return t
}

// MakeEmptyInterfaceType returns the interface{} type.
func (p *Program) MakeEmptyInterfaceType() *InterfaceType {
	return p.typeCache.anonCache[[1]interface{}{"EmptyInterfaceType"}].(*InterfaceType)
}

// MakeSliceType constructs an unnamed slice type.
func (p *Program) MakeSliceType(elem Type) *SliceType {
	if t := p.typeCache.anonCache[[2]interface{}{"SliceType", elem}]; t != nil {
		return t.(*SliceType)
	}
	t := &SliceType{}
	t.initialize(&p.typeCache, "", elem, p.FindType("runtime.slice").(*StructType))
	return t
}

// MakeStringType returns the string type.
func (p *Program) MakeStringType() *StringType {
	return p.typeCache.anonCache[[1]interface{}{"StringType"}].(*StringType)
}

// MakeChanType constructs an unnamed chan type.
func (p *Program) MakeChanType(dir reflect.ChanDir, elem Type) *ChanType {
	if t := p.typeCache.anonCache[[3]interface{}{"ChanType", dir, elem}]; t != nil {
		return t.(*ChanType)
	}
	t := &ChanType{}
	t.initialize(&p.typeCache, "", dir, elem, p.MakePtrType(p.FindType("runtime.hchan").(*StructType)))
	return t
}

// MakeMapType constructs an unnamed map type.
func (p *Program) MakeMapType(key, elem Type) *MapType {
	if t := p.typeCache.anonCache[[3]interface{}{"MapType", key, elem}]; t != nil {
		return t.(*MapType)
	}
	t := &MapType{}
	t.initialize(&p.typeCache, "", key, elem, p.MakePtrType(p.FindType("runtime.hmap").(*StructType)))
	return t
}

// GCObjectType constructs a TODO: describe.
func (p *Program) MakeGCObjectType(size uint64) *GCObjectType {
	key := [2]interface{}{"GCObjectType", size}
	if t := p.typeCache.anonCache[key]; t != nil {
		return t.(*GCObjectType)
	}
	t := &GCObjectType{}
	t.baseType.initialize(&p.typeCache, "", size)
	p.typeCache.add(t, "", key)
	return t
}

// Type initializers.

func (t *baseType) initialize(tc *typeCache, fullname string, size uint64) {
	t.program = tc.program
	t.size = size
	// Don't split the special internal types that contain "<", like "hchan<pkg.Msg>".
	if strings.Contains(fullname, "<") {
		t.pkgPath = ""
		t.name = fullname
	} else {
		t.pkgPath, t.name = splitPkgPathName(fullname)
	}
}

func (t *NumericType) initialize(tc *typeCache, fullname string, k NumericKind) {
	if fullname == string(k) {
		fullname = ""
	}
	t.Kind = k
	t.baseType.initialize(tc, fullname, numericKindToSize(k))
	tc.add(t, fullname, [2]interface{}{"NumericType", k})
}

func (t *ArrayType) initialize(tc *typeCache, fullname string, elem Type, n uint64) {
	t.Elem = elem
	t.Len = n
	t.baseType.initialize(tc, fullname, n*elem.Size())
	tc.add(t, fullname, [3]interface{}{"ArrayType", elem, n})
}

func (t *PtrType) initialize(tc *typeCache, fullname string, elem Type) {
	t.Elem = elem
	t.baseType.initialize(tc, fullname, uint64(tc.program.RuntimeLibrary.Arch.PointerSize))
	tc.add(t, fullname, [2]interface{}{"PtrType", elem})
}

func (t *StructType) initialize(tc *typeCache, fullname string, fields []StructField, size uint64) {
	sort.Sort(sortFieldByOffset(fields))
	for k := range fields {
		if fields[k].Type.containsPointers() {
			t.hasPtrs = true
			break
		}
	}
	t.Fields = fields
	t.baseType.initialize(tc, fullname, size)
	tc.add(t, fullname, [3]interface{}{"StructType", size, structFieldList(fields).String()})
}

func (t *InterfaceType) initialize(tc *typeCache, fullname string, eface bool, rep *StructType) {
	t.Rep = rep
	if eface {
		if len(rep.Fields) != 2 ||
			rep.Fields[efaceTypeField].Name != "_type" || !isPtrField(rep.Fields[efaceTypeField]) ||
			rep.Fields[efaceDataField].Name != "data" || !isPtrField(rep.Fields[efaceDataField]) {
			panic(fmt.Errorf("expected struct { _type *_type, data ptr }, got %s", rep))
		}
		t.EFace = true
		t.baseType.initialize(tc, "", rep.Size())
		tc.add(t, "", [1]interface{}{"EmptyInterfaceType"})
	} else {
		if fullname == "" {
			panic("unnamed InterfaceType")
		}
		if len(rep.Fields) != 2 ||
			rep.Fields[ifaceTabField].Name != "tab" || !isPtrField(rep.Fields[ifaceTabField]) ||
			rep.Fields[ifaceDataField].Name != "data" || !isPtrField(rep.Fields[ifaceDataField]) {
			panic(fmt.Errorf("expected struct { tab *itab, data ptr }, got %s", rep))
		}
		t.baseType.initialize(tc, fullname, rep.Size())
		tc.add(t, fullname, nil)
	}
}

func (t *SliceType) initialize(tc *typeCache, fullname string, elem Type, rep *StructType) {
	if len(rep.Fields) != 3 || !isPtrField(rep.Fields[sliceArrayField]) ||
		rep.Fields[sliceLenField].Name != "len" || rep.Fields[sliceLenField].Type.String() != "int" ||
		rep.Fields[sliceCapField].Name != "cap" || rep.Fields[sliceCapField].Type.String() != "int" {
		panic(fmt.Errorf("expected struct { ptr, int, int }, got %s", rep))
	}
	t.Rep = rep
	t.Elem = elem
	t.baseType.initialize(tc, fullname, rep.Size())
	tc.add(t, fullname, [2]interface{}{"SliceType", elem})
}

func (t *StringType) initialize(tc *typeCache, fullname string, rep *StructType) {
	if len(rep.Fields) != 2 || !isPtrField(rep.Fields[stringArrayField]) ||
		rep.Fields[stringLenField].Name != "len" || rep.Fields[stringLenField].Type.String() != "int" {
		panic(fmt.Errorf("expected struct { ptr, int, int }, got %s", rep))
	}
	t.Rep = rep
	t.baseType.initialize(tc, fullname, rep.Size())
	tc.add(t, fullname, [1]interface{}{"StringType"})
}

func (t *ChanType) initialize(tc *typeCache, fullname string, dir reflect.ChanDir, elem Type, rep *PtrType) {
	repst := rep.Elem.(*StructType)
	if len(repst.Fields) < 3 || !isPtrField(repst.Fields[chanBufferField]) ||
		repst.Fields[chanLenField].Name != "qcount" || repst.Fields[chanLenField].Type.String() != "uint" ||
		repst.Fields[chanCapField].Name != "dataqsiz" || repst.Fields[chanCapField].Type.String() != "uint" {
		panic(fmt.Errorf("expected *struct { uint, uint, ptr, ... }, got %s", rep))
	}
	t.Rep = rep
	t.Dir = dir
	t.Elem = elem
	t.baseType.initialize(tc, fullname, rep.Size())
	tc.add(t, fullname, [3]interface{}{"ChanType", dir, elem})
}

func (t *MapType) initialize(tc *typeCache, fullname string, key, elem Type, rep *PtrType) {
	repst := rep.Elem.(*StructType)
	if len(repst.Fields) < 1 ||
		repst.Fields[mapLenField].Name != "count" || repst.Fields[mapLenField].Type.String() != "int" {
		panic(fmt.Errorf("expected *struct { int, ... }, got %s", rep))
	}
	t.Rep = rep
	t.Key = key
	t.Elem = elem
	t.baseType.initialize(tc, fullname, rep.Size())
	tc.add(t, fullname, [3]interface{}{"MapType", key, elem})
}

func (t *FuncType) initialize(tc *typeCache, fullname string, size uint64) {
	t.baseType.initialize(tc, fullname, size)
	tc.add(t, fullname, [1]interface{}{"FuncType"})
}

func isPtrToStruct(t Type) bool {
	ptr, ok := t.(*PtrType)
	if !ok {
		return false
	}
	_, ok = ptr.Elem.(*StructType)
	return ok
}

func isPtrField(f StructField) bool {
	_, ok := f.Type.(*PtrType)
	return ok || f.Type.String() == "unsafe.Pointer"
}
