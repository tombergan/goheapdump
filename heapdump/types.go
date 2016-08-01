package heapdump

import (
	"bytes"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// Type is the interface implemented by all types.
// Inspired by reflect.Type. Possible concrete types are:
//   - NumericType
//   - ArrayType
//   - PtrType
//   - StructType
//   - UnknownType
//
// Additionally, the following wrapper types provide more
// convenient interfaces than their raw runtime representations:
//   - InterfaceType
//   - SliceType
//   - StringType
//
// Types are canonicalized so that type equality is simple pointer equality.
type Type interface {
	// Dump returns the heapdump that contains this type.
	Dump() *Dump

	// String prints the type as a string.
	// For named types, this prints the full name of the type including the PkgPath.
	String() string

	// Name is the name of the type within its package, or "" for unnamed types.
	// See reflect.Type.Name.
	Name() string

	// PkgPath returns a name type's package path.
	// See reflect.Type.PkgPath.
	PkgPath() string

	// Size in bytes of values of this type.
	// Not defined for UnknownType -- calling UnknownType.Size() will panic.
	Size() uint64

	// ContainsPointers returns true if the type contains pointers.
	// Always returns true (conservatively) for UnknownType.
	ContainsPointers() bool

	// DirectIFace returns true if the type is pointer-shaped, meaning it can be
	// stored directly in the value of an iface or eface.
	DirectIFace() bool

	// base returns the shared type info.
	base() *baseType
}

type baseType struct {
	dump          *Dump
	name, pkgPath string // if named and known
	size          uint64
}

func (t *baseType) String() string {
	if t.pkgPath != "" {
		return t.pkgPath + "." + t.name
	}
	return t.name
}

func (t *baseType) Dump() *Dump       { return t.dump }
func (t *baseType) Name() string      { return t.name }
func (t *baseType) PkgPath() string   { return t.pkgPath }
func (t *baseType) Size() uint64      { return t.size }
func (t *baseType) DirectIFace() bool { return false }
func (t *baseType) base() *baseType   { return t }

// NumericType is the type of booleans and all numbers.
type NumericType struct {
	baseType
	Kind NumericKind
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

func (t *NumericType) String() string {
	if t.Name() != "" {
		return t.baseType.String()
	}
	return string(t.Kind)
}

func (t *NumericType) ContainsPointers() bool {
	return false
}

// ArrayType is the type of arrays.
type ArrayType struct {
	baseType
	Elem   Type   // never UnknownType
	Len    uint64 // number of elements
	Stride uint64 // number of bytes that hold each element
}

func (t *ArrayType) String() string {
	if t.Name() != "" {
		return t.baseType.String()
	}
	return fmt.Sprintf("[%d]", t.Len) + t.Elem.String()
}

func (t *ArrayType) ContainsPointers() bool {
	return t.Elem.ContainsPointers()
}

func (t *ArrayType) DirectIFace() bool {
	return t.Len == 1 && t.Elem.DirectIFace()
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

func (t *PtrType) ContainsPointers() bool {
	return true
}

func (t *PtrType) DirectIFace() bool {
	return true
}

// StructType is the type of structs.
type StructType struct {
	baseType
	Fields []StructField // sorted by offset
}

func (t *StructType) String() string {
	if t.Name() != "" {
		return t.baseType.String()
	}
	var buf bytes.Buffer
	buf.WriteString("struct {")
	for k, f := range t.Fields {
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

func (t *StructType) ContainsPointers() bool {
	for _, f := range t.Fields {
		if f.Type.ContainsPointers() {
			return true
		}
	}
	return false
}

func (t *StructType) DirectIFace() bool {
	return t.size == t.dump.Raw.Params.PtrSize && len(t.Fields) == 1 && t.Fields[0].Type.DirectIFace()
}

// FieldByName returns the field with the given name. Never returns an unnamed field.
// The result is a pointer into t.Fields, or nil if not found.
func (t *StructType) FieldByName(name string) *StructField {
	if name == "" {
		return nil
	}
	for k := range t.Fields {
		if t.Fields[k].Name == name {
			return &t.Fields[k]
		}
	}
	return nil
}

// FieldContainingOffset returns the field that contains the given offset.
// The result is a pointer into t.Fields, or nil if not found.
func (t *StructType) FieldContainingOffset(offset uint64) *StructField {
	for k := range t.Fields {
		f := &t.Fields[k]
		if f.Offset <= offset && offset < f.Offset+f.Type.Size() {
			return f
		}
	}
	return nil
}

// StructField is a single field within a struct.
type StructField struct {
	Name   string
	Type   Type // cannot be UnknownType
	Offset uint64
}

type sortFieldByOffset []StructField

func (a sortFieldByOffset) Len() int           { return len(a) }
func (a sortFieldByOffset) Swap(i, k int)      { a[i], a[k] = a[k], a[i] }
func (a sortFieldByOffset) Less(i, k int) bool { return a[i].Offset < a[k].Offset }

// UnknownType represents memory of unknown size and type.
// This type can only be nested in PtrType. All other nestings are invalid.
type UnknownType struct {
	baseType
}

func (t *UnknownType) Size() uint64 {
	panic("unknown size for UnknownType " + t.String())
}

func (t *UnknownType) ContainsPointers() bool {
	return true // unknown, so assume yes
}

// InterfaceType represents an interface.
type InterfaceType struct {
	baseType
	rep   *StructType // struct that represents this interface (e.g., runtime.iface or runtime.eface)
	EFace bool        // true if this is an eface (i.e., "interface{}")
}

func (t *InterfaceType) ContainsPointers() bool {
	return true
}

// SliceType represents a slice.
type SliceType struct {
	baseType
	rep  *StructType // struct that represents this interface (e.g., runtime.iface or runtime.eface)
	Elem Type        // type of elements in this slice
}

func (t *SliceType) String() string {
	if t.Name() != "" {
		return t.baseType.String()
	}
	return "[]" + t.Elem.String()
}

func (t *SliceType) ContainsPointers() bool {
	return true
}

const (
	SliceArrayField = 0 // slice's base pointer (type *[len]Elem)
	SliceLenField   = 1 // slice's len (type int)
	SliceCapField   = 2 // slice's cap (type int)
)

// StringType represents a string.
type StringType struct {
	baseType
	rep *StructType // struct that represents this interface (e.g., runtime.iface or runtime.eface)
}

func (t *StringType) String() string {
	if t.Name() != "" {
		return t.baseType.String()
	}
	return "string"
}

func (t *StringType) ContainsPointers() bool {
	return true
}

const (
	StringStrField = 0 // strings's base pointer (type *[len]uint8)
	StringLenField = 1 // strings's len (type int)
)

// TODO: Wrappers for these types?
//   XXX MapType
//   XXX ChanType
//   XXX FuncType

// typeCache stores memo tables for type canonicalization.
// Named types are compared by name. Unnamed types are compared by structure.
// Named types that are declared by not-yet-defined are called "zygotes".
type typeCache struct {
	dump           *Dump
	names          map[string]Type         // for named types only (fullname != "")
	anon           map[typeCacheKey][]Type // for unnamed types only (fullname == "")
	zygotes        map[string]bool         // zygotes[x]=true if names[x] is a zygote type
	zygoteTypedefs map[string][]string     // if zygotes[x], this lists of typedef names for x
}

type typeCacheKey struct {
	kind interface{}
	a, b interface{}
}

func makeTypeCacheKey(newT Type, a, b interface{}) typeCacheKey {
	return typeCacheKey{reflect.TypeOf(newT), a, b}
}

func makeTypeCache(d *Dump) *typeCache {
	return &typeCache{
		dump:           d,
		names:          make(map[string]Type),
		anon:           make(map[typeCacheKey][]Type),
		zygotes:        make(map[string]bool),
		zygoteTypedefs: make(map[string][]string),
	}
}

// makeType constructs a defined type (not a zygote).
func (tc *typeCache) makeType(fullname string, key typeCacheKey, newT Type) Type {
	if fullname != "" {
		t := tc.names[fullname]
		// Case 1: new type name.
		if t == nil {
			tc.names[fullname] = newT
			return newT
		}

		// Case 2: check for zygotes.
		if tc.zygotes[fullname] {
			tc.updateZygote(fullname, newT)
		}

		// Now, t should match newT.
		if !reflect.DeepEqual(t, newT) {
			panic(fmt.Errorf("unexpected type tc.names[%d]: %s %T != %s %T", fullname, t, t, newT, newT))
		}
		return t
	}

	tt := tc.anon[key]
	if len(tt) == 0 {
		tc.anon[key] = append(tt, newT)
		return newT
	}

	// Struct is the only kind with multiple possible types per cache key.
	if _, isstruct := newT.(*StructType); !isstruct {
		if len(tt) > 1 {
			panic(fmt.Errorf("unexpected type in cache: %s %T and %s %T match %s %T", tt[0], tt[0], tt[1], tt[1], newT, newT))
		}
		t := tt[0]
		if !reflect.DeepEqual(t, newT) {
			panic(fmt.Errorf("unexpected type in cache: %s %T matches %s %T", t, t, newT, newT))
		}
		return t
	}

	// Memo table has a list of possible struct types.
	// We need to compare the fields manually.
	newS := newT.(*StructType)
	for _, t := range tt {
		s := t.(*StructType)
		if len(s.Fields) != len(newS.Fields) {
			panic(fmt.Errorf("bad cache key for structs %s, %s", s, newS))
		}
		eq := true
		for k := range s.Fields {
			if s.Fields[k] != newS.Fields[k] {
				eq = false
				break
			}
		}
		if eq {
			return t
		}
	}

	tc.anon[key] = append(tt, newT)
	return newT
}

// updateZygote copies newT into the zygote named by fullname, then
// transitively updates all zygotes from tc.zygoteTypedefs[fullname].
func (tc *typeCache) updateZygote(fullname string, newT Type) {
	if !tc.zygotes[fullname] {
		panic(fmt.Errorf("updateZygote on non-zygote %s (%s %T)", fullname, newT, newT))
	}

	z := tc.names[fullname]
	copyTypeWithName(z, z.base().name, z.base().pkgPath, newT)
	delete(tc.zygotes, fullname)

	for _, typedef := range tc.zygoteTypedefs[fullname] {
		tc.updateZygote(typedef, newT)
	}
	delete(tc.zygoteTypedefs, fullname)
}

func (tc *typeCache) makeBaseType(fullname string, size uint64) baseType {
	b := baseType{dump: tc.dump, size: size}
	// Special struct types do not have pkgPaths. They may actually contain
	// nested type names (like hchan<foo/bar.X>), and we shouldn't attempt to
	// parse a pkgPath from these names.
	specialStruct := strings.HasPrefix(fullname, "hash<") ||
		strings.HasPrefix(fullname, "bucket<") ||
		strings.HasPrefix(fullname, "hchan<") ||
		strings.HasPrefix(fullname, "waitq<") ||
		strings.HasPrefix(fullname, "sudog<")
	if dot := strings.LastIndex(fullname, "."); 0 <= dot && dot < len(fullname)-1 && !specialStruct {
		b.name = fullname[dot+1:]
		b.pkgPath = fullname[:dot]
	} else {
		b.name = fullname
	}
	return b
}

func (tc *typeCache) makeNumericType(fullname string, k NumericKind) *NumericType {
	if fullname == "" {
		fullname = string(k)
	}

	var size uint64
	switch k {
	case NumericBool, NumericUint8, NumericInt8:
		size = 1
	case NumericUint16, NumericInt16:
		size = 2
	case NumericUint32, NumericInt32, NumericFloat32:
		size = 4
	case NumericUint64, NumericInt64, NumericFloat64, NumericComplex64:
		size = 8
	case NumericComplex128:
		size = 16
	default:
		panic(fmt.Errorf("unknown kind %d for type %s", k, fullname))
	}

	newT := &NumericType{tc.makeBaseType(fullname, size), k}
	return tc.makeType(fullname, makeTypeCacheKey(newT, k, nil), newT).(*NumericType)
}

func (tc *typeCache) makeArrayType(fullname string, elem Type, n, stride uint64) *ArrayType {
	if _, unknown := elem.(*UnknownType); unknown {
		panic(fmt.Errorf("element type unknown for array %s", fullname))
	}
	if stride < elem.Size() {
		panic(fmt.Errorf("stride smaller than element type (%d < %d, %s %T) for array %s", stride, elem.Size(), elem, elem, fullname))
	}

	newT := &ArrayType{tc.makeBaseType(fullname, n*stride), elem, n, stride}
	t := tc.makeType(fullname, makeTypeCacheKey(newT, elem, n), newT).(*ArrayType)

	// Sanity check.
	if stride != t.Stride {
		panic(fmt.Errorf("array types with same element but different stride: [%d]%s (stride=%d,name=%s) vs [%d]%s (stride=%d,name=%s)",
			t.Len, t.Elem, t.Stride, t.baseType.String(), n, elem, stride, fullname))
	}
	return t
}

func (tc *typeCache) makePtrType(fullname string, elem Type) *PtrType {
	newT := &PtrType{tc.makeBaseType(fullname, tc.dump.Raw.Params.PtrSize), elem}
	return tc.makeType(fullname, makeTypeCacheKey(newT, elem, nil), newT).(*PtrType)
}

func (tc *typeCache) makeStructType(fullname string, size uint64, fields []StructField) *StructType {
	for _, f := range fields {
		if _, unknown := f.Type.(*UnknownType); unknown {
			panic(fmt.Errorf("%#v has UnknownType in struct %s", f, fullname))
		}
	}
	sort.Sort(sortFieldByOffset(fields))
	newT := &StructType{tc.makeBaseType(fullname, size), fields}
	return tc.makeType(fullname, makeTypeCacheKey(newT, size, len(fields)), newT).(*StructType)
}

func (tc *typeCache) makeUnknownType(fullname string) *UnknownType {
	if fullname == "" {
		fullname = "$unknown"
	}
	// Names cannot clash with valid go names.
	if !strings.HasPrefix(fullname, "$unknown") {
		panic(fmt.Errorf("bad name for UnknownType: %s", fullname))
	}
	newT := &UnknownType{tc.makeBaseType(fullname, 0)}
	return tc.makeType(fullname, makeTypeCacheKey(newT, nil, nil), newT).(*UnknownType)
}

func (tc *typeCache) makePtrToUnknownType() *PtrType {
	return tc.makePtrType("", tc.makeUnknownType(""))
}

func (tc *typeCache) makeInterfaceType(fullname string, rep *StructType) *InterfaceType {
	if fullname == "" {
		panic("InterfaceTypes must be named")
	}
	if len(rep.Fields) != 2 {
		panic(fmt.Errorf("expected struct { ptr, ptr }, got %s (%d fields)", rep, len(rep.Fields)))
	}
	_, ptr0 := rep.Fields[0].Type.(*PtrType)
	_, ptr1 := rep.Fields[1].Type.(*PtrType)
	if !ptr0 || !ptr1 {
		panic(fmt.Errorf("expected struct { ptr, ptr }, got %s (%d fields, %v, %v)", rep, len(rep.Fields), ptr0, ptr1))
	}

	var eface bool
	switch rep.String() {
	case "runtime.iface":
		eface = false
	case "runtime.eface":
		eface = true
	default:
		panic(fmt.Errorf("InterfaceType has unknown rep %s", rep))
	}
	newT := &InterfaceType{tc.makeBaseType(fullname, rep.size), rep, eface}
	return tc.makeType(fullname, makeTypeCacheKey(newT, rep, nil), newT).(*InterfaceType)
}

func (tc *typeCache) makeSliceType(fullname string, rep *StructType, elem Type) *SliceType {
	wantF0 := tc.makePtrType("", elem)
	if len(rep.Fields) != 3 {
		panic(fmt.Errorf("expected struct { %s, int, int }, got %s (%d fields)", wantF0, rep, len(rep.Fields)))
	}
	f0, f1, f2 := rep.Fields[0].Type, rep.Fields[1].Type, rep.Fields[2].Type
	if f0 != wantF0 || f1.String() != "int" || f2.String() != "int" {
		panic(fmt.Errorf("expected struct { %p/%s, int, int }, got %s struct { %p/%s, %s, %s }",
			wantF0, wantF0, rep, f0, f0, f1, f2))
	}
	newT := &SliceType{tc.makeBaseType(fullname, rep.size), rep, elem}
	return tc.makeType(fullname, makeTypeCacheKey(newT, rep, elem), newT).(*SliceType)
}

func (tc *typeCache) makeStringType(fullname string, rep *StructType) *StringType {
	wantF0 := tc.makePtrType("", tc.makeNumericType("", NumericUint8))
	if len(rep.Fields) != 2 {
		panic(fmt.Errorf("expected struct { %s, int, int }, got %s (%d fields)", wantF0, rep, len(rep.Fields)))
	}
	f0, f1 := rep.Fields[0].Type, rep.Fields[1].Type
	if f0 != wantF0 || f1.String() != "int" {
		panic(fmt.Errorf("expected struct { %p/%s, int }, got %s struct { %p/%s, %s }", wantF0, wantF0, rep, f0, f0, f1))
	}
	newT := &StringType{tc.makeBaseType(fullname, rep.size), rep}
	return tc.makeType(fullname, makeTypeCacheKey(newT, rep, nil), newT).(*StringType)
}

// makeTypedef produces a type identical to oldT but with a different name.
func (tc *typeCache) makeTypedef(oldT Type, fullname string) Type {
	if fullname == "" || oldT.base().String() == fullname {
		return oldT
	}

	bt := tc.makeBaseType(fullname, 0)
	newT := reflect.New(reflect.TypeOf(oldT).Elem()).Interface().(Type)
	copyTypeWithName(newT, bt.name, bt.pkgPath, oldT)

	// If we're making a typedef of a zygote, we can't define this type yet.
	// Just make sure it's declared.
	if zname := oldT.base().String(); tc.zygotes[zname] {
		tc.names[fullname] = newT
		tc.zygotes[fullname] = true
		tc.zygoteTypedefs[zname] = append(tc.zygoteTypedefs[zname], fullname)
		return newT
	}

	// Otherwise, we can define this typedef.
	return tc.makeType(fullname, typeCacheKey{}, newT)
}

// copyTypeWithName copies src into dst using the given name.
// dst and src must be the same kind of type.
func copyTypeWithName(dst Type, dstName, dstPkgPath string, src Type) {
	switch dst := dst.(type) {
	case *NumericType:
		*dst = *src.(*NumericType)
	case *ArrayType:
		*dst = *src.(*ArrayType)
	case *PtrType:
		*dst = *src.(*PtrType)
	case *StructType:
		*dst = *src.(*StructType)
	case *UnknownType:
		*dst = *src.(*UnknownType)
	case *InterfaceType:
		*dst = *src.(*InterfaceType)
	case *SliceType:
		*dst = *src.(*SliceType)
	case *StringType:
		*dst = *src.(*StringType)
	default:
		panic(fmt.Errorf("unhanded type %T", dst))
	}
	dst.base().name = dstName
	dst.base().pkgPath = dstPkgPath
}

// declareNamedType declares a named type using the given zygote. If the name
// has already been declared, that name's type is returned, otherwise this
// declares zygote internally and returns nil. The actual type is not valid
// until it is defined with a call to tc.make*Type(fullname, *).
func (tc *typeCache) declareNamedType(fullname string, zygote Type) Type {
	if zygote == nil {
		panic("zygote is nil")
	}
	if fullname == "" {
		return nil
	}
	if t := tc.names[fullname]; t != nil {
		return t
	}
	*zygote.base() = tc.makeBaseType(fullname, 0)
	tc.zygotes[fullname] = true
	tc.names[fullname] = zygote
	return nil
}

// checkZygotesEmpty fails if there are any zygotes remaining.
func (tc *typeCache) checkZygotesEmpty() error {
	if len(tc.zygotes) == 0 && len(tc.zygoteTypedefs) == 0 {
		return nil
	}
	var buf bytes.Buffer
	for fullname := range tc.zygotes {
		fmt.Fprintf(&buf, "(%s, %T) ", fullname, tc.names[fullname])
	}
	return fmt.Errorf("non-empty zygoteTypedefs (%d) or zygotes: %s", len(tc.zygoteTypedefs), buf.String())
}
