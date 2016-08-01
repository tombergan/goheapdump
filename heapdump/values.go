package heapdump

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
)

// Value represents an object or field in memory.
// Inspired by reflect.Value.
type Value struct {
	Type Type
	seg  *RawSegment
}

// Addr returns the Value's base address.
func (v *Value) Addr() uint64 {
	return v.seg.Addr
}

// Size returns the Value's size in bytes.
func (v *Value) Size() uint64 {
	return v.seg.Size()
}

// Bytes returns the Value's raw bytes.
// The returned slice becomes invalid after the containing Dump is closed
// and caller should not mutate this slice unless the Dump was opened in
// read-write mode. Any attempt to mutate in read-only mode will segfault.
func (v *Value) Bytes() []byte {
	return v.seg.Data
}

// ContainsAddress returns true if the Value contains addr.
func (v *Value) ContainsAddress(addr uint64) bool {
	return v.seg.Contains(addr)
}

// ContainingObject returns the object (heap or global) that contains v.
// If v refers directly to a heap or global object, then this returns v.
// Fail with ErrOutOfRange when v.Addr() is invalid.
func (v *Value) ContainingObject() (*Value, error) {
	if _, err := v.dump().value2heap(v); err == nil {
		return v, nil // fast path with v is offset 0 of a heap object
	}
	if cv := v.dump().FindObject(v.Addr()); cv != nil {
		return cv, nil // slow path when v is offset > 0 of a heap object
	}
	return nil, ErrOutOfRange
}

// IsZero returns true if this value is the zero value.
func (v *Value) IsZero() bool {
	for _, b := range v.Bytes() {
		if b != 0 {
			return false
		}
	}
	return true
}

// Read decodes the contents of v into data, where data can be any
// type supported by encoding/binary.Read. It is caller's responsibility
// to ensure that data has a type compatible with v.
//
// Caveat: encoding/binary.Read does not support booleans. Those must
// be read with uint8 types. TODO: this is ugly, fix this
//
// If v contains pointers, the pointers will be interpreted as scalar
// types (they will not be dereferenced).
func (v *Value) Read(data interface{}) error {
	r := bytes.NewReader(v.Bytes())
	if err := binary.Read(r, v.rawDump().Params.ByteOrder, data); err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return fmt.Errorf("decode error: data too large, want %d", v.Size())
		}
		return err
	}
	if r.Len() != 0 {
		return fmt.Errorf("decode error: data too small, got %d, want %d", v.Size()-uint64(r.Len()), v.Size())
	}
	return nil
}

// ReadUint is a shorthand for reading an integer from v.
// Panics if v.Size() is not 1, 2, 4, or 8.
func (v *Value) ReadUint() (uint64, error) {
	var x interface{}
	switch v.Size() {
	case 1:
		x = new(uint8)
	case 2:
		x = new(uint16)
	case 4:
		x = new(uint32)
	case 8:
		x = new(uint64)
	default:
		panic(fmt.Errorf("ReadUint on non-integer-sized value %v", v.Size()))
	}
	if err := v.Read(x); err != nil {
		return 0, err
	}
	return reflect.ValueOf(x).Elem().Uint(), nil
}

// Write sets the contents of the v to data, where data can be []byte,
// string, or any type supported by encoding/binary.Write. It is caller's
// responsibility to ensure that data has a type compatible with v.
//
// It is an error to call Write if the Dump was open in read-only mode.
// Write will panic in this case.
//
// Caveat: If v contains pointers, the pointers will be overwritten using
// the scalar values from data. These new values may not be valid pointers
// unless care was taken when building data.
func (v *Value) Write(data interface{}) error {
	if !v.rawDump().fmap.writable {
		panic("Value.Set on read-only Dump")
	}

	check := func(gotLen int) error {
		if got, want := uint64(gotLen), v.Size(); got != want {
			return fmt.Errorf("encode error: data wrong size, got %d, want %d", got, want)
		}
		return nil
	}

	switch d := data.(type) {
	case []byte:
		if err := check(len(d)); err != nil {
			return nil
		}
		copy(v.Bytes(), d)

	case string:
		if err := check(len(d)); err != nil {
			return nil
		}
		copy(v.Bytes(), d)

	default:
		w := bytes.NewBuffer(make([]byte, v.Size()))
		if err := binary.Write(w, v.rawDump().Params.ByteOrder, data); err != nil {
			return err
		}
		if err := check(w.Len()); err != nil {
			return err
		}
		copy(v.Bytes(), w.Bytes())
	}

	return nil
}

// Deref dereferences this pointer. Returns (nil, nil) if the pointer is nil.
// Returns ErrOutOfRange if the pointer targets a location that is outside of
// the heapdump. Note that out-of-range pointers are not necessarily invalid,
// as the heapdump may not include all memory mappings from the original process.
//
// Panics if v.Type is not PtrType. XXX or interface type?
func (v *Value) Deref() (*Value, error) {
	baseTarget, offset, err := v.DerefContainer()
	if err != nil {
		return nil, err
	}

	// NB: Should not fail: offset should not be out-of-range.
	target, err := baseTarget.RawOffset(offset)
	if err != nil {
		panic(fmt.Errorf("RawOffset: offset=%d, baseAddr=%x, baseType=%s, err=%v", offset, baseTarget.Addr(), baseTarget.Type, err))
	}

	// Sanity check: compare the type of target with the expected type from v.Type.
	// XXX TODO: Better: check if types are compatible
	ptrT := v.Type.(*PtrType)
	if _, unknown := ptrT.Elem.(*UnknownType); !unknown && ptrT.Elem != target.Type {
		LogPrintf("Warning: type mismatch in Deref: %s != %s @%x+%d", ptrT, target.Type, baseTarget.Addr(), offset)
	}

	return target, nil
}

// DerefContainer returns (target, offset), where "target" is the pointed-to
// object and v points at byte "offset" of target. If v is not an interior
// pointer (meaning offset=0), this is the same as Deref. Otherwise, this is
// effectively equivalent to v.Deref().ContainingObject().
//
// Panics if v.Type is not PtrType. XXX or interface type?
func (v *Value) DerefContainer() (*Value, uint64, error) {
	if _, ok := v.Type.(*PtrType); !ok {
		panic(fmt.Errorf("Deref called on non-ptr type %s (%T)", v.Type.String(), v.Type))
	}
	ptrvalue := v.rawDump().Params.ReadPtr(v.Bytes())
	if ptrvalue == 0 {
		return nil, 0, ErrOutOfRange
	}
	target := v.dump().FindObject(ptrvalue)
	if target == nil {
		return nil, 0, ErrOutOfRange
	}
	// XXX
	LogPrintf("deref ptr at 0x%x to 0x%x %T %s\n", v.Addr(), target.Addr(), target.Type, target.Type)
	return target, ptrvalue - target.Addr(), nil
}

// Index extracts the value at the given index.
// Returns ErrOutOfRange if the index is out-of-range.
// Panics if v.Type is not ArrayType. XXX or slice/string type?
func (v *Value) Index(i uint64) (*Value, error) {
	arrayT, ok := v.Type.(*ArrayType)
	if !ok {
		panic(fmt.Errorf("Index called on non-array type %s (%T)", v.Type.String(), v.Type))
	}
	if i >= arrayT.Len {
		return nil, ErrOutOfRange
	}
	size := arrayT.Elem.Size()
	offset := i * arrayT.Elem.Size()
	return &Value{arrayT.Elem, v.seg.Slice(offset, size)}, nil
}

// Field extracts the value at the given struct field.
// Caller should ensure that f is a valid field of v.Type (this is not checked).
// Panics if v.RepType() is not StructType.
func (v *Value) Field(f *StructField) (*Value, error) {
	t := v.RepType()
	if _, ok := t.(*StructType); !ok {
		panic(fmt.Errorf("Field called on on non-struct type %s (%T)", t.String(), t))
	}
	if f.Offset+f.Type.Size() > v.Size() {
		return nil, ErrOutOfRange
	}
	return &Value{f.Type, v.seg.Slice(f.Offset, f.Type.Size())}, nil
}

// RawOffset extracts the value at the given offset.
// Fails with ErrOutOfRange if the offset is not within v.Size.
//
// If the offset is in range and type information is available, this attempts
// to produce a correctly-typed value by walking the nested array and struct
// types as needed. If the offset points within a scalar type, the returned
// value has UnknownType.
//
// If the offset is in range and type information is not available, this returns
// a value with UnknownType and size v.Size()-offset.
//
// Examples:
// - v.Type=[8]int32, offset=4, returns a value of type int32 (from v[1])
// - v.Type=[8]int32, offset=3, returns a value of UnknownType
// - v.Type=UnknownType, offset=3, returns a value of UnknownType
//
func (v *Value) RawOffset(offset uint64) (*Value, error) {
	if offset >= v.Size() {
		return nil, ErrOutOfRange
	}
	if offset == 0 {
		return v, nil
	}

	// Typed offsets.
	switch t := v.RepType().(type) {
	case *NumericType, *PtrType, *UnknownType:
		// Cannot subdivide these types any further.
		// Fallback to an UnknownType.
		break

	case *ArrayType:
		// Get the index that contains this type.
		x, err := v.Index(offset / t.Elem.Size())
		if err != nil {
			// Index is out-of-range, so fallback to an UnknownType.
			// NB: In practice, this case happens when zero-length arrays are actually non-zero-length.
			LogPrintf("Warning: array index out-of-range: offset=%d, baseAddr=%x, baseType=%s", offset, v.Addr(), v.Type)
			break
		}
		return x.RawOffset(offset - (x.Addr() - v.Addr()))

	case *StructType:
		// Get the index that contains this type.
		f := t.FieldContainingOffset(offset)
		if f == nil {
			// Field is out-of-range, so fallback to an UnknownType.
			LogPrintf("Warning: interior pointer to unknown struct field: offset=%d, baseAddr=%x, baseType=%s", offset, v.Addr(), t)
			break
		}
		x, err := v.Field(f)
		if err != nil {
			panic(fmt.Errorf("%#v out-of-range: offset=%d, baseAddr=%x, baseType=%s, err=%v", f, offset, v.Addr(), t, err))
		}
		return x.RawOffset(offset - (x.Addr() - v.Addr()))

	default:
		panic(fmt.Errorf("unhandled type %s (%T)", t, t))
	}

	// Fallback to an UnknownType.
	return &Value{v.dump().tc.makeUnknownType(""), v.seg.Slice(offset, v.Size()-offset)}, nil
}

// RepType returns the low-level type that represents this value.
// The high-level wrapper types work as follows:
//
// For InterfaceType, if v has dynamic type T, then the result is a struct
// with two fields, where fields[0] points an internal representation of T
// and fields[1] has type "*T". If T cannot be determined, then fields[1] has
// type PtrType(UnknownType).
//
// For SliceType, the result is a struct with fields described by SliceArrayField,
// SliceLenField, and SliceCapField.
//
// For StringType, the result is a struct with fields described by StringStrField
// and StringLenField.
//
// TODO: is this using the correct stride for arrays?
func (v *Value) RepType() Type {
	switch t := v.Type.(type) {
	case *InterfaceType:
		// Extract fields[0].
		// NB: Reading this field should not fail unless v was constructed incorrectly.
		f0 := t.rep.Fields[0]
		vtypeaddr := &Value{f0.Type, v.seg.Slice(f0.Offset, f0.Type.Size())}
		f1val, err := vtypeaddr.ReadUint()
		if err != nil {
			panic(fmt.Errorf("bad type %s for field %s in value at 0x%x: %v", t, vtypeaddr.Type, v.Addr(), err))
		}
		// Lookup the dynamic type of this interface value.
		// Use this to construct the dynamic type of fields[1].
		var f1type Type
		if t.EFace {
			f1type = v.dump().typeFromAddr[f1val]
		} else {
			typeaddr, ok := v.dump().Raw.TypeFromItab[f1val]
			if ok {
				f1type = v.dump().typeFromAddr[typeaddr]
			}
		}
		if f1type != nil {
			// DirectIFace types are stored directly in the iface.
			// Other types need indirection.
			if !f1type.DirectIFace() {
				f1type = v.dump().tc.makePtrType("", f1type)
			}
		} else {
			f1type = v.dump().tc.makePtrToUnknownType()
		}
		return v.dump().tc.makeStructType("", t.rep.Size(), []StructField{
			t.rep.Fields[0],
			StructField{
				Name:   t.rep.Fields[1].Name,
				Offset: t.rep.Fields[1].Offset,
				Type:   f1type,
			},
		})

	case *SliceType:
		flen := t.rep.Fields[SliceLenField]
		vlen := &Value{flen.Type, v.seg.Slice(flen.Offset, flen.Type.Size())}
		n, err := vlen.ReadUint()
		if err != nil {
			panic(fmt.Errorf("bad type %s for field %s in value at 0x%x: %v", t, vlen.Type, v.Addr(), err))
		}
		return v.dump().tc.makeStructType("", t.rep.Size(), []StructField{
			StructField{
				Name:   t.rep.Fields[0].Name,
				Offset: t.rep.Fields[0].Offset,
				Type:   v.dump().tc.makePtrType("", v.dump().tc.makeArrayType("", t.Elem, n, t.Elem.Size())),
			},
			t.rep.Fields[1],
			t.rep.Fields[2],
		})

	case *StringType:
		flen := t.rep.Fields[StringLenField]
		vlen := &Value{flen.Type, v.seg.Slice(flen.Offset, flen.Type.Size())}
		n, err := vlen.ReadUint()
		if err != nil {
			panic(fmt.Errorf("bad type %s for field %s in value at 0x%x: %v", t, vlen.Type, v.Addr(), err))
		}
		elem := v.dump().tc.makeNumericType("", NumericUint8)
		return v.dump().tc.makeStructType("", t.rep.Size(), []StructField{
			StructField{
				Name:   t.rep.Fields[0].Name,
				Offset: t.rep.Fields[0].Offset,
				Type:   v.dump().tc.makePtrType("", v.dump().tc.makeArrayType("", elem, n, elem.Size())),
			},
			t.rep.Fields[1],
		})

	case *NumericType, *PtrType, *UnknownType, *ArrayType, *StructType:
		return t

	default:
		panic(fmt.Errorf("unhandled type %s (%T)", t, t))
	}
}

// ScalarTypesMode controls the definition of "scalar" values. There are
// two modes. In "low-level" mode, only numbers (NumericType) and pointers
// (PtrType) are considered scalar values. In "high-level" mode, the following
// values are additionally considered to be scalars:
//   - interfaces (InterfaceType)
//   - strings and slices (StringType, SliceType)
//   - TODO: MapType, ChanType, FuncType
//
// Low-level mode can be used to walk the raw pointer graph, while high-level
// mode can be used to inspect Values at the Go language level.
//
// Note that arrays (ArrayType), structs (StructType), and unknown objects
// (UnknownType) are never considered to be scalars.
type ScalarTypesMode int

const (
	LowLevelScalarTypes ScalarTypesMode = iota
	HighLevelScalarTypes
)

type fieldVisitor struct {
	// pre: called before visiting a composite value
	// Returning false means that children of v will not be visited.
	pre func(parentName, fieldName string, v *Value) bool

	// post: called after visiting a composite value
	// visit: called to visit a scalar value, as defined by scalarMode
	post, visit func(parentName, fieldName string, v *Value)

	// defines which types are visited by visit
	scalarMode ScalarTypesMode
}

// visitFields allows post traversal of all nested fields in this value.
// For UnknownTypes, this visits only the pointer fields as labeled by GC
// bitmaps. This does not dereference any pointers.
// See FmtOptions.CustomFormatter for examples of parentName and fieldName.
func (v *Value) visitFields(fv *fieldVisitor, parentName, fieldName string) {
	isScalar := func() bool {
		switch v.Type.(type) {
		case *NumericType, *PtrType:
			return true
		case *InterfaceType, *StringType, *SliceType:
			return fv.scalarMode == HighLevelScalarTypes
		}
		return false
	}

	if isScalar() {
		if fv.visit != nil {
			fv.visit(parentName, fieldName, v)
		}
		return
	}

	if fv.pre != nil && !fv.pre(parentName, fieldName, v) {
		return
	}

	switch t := v.RepType().(type) {
	case *ArrayType:
		for i := uint64(0); i < t.Len; i++ {
			x, err := v.Index(i)
			if err != nil {
				panic(fmt.Errorf("unexpected error from Index: %v", err))
			}
			x.visitFields(fv, parentName+fieldName, fmt.Sprintf("[%d]", i))
		}

	case *StructType:
		for i := 0; i < len(t.Fields); i++ {
			f := &t.Fields[i]
			x, err := v.Field(f)
			if err != nil {
				panic(fmt.Errorf("unexpected error from Index: %v", err))
			}
			name := f.Name
			if name == "" {
				name = fmt.Sprintf("$offset_%d", f.Offset)
			}
			p := parentName + fieldName
			if p != "" {
				p += "."
			}
			x.visitFields(fv, p, name)
		}

	case *UnknownType:
		ptrT := v.dump().tc.makePtrToUnknownType()
		for _, offset := range v.seg.PtrFields.Offsets() {
			if offset+ptrT.Size() > v.Size() {
				continue
			}
			name := fmt.Sprintf("$offset_%d", offset)
			p := parentName + fieldName
			if p != "" {
				p += "."
			}
			x := &Value{ptrT, v.seg.Slice(offset, ptrT.Size())}
			x.visitFields(fv, p, name)
		}

	default:
		panic(fmt.Errorf("unhandled type %s (%T)", t, t))
	}

	if fv.post != nil {
		fv.post(parentName, fieldName, v)
	}
}

// ForeachPointer iterates over all pointers in this Value starting from
// the lowest offset and moving to the highest offest. It works on values
// of any type, including UnknownType, which uses GC pointer bitmaps to
// determine where the pointers are.
func (v *Value) ForeachPointer(fn func(*Value)) {
	fv := &fieldVisitor{
		pre: func(_, _ string, v *Value) bool {
			return v.Type.ContainsPointers()
		},
		visit: func(_, _ string, v *Value) {
			if _, ok := v.Type.(*PtrType); ok {
				fn(v)
			}
		},
	}
	v.visitFields(fv, "", "")
}

// ForeachField iterates over all nested fields in this Value starting
// from the lowest offset and moving to the highest offset. For ArrayTypes,
// each element of the array is considered a "field". For UnknownTypes, this
// is equivalent to ForeachPointer. For other types, this iterates over all
// fields (including non-pointers).
//
// The first argument of fn is the name of the field relative to v. For
// example, if v is a struct, the field v.foo[4].x is visited with the name
// "foo[4].x". Similarly, if v is an array, the field v[3] is visited with
// the name "[3]".
//
// scalarMode controls how wrapper types are visited. For example, if v.Type
// is struct { x string }:
//   - v.ForeachField(HighLevelScalarTypes, fn) calls fn(v.x)
//   - v.ForeachField(LowLevelScalarTypes, fn) calls fn(v.x.str) and fn(v.x.len)
//
// XXX rethink this -- maybe visited all fields (including composite fields)
// and return false from fn to not visit kids? (rather than scalarMode)
func (v *Value) ForeachField(scalarMode ScalarTypesMode, fn func(string, *Value)) {
	fv := &fieldVisitor{
		visit:      func(pName, fName string, v *Value) { fn(pName+fName, v) },
		scalarMode: scalarMode,
	}
	v.visitFields(fv, "", "")
}

// FmtOptions gives options for Value.Fmt.
type FmtOptions struct {
	// CustomFormatter allows overriding the default formatter. Returning a
	// nil error means the value was formatted. Returning the special value
	// ErrUseDefaultFormatter means that the default formatter should be
	// applied for this value. Returning any other error causes Fmt to return
	// that error.
	//
	// The parentName and fieldName strings combine to form the complete field
	// name relative to the base value. Examples:
	//   - v = x.foo,        parentName = "x.",        fieldName = "foo"
	//   - v = x.foo[3],     parentName = "x.foo",     fieldName = "[3]"
	//   - v = x.foo[3].bar, parentName = "x.foo[3].", fieldName = "bar"
	CustomFormatter func(w io.Writer, parentName, fieldName string, v *Value, opts *FmtOptions) error

	// CustomScalarFormatter is like CustomFormatter, but is only used to write
	// the value of a scalar field.
	CustomScalarFormatter func(w io.Writer, v *Value) error

	// FieldMode describes how field names should be formatted.
	// The default is FmtNoFieldNames.
	FieldMode FmtFieldMode

	// ScalarMode controls how InterfaceTypes, StringTypes, and SliceTypes are printed.
	// In low-level mode, we underlying StructType.
	// In high-level mode, we print these types in a more Go-like way.
	ScalarMode ScalarTypesMode
}

type FmtFieldMode int

const (
	FmtNoFieldNames       FmtFieldMode = iota // don't show field names, like %v
	FmtFieldNames                             // show field names, like %+v
	FmtFieldNamesAndTypes                     // show field and type names, like %#v
	FmtLongFieldNames                         // show each field name (x[0].a=1, x[0].b=2, x[1].a=5, etc.)
)

// ErrUseDefaultFormatter is a special signal used by custom formatters.
var ErrUseDefaultFormatter = errors.New("use default formatter")

// Fmt writes a formatted version of v to the given writer. All errors, if any,
// come from w.Write. By default, Fmt mimics the fmt package's %v, but this behavior
// can be customized using FmtOptions. If opts is nil, defaults are used.
func (v *Value) Fmt(w io.Writer, opts *FmtOptions) (err error) {
	if opts == nil {
		opts = &FmtOptions{}
	}

	// This is an ugly use of panic, but it's the easiest way to break
	// out of deeply nested visitFields calls on errors.
	type errorContainer struct {
		error
	}
	defer func() {
		if x := recover(); x != nil {
			if ec, ok := x.(*errorContainer); ok {
				err = ec.error
			} else {
				panic(x) // actual panic: rethrow
			}
		}
	}()
	write := func(s string) {
		if _, err := w.Write([]byte(s)); err != nil {
			panic(&errorContainer{err})
		}
	}
	writef := func(fmtstr string, args ...interface{}) {
		if _, err := fmt.Fprintf(w, fmtstr, args...); err != nil {
			panic(&errorContainer{err})
		}
	}
	runCustomFormatter := func(w io.Writer, parentName, fieldName string, v *Value) (handled bool) {
		if opts.CustomFormatter == nil {
			return false
		}
		switch err := opts.CustomFormatter(w, parentName, fieldName, v, opts); err {
		case nil:
			return true
		case ErrUseDefaultFormatter:
			return false
		default:
			panic(&errorContainer{err})
		}
	}
	runScalarFormatter := func(w io.Writer, v *Value) (handled bool) {
		if opts.CustomScalarFormatter == nil {
			return false
		}
		switch err := opts.CustomScalarFormatter(w, v); err {
		case nil:
			return true
		case ErrUseDefaultFormatter:
			return false
		default:
			panic(&errorContainer{err})
		}
	}

	// As the visitor runs, count[depth] is the number of fields printed at depth.
	counts := []int{0}

	// Helpers.
	isArray := func(v *Value) bool {
		_, ok := v.Type.(*ArrayType)
		return ok
	}
	writeSep := func() {
		counts[len(counts)-1]++
		if counts[len(counts)-1] == 1 {
			return
		}
		switch opts.FieldMode {
		case FmtNoFieldNames, FmtFieldNames:
			write(" ")
		case FmtFieldNamesAndTypes, FmtLongFieldNames:
			write(", ")
		}
	}

	fv := &fieldVisitor{
		pre: func(parentName, fieldName string, v *Value) bool {
			if opts.FieldMode != FmtLongFieldNames {
				writeSep()
			}
			if runCustomFormatter(w, parentName, fieldName, v) {
				return false
			}
			switch opts.FieldMode {
			case FmtNoFieldNames:
				if isArray(v) {
					write("[")
				} else {
					write("{")
				}
			case FmtFieldNames:
				if fieldName != "" {
					write(fieldName + ":")
				}
				if isArray(v) {
					write("[")
				} else {
					write("{")
				}
			case FmtFieldNamesAndTypes:
				if fieldName != "" {
					write(fieldName + ":")
				}
				write(v.Type.String() + "{")
			case FmtLongFieldNames:
				// nop: will show parentName+fieldName with each scalar
			}
			if opts.FieldMode != FmtLongFieldNames {
				counts = append(counts, 0)
			}
			return true
		},
		post: func(parentName, fieldName string, v *Value) {
			switch opts.FieldMode {
			case FmtNoFieldNames, FmtFieldNames:
				if isArray(v) {
					write("]")
				} else {
					write("}")
				}
			case FmtFieldNamesAndTypes:
				write("}")
			case FmtLongFieldNames:
				// nop: will show parentName+fieldName with each scalar
			}
			if opts.FieldMode != FmtLongFieldNames {
				counts = counts[:len(counts)-1]
			}
		},
		visit: func(parentName, fieldName string, v *Value) {
			writeSep()
			if runCustomFormatter(w, parentName, fieldName, v) {
				return
			}

			switch opts.FieldMode {
			case FmtNoFieldNames:
				// no field names
			case FmtFieldNames, FmtFieldNamesAndTypes:
				// struct field names
				if fieldName != "" && !strings.HasPrefix(fieldName, "[") {
					write(fieldName + ":")
				}
			case FmtLongFieldNames:
				// all field names
				if parentName+fieldName != "" {
					write(parentName + fieldName + "=")
				}
			}

			if runScalarFormatter(w, v) {
				return
			}

			// x is a ptr to a scalar value of the appropriate type.
			var isBool, isPtr bool
			var x interface{}
			switch t := v.Type.(type) {
			case *NumericType:
				switch t.Kind {
				case NumericBool:
					isBool = true // TODO: fix, this is ugly
					x = new(uint8)
				case NumericUint8:
					x = new(uint8)
				case NumericUint16:
					x = new(uint16)
				case NumericUint32:
					x = new(uint32)
				case NumericUint64:
					x = new(uint64)
				case NumericInt8:
					x = new(int8)
				case NumericInt16:
					x = new(int16)
				case NumericInt32:
					x = new(int32)
				case NumericInt64:
					x = new(int64)
				case NumericFloat32:
					x = new(float32)
				case NumericFloat64:
					x = new(float64)
				case NumericComplex64:
					x = new(complex64)
				case NumericComplex128:
					x = new(complex128)
				default:
					panic(fmt.Errorf("unhandled numeric kind %s", t.Kind))
				}
			case *PtrType:
				isPtr = true
				switch sz := v.rawDump().Params.PtrSize; sz {
				case 4:
					x = new(uint32)
				case 8:
					x = new(uint64)
				default:
					panic(fmt.Errorf("unhandled ptrsize case %v", sz))
				}
			default:
				panic(fmt.Errorf("unhandled scalar value case %s (%T)", t, t))
			}

			if err := v.Read(x); err != nil {
				writef("#valueError{%s, %v}", v.Type, err)
				return
			}
			// Dereference x.
			x = reflect.ValueOf(x).Elem().Interface()
			if isBool {
				if x.(uint8) == 0 {
					write("false")
				} else {
					write("true")
				}
			} else if isPtr {
				writef("0x%x", x)
			} else {
				writef("%v", x)
			}
		},
		scalarMode: opts.ScalarMode,
	}
	v.visitFields(fv, "", "")
	return nil
}

// FmtString is like Fmt but returns a string rather than writing to an io.Writer.
func (v *Value) FmtString(opts *FmtOptions) string {
	var buf bytes.Buffer
	v.Fmt(&buf, opts) // can ignore error because buf.Write never fails
	return string(buf.Bytes())
}

// Shorthands.

func (v *Value) dump() *Dump       { return v.Type.Dump() }
func (v *Value) rawDump() *RawDump { return v.Type.Dump().Raw }
