package corefile

import (
	"errors"
	"fmt"
	"math"
	"reflect"
)

// TODO: We currently assume that a single Value does not span multiple
// dataSegments. This assumption is invalid if the core file contains
// only part of the virtual memory space, for example, if it only contains
// static data pages that were actually dirtied by the application (with
// the remaining pages intended to be loaded from the executable file).
// If this happens, a global variable might be defined by a union of pages
// from the core file and pages from the .data or .bss section of the
// executable file, meaning we'd be unable to produce a single []byte that
// spans the entire value (since the core file pages and executable file
// pages are in different mmap regions).
//
// Should this become a problem, one possible fix is to malloc a []byte
// that covers the entire Value. This is the simplest fix, but requires an
// allocation. Another fix is to dynamically reconstruct the value by walking
// the underlying list of dataSegments. Another fix is to copy the data
// segments into memory rather than just mmap'ing the file(s).
//
// In the short term, it seems unlikely for this case to arise, so it has
// not been handled.

// TODO: Add the following?
//
// // MapLookup looks up the given key in map v.
// // Returns false if the key does not exist.
// // Panics if v.Type is not MapType.
// func (v *Value) MapLookup(key Value) (Value, bool, error)
//
// // MapForEach iterates over all key/value pairs in the map.
// // Iteration stops early if f returns false.
// // Panics if v.Type is not MapType.
// func (v *Value) MapForeach(f(key, elem Value) bool) error

// Errors commonly returned by Value methods.
var (
	ErrNil         = errors.New("nil pointer")
	ErrOutOfBounds = errors.New("access is out-of-bounds")
)

// Value describes a typed region of memory.
type Value struct {
	Type  Type
	Addr  uint64 // base address of Bytes
	Bytes []byte // raw bytes that define this value
}

// IsZero reports whether v is a zero value, i.e., if v.Bytes contains all zeros.
// For types that support a "nil" value, IsZero reports if v is "nil".
func (v Value) IsZero() bool {
	for _, b := range v.Bytes {
		if b != 0 {
			return false
		}
	}
	return true
}

// Size reports the size of v in bytes.
func (v Value) Size() uint64 {
	return v.Type.Size()
}

// ContainsAddress reports whether addr is in [v.Addr, v.Addr+v.Size()).
func (v Value) ContainsAddress(addr uint64) bool {
	return v.Addr <= addr && addr < v.Addr+v.Type.Size()
}

// Deref dereferences v.
// For values of InterfaceType, Deref returns the value contained in the interface.
// Fails with ErrNil if v is nil or ErrOutOfBounds if v points to an out-of-bound address.
// Panics if v.Type is not PtrType or InterfaceType.
func (v Value) Deref() (Value, error) {
	switch t := v.Type.(type) {
	case *PtrType:
		return v.Type.Program().Value(v.ReadScalar().(uint64), t.Elem)

	case *InterfaceType:
		if v.IsZero() {
			return Value{}, ErrNil
		}
		elemType, err := v.DynamicType()
		if err != nil {
			return Value{}, err
		}
		datafield := ifaceDataField
		if t.EFace {
			datafield = efaceDataField
		}

		v.Type = t.Rep
		if elemType.directIface() {
			// For direct interfaces, the value is stored directly in the data field.
			data, err := v.Field(t.Rep.Fields[datafield])
			if err != nil {
				return Value{}, err
			}
			data.Type = elemType
			return data, nil
		} else {
			// For indirect interfaces, the data field is actually a pointer to the data.
			dataptr, err := v.Field(t.Rep.Fields[datafield])
			if err != nil {
				return Value{}, err
			}
			dataptr.Type = v.Type.Program().MakePtrType(elemType)
			return dataptr.Deref()
		}

	default:
		panic(fmt.Sprintf("bad type for Value.Deref(): %s (%T)", v.Type, v.Type))
	}
}

// DynamicType returns v’s dynamic type. For non-interface types, this is
// equivalent to v.Type. For interface types, this is equivalent to Deref().Type,
// but unlike Deref, it does not fail if the interface’s data pointer references
// out-of-bounds data.
func (v Value) DynamicType() (Type, error) {
	t, ok := v.Type.(*InterfaceType)
	if !ok {
		return v.Type, nil
	}
	rep := t.Rep
	if t.EFace {
		v.Type = rep
		rtypePtr, err := v.Field(rep.Fields[efaceTypeField])
		if err != nil {
			return nil, err
		}
		return rep.Program().typeCache.convertRuntimeType(rtypePtr)
	} else {
		v.Type = rep
		itabPtr, err := v.Field(rep.Fields[ifaceTabField])
		if err != nil {
			return nil, err
		}
		return rep.Program().typeCache.convertRuntimeItab(itabPtr)
	}
}

// typedSlice casts the value at v.Addr+offset to type t.
// Fails if [offset, offset+t.Size()) is out-of-bounds.
func (v Value) typedSlice(offset uint64, t Type) (Value, error) {
	end := offset + t.Size()
	if end > v.Type.Size() {
		return Value{}, ErrOutOfBounds
	}
	return Value{
		Addr:  v.Addr + offset,
		Type:  t,
		Bytes: v.Bytes[offset:end:end],
	}, nil
}

// Field returns the given field. Fails with ErrOutOfBounds if f is out-of-bounds.
// Panics if v.Type is not StructType.
func (v Value) Field(f StructField) (Value, error) {
	if _, ok := v.Type.(*StructType); !ok {
		panic(fmt.Sprintf("bad type for Value.Field(): %s (%T)", v.Type, v.Type))
	}
	v, err := v.typedSlice(f.Offset, f.Type)
	if err != nil {
		return Value{}, fmt.Errorf("error reading field %s.%s, type %s: %v", v.Type, f.Name, f.Type, err)
	}
	return v, nil
}

// FieldByName is a shorthand for v.Type.FieldByName followed by v.Field.
func (v Value) FieldByName(name string) (Value, error) {
	st, ok := v.Type.(*StructType)
	if !ok {
		panic(fmt.Sprintf("bad type for Value.FieldByName(): %s (%T)", v.Type, v.Type))
	}
	f, ok := st.FieldByName(name)
	if !ok {
		return Value{}, fmt.Errorf("cannot find field %s in %s", name, st)
	}
	return v.Field(f)
}

// DerefArray dereferences v to an array containing all buffered elements in v.
// The returned value will have ArrayType with length equal to v.Cap().
// Panics if v.Type is not SliceType, StringType, or ChanType.
func (v Value) DerefArray() (Value, error) {
	vcap, err := v.Cap()
	if err != nil {
		return Value{}, err
	}

	p := v.Type.Program()

	var f StructField
	switch t := v.Type.(type) {
	case *SliceType:
		f = t.Rep.Fields[sliceArrayField]
		f.Type = p.MakePtrType(p.MakeArrayType(t.Elem, vcap))
		v.Type = t.Rep
	case *StringType:
		f = t.Rep.Fields[stringArrayField]
		f.Type = p.MakePtrType(p.MakeArrayType(p.MakeNumericType(NumericUint8), vcap))
		v.Type = t.Rep
	case *ChanType:
		v.Type = t.Rep
		v, err = v.Deref()
		if err != nil {
			return Value{}, err
		}
		f = v.Type.(*StructType).Fields[chanBufferField]
		f.Type = p.MakePtrType(p.MakeArrayType(t.Elem, vcap))
	default:
		panic(fmt.Sprintf("bad type for Value.DerefArray(): %s (%T)", v.Type, v.Type))
	}
	fv, err := v.Field(f)
	if err != nil {
		return Value{}, err
	}
	return fv.Deref()
}

// Index returns v’s n’th element. Fails with ErrOutOfBounds if n >= v.Cap().
// Panics if v.Type is not ArrayType, SliceType, StringType, or ChanType.
func (v Value) Index(n uint64) (Value, error) {
	vcap, err := v.Cap()
	if err != nil {
		return Value{}, err
	}
	if n >= vcap {
		return Value{}, ErrOutOfBounds
	}

	var addrf StructField
	var elem Type

	switch t := v.Type.(type) {
	case *ArrayType:
		return v.typedSlice(n*t.Elem.Size(), t.Elem)
	case *SliceType:
		v.Type = t.Rep
		addrf = t.Rep.Fields[sliceArrayField]
		elem = t.Elem
	case *StringType:
		v.Type = t.Rep
		addrf = t.Rep.Fields[stringArrayField]
		elem = t.Program().MakeNumericType(NumericUint8)
	case *ChanType:
		v.Type = t.Rep
		v, err := v.Deref()
		if err != nil {
			return Value{}, err
		}
		addrf = v.Type.(*StructType).Fields[chanBufferField]
		elem = t.Elem
	default:
		panic(fmt.Sprintf("bad type for Value.Len(): %s (%T)", v.Type, v.Type))
	}

	// Get the array base address.
	addr, err := v.ReadUintField(addrf)
	if err != nil {
		return Value{}, err
	}
	if addr == 0 {
		return Value{}, ErrNil
	}

	// Return array[n].
	return v.Type.Program().Value(addr+n*elem.Size(), elem)
}

// Len returns v’s length.
// Panics if v.Type is not ArrayType, SliceType, StringType, ChanType, or MapType.
func (v Value) Len() (uint64, error) {
	switch t := v.Type.(type) {
	case *ArrayType:
		return t.Len, nil
	case *SliceType:
		v.Type = t.Rep
		return v.ReadUintField(t.Rep.Fields[sliceLenField])
	case *StringType:
		v.Type = t.Rep
		return v.ReadUintField(t.Rep.Fields[stringLenField])
	case *ChanType:
		v.Type = t.Rep
		v, err := v.Deref()
		if err != nil {
			return 0, err
		}
		return v.ReadUintField(v.Type.(*StructType).Fields[chanLenField])
	case *MapType:
		v.Type = t.Rep
		v, err := v.Deref()
		if err != nil {
			return 0, err
		}
		return v.ReadUintField(v.Type.(*StructType).Fields[mapLenField])
	default:
		panic(fmt.Sprintf("bad type for Value.Len(): %s (%T)", v.Type, v.Type))
	}
}

// Cap returns v’s capacity. For ArrayType and StringType, this is equivalent to Len.
// Panics if v.Type is not ArrayType, SliceType, StringType, or ChanType.
func (v Value) Cap() (uint64, error) {
	switch t := v.Type.(type) {
	case *ArrayType:
		return t.Len, nil
	case *SliceType:
		v.Type = t.Rep
		return v.ReadUintField(t.Rep.Fields[sliceCapField])
	case *StringType:
		v.Type = t.Rep
		return v.ReadUintField(t.Rep.Fields[stringLenField])
	case *ChanType:
		v.Type = t.Rep
		v, err := v.Deref()
		if err != nil {
			return 0, err
		}
		return v.ReadUintField(v.Type.(*StructType).Fields[chanCapField])
	default:
		panic(fmt.Sprintf("bad type for Value.Cap(): %s (%T)", v.Type, v.Type))
	}
}

// ReadScalar parses v into a Go scalar value. NumericType becomes the
// corresponding Go type. PtrType becomes uint64. ReadScalar will panic
// if called for any other type.
func (v Value) ReadScalar() interface{} {
	a := v.Type.Program().RuntimeLibrary.Arch

	switch t := v.Type.(type) {
	case *NumericType:
		switch t.Kind {
		case NumericBool:
			return v.Bytes[0] != 0
		case NumericUint8:
			return uint8(v.Bytes[0])
		case NumericUint16:
			return a.Uint16(v.Bytes)
		case NumericUint32:
			return a.Uint32(v.Bytes)
		case NumericUint64:
			return a.Uint64(v.Bytes)
		case NumericInt8:
			return int8(v.Bytes[0])
		case NumericInt16:
			return a.Int16(v.Bytes)
		case NumericInt32:
			return a.Int32(v.Bytes)
		case NumericInt64:
			return a.Int64(v.Bytes)
		case NumericFloat32:
			return a.Float32(v.Bytes)
		case NumericFloat64:
			return a.Float64(v.Bytes)
		case NumericComplex64:
			return a.Complex64(v.Bytes)
		case NumericComplex128:
			return a.Complex128(v.Bytes)
		}
		panic(fmt.Sprintf("bad numeric type for Value.ReadScalar(): %s (%T)", t, t))

	case *PtrType:
		return a.Uintptr(v.Bytes)

	default:
		panic(fmt.Sprintf("bad type for Value.ReadScalar(): %s (%T)", t, t))
	}
}

// ReadUint parses v into a uint64. ReadUint is a shorthand for v.ReadScalar followed
// by a conversion to uint64. Panics if v is not an integer or pointer.
func (v Value) ReadUint() uint64 {
	a := v.Type.Program().RuntimeLibrary.Arch
	if t, ok := v.Type.(*NumericType); ok {
		switch t.Kind {
		case NumericUint8:
			return uint64(v.Bytes[0])
		case NumericUint16, NumericInt16:
			return uint64(a.Uint16(v.Bytes))
		case NumericUint32, NumericInt32:
			return uint64(a.Uint32(v.Bytes))
		case NumericUint64, NumericInt64:
			return uint64(a.Uint64(v.Bytes))
		}
	}
	if _, ok := v.Type.(*PtrType); ok {
		return a.Uintptr(v.Bytes)
	}
	panic(fmt.Sprintf("bad type for Value.ReadUint(): %s (%T)", v.Type, v.Type))
}

// ReadScalarField is a shorthand for v.Field followed by ReadScalar.
func (v Value) ReadScalarField(f StructField) (interface{}, error) {
	fv, err := v.Field(f)
	if err != nil {
		return nil, err
	}
	return fv.ReadScalar(), nil
}

// ReadUintField is a shorthand for v.Field followed by ReadUint.
func (v Value) ReadUintField(f StructField) (uint64, error) {
	fv, err := v.Field(f)
	if err != nil {
		return 0, err
	}
	return fv.ReadUint(), nil
}

// ReadScalarFieldByName is a shorthand for v.FieldByName followed by ReadScalar.
func (v Value) ReadScalarFieldByName(name string) (interface{}, error) {
	fv, err := v.FieldByName(name)
	if err != nil {
		return nil, err
	}
	return fv.ReadScalar(), nil
}

// ReadUintFieldByName is a shorthand for v.Field followed by ReadUint.
func (v Value) ReadUintFieldByName(name string) (uint64, error) {
	fv, err := v.FieldByName(name)
	if err != nil {
		return 0, err
	}
	return fv.ReadUint(), nil
}

// IsWritable reports whether v is wholly contained in writable memory segments.
// If this is true, then updates to v.Bytes will be reflected in the core file.
// If this is false, then updates to v.Bytes may segfault.
// Always returns false if the core file was not opened in writable mode.
//
// Writing to a value allows updating a core file; for example, to sanitize private
// or personally-identifying data.
func (v *Value) IsWritable() bool {
	ds, found := v.Type.Program().dataSegments.findSegment(v.Addr)
	return found && ds.writable && ds.containsRange(v.Addr, v.Type.Size())
}

// WriteScalar overwrites v in the core file. WriteScalar is the inverse of ReadScalar.
// Panics if !v.IsWritable(), if v has a non-scalar type, or if the type of x is not
// compatible with v.Type.
func (v Value) WriteScalar(x interface{}) {
	if !v.IsWritable() {
		panic(fmt.Sprintf("value at addr 0x%x, type %s (%T) is not writable", v.Addr, v.Type, v.Type))
	}

	a := v.Type.Program().RuntimeLibrary.Arch

	switch t := v.Type.(type) {
	case *NumericType:
		switch t.Kind {
		case NumericBool:
			if x.(bool) {
				v.Bytes[0] = 1
			} else {
				v.Bytes[0] = 0
			}
		case NumericUint8, NumericInt8:
			v.Bytes[0] = byte(uint8(reflect.ValueOf(x).Uint()))
		case NumericUint16, NumericInt16:
			a.ByteOrder.PutUint16(v.Bytes, uint16(reflect.ValueOf(x).Uint()))
		case NumericUint32, NumericInt32:
			a.ByteOrder.PutUint32(v.Bytes, uint32(reflect.ValueOf(x).Uint()))
		case NumericUint64, NumericInt64:
			a.ByteOrder.PutUint64(v.Bytes, uint64(reflect.ValueOf(x).Uint()))
		case NumericFloat32:
			a.FloatByteOrder.PutUint32(v.Bytes, math.Float32bits(float32(reflect.ValueOf(x).Float())))
		case NumericFloat64:
			a.FloatByteOrder.PutUint64(v.Bytes, math.Float64bits(float64(reflect.ValueOf(x).Float())))
		case NumericComplex64:
			c := reflect.ValueOf(x).Complex()
			a.FloatByteOrder.PutUint32(v.Bytes[0:4], math.Float32bits(float32(real(c))))
			a.FloatByteOrder.PutUint32(v.Bytes[4:8], math.Float32bits(float32(imag(c))))
		case NumericComplex128:
			c := reflect.ValueOf(x).Complex()
			a.FloatByteOrder.PutUint64(v.Bytes[0:8], math.Float64bits(float64(real(c))))
			a.FloatByteOrder.PutUint64(v.Bytes[8:16], math.Float64bits(float64(imag(c))))
		}

	case *PtrType:
		switch a.PointerSize {
		case 4:
			a.ByteOrder.PutUint32(v.Bytes, uint32(reflect.ValueOf(x).Uint()))
		case 8:
			a.ByteOrder.PutUint64(v.Bytes, uint64(reflect.ValueOf(x).Uint()))
		default:
			panic(fmt.Sprintf("unexpected PointerSize %v", a.PointerSize))
		}

	default:
		panic(fmt.Sprintf("bad type for Value.WriteScalar(): %s (%T)", t, t))
	}
}

// Value casts the given address to the given type.
// Returns ErrNil or ErrOutOfBounds if the address is out-of-bounds.
func (p *Program) Value(addr uint64, t Type) (Value, error) {
	if addr == 0 {
		return Value{}, ErrNil
	}
	ds, ok := p.dataSegments.slice(addr, t.Size())
	if !ok {
		return Value{}, ErrOutOfBounds
	}
	return Value{
		Addr:  addr,
		Type:  t,
		Bytes: ds.data,
	}, nil
}
