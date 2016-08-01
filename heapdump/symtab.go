package heapdump

import (
	"fmt"
	"golang.org/x/debug/dwarf"
	"golang.org/x/debug/elf"
	"golang.org/x/debug/gosym"
	"golang.org/x/debug/macho"
	"regexp"
	"strings"
)

// DWARF constants
const (
	dw_op_addr           = 3
	dw_op_consts         = 17
	dw_op_call_frame_cfa = 156
	dw_op_plus           = 34
	dw_op_plus_uconst    = 35
)

// loadTypes opens a symbol table from an executable file, then creates
// all RootVars, Types, and Values needed by the dump.
// Currently supports elf and machoe executables (TODO: support PE).
func loadTypes(d *Dump, execfile string) error {
	readers := map[string]func(string) (*gosym.Table, *dwarf.Data, error){
		"elf":   readElf,
		"macho": readMacho,
	}

	var dw *dwarf.Data

	for ftype, reader := range readers {
		var err error
		d.symtab, dw, err = reader(execfile)
		if err == nil {
			LogPrintf("%s: opened %s file", execfile, ftype)
			break
		}
		LogPrintf("%s: %s.open: %v", execfile, ftype, err)
	}
	if d.symtab == nil || dw == nil {
		return fmt.Errorf("%s: unknown executable type", execfile)
	}

	// Extract all types mentioned in the executable image.
	dwarf2type, err := readTypes(d, dw)
	if err != nil {
		return err
	}

	// Create RootVars and propagate types through the heap.
	prop := &typePropagator{
		dump:       d,
		dw:         dw,
		dwarf2type: dwarf2type,
	}
	return prop.run()
}

func readElf(execname string) (*gosym.Table, *dwarf.Data, error) {
	f, err := elf.Open(execname)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	dw, err := f.DWARF()
	if err != nil {
		return nil, nil, err
	}
	var textStart uint64
	var symtab, pclntab []byte
	if s := f.Section(".text"); s != nil {
		textStart = s.Addr
	}
	if s := f.Section(".gosymtab"); s != nil {
		if symtab, err = s.Data(); err != nil {
			return nil, nil, err
		}
	}
	if s := f.Section(".gopclntab"); s != nil {
		if pclntab, err = s.Data(); err != nil {
			return nil, nil, err
		}
	}
	st, err := gosym.NewTable(symtab, gosym.NewLineTable(pclntab, textStart))
	if err != nil {
		return nil, nil, err
	}
	return st, dw, nil
}

func readMacho(execname string) (*gosym.Table, *dwarf.Data, error) {
	f, err := macho.Open(execname)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	dw, err := f.DWARF()
	if err != nil {
		return nil, nil, err
	}
	var textStart uint64
	var symtab, pclntab []byte
	if s := f.Section("__text"); s != nil {
		textStart = s.Addr
	}
	if s := f.Section("__gosymtab"); s != nil {
		if symtab, err = s.Data(); err != nil {
			return nil, nil, err
		}
	}
	if s := f.Section("__gopclntab"); s != nil {
		if pclntab, err = s.Data(); err != nil {
			return nil, nil, err
		}
	}
	st, err := gosym.NewTable(symtab, gosym.NewLineTable(pclntab, textStart))
	if err != nil {
		return nil, nil, err
	}
	return st, dw, nil
}

func readTypes(d *Dump, dw *dwarf.Data) (map[dwarf.Type]Type, error) {
	LogPrintf("Loading types")
	conv := &dwarfTypeConverter{
		dump:        d,
		cache:       make(map[dwarf.Type]Type),
		string2type: make(map[string]Type),
	}

	// Load types from dw.
	r := dw.Reader()
	for {
		e, err := r.Next()
		if err != nil {
			return nil, err
		}
		if e == nil {
			break
		}
		dt, err := dw.EntryType(e)
		if err != nil {
			LogPrintf("Skipping DWARF entry at offset %d: %v", e.Offset, err)
			continue
		}
		if _, err := conv.convert(dt); err != nil {
			return nil, fmt.Errorf("error converting type %s: %v", dt, err)
		}
	}
	if err := d.tc.checkZygotesEmpty(); err != nil {
		return nil, err
	}

	// Fill out type address table for interface resolution.
	for addr, rt := range d.Raw.TypeFromAddr {
		t := conv.string2type[rt.Name]
		if t == nil {
			LogPrintf("warning: type not found: %s", rt.Name)
			continue
		}
		if rt.DirectIFace != t.DirectIFace() || rt.Size != t.Size() {
			LogPrintf("warning: type %s (DirectIFace=%v, Size=%v) not compatible with %s (DirectIFace=%v, Size=%v)",
				t, t.DirectIFace(), t.Size(), rt.Name, rt.DirectIFace, rt.Size)
			continue
		}
		d.typeFromAddr[addr] = t
	}

	return conv.cache, nil
}

// dwarfTypeConverter converts a DWARF type to our internal representation.
// The converted type and all nested types are added to cache and string2type.
type dwarfTypeConverter struct {
	dump        *Dump
	cache       map[dwarf.Type]Type
	string2type map[string]Type // for building dump.typeFrom{Addr,Itab}
	depth       int             // for conv.logf
}

func (conv *dwarfTypeConverter) logf(fmtstr string, args ...interface{}) {
	LogPrintf(strings.Repeat(" ", conv.depth)+fmtstr, args...)
}

func (conv *dwarfTypeConverter) convert(dt dwarf.Type) (Type, error) {
	conv.logf("convert (%s, %T)", dt, dt)
	tc := conv.dump.tc

	if t := conv.cache[dt]; t != nil {
		conv.logf("cached (%s, %T) -> (%s, %T, n=%s, p=%s)", dt, dt, t, t, t.Name(), t.PkgPath())
		return t, nil
	}

	// Pre-declare named types to guard against recursive references.
	name := conv.typeName(dt)
	if name != "" {
		if t := tc.declareNamedType(name, conv.typeZygote(dt)); t != nil {
			conv.cache[dt] = t
			conv.logf("convert (%s, %T) -> (%s, %T, n=%s, p=%s)", dt, dt, t, t, t.Name(), t.PkgPath())
			return t, nil
		}
		conv.logf("declare %s", name)
	}

	conv.depth++
	t, err := conv.convertInternal(dt, name)
	conv.depth--
	if err != nil {
		return nil, err
	}

	// Sanity check: size of the converted type should match.
	// NB: We don't yet know the size of zygotes.
	unknownSize := func() bool {
		if _, unknown := t.(*UnknownType); unknown || tc.zygotes[t.base().String()] {
			return true
		}
		return unknownTypeSizeDWARF(dt)
	}
	if !unknownSize() && t.Size() != uint64(dt.Size()) {
		return nil, fmt.Errorf("type size mismatch: %s (%T; %d bytes) vs %s (%T; %d bytes)", t, t, t.Size(), dt, dt, dt.Size())
	}

	// Add all converted types to the cache.
	conv.cache[dt] = t
	conv.string2type[t.String()] = t
	conv.logf("converted (%s, %T) -> (%s, %T, n=%s, p=%s)", dt, dt, t, t, t.Name(), t.PkgPath())
	return t, nil
}

func (conv *dwarfTypeConverter) convertInternal(dt dwarf.Type, name string) (Type, error) {
	tc := conv.dump.tc

	switch dt := dt.(type) {
	// NumericTypes.

	case *dwarf.BoolType:
		return tc.makeNumericType(name, NumericBool), nil
	case *dwarf.CharType:
		return tc.makeNumericType(name, NumericInt8), nil
	case *dwarf.UcharType:
		return tc.makeNumericType(name, NumericUint8), nil

	case *dwarf.IntType:
		switch dt.Size() {
		case 1:
			return tc.makeNumericType(name, NumericInt8), nil
		case 2:
			return tc.makeNumericType(name, NumericInt16), nil
		case 4:
			return tc.makeNumericType(name, NumericInt32), nil
		case 8:
			return tc.makeNumericType(name, NumericInt64), nil
		default:
			return nil, fmt.Errorf("unsupported IntType %s size=%d", dt.String(), dt.Size())
		}

	case *dwarf.UintType:
		switch dt.Size() {
		case 1:
			return tc.makeNumericType(name, NumericUint8), nil
		case 2:
			return tc.makeNumericType(name, NumericUint16), nil
		case 4:
			return tc.makeNumericType(name, NumericUint32), nil
		case 8:
			return tc.makeNumericType(name, NumericUint64), nil
		default:
			return nil, fmt.Errorf("unsupported UintType %s size=%d", dt.String(), dt.Size())
		}

	case *dwarf.FloatType:
		switch dt.Size() {
		case 4:
			return tc.makeNumericType(name, NumericFloat32), nil
		case 8:
			return tc.makeNumericType(name, NumericFloat64), nil
		default:
			return nil, fmt.Errorf("unsupported FloatType %s size=%d", dt.String(), dt.Size())
		}

	case *dwarf.ComplexType:
		switch dt.Size() {
		case 8:
			return tc.makeNumericType(name, NumericComplex64), nil
		case 16:
			return tc.makeNumericType(name, NumericComplex128), nil
		default:
			return nil, fmt.Errorf("unsupported ComplexType %s size=%d", dt.String(), dt.Size())
		}

	// UnknownTypes.

	case *dwarf.UnspecifiedType:
		return tc.makeUnknownType(""), nil

	case *dwarf.VoidType:
		return tc.makeUnknownType(""), nil

	// Composites.

	case *dwarf.ArrayType:
		elem, err := conv.convert(dt.Type)
		if err != nil {
			return nil, err
		}
		stride := elem.Size()
		if dt.StrideBitSize > 0 {
			stride = uint64(dt.StrideBitSize) / 8
			if dt.StrideBitSize%8 != 0 {
				stride++
			}
		}
		return tc.makeArrayType(name, elem, uint64(dt.Count), stride), nil

	case *dwarf.PtrType:
		elem, err := conv.convert(dt.Type)
		if err != nil {
			return nil, err
		}
		return tc.makePtrType(name, elem), nil

	case *dwarf.StructType:
		if dt.Kind != "struct" {
			return nil, fmt.Errorf("unsupported DWARF struct kind %s (type is %s)", dt.Kind, dt)
		}
		if dt.Incomplete {
			return nil, fmt.Errorf("DWARF incomplete structs are not supported (type is %s)", dt)
		}
		var fields []StructField
		for _, df := range dt.Field {
			conv.logf("field %s", df.Name)
			if df.BitSize != 0 {
				return nil, fmt.Errorf("struct bit fields not supported %s.%s", dt, df.Name)
			}
			t, err := conv.convert(df.Type)
			if err != nil {
				return nil, err
			}
			if _, unknown := t.(*UnknownType); unknown {
				return nil, fmt.Errorf("struct field has unknown type: %s field %s:%s", dt, df.Name, df.Type)
			}
			fields = append(fields, StructField{
				Name:   df.Name,
				Type:   t,
				Offset: uint64(df.ByteOffset),
			})
		}
		return tc.makeStructType(name, uint64(dt.Size()), fields), nil

	case *dwarf.TypedefType:
		elem, err := conv.convert(dt.Type)
		if err != nil {
			return nil, err
		}
		return tc.makeTypedef(elem, name), nil

	// Wrappers.

	case *dwarf.SliceType:
		elem, err := conv.convert(dt.ElemType)
		if err != nil {
			return nil, err
		}
		dt.StructType.StructName = fmt.Sprintf("$sliceHeader<%s>", elem)
		rep, err := conv.convertToStruct(&dt.StructType, "rep of slice")
		if err != nil {
			return nil, err
		}
		return tc.makeSliceType(name, rep, elem), nil

	case *dwarf.StringType:
		dt.StructType.StructName = "$stringHeader"
		rep, err := conv.convertToStruct(&dt.StructType, "rep of string")
		if err != nil {
			return nil, err
		}
		return tc.makeStringType(name, rep), nil

	case *dwarf.InterfaceType:
		rep, err := conv.convertToStruct(dt.TypedefType.Type, "rep of interface")
		if err != nil {
			return nil, err
		}
		return tc.makeInterfaceType(name, rep), nil

	case *dwarf.MapType:
		// TODO
		return conv.convert(&dt.TypedefType)

	case *dwarf.ChanType:
		// TODO
		return conv.convert(&dt.TypedefType)

	case *dwarf.FuncType:
		// TODO
		return tc.makePtrType(name, tc.makeUnknownType("$unknownFuncType")), nil

	// TODO: QualType, EnumType, DotDotDotType?
	default:
		return nil, fmt.Errorf("unsupported DWARF type %s (%T)", dt, dt)
	}
}

func (conv *dwarfTypeConverter) convertToStruct(dt dwarf.Type, dbg string) (*StructType, error) {
	rep, err := conv.convert(dt)
	if err != nil {
		return nil, err
	}
	if _, ok := rep.(*StructType); !ok {
		return nil, fmt.Errorf("expected StructType for %s, got %s %T", dbg, rep, rep)
	}
	return rep.(*StructType), err
}

func (conv *dwarfTypeConverter) typeName(dt dwarf.Type) string {
	switch dt := dt.(type) {
	case *dwarf.BoolType, *dwarf.CharType, *dwarf.UcharType, *dwarf.IntType,
		*dwarf.UintType, *dwarf.FloatType, *dwarf.ComplexType:
		return dt.Common().Name // numeric types

	case *dwarf.UnspecifiedType, *dwarf.VoidType:
		return "" // unknown types

	case *dwarf.InterfaceType, *dwarf.FuncType:
		return dt.Common().Name // composites with simple names

	case *dwarf.TypedefType:
		name := dt.Common().Name
		if name == conv.typeName(dt.Type) {
			return "" // typedef is redundant
		}
		return name

	case *dwarf.ArrayType:
		name := dt.Name
		if strings.HasPrefix(name, "[") {
			name = "" // anonymous type
		}
		return name

	case *dwarf.PtrType:
		name := dt.Name
		if strings.HasPrefix(name, "*") {
			name = "" // anonymous type
		}
		return name

	case *dwarf.StructType:
		name := dt.StructName
		if strings.HasPrefix(name, "struct {") {
			name = "" // anonymous struct
		}
		return name

	case *dwarf.SliceType:
		name := dt.Name
		if strings.HasPrefix(name, "[") {
			name = "" // anonymous type
		}
		return name

	case *dwarf.StringType:
		name := dt.Name
		if name == "string" {
			name = "" // anonymous type
		}
		return name

	case *dwarf.MapType, *dwarf.ChanType:
		return "" // for now, redundant with nested typedef

	default:
		return "$???"
	}
}

func (conv *dwarfTypeConverter) typeZygote(dt dwarf.Type) Type {
	switch dt := dt.(type) {
	case *dwarf.BoolType, *dwarf.CharType, *dwarf.UcharType, *dwarf.IntType,
		*dwarf.UintType, *dwarf.FloatType, *dwarf.ComplexType:
		return &NumericType{}

	case *dwarf.UnspecifiedType, *dwarf.VoidType:
		return &UnknownType{}

	case *dwarf.ArrayType:
		return &ArrayType{}
	case *dwarf.PtrType:
		return &PtrType{}
	case *dwarf.StructType:
		return &StructType{}
	case *dwarf.InterfaceType:
		return &InterfaceType{}
	case *dwarf.SliceType:
		return &SliceType{}
	case *dwarf.StringType:
		return &StringType{}

	case *dwarf.TypedefType:
		return conv.typeZygote(dt.Type)
	case *dwarf.MapType:
		return conv.typeZygote(dt.TypedefType.Type)
	case *dwarf.ChanType:
		return conv.typeZygote(dt.TypedefType.Type)
	case *dwarf.FuncType:
		return &PtrType{}

	default:
		return nil
	}
}

// unknownTypeSizeDWARF returns true if the given dwarf type has an unknown size.
// Returns true for any type that contains a FuncType. This type should have size
// PtrSize, but the dwarf package currently uses -1.
func unknownTypeSizeDWARF(dt dwarf.Type) bool {
	switch dt := dt.(type) {
	case *dwarf.FuncType:
		return true

	case *dwarf.TypedefType:
		return unknownTypeSizeDWARF(dt.Type)
	case *dwarf.ArrayType:
		return unknownTypeSizeDWARF(dt.Type)
	case *dwarf.StructType:
		for _, f := range dt.Field {
			if unknownTypeSizeDWARF(f.Type) {
				return true
			}
		}
		return false

	case *dwarf.SliceType:
		return unknownTypeSizeDWARF(&dt.StructType)
	case *dwarf.StringType:
		return unknownTypeSizeDWARF(&dt.StructType)

	case *dwarf.InterfaceType:
		return unknownTypeSizeDWARF(&dt.TypedefType)
	case *dwarf.MapType:
		return unknownTypeSizeDWARF(&dt.TypedefType)
	case *dwarf.ChanType:
		return unknownTypeSizeDWARF(&dt.TypedefType)

	default:
		return false
	}
}

// typePropagator creates and types root objects, then propagates types through the heap.
type typePropagator struct {
	dump          *Dump
	dw            *dwarf.Data
	dwarf2type    map[dwarf.Type]Type
	frames        map[string]*stackFrameLayout
	gcsig, valsig []uint64 // tmps for validateType
}

type stackFrameLayout struct {
	name string
	// offset is distance from stack.Addr
	locals []stackFrameVar
	// offset is distance from callerStack.Addr
	args []stackFrameVar
}

type stackFrameVar struct {
	Offset uint64
	Name   string
	Type   Type
}

func (prop *typePropagator) run() error {
	LogPrintf("Propagating types")
	d := prop.dump

	// Create all RootVars.
	if err := prop.createGlobals(); err != nil {
		return err
	}
	if err := prop.createFrameLayouts(); err != nil {
		return err
	}
	for _, g := range d.Goroutines {
		for sf := g.Stack; sf != nil; sf = sf.Caller {
			if err := prop.createLocals(sf); err != nil {
				return err
			}
		}
	}
	if err := prop.createOtherRoots(); err != nil {
		return err
	}

	// Create all the heap objects, starting with default (unknown) types.
	d.HeapObjects = make([]Value, len(d.Raw.HeapObjects))
	for k := range d.Raw.HeapObjects {
		seg := &d.Raw.HeapObjects[k]
		d.HeapObjects[k] = Value{Type: defaultTypeForSegment(d, seg), seg: seg}
	}

	// Now propagate type information from the roots through the heap.
	var objstack []*Value
	d.ForeachRootVar(func(rv *RootVar) {
		objstack = append(objstack, rv.Value)
	})

	for len(objstack) != 0 {
		src := objstack[len(objstack)-1]
		objstack = objstack[:len(objstack)-1]

		src.ForeachPointer(func(ptr *Value) {
			t := ptr.Type.(*PtrType).Elem
			// Skip if the pointed-to type is unknown.
			if _, unknown := t.(*UnknownType); unknown {
				return
			}
			// Skip if ptr doesn't point to the start of a heap object.
			dst, offset, err := ptr.DerefContainer()
			if err != nil || offset != 0 {
				return
			}
			idx, err := d.value2heap(dst)
			if err != nil {
				return
			}
			// Sanity check.
			if dst != &d.HeapObjects[idx] {
				panic(fmt.Errorf("DerefContainer returned %#v, value2heap returned %#v", dst, &d.HeapObjects[idx]))
			}
			// Already visited?
			if _, unknown := dst.Type.(*UnknownType); !unknown {
				visited := true
				switch {
				case dst.Type != t && dst.Type.Size() >= t.Size():
					LogPrintf("ambiguous types for value at 0x%x: %s (%T) and %s (%T)", dst.Addr(), dst.Type, dst.Type, t, t)
				case dst.Type != t:
					// Type pointed-to by ptr is bigger than the current type for this heap
					// object, so assume t is more correct than dst.Type (means we need to
					// visit the heap object again).
					// FIXME: It should be sufficient skip this type unless dst.Size() == t.Size(),
					// however there are many cases where the type is legitimately smaller than
					// the object (such as arrays that are smaller than capacity). Not sure how
					// to best handle this.
					LogPrintf("ambiguous types for value at 0x%x: %s (%T) and %s (%T), moving to larger type", dst.Addr(), dst.Type, dst.Type, t, t)
					visited = false
				}
				if visited {
					return
				}
			}
			//oldT := dst.Type
			dst.Type = t
			if err := prop.validateType(dst); err != nil {
				// TODO: why is gcsig too small for many objects?
				LogPrintf("warning mismatched type %s %T %d bytes for heap object 0x%x %d bytes from object %s: %v",
					t, t, t.Size(), dst.Addr(), dst.Size(), src.Type, err)
				//dst.Type = oldT // XXX
				//return
			}
			objstack = append(objstack, dst)
		})
	}

	return nil
}

func (prop *typePropagator) createGlobals() error {
	r := prop.dw.Reader()
	d := prop.dump
	raw := d.Raw
	for {
		e, err := r.Next()
		if err != nil {
			return err
		}
		if e == nil {
			break
		}
		if e.Tag != dwarf.TagVariable {
			continue
		}
		loc := e.Val(dwarf.AttrLocation).([]uint8)
		if len(loc) == 0 || loc[0] != dw_op_addr {
			continue // skip non-global vars
		}

		name := e.Val(dwarf.AttrName).(string)
		addr := raw.Params.ReadPtr(loc[1:])
		dbgInfo := func() string {
			return fmt.Sprintf("global %s at address 0x%x", name, addr)
		}
		t, err := prop.typeFromEntry(e, dbgInfo)
		if err != nil {
			LogPrintf("skipping: %v", err)
			continue
		}

		// Ignore globals in unknown segments.
		var seg *RawSegment
		for k := range raw.GlobalSegments {
			if raw.GlobalSegments[k].ContainsRange(addr, t.Size()) {
				seg = &raw.GlobalSegments[k]
				seg = seg.Slice(addr-seg.Addr, t.Size())
				break
			}
		}
		if seg == nil {
			LogPrintf("skipping: %s not in known global segment", dbgInfo())
			continue
		}

		// Validate.
		v := &Value{Type: t, seg: seg}
		if err := prop.validateType(v); err != nil {
			LogPrintf("skipping: %s %v", dbgInfo(), err)
			continue
		}

		// Create this global.
		rv := &RootVar{
			Kind:  RootVarGlobal,
			Name:  name,
			Value: v,
		}
		d.GlobalVars.add(rv)
	}

	for k := range raw.GlobalSegments {
		prop.createMissingRootPointers(&d.GlobalVars, &raw.GlobalSegments[k], RootVarGlobal)
	}
	return nil
}

func (prop *typePropagator) createFrameLayouts() error {
	var curr *stackFrameLayout

	prop.frames = make(map[string]*stackFrameLayout)
	emitCurrFrame := func() {
		if curr == nil {
			return
		}
		if old := prop.frames[curr.name]; old != nil {
			LogPrintf("warning: possibly ambiguous layout for frames: %#v and %#v", *old, *curr)
		}
		prop.frames[curr.name] = curr
		curr = nil
	}

	r := prop.dw.Reader()
	for {
		e, err := r.Next()
		if err != nil {
			return err
		}
		if e == nil {
			break
		}
		// Each TagSubprogram is preceded by Variable and FormatParameter
		// definitions for the local names defined in that function.
		switch e.Tag {
		case dwarf.TagSubprogram:
			emitCurrFrame()
			curr = &stackFrameLayout{name: e.Val(dwarf.AttrName).(string)}

		case dwarf.TagVariable, dwarf.TagFormalParameter:
			if e.Val(dwarf.AttrName) == nil {
				continue
			}
			name := e.Val(dwarf.AttrName).(string)
			loc := e.Val(dwarf.AttrLocation).([]uint8)
			if len(loc) == 0 || loc[0] != dw_op_call_frame_cfa {
				continue
			}
			var offset int64
			if len(loc) == 1 {
				offset = 0
			} else if len(loc) >= 3 && loc[1] == dw_op_consts && loc[len(loc)-1] == dw_op_plus {
				loc, offset = readSleb(loc[2 : len(loc)-1])
				if len(loc) != 0 {
					LogPrintf("skipping: %s has an incomplete sleb: %q", name, loc)
					continue
				}
			}
			if e.Tag == dwarf.TagVariable {
				offset = -offset // convert from FP-relative to SP-relative
			}
			if name == "" {
				if e.Tag == dwarf.TagVariable {
					name = fmt.Sprintf("$local_%x", offset)
				} else {
					name = fmt.Sprintf("$arg_%x", offset)
				}
			}

			dbgInfo := func() string {
				return fmt.Sprintf("var %s in %s at offset %d", name, curr.name, offset)
			}
			t, err := prop.typeFromEntry(e, dbgInfo)
			if err != nil {
				LogPrintf("skipping: %v", err)
				continue
			}
			if curr == nil {
				LogPrintf("skipping: %s outside of subroutine", dbgInfo())
				continue
			}

			if e.Tag == dwarf.TagVariable {
				curr.locals = append(curr.locals, stackFrameVar{uint64(offset), name, t})
			} else {
				curr.args = append(curr.args, stackFrameVar{uint64(offset), name, t})
			}
			LogPrintf("frameVar: %s", dbgInfo())
		}
	}

	emitCurrFrame()
	return nil
}

func (prop *typePropagator) createLocals(sf *StackFrame) error {
	layout := prop.frames[sf.Raw.Name]
	if layout == nil {
		return fmt.Errorf("no layout for stack frame %s", sf.Raw.Name)
	}

	// Add x to sf.LocalVars.
	add := func(data *RawSegment, x stackFrameVar, kind RootVarKind) error {
		addr := data.Addr + x.Offset
		if !data.ContainsRange(addr, x.Type.Size()) {
			return fmt.Errorf("%s %s [%d] outside frame %s [sz=%d]", kind, x.Name, int64(x.Offset), sf.Raw.Name, data.Size())
		}
		v := &Value{
			Type: x.Type,
			seg:  data.Slice(x.Offset, x.Type.Size()),
		}
		if err := prop.validateType(v); err != nil {
			LogPrintf("skipping: %s %s in %s at 0x%x: %v", kind, x.Name, sf.Raw.Name, addr, err)
			return nil
		}
		sf.LocalVars.add(&RootVar{Kind: kind, Name: x.Name, Value: v})
		return nil
	}

	// Find all live fn paramters. These live in the caller's stack frame.
	// NB: We assume createLocals(sf) is called before createLocals(caller).
	// This means we can delay sorting caller.LocalVars until the next call,
	// which will fill out all local vars in caller.
	if caller := sf.Caller; caller != nil {
		for _, arg := range layout.args {
			if err := add(&caller.Raw.Segment, arg, RootVarFuncParameter); err != nil {
				return err
			}
		}
	}

	// Find all live locals.
	for _, local := range layout.locals {
		if err := add(&sf.Raw.Segment, local, RootVarLocal); err != nil {
			return err
		}
	}

	// Finalize.
	prop.createMissingRootPointers(&sf.LocalVars, &sf.Raw.Segment, RootVarLocal)
	return nil
}

// TODO XXX: for Obj and Fn, lookup via {*}TypeAddr fields
// TODO XXX: could also lookup {*}Type fields via "*runtime._type"?
func (prop *typePropagator) createOtherRoots() error {
	d := prop.dump
	for k, f := range d.Finalizers {
		name := fmt.Sprintf("$finalizer%d", k)
		f.Obj = defaultRootVarForAddr(d, f.Raw.ObjAddr, name+"obj", RootVarFinalizer)
		f.ObjType = defaultRootVarForAddr(d, f.Raw.ObjTypeAddr, name+"objtype", RootVarFinalizer)
		f.Fn = defaultRootVarForAddr(d, f.Raw.FnAddr, name+"fn", RootVarFinalizer)
		f.FnArgType = defaultRootVarForAddr(d, f.Raw.FnArgTypeAddr, name+"fnargtype", RootVarFinalizer)
	}
	re := regexp.MustCompile(`[^a-zA-Z0-9]`)
	for k, x := range d.Raw.OtherRoots {
		desc := re.ReplaceAllString(x.Description, "_")
		v := defaultRootVarForAddr(d, x.Addr, fmt.Sprintf("$otherRoot%d_%s", k, desc), RootVarOther)
		d.OtherRoots = append(d.OtherRoots, v)
	}
	return nil
}

// createMissingRootPointers scans seg's GC signature and creates default
// pointer variables to represent all pointers from the GC signature that
// are not already covered by vars.
//
// After this call, vars is always sorted.
func (prop *typePropagator) createMissingRootPointers(vars *RootVarSet, seg *RawSegment, kind RootVarKind) {
	// NB: Need to sort so that vars.FindAddr works.
	vars.sort()
	if seg == nil {
		return
	}
	// NB: We've already verified the types of existing vars.
	// We just need to add any missing vars.
	// TODO: some of these missing vars will be args that we actually
	// include in the callee's StackFrame
	for _, offset := range seg.PtrFields.Offsets() {
		addr := seg.Addr + offset
		if vars.FindAddr(addr) != nil {
			continue
		}
		t := prop.dump.tc.makePtrToUnknownType()
		vars.add(&RootVar{
			Kind:  kind,
			Name:  fmt.Sprintf("$%sptr_%x", strings.ToLower(string(kind)), addr),
			Value: &Value{Type: t, seg: seg.Slice(offset, t.Size())},
		})
		vars.sort()
	}
}

// typeFromEntry looks up the type for the given DWARF entry.
// Returns an error if the type is unknown.
func (prop *typePropagator) typeFromEntry(e *dwarf.Entry, dbgInfo func() string) (Type, error) {
	dt, err := prop.dw.EntryType(e)
	if err != nil {
		return nil, fmt.Errorf("%s does not have a type", dbgInfo())
	}
	t := prop.dwarf2type[dt]
	if t == nil {
		panic(fmt.Errorf("type not found for dwarf type %s (%T) for %s", dt, dt, dbgInfo()))
	}
	if _, unknown := t.(*UnknownType); unknown {
		return nil, fmt.Errorf("%s has unknown type %s", dbgInfo(), t)
	}
	return t, nil
}

// validateType compares the ptr bitfield from the GC signature with the
// pointers in v.Type. If they match exactly, then v is a valid type for
// a live value at v.Addr. If they do not match, then either:
//   - v.Type is invalid, or
//   - v is a dead local variable (only possible if v is a local variable
//     and if the GC signature is empty)
//
// Returns an error if the type and GC signature do not match.
func (prop *typePropagator) validateType(v *Value) error {
	prop.gcsig = prop.gcsig[:0]
	prop.valsig = prop.valsig[:0]

	for _, x := range v.seg.PtrFields.Offsets() {
		prop.gcsig = append(prop.gcsig, x)
	}

	n, ok := 0, true
	v.ForeachPointer(func(ptr *Value) {
		x := ptr.Addr() - v.Addr()
		n++
		if n > len(prop.gcsig) || prop.gcsig[n-1] != x {
			ok = false
		}
		prop.valsig = append(prop.valsig, x)
	})
	if !ok {
		return fmt.Errorf("gcsig %#v != valsig %#v, v.Type is %s", prop.gcsig, prop.valsig, v.Type)
	}

	// XXX
	LogPrintf("HEAP 0x%x : %T %s\n", v.Addr(), v.Type, v.Type)
	return nil
}

func readUleb(b []byte) ([]byte, uint64) {
	r := uint64(0)
	s := uint(0)
	for {
		x := b[0]
		b = b[1:]
		r |= uint64(x&127) << s
		if x&128 == 0 {
			break
		}
		s += 7

	}
	return b, r
}

func readSleb(b []byte) ([]byte, int64) {
	c, v := readUleb(b)
	// sign extend
	k := (len(b) - len(c)) * 7
	return c, int64(v) << uint(64-k) >> uint(64-k)
}
