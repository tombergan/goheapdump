package corefile

import (
	"errors"
	"fmt"

	"golang.org/x/debug/arch"
)

// OSThread describes a kernel thread.
type OSThread struct {
	PID    uint64            // kernel's id for this thread
	GPRegs map[string]uint64 // values of general-purpose registers for this thread (arch specific)

	// For threads controlled by the Go runtime library.
	M       Value      // thread descriptor
	CurG    *Goroutine // currently running goroutine, if any
	G0      *Goroutine // system stack goroutine for this thread
	GSignal *Goroutine // signal stack goroutine for this thread, if any
}

// RuntimeLibrary describes a Program’s Go runtime library.
type RuntimeLibrary struct {
	Arch    arch.Architecture // architecture-specific information
	Version string            // runtime.Version()
	GOARCH  string            // runtime.GOARCH
	GOOS    string            // runtime.GOOS

	Program    *Program     // parent program
	Goroutines []*Goroutine // internal goroutines, such as GC workers
	Threads    []*OSThread  // kernel threads that are controlled by the runtime library
	Vars       *VarSet      // global variables internal to the runtime library (includes the "runtime" package)

	// Finalizers enumerates all registered finalizers.
	// This field cannot be used except as an argument to NewQuery.
	Finalizers runtimeFinalizers

	// GCRoots enumerates all garbage collection roots.
	// This field cannot be used except as an argument to NewQuery.
	GCRoots runtimeGCRoots

	// HeapObjects enumerates all heap objects allocated in the runtime
	// library's heap. This exclues objects allocated on a stack, in custom
	// mmap segments, or the runtime library's internal unmanaged memory.
	// This field cannot be used except as an argument to NewQuery.
	HeapObjects runtimeHeapObjects

	// Memory areas known to or managed by the runtime library.
	moduledatas []*runtimeModuleData // from runtime.moduledata
	mheapArena  dataSegment          // from runtime.mheap_: [arena_start, arena_used)
	mheapBitmap dataSegment          // from runtime.mheap_: [bitmap - bitmap_mapped, bitmap)
	mheapSpans  Value                // DerefArray version of runtime.mheap_.spans

	// Types and fields used for heap traversal.
	mspantypeType       Type        // runtime.mspan
	mspanStartAddrField StructField // runtime.mspan.startAddr
	mspanNpagesField    StructField // runtime.mspan.npages
	mspanFreeindexField StructField // runtime.mspan.freeindex
	mspanNelemsField    StructField // runtime.mspan.nelems
	mspanAllocBitsField StructField // runtime.mspan.allocBits
	mspanStateField     StructField // runtime.mspan.state
	mspanElemsizeField  StructField // runtime.mspan.elemsize
	mspanLimitField     StructField // runtime.mspan.limit

	// Types and fields used for type conversions from the runtime type structures.
	itabTypeField            StructField // runtime.itab._type
	typeType                 Type        // runtime._type
	typeSizeField            StructField // runtime._type.size
	typeKindField            StructField // runtime._type.kind
	typeTflagField           StructField // runtime._type.tflag
	typeStrField             StructField // runtime._type.str
	arraytypeType            Type        // runtime.arraytype
	arraytypeLenField        StructField // runtime.arraytype.len
	arraytypeElemField       StructField // runtime.arraytype.elem
	ptrtypeType              Type        // runtime.ptrtype
	ptrtypeElemField         StructField // runtime.ptrtype.elem
	structtypeType           Type        // runtime.structtype
	structtypeFieldsField    StructField // runtime.structtype.fields
	structfieldType          Type        // runtime.structfield
	structfieldNameField     StructField // runtime.structfield.name
	structfieldTypeField     StructField // runtime.structfield.typ
	structfieldOffsetField   StructField // runtime.structfield.offset
	interfacetypeType        Type        // runtime.interfacetype
	slicetypeType            Type        // runtime.slicetype
	slicetypeElemField       StructField // runtime.slicetype.elem
	chantypeType             Type        // runtime.chantype
	chantypeDirField         StructField // runtime.chantype.dir
	chantypeElemField        StructField // runtime.chantype.elem
	maptypeType              Type        // runtime.maptype
	maptypeKeyField          StructField // runtime.maptype.key
	maptypeElemField         StructField // runtime.maptype.elem
	uncommontypeType         Type        // runtime.uncommontype
	uncommontypePkgPathField StructField // runtime.uncommontype.pkgPath
	sliceRepType             *StructType // runtime.slice
	chanRepType              *PtrType    // *runtime.hchan
	mapRepType               *PtrType    // *runtime.hchan

	// Types used when looking into function stackmaps.
	funcType           *StructType // runtime._func
	findfuncbucketType *StructType // runtime.findfuncbucket
	ptrToStackmapType  *PtrType    // *runtime.stackmap
}

type runtimeFinalizers struct{ p *Program }
type runtimeGCRoots struct{ p *Program }
type runtimeHeapObjects struct{ p *Program }

// RegisteredFinalizer describes a finalizer that has been registered with the
// runtime library via runtime.SetFinalizer.
// TODO: Can we infer the Go types of Obj and Fn from runtime metadata?
// TODO: Finalizers are not yet supported
type RegisteredFinalizer struct {
	Obj Value // the object to finalize
	Fn  Value // the finalizer function to run when Obj is garbage collected
}

type runtimeMSpan struct {
	base      uint64
	npages    uint64
	freeindex uint64
	nelems    uint64
	allocBits dataSegment
	state     uint64
	elemsize  uint64
	limit     uint64
}

func (rt *RuntimeLibrary) readMSpan(idx uint64) (*runtimeMSpan, error) {
	spanPtr, err := rt.mheapSpans.Index(idx)
	if err != nil {
		logf("unexpected error in mheap.spans[%d]: %v", idx, err)
		return nil, err
	}
	if spanPtr.IsZero() {
		return nil, ErrNil
	}
	span, err := spanPtr.Deref()
	if err != nil {
		logf("unexpected error in *mheap.spans[%d] (0x%x): %v", idx, spanPtr.ReadUint(), err)
		return nil, err
	}

	s := &runtimeMSpan{}
	var allocBitsAddr uint64
	fields := []struct {
		x *uint64
		f StructField
	}{
		{&s.base, rt.mspanStartAddrField},
		{&s.npages, rt.mspanNpagesField},
		{&s.freeindex, rt.mspanFreeindexField},
		{&s.nelems, rt.mspanNelemsField},
		{&allocBitsAddr, rt.mspanAllocBitsField},
		{&s.state, rt.mspanStateField},
		{&s.elemsize, rt.mspanElemsizeField},
		{&s.limit, rt.mspanLimitField},
	}
	for _, f := range fields {
		*f.x, err = span.ReadUintField(f.f)
		if err != nil {
			return nil, err
		}
	}
	var ok bool
	s.allocBits, ok = rt.Program.dataSegments.slice(allocBitsAddr, (s.nelems+7)/8)
	if !ok {
		err := fmt.Errorf("could not load mheap.spans[%d].allocBits from mspan 0x%x, allocBits 0x%x, nelem %d",
			idx, spanPtr.ReadUint(), allocBitsAddr, s.nelems)
		logf("unexpected error: %v", err)
		return nil, err
	}

	return s, nil
}

// FindHeapObject returns a Value representing the heap allocation slot that
// contains targetAddr. The returned value always has GCObjectType. For example,
// the following struct is 21 bytes, but might be allocated in a 24-byte slot:
//
//    type foo struct { x uint64, buf [13]byte }
//
// Given that targetAddr is &foo{}, or &foo{}.x, or &foo{}.buf[5], then
// FindHeapSlot(targetAddr) returns a value of type GCObjectType, size 24,
// and address &foo{}.
//
// FindHeapObject returns false if targetAddr is not contained within a
// currently allocated heap object.
func (rt *RuntimeLibrary) FindHeapObject(targetAddr uint64) (Value, bool) {
	// See runtime/mbitmap.go:heapBitsForObject.
	if !rt.mheapArena.contains(targetAddr) {
		return Value{}, false
	}
	const _PageShift = 13 // see runtime._PageShift
	const _MSpanInUse = 1 // see runtime._MSpanInUse
	spanIdx := (targetAddr - rt.mheapArena.addr) >> _PageShift
	span, err := rt.readMSpan(spanIdx)
	if err != nil || targetAddr < span.base || targetAddr >= span.limit || span.state != _MSpanInUse {
		return Value{}, false
	}
	objIdx := (targetAddr - span.base) / span.elemsize

	// See runtime/mbitmap.go:mspan.isFree.
	if objIdx >= span.freeindex {
		return Value{}, false
	}
	mask := uint8(1) << (objIdx % 8)
	if isFree := (span.allocBits.data[objIdx/8] & mask) == 0; isFree {
		return Value{}, false
	}

	baseAddr := span.base + objIdx*span.elemsize
	obj, err := rt.Program.Value(baseAddr, rt.Program.MakeGCObjectType(span.elemsize))
	if err != nil {
		logf("unexpected error loading value from 0x%x, size 0x%x: %v", baseAddr, span.elemsize, err)
		return Value{}, false
	}
	return obj, true
}

// gcHeapBitvectorForObject returns the GC bitmap for the given heap object,
// which must have been generated by FindHeapObject.
func (rt *RuntimeLibrary) gcHeapBitvectorForObject(v Value) gcHeapBitvector {
	ptrSize := uint64(rt.Arch.PointerSize)
	return makeGCHeapBitvector(rt.mheapArena.addr, v.Addr, v.Size(), ptrSize, rt.mheapBitmap.data)
}

// foreachGCPointer calls fn with each GC-visible pointer in Value.
// The Value is assumed to be derived from a single program value
// (i.e., a single Var or heap object).
func (rt *RuntimeLibrary) foreachGCPointer(v Value, fn func(ptrValue uint64)) {
	ptrSize := uint64(rt.Arch.PointerSize)
	endAddr := v.Addr + v.Size()
	startAddr := roundUp(v.Addr, ptrSize)
	if startAddr >= endAddr {
		return
	}

	// Heap?
	if heapObj, ok := rt.FindHeapObject(v.Addr); ok {
		bv := rt.gcHeapBitvectorForObject(heapObj)
		bv.foreachPointer(startAddr, endAddr-startAddr, fn)
		return
	}

	// Global?
	for _, md := range rt.moduledatas {
		if md.data.contains(startAddr) {
			md.gcdatabv.foreachPointer(startAddr, endAddr-startAddr, fn)
			return
		}
		if md.bss.contains(startAddr) {
			md.gcbssbv.foreachPointer(startAddr, endAddr-startAddr, fn)
			return
		}
		if md.noptrdata.contains(startAddr) || md.noptrbss.contains(startAddr) {
			return
		}
	}

	// Stack?
	// TODO: more efficient search for large stacks?
	findStack := func(gs []*Goroutine) *gcBitvector {
		for _, g := range gs {
			for sf := g.Stack; sf != nil; sf = sf.Callee {
				if sf.argsBV.contains(startAddr) {
					return sf.argsBV
				}
				if sf.localsBV.contains(startAddr) {
					return sf.localsBV
				}
			}
		}
		return nil
	}
	bv := findStack(rt.Program.Goroutines)
	if bv == nil {
		bv = findStack(rt.Goroutines)
	}
	if bv != nil {
		bv.foreachPointer(startAddr, endAddr-startAddr, fn)
	}
}

// runtimeModuleData mirrors runtime.moduledata.
type runtimeModuleData struct {
	pclntable    Value // type Array of byte
	ftab         []runtimeFunctab
	findfunctab  uint64
	minpc, maxpc uint64

	data      dataSegment // [moduledata.data, moduledata.edata)
	bss       dataSegment // [moduledata.bss, moduledata.ebss)
	noptrdata dataSegment // [moduledata.noptrdata, moduledata.enoptrdata)
	noptrbss  dataSegment // [moduledata.noptrbss, moduledata.enoptrbss)
	types     dataSegment // [moduledata.types, moduledata.etypes)

	gcdatabv *gcBitvector // moduledata.gcdatamask
	gcbssbv  *gcBitvector // moduledata.gcbssmask
}

// runtimeFunctab mirrors runtime.functab.
type runtimeFunctab struct {
	entry   uint64
	funcoff uint64
}

// initialize rt. Must be called after global variables have been loaded.
// This checks the runtime library version and loads all goroutines.
func (rt *RuntimeLibrary) initialize(threads []*OSThread) error {
	// Determine the runtime version.
	// TODO: use this to guide the rest of the initialization to support multiple versions
	if buildVersion, ok := rt.Vars.FindName("runtime.buildVersion"); !ok {
		logf("WARNING: could not find runtime.buildVersion")
	} else if s, err := buildVersion.Value.DerefArray(); err != nil {
		logf("WARNING: could not load runtime.buildVersion: %v", err)
	} else {
		rt.Version = string(s.Bytes)
		logf("Go runtime version %s", rt.Version)
	}

	switch rt.GOARCH {
	case "386", "amd64":
	default:
		return fmt.Errorf("unsupported GOARCH %q", rt.GOARCH)
	}

	init := &runtimeInitializer{
		rt:                 rt,
		bottomOfStackPCs:   make(map[uint64]bool),
		systemGoroutinePCs: make(map[uint64]bool),
		mptrToThread:       make(map[uint64]*OSThread),
	}
	if err := init.loadInfo(); err != nil {
		return err
	}
	if err := init.loadImportantTypes(); err != nil {
		return err
	}
	if err := init.loadModuleData(); err != nil {
		return err
	}
	if err := init.loadHeapInfo(); err != nil {
		return err
	}
	if err := init.loadThreads(threads); err != nil {
		return err
	}
	if err := init.loadGoroutines(); err != nil {
		return err
	}

	logf("RuntimeLibrary initialized")
	return nil
}

// runtimeInitializer holds data needed only during RuntimeLibrary initialization.
type runtimeInitializer struct {
	rt                  *RuntimeLibrary
	bottomOfStackPCs    map[uint64]bool      // PCs of function entry points
	systemGoroutinePCs  map[uint64]bool      // PCs of function entry points
	mptrToThread        map[uint64]*OSThread // &m -> OSThread
	framepointerEnabled bool
}

func (init *runtimeInitializer) loadInfo() error {
	rt := init.rt

	loadPCIntoMap := func(vname string, m map[uint64]bool) {
		v, ok := rt.Vars.FindName(vname)
		if !ok {
			logf("WARNING: couldn't find %s", vname)
			return
		}
		if v.Value.IsZero() {
			logf("WARNING: %s is zero", vname)
			return
		}
		m[v.Value.ReadUint()] = true
	}

	// See runtime/traceback.go:topofstack().
	// Caveat: we define bottom=oldest, but traceback.go defines top=oldest.
	bottomOfStackVars := []string{
		"runtime.goexitPC",
		"runtime.mstartPC",
		"runtime.mcallPC",
		"runtime.morestackPC",
		"runtime.rt0_goPC",
		"runtime.externalthreadhandlerp",
	}
	for _, vname := range bottomOfStackVars {
		loadPCIntoMap(vname, init.bottomOfStackPCs)
	}

	// See runtime/traceback.go:isSystemGoroutine().
	systemGoroutinePCs := []string{
		"runtime.bgsweepPC",
		"runtime.forcegchelperPC",
		"runtime.timerprocPC",
		"runtime.gcBgMarkWorkerPC",
	}
	for _, vname := range systemGoroutinePCs {
		loadPCIntoMap(vname, init.systemGoroutinePCs)
	}
	// runfinq is a system goroutine only if there's no finalizer currently running.
	// Otherwise it becomes a user goroutine (since the finalizer is user code).
	fingRunning, ok := rt.Vars.FindName("runtime.fingRunning")
	if !ok {
		return errors.New("could not find runtime.fingRunning")
	}
	if !fingRunning.Value.ReadScalar().(bool) {
		loadPCIntoMap("runtime.runfinq", init.systemGoroutinePCs)
	}

	fpe, ok := rt.Vars.FindName("runtime.framepointer_enabled")
	if !ok {
		return errors.New("could not find runtime.framepointerEnabled")
	}
	init.framepointerEnabled = fpe.Value.ReadScalar().(bool)

	return nil
}

func (init *runtimeInitializer) loadImportantTypes() error {
	logf("RuntimeLibrary: loading types")
	rt := init.rt

	loadFields := func(structName string, structType *Type, fields map[string]*StructField) error {
		s, ok := rt.Program.FindType(structName).(*StructType)
		if !ok {
			// TODO: Sometimes these structs are not in the DWARF, possibly if they're never
			// referenced by a runtime.itab?
			logf("WARNING: could not find struct %s", structName)
			return nil
		}
		if structType != nil {
			*structType = s
		}
		for fieldName, fptr := range fields {
			*fptr, ok = s.FieldByName(fieldName)
			if !ok {
				return fmt.Errorf("could not find field %s.%s", structName, fieldName)
			}
			verbosef("loaded %s.%s, type %s, offset %d", structName, fieldName, fptr.Type, fptr.Offset)
		}
		return nil
	}

	if err := loadFields("runtime.mspan", &rt.mspantypeType, map[string]*StructField{
		"startAddr": &rt.mspanStartAddrField,
		"npages":    &rt.mspanNpagesField,
		"freeindex": &rt.mspanFreeindexField,
		"nelems":    &rt.mspanNelemsField,
		"allocBits": &rt.mspanAllocBitsField,
		"state":     &rt.mspanStateField,
		"elemsize":  &rt.mspanElemsizeField,
		"limit":     &rt.mspanLimitField,
	}); err != nil {
		return err
	}

	if err := loadFields("runtime.itab", nil, map[string]*StructField{
		"_type": &rt.itabTypeField,
	}); err != nil {
		return err
	}

	if err := loadFields("runtime._type", &rt.typeType, map[string]*StructField{
		"size":  &rt.typeSizeField,
		"kind":  &rt.typeKindField,
		"tflag": &rt.typeTflagField,
		"str":   &rt.typeStrField,
	}); err != nil {
		return err
	}

	if err := loadFields("runtime.arraytype", &rt.arraytypeType, map[string]*StructField{
		"len":  &rt.arraytypeLenField,
		"elem": &rt.arraytypeElemField,
	}); err != nil {
		return err
	}

	if err := loadFields("runtime.ptrtype", &rt.ptrtypeType, map[string]*StructField{
		"elem": &rt.ptrtypeElemField,
	}); err != nil {
		return err
	}

	if err := loadFields("runtime.structtype", &rt.structtypeType, map[string]*StructField{
		"fields": &rt.structtypeFieldsField,
	}); err != nil {
		return err
	}

	if err := loadFields("runtime.structfield", &rt.structfieldType, map[string]*StructField{
		"name":   &rt.structfieldNameField,
		"typ":    &rt.structfieldTypeField,
		"offset": &rt.structfieldOffsetField,
	}); err != nil {
		return err
	}

	if err := loadFields("runtime.interfacetype", &rt.interfacetypeType, map[string]*StructField{}); err != nil {
		return err
	}

	if err := loadFields("runtime.slicetype", &rt.slicetypeType, map[string]*StructField{
		"elem": &rt.slicetypeElemField,
	}); err != nil {
		return err
	}

	if err := loadFields("runtime.chantype", &rt.chantypeType, map[string]*StructField{
		"dir":  &rt.chantypeDirField,
		"elem": &rt.chantypeElemField,
	}); err != nil {
		return err
	}

	if err := loadFields("runtime.maptype", &rt.maptypeType, map[string]*StructField{
		"key":  &rt.maptypeKeyField,
		"elem": &rt.maptypeElemField,
	}); err != nil {
		return err
	}

	if err := loadFields("runtime.uncommontype", &rt.uncommontypeType, map[string]*StructField{
		"pkgpath": &rt.uncommontypePkgPathField,
	}); err != nil {
		return err
	}

	// TODO: The above types don't always exist. Why not?
	// For now, hack around this by looking for package reflect.

	if rt.arraytypeType == nil {
		if err := loadFields("reflect.arrayType", &rt.arraytypeType, map[string]*StructField{
			"len":  &rt.arraytypeLenField,
			"elem": &rt.arraytypeElemField,
		}); err != nil {
			return err
		}
		if rt.arraytypeType == nil {
			// TODO: why is this not in the DWARF?
			// XXX: PtrSizes instead of hard-coded
			verbosef("WARNING: runtime.arraytype not found (creating instead)")
			p := rt.Program
			rt.arraytypeType = p.MakeStructType([]StructField{
				{Name: "typ", Offset: 0, Type: p.MakePtrType(rt.typeType)},
				{Name: "elem", Offset: 8, Type: p.MakePtrType(rt.typeType)},
				{Name: "slice", Offset: 16, Type: p.MakePtrType(rt.typeType)},
				{Name: "len", Offset: 24, Type: p.MakeNumericType(NumericUint64)},
			}, 0)
			rt.arraytypeLenField = rt.arraytypeType.(*StructType).Fields[3]
			rt.arraytypeElemField = rt.arraytypeType.(*StructType).Fields[1]
		}
	}

	if rt.ptrtypeType == nil {
		if err := loadFields("reflect.ptrType", &rt.ptrtypeType, map[string]*StructField{
			"elem": &rt.ptrtypeElemField,
		}); err != nil {
			return err
		}
	}

	if rt.structtypeType == nil {
		if err := loadFields("reflect.structType", &rt.structtypeType, map[string]*StructField{
			"fields": &rt.structtypeFieldsField,
		}); err != nil {
			return err
		}
	}

	if rt.structfieldType == nil {
		if err := loadFields("reflect.structField", &rt.structfieldType, map[string]*StructField{
			"name":   &rt.structfieldNameField,
			"typ":    &rt.structfieldTypeField,
			"offset": &rt.structfieldOffsetField,
		}); err != nil {
			return err
		}
	}

	if rt.interfacetypeType == nil {
		if err := loadFields("reflect.interfaceType", &rt.interfacetypeType, map[string]*StructField{}); err != nil {
			return err
		}
	}

	if rt.slicetypeType == nil {
		if err := loadFields("reflect.sliceType", &rt.slicetypeType, map[string]*StructField{
			"elem": &rt.slicetypeElemField,
		}); err != nil {
			return err
		}
	}

	if rt.chantypeType == nil {
		if err := loadFields("reflect.chanType", &rt.chantypeType, map[string]*StructField{
			"dir":  &rt.chantypeDirField,
			"elem": &rt.chantypeElemField,
		}); err != nil {
			return err
		}
	}

	if rt.maptypeType == nil {
		if err := loadFields("reflect.mapType", &rt.maptypeType, map[string]*StructField{
			"key":  &rt.maptypeKeyField,
			"elem": &rt.maptypeElemField,
		}); err != nil {
			return err
		}
	}

	if rt.uncommontypeType == nil {
		if err := loadFields("reflect.uncommonType", &rt.uncommontypeType, map[string]*StructField{
			"pkgpath": &rt.uncommontypePkgPathField,
		}); err != nil {
			return err
		}
	}

	loadStruct := func(structName string, structType **StructType) error {
		s, ok := rt.Program.FindType(structName).(*StructType)
		if !ok {
			return fmt.Errorf("could not find struct %s", structName)
		}
		*structType = s
		return nil
	}
	loadPtrToStruct := func(structName string, ptrType **PtrType) error {
		var st *StructType
		if err := loadStruct(structName, &st); err != nil {
			return err
		}
		*ptrType = rt.Program.MakePtrType(st)
		return nil
	}

	if err := loadStruct("runtime.slice", &rt.sliceRepType); err != nil {
		return err
	}
	if err := loadPtrToStruct("runtime.hchan", &rt.chanRepType); err != nil {
		return err
	}
	if err := loadPtrToStruct("runtime.hmap", &rt.mapRepType); err != nil {
		return err
	}
	if err := loadStruct("runtime._func", &rt.funcType); err != nil {
		return err
	}
	if err := loadStruct("runtime.findfuncbucketType", &rt.findfuncbucketType); err != nil {
		// TODO: why is this not in the DWARF?
		verbosef("WARNING: %v (creating instead)", err)
		p := rt.Program
		rt.findfuncbucketType = p.MakeStructType([]StructField{
			{Name: "idx", Offset: 0, Type: p.MakeNumericType(NumericUint32)},
			{Name: "subbuckets", Offset: 4, Type: p.MakeArrayType(p.MakeNumericType(NumericUint32), 16)},
		}, 0)
	}
	if err := loadPtrToStruct("runtime.stackmap", &rt.ptrToStackmapType); err != nil {
		return err
	}

	return nil
}

func (init *runtimeInitializer) loadModuleData() error {
	logf("RuntimeLibrary: loading moduledata")
	rt := init.rt

	mdvar, ok := rt.Vars.FindName("runtime.firstmoduledata")
	if !ok {
		return errors.New("could not find runtime.firstmoduledata")
	}
	md := mdvar.Value
	for {
		readSegment := func(startfield, endfield string) (dataSegment, error) {
			start, err := md.ReadUintFieldByName(startfield)
			if err != nil {
				return dataSegment{}, err
			}
			end, err := md.ReadUintFieldByName(endfield)
			if err != nil {
				return dataSegment{}, err
			}
			// TODO: We currently assume [start, end-start) does not span multiple
			// program data segments. This is might be an invalid assumption,
			// especially if global data was only partially dirtied. We should
			// instead return a list of dataSegments.
			verbosef("loading module segment %s [0x%x, 0x%x)", startfield, start, end)
			s, ok := rt.Program.dataSegments.slice(start, end-start)
			if !ok {
				return dataSegment{}, fmt.Errorf("module segment %s [0x%x, 0x%x) not found", startfield, start, end)
			}
			return s, nil
		}
		readBitvector := func(field string, seg dataSegment) (*gcBitvector, error) {
			bv, err := md.FieldByName(field) // runtime.bitvector
			if err != nil {
				return nil, err
			}
			nbits, err := bv.ReadUintFieldByName("n")
			if err != nil {
				return nil, err
			}
			bitsAddr, err := bv.ReadUintFieldByName("bytedata")
			if err != nil {
				return nil, err
			}
			verbosef("loading global bitvector %s with %d bits at 0x%x", field, nbits, bitsAddr)
			bits, ok := rt.Program.dataSegments.slice(bitsAddr, (nbits+7)/8)
			if !ok {
				return nil, fmt.Errorf("global bitvector %s at 0x%x not found", field, bitsAddr)
			}
			return newGCBitvector(rt.Program, seg, bits.data, nbits), nil
		}

		var err error
		moduledata := &runtimeModuleData{}
		moduledata.data, err = readSegment("data", "edata")
		if err != nil {
			return err
		}
		moduledata.bss, err = readSegment("bss", "ebss")
		if err != nil {
			return err
		}
		moduledata.noptrdata, err = readSegment("noptrdata", "enoptrdata")
		if err != nil {
			return err
		}
		moduledata.noptrbss, err = readSegment("noptrbss", "enoptrbss")
		if err != nil {
			return err
		}
		moduledata.types, err = readSegment("types", "etypes")
		if err != nil {
			return err
		}
		moduledata.gcdatabv, err = readBitvector("gcdatamask", moduledata.data)
		if err != nil {
			return err
		}
		moduledata.gcbssbv, err = readBitvector("gcbssmask", moduledata.bss)
		if err != nil {
			return err
		}
		moduledata.minpc, err = md.ReadUintFieldByName("minpc")
		if err != nil {
			return err
		}
		moduledata.maxpc, err = md.ReadUintFieldByName("maxpc")
		if err != nil {
			return err
		}
		moduledata.findfunctab, err = md.ReadUintFieldByName("findfunctab")
		if err != nil {
			return err
		}
		// Read pclntable as the actual []byte array.
		moduledata.pclntable, err = md.FieldByName("pclntable")
		if err != nil {
			return err
		}
		moduledata.pclntable, err = moduledata.pclntable.DerefArray()
		if err != nil {
			return err
		}
		// Convert ftab into a mirrored list for ease of use.
		ftabs, err := md.FieldByName("ftab")
		if err != nil {
			return err
		}
		ftabs, err = ftabs.DerefArray()
		if err != nil {
			return err
		}
		for k := uint64(0); k < ftabs.Type.(*ArrayType).Len; k++ {
			ftab, err := ftabs.Index(k)
			if err != nil {
				return err
			}
			var ft runtimeFunctab
			ft.entry, err = ftab.ReadUintFieldByName("entry")
			if err != nil {
				return err
			}
			ft.funcoff, err = ftab.ReadUintFieldByName("funcoff")
			if err != nil {
				return err
			}
			moduledata.ftab = append(moduledata.ftab, ft)
		}
		rt.moduledatas = append(rt.moduledatas, moduledata)

		// Next module.
		next, err := md.FieldByName("next")
		if err != nil {
			return err
		}
		if next.IsZero() {
			return nil
		}
		md, err = next.Deref()
		if err != nil {
			return err
		}
	}
}

func (init *runtimeInitializer) loadHeapInfo() error {
	logf("RuntimeLibrary: loading heap info")
	rt := init.rt

	mheap, ok := rt.Vars.FindName("runtime.mheap_")
	if !ok {
		return errors.New("could not find runtime.mheap_")
	}

	// mheapArena.
	arenaStart, err := mheap.Value.ReadUintFieldByName("arena_start")
	if err != nil {
		return err
	}
	arenaUsed, err := mheap.Value.ReadUintFieldByName("arena_used")
	if err != nil {
		return err
	}
	rt.mheapArena, ok = rt.Program.dataSegments.slice(arenaStart, arenaUsed-arenaStart)
	if !ok {
		return fmt.Errorf("failed to load heap arena start=0x%x used=0x%x", arenaStart, arenaUsed)
	}
	logf("loaded heap arena %s", rt.mheapArena)

	// mheapBitmap.
	bitmapTop, err := mheap.Value.ReadUintFieldByName("bitmap")
	if err != nil {
		return err
	}
	bitmapMapped, err := mheap.Value.ReadUintFieldByName("bitmap_mapped")
	if err != nil {
		return err
	}
	rt.mheapBitmap, ok = rt.Program.dataSegments.slice(bitmapTop-bitmapMapped, bitmapMapped)
	if !ok {
		return fmt.Errorf("failed to load heap bitmap top=0x%x mapped=0x%x", bitmapTop, bitmapMapped)
	}
	logf("loaded heap bitmap %s", rt.mheapBitmap)

	// mheapSpans.
	// cap(mheap.spans) potentially covers more memory than was actually
	// allocated by the process -- see comments at runtime.mheap.spans.
	// This means spans.DerefArray with fail with ErrOutOfBounds. Instead,
	// we do a manual version of DerefArray that uses len instead of cap.
	spans, err := mheap.Value.FieldByName("spans")
	if err != nil {
		return err
	}
	numSpans, err := spans.Len()
	if err != nil {
		return err
	}
	spansElemType := spans.Type.(*SliceType).Elem
	spans.Type = spans.Type.InternalRepresentation()
	spansAddr, err := spans.ReadUintField(spans.Type.(*StructType).Fields[sliceArrayField])
	if err != nil {
		return err
	}
	rt.mheapSpans, err = rt.Program.Value(spansAddr, rt.Program.MakeArrayType(spansElemType, numSpans))
	if err != nil {
		return err
	}
	logf("loaded heap spans with %d entries", numSpans)

	return nil
}

func (init *runtimeInitializer) loadThreads(threads []*OSThread) error {
	logf("RuntimeLibrary: loading threads")
	rt := init.rt

	// Mapping from kernel pid to m.
	pidToM := make(map[uint64]Value)
	allmv, ok := rt.Vars.FindName("runtime.allm")
	if !ok {
		return errors.New("could not find runtime.allm")
	}
	allm := allmv.Value
	for !allm.IsZero() {
		m, err := allm.Deref()
		if err != nil {
			return fmt.Errorf("deref(allm): %v", err)
		}
		procid, err := m.ReadUintFieldByName("procid")
		if err != nil {
			return err
		}
		pidToM[procid] = m
		verbosef("M at 0x%x has procid=%d", m.Addr, procid)
		// Next M.
		allm, err = m.FieldByName("alllink")
		if err != nil {
			return err
		}
	}

	// Assign M values to OSThreads.
	for _, thread := range threads {
		m, ok := pidToM[thread.PID]
		if !ok {
			continue
		}
		verbosef("found M for procid=%d at addr=0x%x", thread.PID, m.Addr)
		thread.M = m
		rt.Threads = append(rt.Threads, thread)
		init.mptrToThread[m.Addr] = thread
		delete(pidToM, thread.PID)
	}
	if len(pidToM) > 0 {
		// TODO: why is there an M with procid=0?
		// TODO: this probably can happen with cgo programs?
		for pid, m := range pidToM {
			logf("WARNING: M struct at addr=0x%x pid=%d not matched to OSThread", m.Addr, pid)
		}
	}

	return nil
}

const (
	gstatusIdle      = 0
	gstatusRunnable  = 1
	gstatusRunning   = 2
	gstatusSyscall   = 3
	gstatusWaiting   = 4
	gstatusDead      = 6
	gstatusCopystack = 8
	gstatusScanBit   = 0x1000
)

func (init *runtimeInitializer) loadGoroutines() error {
	logf("RuntimeLibrary: loading goroutines")
	rt := init.rt

	allgsv, ok := rt.Vars.FindName("runtime.allgs")
	if !ok {
		return errors.New("could not find runtime.allgs")
	}
	allgsLen, err := allgsv.Value.Len()
	if err != nil {
		return fmt.Errorf("allgs.Len: %v", err)
	}
	allgs, err := allgsv.Value.DerefArray()
	if err != nil {
		return fmt.Errorf("allgs.DerefArray: %v", err)
	}

	for k := uint64(0); k < allgsLen; k++ {
		verbosef("loading allgs[%d]", k)
		gptr, err := allgs.Index(k)
		if err != nil {
			return fmt.Errorf("allgs.Index(%d): %v", k, err)
		}
		if err := init.loadGoroutine(gptr); err != nil {
			return fmt.Errorf("loading allgs[%d]: %v", k, err)
		}
	}

	return nil
}

func (init *runtimeInitializer) loadGoroutine(gptr Value) error {
	g := &Goroutine{Program: init.rt.Program}

	var err error
	g.G, err = gptr.Deref()
	if err != nil {
		return fmt.Errorf("deref(&g): %v", err)
	}

	// Load fields of g.G.
	g.CreatorPC, err = g.G.ReadUintFieldByName("gopc")
	if err != nil {
		return err
	}
	status, err := g.G.ReadUintFieldByName("atomicstatus")
	if err != nil {
		return err
	}
	mptr, err := g.G.ReadUintFieldByName("m")
	if err != nil {
		return err
	}
	waitreason, err := g.G.FieldByName("waitreason")
	if err != nil {
		return err
	}
	waiting, err := g.G.FieldByName("waiting")
	if err != nil {
		return err
	}

	// Status info.
	g.StatusString = goroutineStatus(status, waitreason)
	for !waiting.IsZero() {
		sudog, err := waiting.Deref()
		if err != nil {
			return err
		}
		elem, err := sudog.ReadUintFieldByName("elem")
		if err != nil {
			return err
		}
		g.WaitingOn = append(g.WaitingOn, elem)
		waiting, err = sudog.FieldByName("waitlink")
		if err != nil {
			return err
		}
	}
	verbosef("goroutine G=0x%x CreatorPC=0x%x, StatusString=%q, WaitingOn=%v, M=0x%x", g.G.Addr, g.CreatorPC, g.StatusString, g.WaitingOn, mptr)

	// Link to the OSThread, if any.
	var thread *OSThread
	if mptr != 0 {
		thread = init.mptrToThread[mptr]
		if thread != nil {
			thread.attachGoroutine(g, gptr.ReadUint())
		}
	}

	// Get PC, SP, and LR of this goroutine.
	var pc, sp, lr uint64
	switch status &^ gstatusScanBit {
	case gstatusIdle, gstatusDead, gstatusCopystack:
		// G in these states are not used.
		// TODO: should gstatusCopystack be handled differently?
		return nil

	case gstatusRunning:
		// Read PC, SP, and LR from the OSThread.
		if thread == nil {
			return errors.New("running goroutine has no thread; cannot read registers")
		}
		pc, sp, lr = thread.readFrameRegs(init.rt.GOARCH)

	default:
		// TODO: use syscallpc and syscallsp instead for state gstatusSyscall?
		schedf, ok := g.G.Type.(*StructType).FieldByName("sched")
		if !ok {
			return fmt.Errorf("cannot find field sched in %s", g.G.Type)
		}
		sched, err := g.G.Field(schedf)
		if err != nil {
			return err
		}
		pc, err = sched.ReadUintFieldByName("pc")
		if err != nil {
			return err
		}
		sp, err = sched.ReadUintFieldByName("sp")
		if err != nil {
			return err
		}
		lr, err = sched.ReadUintFieldByName("lr")
		if err != nil {
			return err
		}
	}

	var oldest *StackFrame
	g.Stack, oldest, err = init.walkStack(g, pc, sp, lr)
	if err != nil {
		return fmt.Errorf("failed walking stack for goroutine at 0x%x: %v", g.G.Addr, err)
	}

	// Add to either Program.Goroutines or rt.Goroutines.
	if init.systemGoroutinePCs[oldest.Func.EntryPC] {
		init.rt.Goroutines = append(init.rt.Goroutines, g)
	} else {
		init.rt.Program.Goroutines = append(init.rt.Program.Goroutines, g)
	}
	return nil
}

func goroutineStatus(status uint64, waitreason Value) string {
	var str string

	switch status &^ gstatusScanBit {
	case gstatusIdle:
		str = "idle"
	case gstatusRunnable:
		str = "runnable"
	case gstatusRunning:
		str = "running"
	case gstatusSyscall:
		str = "syscall"
	case gstatusWaiting:
		str = "waiting"
		if wrstr, err := waitreason.DerefArray(); err == nil {
			str += " (" + string(wrstr.Bytes) + ")"
		}
	case gstatusDead:
		str = "dead"
	case gstatusCopystack:
		str = "copystack"
	default:
		str = "unknown"
	}

	if (status & gstatusScanBit) != 0 {
		str += " (stack being scanned by GC)"
	}

	return str
}

// walkStack builds StackFrames starting from the given PC, SP, and LR.
// Returns the youngest (top) frame and oldest (bottom) frame.
func (init *runtimeInitializer) walkStack(g *Goroutine, pc, sp, lr uint64) (*StackFrame, *StackFrame, error) {
	var top *StackFrame
	var bottom *StackFrame

	// Walk top-down.
	for {
		verbosef("lookupDWARFFrame(pc=0x%x, sp=0x%x, lr=0x%x)", pc, sp, lr)
		df, err := init.rt.Program.lookupDWARFFrame(pc, sp, lr)
		if err != nil {
			verbosef("lookupDWARFFrame failed: %v", err)
			return nil, nil, err
		}
		fp := df.callerSP
		if DebugLogf != nil {
			verbosef("lookupDWARFFrame returned frame in func %s:", df.funcInfo.Name)
			verbosef("  callerPC=0x%x", df.callerPC)
			verbosef("  callerSP=0x%x", df.callerSP)
			verbosef("  callerLR=0x%x", df.callerLR)
			if pcinfo, err := init.rt.Program.PCInfo(pc); err == nil {
				verbosef("  file=%s", pcinfo.File)
				verbosef("  line=%d", pcinfo.Line)
			}
		}
		f := &StackFrame{
			PC:        pc,
			Callee:    bottom,
			Goroutine: g,
			LocalVars: &VarSet{},
			Func:      df.funcInfo,
		}
		// f becomes the new bottom stack.
		if bottom != nil {
			bottom.Caller = f
		}
		if top == nil {
			top = f
		}
		bottom = f

		// Lookup GC bitmaps.
		fdesc, err := init.findFunc(pc)
		if err != nil {
			return nil, nil, err
		}
		verbosef("  fdesc at 0x%x", fdesc.Addr)
		f.argsBV, err = init.getFuncStackmap(fdesc, pc, sp, fp, funcStackMapArgs)
		if err != nil {
			return nil, nil, err
		}
		verbosef("  argsBV   %s", f.argsBV)
		f.localsBV, err = init.getFuncStackmap(fdesc, pc, sp, fp, funcStackMapLocals)
		if err != nil {
			return nil, nil, err
		}
		verbosef("  localsBV %s", f.localsBV)

		// Add args and locals, skipping those that are not live.
		addVars := func(kind string, dvs []dwarfVar, bv *gcBitvector) error {
			for _, dv := range dvs {
				ds, ok := init.rt.Program.dataSegments.slice(dv.addr, dv.vtype.Size())
				if !ok {
					return fmt.Errorf("error loading %s 0x%x in func %s: out-of-bounds", dv.name, dv.addr, df.funcInfo.Name)
				}
				if isLive, err := bv.isStackVarLive(dv.addr, dv.vtype); err != nil {
					return fmt.Errorf("error loading %s 0x%x in func %s: %v", dv.name, dv.addr, df.funcInfo.Name, err)
				} else if !isLive {
					verbosef("  dead %s 0x%x %s %s", kind, dv.addr, dv.name, dv.vtype)
					continue
				}
				verbosef("  live %s 0x%x %s %s", kind, dv.addr, dv.name, dv.vtype)
				err := f.LocalVars.insert(Var{
					Name:  dv.name,
					Frame: f,
					Value: Value{
						Addr:  dv.addr,
						Type:  dv.vtype,
						Bytes: ds.data,
					},
				})
				if err != nil {
					return err
				}
			}
			return nil
		}
		if err := addVars("arg", df.args, f.argsBV); err != nil {
			return nil, nil, err
		}
		if err := addVars("local", df.locals, f.localsBV); err != nil {
			return nil, nil, err
		}

		if init.bottomOfStackPCs[df.funcInfo.EntryPC] {
			verbosef("found bottom-of-stack")
			break
		}
		pc = df.callerPC
		sp = df.callerSP
		lr = df.callerLR
	}

	return top, bottom, nil
}

// See runtime/symtab.go:findmoduledatap.
func (init *runtimeInitializer) findModuleDataForPC(pc uint64) *runtimeModuleData {
	for _, md := range init.rt.moduledatas {
		if md.minpc <= pc && pc < md.maxpc {
			return md
		}
	}
	return nil
}

// See runtime/symtab.go:findfunc.
func (init *runtimeInitializer) findFunc(pc uint64) (Value, error) {
	md := init.findModuleDataForPC(pc)
	if md == nil {
		return Value{}, fmt.Errorf("could not find moduledata for pc 0x%x", pc)
	}

	const minfunc = 16
	const pcbucketsize = 256 * minfunc

	nsubField, ok := init.rt.findfuncbucketType.FieldByName("subbuckets")
	if !ok {
		return Value{}, errors.New("could not find field runtime.findfuncbucket.subbuckets")
	}
	nsub := nsubField.Type.(*ArrayType).Len

	x := pc - md.minpc
	b := x / pcbucketsize
	i := x % pcbucketsize / (pcbucketsize / nsub)

	ffb, err := init.rt.Program.Value(md.findfunctab+b*init.rt.findfuncbucketType.Size(), init.rt.findfuncbucketType)
	if err != nil {
		return Value{}, fmt.Errorf("error loading findfuncbucket for pc 0x%x at (0x%x + 0x%x*0x%x): %v",
			pc, md.findfunctab, b, init.rt.findfuncbucketType.Size(), err)
	}

	// idx := ffb.idx + uint32(ffb.subbuckets[i])
	ffbIdx, err := ffb.ReadUintFieldByName("idx")
	if err != nil {
		return Value{}, fmt.Errorf("error loading findfuncbucket for pc 0x%x at 0x%x: %v", pc, ffb.Addr, err)
	}
	ffbSubbuckets, err := ffb.FieldByName("subbuckets")
	if err != nil {
		return Value{}, err
	}
	ffbSubbucketsElem, err := ffbSubbuckets.Index(i)
	if err != nil {
		return Value{}, err
	}
	idx := ffbIdx + ffbSubbucketsElem.ReadUint()

	// Following conditions are verbatim copied from runtime/symtab.go:findfunc.
	if idx >= uint64(len(md.ftab)) {
		idx = uint64(len(md.ftab)) - 1
	}
	if pc < md.ftab[idx].entry {
		for md.ftab[idx].entry > pc && idx > 0 {
			idx--
		}
		if idx == 0 {
			return Value{}, fmt.Errorf("error loading findfuncbucket for pc 0x%x at 0x%x: bad findfunctab entry idx", pc, ffb.Addr)
		}
	} else {
		for md.ftab[idx+1].entry <= pc {
			idx++
		}
	}

	f, err := init.rt.Program.Value(md.pclntable.Addr+md.ftab[idx].funcoff, init.rt.funcType)
	if err != nil {
		return Value{}, fmt.Errorf("error loading func for pc 0x%x at (0x%x (sz=0x%x) + 0x%x): %v",
			pc, md.pclntable.Addr, md.pclntable.Type.(*ArrayType).Len, md.ftab[idx].funcoff, err)
	}
	return f, nil
}

type funcStackMapKind int

const (
	funcStackMapArgs   = 0 // see runtime._FUNCDATA_ArgsPointerMaps
	funcStackMapLocals = 1 //  see runtime._FUNCDATA_LocalsPointerMaps
)

func (init *runtimeInitializer) getFuncStackmap(fdesc Value, pc, sp, fp uint64, which funcStackMapKind) (*gcBitvector, error) {
	// See various places, such as runtime/mgcmark.go:scanframeworker.
	// This implements:
	//
	// pcdata := pcdatavalue(fdesc, which, pc, nil)
	// if pcdata == -1 {
	//   pcdata = 0
	// }
	// stkmap := (*stackmap)(funcdata(fdesc, which))
	// if stkmap == nil || stkmap.n <= 0 || stkmap.n <= pcdata {
	//   error
	// }
	// return stackmapdata(stkmap, pcdata)

	const _PCDATA_StackMapIndex = 0
	pcdata, err := init.pcDataValue(fdesc, _PCDATA_StackMapIndex, pc)
	if err != nil {
		return nil, err
	}
	if pcdata < 0 {
		pcdata = 0
	}

	// See runtime.funcdata.
	nfuncdata, err := fdesc.ReadUintFieldByName("nfuncdata")
	if err != nil {
		return nil, err
	}
	if uint64(which) >= nfuncdata {
		// TODO: I thought this shouldn't happen?
		verbosef("WARNING: function at pc 0x%x does not have stkmap %d?", pc, which)
		return gcEmptyBitvector, nil
	}
	// p := add(unsafe.Pointer(&f.nfuncdata), unsafe.Sizeof(f.nfuncdata)+uintptr(f.npcdata)*4)
	nfuncdataField, err := fdesc.FieldByName("nfuncdata")
	if err != nil {
		return nil, err
	}
	npcdata, err := fdesc.ReadUintFieldByName("npcdata")
	if err != nil {
		return nil, err
	}
	p := nfuncdataField.Addr + nfuncdataField.Type.Size() + npcdata*4
	if init.rt.Arch.PointerSize == 8 && p&4 != 0 {
		p += 4
	}
	stkmapPtrPtr := p + uint64(which)*uint64(init.rt.Arch.PointerSize)
	stkmapPtr, err := init.rt.Program.Value(stkmapPtrPtr, init.rt.ptrToStackmapType)
	if err != nil {
		return nil, fmt.Errorf("failed to get stkmapPtr at 0x%x: %v", stkmapPtrPtr, err)
	}
	stkmap, err := stkmapPtr.Deref()
	if err != nil {
		return nil, fmt.Errorf("failed to deref stkmapPtr 0x%x: %v", stkmapPtr.ReadUint(), err)
	}

	stkmapN, err := stkmap.ReadUintFieldByName("n")
	if err != nil {
		return nil, err
	}
	if stkmapN <= 0 || stkmapN <= uint64(pcdata) {
		return nil, fmt.Errorf("bad pcdata %d for stkmap with %d bitmaps", pcdata, stkmapN)
	}

	// See runtime.stackmapdata.
	stkmapNbit, err := stkmap.ReadUintFieldByName("nbit")
	if err != nil {
		return nil, err
	}
	stkmapBytedata, err := stkmap.FieldByName("bytedata")
	if err != nil {
		return nil, err
	}

	// Build a data segment that covers this stack region.
	var s dataSegment
	var ok bool

	switch which {
	case funcStackMapArgs:
		const _ArgsSizeUnknown = -0x80000000 // see runtime._ArgsSizeUnknown
		// See runtime/traceback.go.
		// The args section starts at fp + sys.MinFrameSize.
		segAddr := fp
		switch init.rt.GOARCH {
		case "386", "amd64":
			// sys.MinFrameSize == 0
		default:
			panic(fmt.Sprintf("unsupported GOARCH %q", init.rt.GOARCH))
		}
		segSize, err := fdesc.ReadUintFieldByName("args")
		if err != nil {
			return nil, err
		}
		if int32(segSize) == _ArgsSizeUnknown {
			// TODO: see runtime.getArgInfo for special cases
			verbosef("WARNING: function at pc 0x%x has unknown args size", pc)
			return gcEmptyBitvector, nil
		}
		var ok bool
		if s, ok = init.rt.Program.dataSegments.slice(segAddr, segSize); !ok {
			return nil, fmt.Errorf("could not build args segment at 0x%x, size=0x%x", segAddr, segSize)
		}

	case funcStackMapLocals:
		// See runtime/traceback.go.
		// The locals section is sp to fp, but does not include the pushed return PC or FP (if any).
		segEnd := fp
		switch init.rt.GOARCH {
		case "386":
			segEnd -= uint64(init.rt.Arch.PointerSize) // drop PC
		case "amd64":
			segEnd -= uint64(init.rt.Arch.PointerSize) // drop PC
			if segEnd > sp && init.framepointerEnabled {
				segEnd -= uint64(init.rt.Arch.PointerSize) // drop FP
			}
		default:
			panic(fmt.Sprintf("unsupported GOARCH %q", init.rt.GOARCH))
		}
		segAddr := segEnd - stkmapNbit*uint64(init.rt.Arch.PointerSize)
		segSize := segEnd - segAddr
		s, ok = init.rt.Program.dataSegments.slice(segAddr, segSize)
		if !ok {
			return nil, fmt.Errorf("could not build locals segment at 0x%x, size=0x%x", segAddr, segSize)
		}

	default:
		panic(fmt.Sprintf("unexpected which=%d", which))
	}

	bitsAddr := stkmapBytedata.Addr + uint64(pcdata)*((stkmapNbit+7)/8)
	bits, ok := init.rt.Program.dataSegments.slice(bitsAddr, (stkmapNbit+7)/8)
	if !ok {
		return nil, fmt.Errorf("error loading bitvector with %d bits at at 0x%x", bitsAddr, stkmapNbit)
	}
	return newGCBitvector(init.rt.Program, s, bits.data, stkmapNbit), nil
}

// See runtime/symtab.go:pcdatavalue.
func (init *runtimeInitializer) pcDataValue(fdesc Value, table uint64, pc uint64) (int32, error) {
	npcdata, err := fdesc.ReadUintFieldByName("npcdata")
	if err != nil {
		return -1, err
	}
	if table >= npcdata {
		return -1, nil
	}
	nfuncdataField, err := fdesc.FieldByName("nfuncdata")
	if err != nil {
		return -1, err
	}
	offPtr := nfuncdataField.Addr + nfuncdataField.Type.Size() + table*4
	off, err := init.rt.Program.Value(offPtr, init.rt.Program.MakePtrType(init.rt.Program.MakeNumericType(NumericInt32)))
	if err != nil {
		return -1, fmt.Errorf("failed to deref offPtr at 0x%x: %v", offPtr, err)
	}
	return init.pcValue(fdesc, off.ReadUint(), pc)
}

// See runtime/symtab.go:pcdata.
func (init *runtimeInitializer) pcValue(fdesc Value, off, targetpc uint64) (int32, error) {
	if off == 0 {
		return -1, nil
	}

	fentry, err := fdesc.ReadUintFieldByName("entry")
	if err != nil {
		return -1, err
	}
	md := init.findModuleDataForPC(fentry)
	if md == nil {
		return -1, fmt.Errorf("could not find moduledata for pc 0x%x (targetpc 0x%x)", fentry, targetpc)
	}

	// NB: In the runtime package, this is done by pcdatavalue's caller,
	// but it's easier to do here since we've already computed fentry.
	if targetpc != fentry {
		targetpc--
	}

	// See runtime/internal/sys.PCQuantum.
	var pcQuantum uint32
	switch init.rt.GOARCH {
	case "386", "amd64":
		pcQuantum = 1
	default:
		return -1, fmt.Errorf("unsupported GOARCH %q", init.rt.GOARCH)
	}

	// The following code is copied nearly verbatim from runtime/symtab.go:readvarint.
	// TODO: use encoding/binary instead.
	readvarint := func(p []byte) (newp []byte, val uint32) {
		var v, shift uint32
		for {
			b := p[0]
			p = p[1:]
			v |= (uint32(b) & 0x7F) << shift
			if b&0x80 == 0 {
				break
			}
			shift += 7
		}
		return p, v
	}
	// The following code is copied nearly verbatim from runtime/symtab.go:step.
	// step advances to the next pc, value pair in the encoded table.
	step := func(p []byte, pc *uint64, val *int32, first bool) (newp []byte, ok bool) {
		p, uvdelta := readvarint(p)
		if uvdelta == 0 && !first {
			return nil, false
		}
		if uvdelta&1 != 0 {
			uvdelta = ^(uvdelta >> 1)
		} else {
			uvdelta >>= 1
		}
		vdelta := int32(uvdelta)
		p, pcdelta := readvarint(p)
		*pc += uint64(pcdelta * pcQuantum)
		*val += vdelta
		return p, true
	}

	// The following code is copied nearly verbatim from runtime/symtab.go:pcdata.
	p := md.pclntable.Bytes[off:]
	pc := fentry
	val := int32(-1)
	for {
		var ok bool
		p, ok = step(p, &pc, &val, pc == fentry)
		if !ok {
			return -1, fmt.Errorf("pcDataValue(0x%x, %d, 0x%x) failed", fdesc.Addr, off, targetpc)
		}
		if targetpc < pc {
			return val, nil
		}
	}
}

func (t *OSThread) attachGoroutine(g *Goroutine, gptr uint64) {
	if g0, err := t.M.ReadUintFieldByName("g0"); err != nil {
		logf("error reading runtime.m.g0 in M at addr=0x%x", t.M.Addr)
	} else if g0 == gptr {
		t.G0 = g
		return
	}

	if gsignal, err := t.M.ReadUintFieldByName("gsignal"); err != nil {
		logf("error reading runtime.m.gsignal in M at addr=0x%x", t.M.Addr)
	} else if gsignal == gptr {
		t.GSignal = g
		return
	}

	if curg, err := t.M.ReadUintFieldByName("curg"); err != nil {
		logf("error reading runtime.m.curg in M at addr=0x%x", t.M.Addr)
	} else if curg == gptr {
		t.CurG = g
		return
	}

	logf("WARNING: goroutine's g (0x%x) not found in g.M (0x%x)", gptr, t.M.Addr)
}

func (t *OSThread) readFrameRegs(goarch string) (pc uint64, sp uint64, lr uint64) {
	switch goarch {
	case "386":
		return t.GPRegs["eip"], t.GPRegs["esp"], 0
	case "amd64":
		return t.GPRegs["rip"], t.GPRegs["rsp"], 0
	default:
		panic(fmt.Sprintf("unsupported GOARCH %q", goarch))
	}
}
