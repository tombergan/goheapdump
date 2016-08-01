package heapdump

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

var LogPrintf = func(string, ...interface{}) {}

const (
	tagEOF             = 0
	tagObject          = 1
	tagOtherRoot       = 2
	tagType            = 3
	tagGoroutine       = 4
	tagStackFrame      = 5
	tagParams          = 6
	tagFinalizer       = 7
	tagItab            = 8
	tagOSThread        = 9
	tagMemStats        = 10
	tagQueuedFinalizer = 11
	tagData            = 12
	tagBSS             = 13
	tagDefer           = 14
	tagPanic           = 15
	tagMemProf         = 16
	tagAllocSample     = 17
)

// ReadRaw reads a heapdump from the given file.
// The underlying file is held open by mmap and must be closed with RawDump.Close.
//
// The file can be open in read-only or read-write mode. In read-write mode, all
// []byte slices in RawDump can be written to and those updates will be reflected in
// the underlying file once the RawDump is closed. This allows mutation of the heap.
// In read-only mode, those []byte slices cannot be written to -- any attempt to do
// so will segfault.
//
// ReadRaw can understand heapdumps written by any architecure, including archicetures
// with different pointer sizes or endianness than the current architecture. However,
// Read will crash if the heapdump cannot fit into available virtual memory. This is
// especially possible when a 64bit heapdump is opened on a 32bit machine.
func ReadRaw(dumpname string, writable bool) (*RawDump, error) {
	fmap, err := mmapOpen(dumpname, writable)
	if err != nil {
		return nil, err
	}
	r := &RawDump{fmap: fmap}
	if err := readRaw(r); err != nil {
		r.Close()
		return nil, err
	}
	return r, nil
}

func readRaw(r *RawDump) error {
	const (
		version17            = "go1.7 heap dump\n"
		maxVersionHeaderSize = 32 // large enough for any known version header
	)

	// Check the version header.
	hdr := make([]byte, maxVersionHeaderSize)
	if _, err := r.fmap.Read(hdr); err != nil {
		return fmt.Errorf("failed reading heapdump header: %v", err)
	}
	if !strings.HasPrefix(string(hdr), version17) {
		return errors.New("not a supported heapdump file")
	}
	r.fmap.SeekTo(uint64(len(version17)))

	// Alloc maps.
	r.TypeFromItab = map[uint64]uint64{}
	r.TypeFromAddr = map[uint64]*RawType{}
	r.MemProfMap = map[uint64]*RawMemProfEntry{}

	// Interleaving error handling in the main for loop is very annoying.
	// Instead, we store errors here and check them once per loop iteration.
	var (
		recordOffset uint64 // file position of the current record
		recordErr    error  // error handling the current record, if any
	)

	// Parsing helpers: each helper advances the file position.
	readUint64 := func() uint64 {
		x, err := binary.ReadUvarint(r.fmap)
		if err != nil {
			recordErr = err
		}
		return x
	}
	readBool := func() bool {
		b, err := r.fmap.ReadByte()
		if err != nil {
			recordErr = err
		}
		return b != 0
	}
	readBytes := func() []byte {
		n := readUint64()
		b, err := r.fmap.ReadSlice(n)
		if err != nil {
			recordErr = err
		}
		return b
	}
	readFieldList := func() RawPtrFields {
		start := r.fmap.Pos()
		for count := 0; ; count++ {
			k := readUint64()
			switch k {
			case 0: // end
				end := r.fmap.Pos()
				if count == 0 {
					return RawPtrFields{}
				}
				encoded, err := r.fmap.ReadSliceAt(start, end-start)
				if err != nil {
					recordErr = err
				}
				return RawPtrFields{
					encoded:  encoded,
					startOff: 0,
					endOff:   end - start,
				}
			case 1: // ptr
				readUint64() // read offset
			default:
				recordErr = fmt.Errorf("unexpected FieldKind %d", k)
			}
		}
	}
	readRawSegment := func() RawSegment {
		x := RawSegment{}
		x.Addr = readUint64()
		x.Data = readBytes()
		x.PtrFields = readFieldList()
		return x
	}

	// Scan through all records, stopping on error.
	for {
		if recordErr != nil {
			return fmt.Errorf("error parsing record at offset %d: %v", recordOffset, recordErr)
		}

		recordOffset = r.fmap.Pos()
		LogPrintf("file offset %d", recordOffset)

		switch kind := readUint64(); kind {
		case tagEOF:
			LogPrintf("read EOF")
			return nil

		case tagObject:
			x := readRawSegment()
			LogPrintf("read object{Addr:%x Size:%d Offsets%v}", x.Addr, len(x.Data), x.PtrFields.Offsets())
			r.HeapObjects = append(r.HeapObjects, x)

		case tagOtherRoot:
			x := &RawOtherRoot{}
			x.Description = string(readBytes())
			x.Addr = readUint64()
			LogPrintf("read %#v", *x)
			r.OtherRoots = append(r.OtherRoots, x)

		case tagType:
			x := &RawType{}
			x.Addr = readUint64()
			x.Size = readUint64()
			x.Name = string(readBytes())
			x.DirectIFace = readBool()
			LogPrintf("read %#v", *x)
			// NB: there may be duplicate type records in a dump.
			// They are thrown away.
			if _, ok := r.TypeFromAddr[x.Addr]; !ok {
				r.TypeFromAddr[x.Addr] = x
			}

		case tagGoroutine:
			x := &RawGoroutine{}
			x.GAddr = readUint64()
			x.SP = readUint64()
			x.GoID = readUint64()
			x.GoPC = readUint64()
			x.Status = readUint64()
			x.IsSystem = readBool()
			x.IsBackground = readBool()
			x.WaitSince = readUint64()
			x.WaitReason = string(readBytes())
			x.CtxtAddr = readUint64()
			x.MAddr = readUint64()
			x.TopDeferAddr = readUint64()
			x.TopPanicAddr = readUint64()
			LogPrintf("read %#v", *x)
			r.Goroutines = append(r.Goroutines, x)

		case tagStackFrame:
			x := &RawStackFrame{}
			x.Segment.Addr = readUint64()
			x.Depth = readUint64()
			x.CalleeSP = readUint64()
			x.Segment.Data = readBytes()
			x.EntryPC = readUint64()
			x.PC = readUint64()
			x.NextPC = readUint64()
			x.Name = string(readBytes())
			x.Segment.PtrFields = readFieldList()
			LogPrintf("read StackFrame %x Size:%d Depth:%d Name:%s CalleeSP:%x PC:%x EntryPC:%x NextPC:%x fields %v",
				x.Segment.Addr, len(x.Segment.Data), x.Depth, x.Name, x.CalleeSP, x.PC, x.EntryPC, x.NextPC, x.Segment.PtrFields.Offsets())
			r.StackFrames = append(r.StackFrames, x)

		case tagParams:
			if r.Params != nil {
				return fmt.Errorf("multiple params records, old:{%#v}", *r.Params)
			}
			r.Params = &RawParams{}
			if readUint64() == 0 {
				r.Params.ByteOrder = binary.LittleEndian
			} else {
				r.Params.ByteOrder = binary.BigEndian
			}
			r.Params.PtrSize = readUint64()
			r.Params.HeapStart = readUint64()
			r.Params.HeapEnd = readUint64()
			r.Params.GoArch = string(readBytes())
			r.Params.GoExperiment = string(readBytes())
			r.Params.NCPU = readUint64()
			LogPrintf("read %#v", *r.Params)

		case tagFinalizer, tagQueuedFinalizer:
			x := &RawFinalizer{}
			x.IsQueued = (kind == tagQueuedFinalizer)
			x.ObjAddr = readUint64()
			x.FnAddr = readUint64()
			x.FnPC = readUint64()
			x.FnArgTypeAddr = readUint64()
			x.ObjTypeAddr = readUint64()
			LogPrintf("read %#v", *x)
			r.Finalizers = append(r.Finalizers, x)

		case tagData, tagBSS:
			x := readRawSegment()
			LogPrintf("read globalSegment{Tag:%d, Addr:%x Size:%d NumOffsets:%d}", kind, x.Addr, len(x.Data), len(x.PtrFields.Offsets()))
			r.GlobalSegments = append(r.GlobalSegments, x)

		case tagItab:
			addr := readUint64()
			typaddr := readUint64()
			LogPrintf("read Itab %x -> %x", addr, typaddr)
			r.TypeFromItab[addr] = typaddr

		case tagOSThread:
			x := &RawOSThread{}
			x.MAddr = readUint64()
			x.GoID = readUint64()
			x.ProcID = readUint64()
			LogPrintf("read %#v", *x)
			r.OSThreads = append(r.OSThreads, x)

		case tagMemStats:
			if r.MemStats != nil {
				return fmt.Errorf("multiple MemStats records, old:%#v", *r.MemStats)
			}
			r.MemStats = &runtime.MemStats{}
			r.MemStats.Alloc = readUint64()
			r.MemStats.TotalAlloc = readUint64()
			r.MemStats.Sys = readUint64()
			r.MemStats.Lookups = readUint64()
			r.MemStats.Mallocs = readUint64()
			r.MemStats.Frees = readUint64()
			r.MemStats.HeapAlloc = readUint64()
			r.MemStats.HeapSys = readUint64()
			r.MemStats.HeapIdle = readUint64()
			r.MemStats.HeapInuse = readUint64()
			r.MemStats.HeapReleased = readUint64()
			r.MemStats.HeapObjects = readUint64()
			r.MemStats.StackInuse = readUint64()
			r.MemStats.StackSys = readUint64()
			r.MemStats.MSpanInuse = readUint64()
			r.MemStats.MSpanSys = readUint64()
			r.MemStats.MCacheInuse = readUint64()
			r.MemStats.MCacheSys = readUint64()
			r.MemStats.BuckHashSys = readUint64()
			r.MemStats.GCSys = readUint64()
			r.MemStats.OtherSys = readUint64()
			r.MemStats.NextGC = readUint64()
			r.MemStats.LastGC = readUint64()
			r.MemStats.PauseTotalNs = readUint64()
			for i := 0; i < 256; i++ {
				r.MemStats.PauseNs[i] = readUint64()
			}
			r.MemStats.NumGC = uint32(readUint64())
			LogPrintf("read %#v", *r.MemStats)

		case tagDefer:
			x := &RawDefer{}
			x.Addr = readUint64()
			x.GAddr = readUint64()
			x.ArgP = readUint64()
			x.PC = readUint64()
			x.FnAddr = readUint64()
			x.FnPC = readUint64()
			x.LinkAddr = readUint64()
			LogPrintf("read %#v", *x)
			r.Defers = append(r.Defers, x)

		case tagPanic:
			x := &RawPanic{}
			x.Addr = readUint64()
			x.GAddr = readUint64()
			x.ArgTypeAddr = readUint64()
			x.ArgAddr = readUint64()
			x.DeferAddr = readUint64()
			x.LinkAddr = readUint64()
			LogPrintf("read %#v", *x)
			r.Panics = append(r.Panics, x)

		case tagMemProf:
			x := &RawMemProfEntry{}
			key := readUint64()
			x.Size = readUint64()
			nstk := readUint64()
			for i := uint64(0); i < nstk; i++ {
				fn := readBytes()
				file := readBytes()
				line := readUint64()
				x.Stacks = append(x.Stacks, RawMemProfFrame{fn, file, line})
			}
			x.NumAllocs = readUint64()
			x.NumFrees = readUint64()
			LogPrintf("read id:%x -> %#v", key, *x)
			r.MemProfMap[key] = x

		case tagAllocSample:
			x := &RawAllocSample{}
			x.Addr = readUint64()
			x.Prof = r.MemProfMap[readUint64()]
			LogPrintf("read AllocSample %#v", *x)
			r.AllocSamples = append(r.AllocSamples, x)

		default:
			return fmt.Errorf("unknown record kind %v", kind)
		}
	}

	// Final sorting.
	sort.Sort(sortSegByAddr(r.HeapObjects))
	return nil
}

type sortSegByAddr []RawSegment

func (a sortSegByAddr) Len() int           { return len(a) }
func (a sortSegByAddr) Swap(i, k int)      { a[i], a[k] = a[k], a[i] }
func (a sortSegByAddr) Less(i, k int) bool { return a[i].Addr < a[k].Addr }

type sortUint64 []uint64

func (a sortUint64) Len() int           { return len(a) }
func (a sortUint64) Swap(i, k int)      { a[i], a[k] = a[k], a[i] }
func (a sortUint64) Less(i, k int) bool { return a[i] < a[k] }

// Read reads a heapdump from the file named by dumpname. It also reads type information
// from the executable file named by execname. execname is optional, but if specified, it
// must name the program that generated the heapdump. If execname is not specified, all
// objects will have unknown type.
//
// See ReadRaw for the meaning of writable and for notes about loading cross-platform
// heapdumps. Currently only ELF executables are supported.
//
// Dump.Close should be called to free internal file handles when the dump is no longer needed.
func Read(dumpname, execname string, writable bool) (d *Dump, err error) {
	raw, err := ReadRaw(dumpname, writable)
	if err != nil {
		return nil, err
	}

	// Need to close raw if we fail after this point.
	defer func() {
		if err != nil {
			raw.Close()
		}
	}()

	// Sanity check: must have params otherwise we don't know which endianness to use.
	if raw.Params == nil {
		return nil, errors.New("heapdump is missing params")
	}

	// All wrappers except Types, RootVars, and Values.
	d = &Dump{
		Raw:          raw,
		typeFromAddr: make(map[uint64]Type),
	}
	d.tc = makeTypeCache(d)
	if err := makeSimpleWrapperStructs(d); err != nil {
		return nil, err
	}

	// Load Types, RootVars, and Values.
	// If an executable image is given, use symbols and types from that image.
	// Otherwise, create default names and types.
	if execname != "" {
		if err := loadTypes(d, execname); err != nil {
			return nil, err
		}
	} else {
		if err := makeDefaultTypes(d); err != nil {
			return nil, err
		}
	}

	// Final linking after we have types.
	if err := linkValuesAndTypes(d); err != nil {
		return nil, err
	}

	return d, nil
}

// makeSimpleWrapperStructs constructs wrapper structs for d except for Types, Values, and RootVars.
func makeSimpleWrapperStructs(d *Dump) error {
	osthreads := make(map[uint64]*OSThread)
	goroutines := make(map[uint64]*Goroutine)

	for _, r := range d.Raw.OSThreads {
		x := &OSThread{Raw: r}
		osthreads[r.MAddr] = x
		d.OSThreads = append(d.OSThreads, x)
	}
	for _, r := range d.Raw.Goroutines {
		x := &Goroutine{Raw: r}
		goroutines[r.GAddr] = x
		d.Goroutines = append(d.Goroutines, x)
	}
	for _, r := range d.Raw.Finalizers {
		x := &Finalizer{Raw: r}
		d.Finalizers = append(d.Finalizers, x)
	}

	// OSThread <-> Goroutines.
	for _, g := range d.Goroutines {
		if t, ok := osthreads[g.Raw.MAddr]; ok {
			g.OSThread = t
			t.Goroutines = append(t.Goroutines, g)
		}
	}

	// Globals.
	d.GlobalVars.init()

	// Stack frames may be zero-sized, so we add call depth to the key to ensure uniqueness.
	type frameKey struct {
		sp, depth uint64
	}
	frames := make(map[frameKey]*StackFrame)
	for _, r := range d.Raw.StackFrames {
		x := &StackFrame{Raw: r}
		x.LocalVars.init()
		frames[frameKey{r.Segment.Addr, r.Depth}] = x
	}
	// StackFrame <-> StackFrame.
	for _, sf := range frames {
		if sf.Raw.Depth == 0 {
			continue
		}
		callee, ok := frames[frameKey{sf.Raw.CalleeSP, sf.Raw.Depth - 1}]
		if !ok {
			return fmt.Errorf("callee not found for %#v", *sf.Raw)
		}
		sf.Callee = callee
		callee.Caller = sf
	}

	// Goroutine <-> StackFrames.
	for _, g := range d.Goroutines {
		sf, ok := frames[frameKey{g.Raw.SP, 0}]
		if !ok {
			return fmt.Errorf("couldn't find youngest stack for %#v", *g)
		}
		g.Stack = sf
		for ; sf != nil; sf = sf.Caller {
			sf.Goroutine = g
		}
	}

	return nil
}

// makeDefaultTypes constructs dummy Types and RootVars for all objects in the dump.
// Used when an executable image is not provided.
func makeDefaultTypes(d *Dump) error {
	for k := range d.Raw.GlobalSegments {
		d.GlobalVars.add(defaultRootVarForSegment(d, &d.Raw.GlobalSegments[k], RootVarGlobal))
	}
	d.GlobalVars.sort()

	for _, g := range d.Goroutines {
		for sf := g.Stack; sf != nil; sf = sf.Caller {
			sf.LocalVars.add(defaultRootVarForSegment(d, &sf.Raw.Segment, RootVarLocal))
		}
	}

	d.HeapObjects = make([]Value, len(d.Raw.HeapObjects))
	for k := range d.Raw.HeapObjects {
		seg := &d.Raw.HeapObjects[k]
		d.HeapObjects[k] = Value{Type: defaultTypeForSegment(d, seg), seg: seg}
	}

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

// defaultRootVarForAddr builds RootVar of PtrType(UnknownType) with the given ptr value.
func defaultRootVarForAddr(d *Dump, addr uint64, name string, kind RootVarKind) *RootVar {
	data := make([]byte, d.Raw.Params.PtrSize)
	d.Raw.Params.WritePtr(data, addr)

	// Make a RawSegment containing data, which has a single ptr at offset 0.
	pf := &d.singlePtrField
	if pf.encoded == nil {
		pf.encoded = []byte{1 /*ptr*/, 0 /*offset*/, 0 /*end*/}
		pf.startOff = 0
		pf.endOff = d.Raw.Params.PtrSize
	}
	seg := &RawSegment{
		Addr:      0, // unknown
		Data:      data,
		PtrFields: *pf,
	}

	return &RootVar{
		Kind: kind,
		Name: name,
		Value: &Value{
			Type: d.tc.makePtrToUnknownType(),
			seg:  seg,
		},
	}
}

// defaultRootVarForSegment builds RootVar with UnknownType for the given segment.
func defaultRootVarForSegment(d *Dump, seg *RawSegment, kind RootVarKind) *RootVar {
	return &RootVar{
		Kind: kind,
		Name: fmt.Sprintf("$%s_%x", strings.ToLower(string(kind)), seg.Addr),
		Value: &Value{
			Type: defaultTypeForSegment(d, seg),
			seg:  seg,
		},
	}
}

// defaultTypeForSegment builds an UnknownType for the given segment.
func defaultTypeForSegment(d *Dump, seg *RawSegment) Type {
	sz := uint64(len(seg.Data))
	ptrsz := d.Raw.Params.PtrSize

	// 'S' means scalar field, 'P' means ptr field
	var name []byte
	if sz%ptrsz == 0 {
		name = bytes.Repeat([]byte("S"), int(sz/ptrsz))
	} else {
		name = bytes.Repeat([]byte("S"), int(sz/ptrsz+1))
	}
	for _, k := range seg.PtrFields.Offsets() {
		name[k/ptrsz] = 'P'
	}

	// NB: Technically, seg may not be perfectly aligned to PtrSize. To account
	// for this possibility, we prefix the S/P string with the alignment and size.
	return d.tc.makeUnknownType(fmt.Sprintf("$unknown{Align:%d,Size:%d,Fields:%s}", seg.Addr%ptrsz, len(seg.Data), string(name)))
}

// linkValuesAndTypes links wrapper structs to Values and Types.
func linkValuesAndTypes(d *Dump) error {
	findPreciseObject := func(addr uint64, name string) (*Value, error) {
		v := d.FindObject(addr)
		if v == nil {
			return nil, fmt.Errorf("%s %x out-of-bounds", name, addr)
		}
		if v.Addr() != addr {
			return nil, nil
		}
		return v, nil
	}

	var err error

	// NB: The initial goroutine and thread (runtime.g0 and runtime.m0) are declared
	// in global data. If we don't have types, we can't get a precise pointer to those
	// values. We save M and G only when we have precise pointers.
	for _, t := range d.OSThreads {
		t.M, err = findPreciseObject(t.Raw.MAddr, "MAddr")
		if err != nil {
			return err
		}
	}

	for _, g := range d.Goroutines {
		g.G, err = findPreciseObject(g.Raw.GAddr, "GAddr")
		if err != nil {
			return err
		}
	}

	return nil
}

// TODO: Sanity check Values after loading?
//  - for all RawSegments, all PtrFields.Offsets should be within len(seg.Data)
//  - for all values:
//     - check that v.Size() == v.Type.Size() except when v.Type is UnknownType
//     - lookup the seg from v.addr, then if found, check that ptrs in the
//       seg match offsets in the type
//     - note: this is being checked by typePropagator.validateType
