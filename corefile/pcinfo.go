package corefile

import (
	"errors"
	"fmt"

	"golang.org/x/debug/dwarf"
)

// PCInfo gives information about a program counter.
type PCInfo struct {
	PC   uint64    // program counter value
	File string    // path to the file containing the line that compiled to PC
	Line uint64    // line number in File that compiled to PC
	Func *FuncInfo // function that contains PC
}

// FuncInfo gives information about a function.
type FuncInfo struct {
	Name    string
	EntryPC uint64
}

// PCInfo returns information about the given program counter.
func (p *Program) PCInfo(pc uint64) (*PCInfo, error) {
	var dwarfFilename string
	var d *dwarf.Data

	info := &PCInfo{PC: pc}
	for fname, dd := range p.dwarfs {
		var err error
		info.File, info.Line, err = dd.PCToLine(pc)
		if err == nil {
			dwarfFilename = fname
			d = dd
			break
		}
	}
	if d == nil {
		return nil, fmt.Errorf("could not find DWARF information about PC 0x%x", pc)
	}

	e, fentryPC, err := d.PCToFunction(pc)
	if err != nil {
		return nil, fmt.Errorf("PC 0x%x not contained in a function? in DWARF from %s", pc, dwarfFilename)
	}
	fname, _ := e.Val(dwarf.AttrName).(string)
	info.Func = &FuncInfo{
		Name:    fname,
		EntryPC: fentryPC,
	}

	return info, nil
}

// dwarfFrame summarizes a stack frame extracted from DWARF info.
type dwarfFrame struct {
	callerPC uint64
	callerSP uint64
	callerLR uint64
	funcInfo *FuncInfo
	args     []dwarfVar
	locals   []dwarfVar
}

type dwarfVar struct {
	name  string
	addr  uint64
	vtype Type
}

// lookupDWARFFrame returns information about the stack frame at the given
// program counter, stack pointer, and link register (for architectures that
// support a link register).
func (p *Program) lookupDWARFFrame(pc, sp, lr uint64) (*dwarfFrame, error) {
	var (
		dwarfFilename string
		d             *dwarf.Data
		fpOffset      int64
	)

	// Find the DWARF that contains PC.
	for fname, dd := range p.dwarfs {
		var err error
		fpOffset, err = dd.PCToSPOffset(pc)
		if err == nil {
			dwarfFilename = fname
			d = dd
			break
		}
	}
	if d == nil {
		return nil, fmt.Errorf("could not find DWARF information about PC 0x%x", pc)
	}

	// TODO: most of the following should be implemented internally by the dwarf package
	fp := sp + uint64(fpOffset)
	funcDEntry, fentryPC, err := d.PCToFunction(pc)
	if err != nil {
		return nil, fmt.Errorf("PC 0x%x not contained in a function? in DWARF from %s", pc, dwarfFilename)
	}
	fname, _ := funcDEntry.Val(dwarf.AttrName).(string)
	dframe := &dwarfFrame{
		funcInfo: &FuncInfo{
			Name:    fname,
			EntryPC: fentryPC,
		},
	}

	reportError := func(format string, args ...interface{}) error {
		return fmt.Errorf(fmt.Sprintf("in func %s (DWARF offset 0x%x), ", fname, funcDEntry.Offset)+format, args...)
	}

	// Load function args and local variables.
	r := d.Reader()
	r.Seek(funcDEntry.Offset)
	if e, err := r.Next(); err != nil {
		return nil, reportError("failed reading DWARF: %v", err)
	} else if e.Tag != dwarf.TagSubprogram {
		return nil, reportError("expected Subprogram, got : %v", *e)
	}
	for {
		e, err := r.Next()
		if err != nil {
			return nil, err
		}
		if e.Tag == 0 {
			break // done with this function definition
		}
		if e.Tag != dwarf.TagFormalParameter && e.Tag != dwarf.TagVariable {
			r.SkipChildren()
			continue
		}
		name, _ := e.Val(dwarf.AttrName).(string)
		dt, err := d.EntryType(e)
		if err != nil {
			return nil, reportError("no type for variable %s: %v", name, err)
		}
		t := p.typeCache.findDWARF(dt)
		if t == nil {
			return nil, reportError("unknown DWARF type %s for variable %s", fname, dt, name)
		}
		addr, err := dwarfEntryLocation(e, fp)
		if err != nil {
			return nil, reportError("bad location for variable %s: %v", name, err)
		}
		dv := dwarfVar{name, addr, t}
		switch e.Tag {
		case dwarf.TagFormalParameter:
			dframe.args = append(dframe.args, dv)
		case dwarf.TagVariable:
			dframe.locals = append(dframe.locals, dv)
		}
	}

	// Unwind to the caller's frame.
	// TODO: better handling for the oldest stack frame?
	// TODO: use LR for architectures that support it
	a := p.RuntimeLibrary.Arch
	ds, ok := p.dataSegments.slice(fp-uint64(a.PointerSize), uint64(a.PointerSize))
	if !ok {
		return nil, reportError("couldn't read return address from stack at 0x%x", fp-uint64(a.PointerSize))
	}
	dframe.callerPC = a.Uint64(ds.data)
	dframe.callerSP = fp
	return dframe, nil
}

// TODO: The following should be implemented in dwarf.EntryLocation().
// It was copied from golang.org/x/debug/server/dwarf.go:evalLocation.
func dwarfEntryLocation(e *dwarf.Entry, fp uint64) (uint64, error) {
	const (
		dwarfOpConsts       = 0x11
		dwarfOpPlus         = 0x22
		dwarfOpCallFrameCFA = 0x9C
	)
	v, ok := e.Val(dwarf.AttrLocation).([]uint8)
	if !ok || len(v) == 0 {
		return 0, errors.New("empty location attribute")
	}
	if v[0] != dwarfOpCallFrameCFA {
		return 0, errors.New("unsupported location specifier")
	}
	if len(v) == 1 {
		// The location description was just DW_OP_call_frame_cfa, so the location is exactly the CFA.
		return fp, nil
	}
	if v[1] != dwarfOpConsts {
		return 0, errors.New("unsupported location specifier")
	}
	offset, v, err := sleb128(v[2:])
	if err != nil {
		return 0, err
	}
	if len(v) == 1 && v[0] == dwarfOpPlus {
		// The location description was DW_OP_call_frame_cfa, DW_OP_consts <offset>, DW_OP_plus.
		return fp + uint64(offset), nil
	}
	return 0, errors.New("unsupported location specifier")
}

// TODO: The following should be implemented in dwarf.EntryLocation().
// It was copied from golang.org/x/debug/server/dwarf.go:sleb128.
func sleb128(v []uint8) (s int64, rest []uint8, err error) {
	var shift uint
	var sign int64 = -1
	var i int
	var x uint8
	for i, x = range v {
		s |= (int64(x) & 0x7F) << shift
		shift += 7
		sign <<= 7
		if x&0x80 == 0 {
			if x&0x40 != 0 {
				s |= sign
			}
			break
		}
	}
	if i == len(v) {
		return 0, nil, errors.New("truncated sleb128")
	}
	return s, v[i+1:], nil
}
