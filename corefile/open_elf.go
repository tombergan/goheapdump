package corefile

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"reflect"
	"sort"
	"strings"

	"golang.org/x/debug/arch"
	"golang.org/x/debug/elf"
)

func readELFCore(mmapf *mmapFile, rp *rawProgram, writable bool) error {
	f, err := elf.NewFile(mmapf)
	if err != nil {
		return err
	}
	if err := readELF(mmapf, f, rp, writable, true); err != nil {
		return err
	}
	if err := readELFCoreNotes(f, rp); err != nil {
		return err
	}
	return nil
}

func readELFExec(mmapf *mmapFile, rp *rawProgram) error {
	f, err := elf.NewFile(mmapf)
	if err != nil {
		return err
	}
	return readELF(mmapf, f, rp, false, false)
}

func readELF(mmapf *mmapFile, f *elf.File, rp *rawProgram, writable, isCoreFile bool) error {
	var goarch string
	switch f.Machine {
	case elf.EM_386:
		switch f.Class {
		case elf.ELFCLASS32:
			goarch = "386"
		case elf.ELFCLASS64:
			goarch = "amd64"
		}
	case elf.EM_X86_64:
		goarch = "amd64"
	default:
		// TODO: support elf.EM_ARM ("arm"), elf.EM_PPC64 ("ppc64"), and EM_S390 ("s390x")
		return fmt.Errorf("unsupported ELF machine type %s", f.Machine)
	}

	var goos string
	switch f.OSABI {
	case elf.ELFOSABI_LINUX, elf.ELFOSABI_NONE:
		// TODO: why do linux core ELFs use "UNIX System V" instead of "Linux"?
		goos = "linux"
	default:
		// TODO: support BSDs
		return fmt.Errorf("unsupported ELF OS type %s", f.OSABI)
	}

	verbosef("ReadELF: GOARCH=%s GOOS=%s", goarch, goos)

	// Core files determine goarch and goos.
	// Exec files must match.
	if isCoreFile {
		rp.goarch = goarch
		rp.goos = goos
	} else {
		if rp.goarch != goarch {
			return fmt.Errorf("mismatched machine types: core is %s, executable is %s", rp.goarch, goarch)
		}
		if rp.goos != goos {
			return fmt.Errorf("mismatched OS types: core is %s, executable is %s", rp.goos, goos)
		}
	}

	// Sort loadable memory segments by target virtual address.
	// They seem to be sorted in linux core dumps, but that's not guaranteed.
	var progs elfSortedProgHeaders
	for _, ph := range f.Progs {
		verbosef("ReadELF: %#v", ph.ProgHeader)
		if ph.Type != elf.PT_LOAD || ph.Memsz == 0 {
			continue
		}
		if ph.Memsz < ph.Filesz {
			return fmt.Errorf("ReadELF: unexpected Memsz < Filesz at %#v", ph.ProgHeader)
		}
		progs = append(progs, ph.ProgHeader)
	}
	sort.Sort(progs)

	// Merge adjacent segments that have the same R/W mode.
	for k := 1; k < len(progs); {
		prev := &progs[k-1]
		curr := &progs[k]
		sameMode := (prev.Flags&(elf.PF_W|elf.PF_R) == curr.Flags&(elf.PF_W|elf.PF_R))
		if sameMode && prev.Memsz == prev.Filesz && prev.Vaddr+prev.Memsz == curr.Vaddr && prev.Off+prev.Filesz == curr.Off {
			verbosef("ReadELF: merging:\n%#v\n%#v", *prev, *curr)
			prev.Memsz += curr.Memsz
			prev.Filesz += curr.Filesz
			progs = append(progs[:k], progs[k+1:]...)
			continue
		}
		k++
	}

	// Load all memory segments.
	for _, ph := range progs {
		verbosef("ReadELF: %#v", ph)
		// Map from the file.
		if ph.Filesz > 0 {
			err := rp.insertDataSegment(ph.Vaddr, ph.Filesz, func(addr, size uint64) (dataSegment, error) {
				data, err := mmapf.ReadSliceAt(ph.Off, ph.Filesz)
				if err != nil {
					return dataSegment{}, fmt.Errorf("bad ELF segment %+v: %v", ph, err)
				}
				return dataSegment{
					addr:     ph.Vaddr,
					data:     data,
					writable: writable && (ph.Flags&elf.PF_W) != 0,
					readable: (ph.Flags & elf.PF_R) != 0,
				}, nil
			})
			if err != nil {
				return err
			}
		}
		// TODO: The core file sometimes has MemSz > Filesz. In the exec
		// file, this means the extra space is taken up by zeros (e.g.,
		// for BSS segments, Filesz == 0 and Memsz > 0). However, for the
		// core file, I *think* the extra space comes from the exec file,
		// so for now we're ignoring extra space from the core file.
		if ph.Memsz > ph.Filesz && !isCoreFile {
			err := rp.insertDataSegment(ph.Vaddr+ph.Filesz, ph.Memsz-ph.Filesz, func(addr, size uint64) (dataSegment, error) {
				if int(size) < 0 {
					panic(fmt.Sprintf("size out of bounds: %v", size))
				}
				anonf, err := mmapOpenAnonymous(int(size), false)
				if err != nil {
					return dataSegment{}, fmt.Errorf("MAP_ANONYMOUS failed on size=%v: %v", size, err)
				}
				return dataSegment{
					addr:     ph.Vaddr + ph.Filesz,
					data:     anonf.data,
					writable: false, // writes to this segment cannot be reflected back into the core file
					readable: true,
				}, nil
			})
			if err != nil {
				return err
			}
		}
	}

	// Load DWARF data from exec files.
	if !isCoreFile {
		dw, err := f.DWARF()
		if err != nil {
			return fmt.Errorf("could not load DWARF: %v", err)
		}
		rp.dwarfs[mmapf.Name()] = dw
	}

	return nil
}

type elfSortedProgHeaders []elf.ProgHeader

func (p elfSortedProgHeaders) Len() int           { return len(p) }
func (p elfSortedProgHeaders) Swap(i, k int)      { p[i], p[k] = p[k], p[i] }
func (p elfSortedProgHeaders) Less(i, k int) bool { return p[i].Vaddr < p[k].Vaddr }

// Parsing ELF notes.
// TODO: currently only supporting Linux note structs

// See /usr/include/linux/elf.h.
const (
	elf_nt_prstatus   = 1
	elf_nt_prfpreg    = 2
	elf_nt_prpsinfo   = 3
	elf_nt_x86_xstate = 0x202
)

type elfNote struct {
	Namesz uint32
	Descsz uint32
	Ntype  uint32
}

// See /usr/include/linux/elfcore.h.
type elfLinuxPsinfo32 struct {
	State  uint8 // numeric process state
	Sname  byte  // process state as a character
	Zombie uint8
	Nice   int8
	Flag   uint32
	Uid    uint16
	Gid    uint16
	Pid    uint32
	Ppid   uint32
	Pgrp   uint32
	Sid    uint32
	Fname  [16]byte // file name, truncated, usually no directory
	Psargs [80]byte // executable args, truncated
}

type elfLinuxPsinfo64 struct {
	State  uint8 // numeric process state
	Sname  byte  // process state as a character
	Zombie uint8
	Nice   int8
	Flag   uint64
	_      uint32
	Uid    uint32
	Gid    uint32
	Pid    uint32
	Ppid   uint32
	Pgrp   uint32
	Sid    uint32
	Fname  [16]byte // file name, truncated, usually no directory
	Psargs [80]byte // executable args, truncated
}

type elfLinuxSiginfo struct {
	Signo int32
	Code  int32
	Errno int32
}

type elfLinuxTimeval32 struct {
	Sec  int32
	Usec int32
}

type elfLinuxTimeval64 struct {
	Sec  int64
	Usec int64
}

type elfLinuxPrstatus32 struct {
	Siginfo elfLinuxSiginfo // info about the current signal
	Cursig  uint16          // current signal
	_       uint16
	Sigpend uint32 // set of pending signals
	Sighold uint32 // set of held signals
	Pid     uint32
	Ppid    uint32
	Pgrp    uint32
	Sid     uint32
	Utime   elfLinuxTimeval32 // user time
	Stime   elfLinuxTimeval32 // system time
	Cutime  elfLinuxTimeval32 // cumulative user time
	Cstime  elfLinuxTimeval32 // cumulative system time
	Reg     elfLinuxGPRegs32  // GP registers
}

type elfLinuxPrstatus64 struct {
	Siginfo elfLinuxSiginfo // info about the current signal
	Cursig  uint16          // current signal
	_       uint16
	Sigpend uint64 // set of pending signals
	Sighold uint64 // set of held signals
	Pid     uint32
	Ppid    uint32
	Pgrp    uint32
	Sid     uint32
	Utime   elfLinuxTimeval64 // user time
	Stime   elfLinuxTimeval64 // system time
	Cutime  elfLinuxTimeval64 // cumulative user time
	Cstime  elfLinuxTimeval64 // cumulative system time
	Reg     elfLinuxGPRegs64  // GP registers
	Fpvalid int32
	_       int32
}

// See linux's arch/x86/include/uapi/asm/ptrace.h.
type elfLinuxGPRegs64 struct {
	R15      uint64
	R14      uint64
	R13      uint64
	R12      uint64
	Rbp      uint64
	Rbx      uint64
	R11      uint64
	R10      uint64
	R9       uint64
	R8       uint64
	Rax      uint64
	Rcx      uint64
	Rdx      uint64
	Rsi      uint64
	Rdi      uint64
	Orig_rax uint64
	Rip      uint64
	Cs       uint64
	Rflags   uint64
	Rsp      uint64
	Ss       uint64
	Fs_base  uint64
	Gs_base  uint64
	Ds       uint64
	Es       uint64
	Fs       uint64
	Gs       uint64
}

type elfLinuxGPRegs32 struct {
	Ebx      uint32
	Ecx      uint32
	Edx      uint32
	Esi      uint32
	Edi      uint32
	Ebp      uint32
	Eax      uint32
	Ds       uint32
	Es       uint32
	Fs       uint32
	Gs       uint32
	Orig_eax uint32
	Eip      uint32
	Cs       uint32
	Eflags   uint32
	Esp      uint32
	Ss       uint32
}

func readELFCoreNotes(f *elf.File, rp *rawProgram) error {
	a := goarchToArch(rp.goarch)

	// Load execpath and threads from PT_NOTES.
	for _, ph := range f.Progs {
		if ph.Type != elf.PT_NOTE {
			continue
		}
		verbosef("ReadELFNote: %#v", ph.ProgHeader)
		r := ph.Open()

		for {
			// Read the note header.
			var note elfNote
			err := binary.Read(r, a.ByteOrder, &note)
			if err == io.EOF {
				break
			}
			if err != nil {
				return fmt.Errorf("error reading PT_NOTE at offset %v: %v", ph.Off, err)
			}
			verbosef("ReadELFNote: %#v", note)

			// These are badded to 4-byte alignments.
			if note.Namesz%4 != 0 {
				note.Namesz += 4 - note.Namesz%4
			}
			if note.Descsz%4 != 0 {
				note.Descsz += 4 - note.Descsz%4
			}

			// Skip over the name.
			if _, err := r.Seek(int64(note.Namesz), io.SeekCurrent); err != nil {
				return fmt.Errorf("error reading PT_NOTE at offset %v+%v: %v", ph.Off, note.Namesz, err)
			}

			// Read the note contents.
			// TODO: also elf_nt_prfpreg and add fp regs to the current thread?
			switch note.Ntype {
			case elf_nt_prstatus:
				var (
					pid  uint32
					regs reflect.Value
				)
				switch f.Class {
				case elf.ELFCLASS32:
					var prstatus elfLinuxPrstatus32
					if err := readELFCoreNoteDesc(note, r, a, &prstatus, "prstatus32"); err != nil {
						return err
					}
					verbosef("ReadELFNote: ELF_NT_PRSTATUS is %#v", prstatus)
					pid, regs = prstatus.Pid, reflect.ValueOf(prstatus.Reg)
				case elf.ELFCLASS64:
					var prstatus elfLinuxPrstatus64
					if err := readELFCoreNoteDesc(note, r, a, &prstatus, "prstatus64"); err != nil {
						return err
					}
					verbosef("ReadELFNote: ELF_NT_PRSTATUS is %#v", prstatus)
					pid, regs = prstatus.Pid, reflect.ValueOf(prstatus.Reg)
				}
				// New thread.
				// TODO: save signal info?
				thread := &OSThread{
					PID:    uint64(pid),
					GPRegs: map[string]uint64{},
				}
				for k := 0; k < regs.Type().NumField(); k++ {
					thread.GPRegs[strings.ToLower(regs.Type().Field(k).Name)] = regs.Field(k).Uint()
				}
				verbosef("ReadELFNote: ELF_NT_PRSTATUS translated to thread %#v", thread)
				rp.osthreads = append(rp.osthreads, thread)

			case elf_nt_prpsinfo:
				var fname []byte
				switch f.Class {
				case elf.ELFCLASS32:
					var psinfo elfLinuxPsinfo32
					if err := readELFCoreNoteDesc(note, r, a, &psinfo, "psinfo32"); err != nil {
						return err
					}
					verbosef("ReadELFNote: ELF_NT_PSINFO is %#v", psinfo)
					fname = psinfo.Fname[:]
				case elf.ELFCLASS64:
					var psinfo elfLinuxPsinfo64
					if err := readELFCoreNoteDesc(note, r, a, &psinfo, "psinfo64"); err != nil {
						return err
					}
					verbosef("ReadELFNote: ELF_NT_PSINFO is %#v", psinfo)
					fname = psinfo.Fname[:]
				}
				if k := bytes.IndexByte(fname, 0); k >= 0 {
					rp.execpath = string(fname[:k])
				} else {
					rp.execpath = string(fname)
				}
				verbosef("ReadELFNote: ELF_NT_PSINFO has execpath=%q", rp.execpath)

			default:
				if err := readELFCoreNoteDesc(note, r, a, nil, ""); err != nil {
					return err
				}
			}
		}
	}

	verbosef("ReadELFNote: found %v threads", len(rp.osthreads))
	return nil
}

func readELFCoreNoteDesc(note elfNote, r io.ReadSeeker, a arch.Architecture, desc interface{}, descType string) error {
	if desc == nil {
		verbosef("ReadELFNote: skipping %v bytes", note.Descsz)
		if _, err := r.Seek(int64(note.Descsz), io.SeekCurrent); err != nil {
			return fmt.Errorf("error skipping PT_NOTE desc sz=%v: %v", note.Descsz, err)
		}
		return nil
	}

	if err := binary.Read(r, a.ByteOrder, desc); err != nil {
		return fmt.Errorf("error reading %s in PT_NOTE: %v", descType, err)
	}
	if n := int64(note.Descsz) - int64(reflect.ValueOf(desc).Elem().Type().Size()); n > 0 {
		verbosef("ReadELFNote: skipping %v bytes", n)
		if _, err := r.Seek(n, io.SeekCurrent); err != nil {
			return fmt.Errorf("error skipping space after desc in PT_NOTE desc sz=%v: %v", note.Descsz, err)
		}
	}
	return nil
}
