package corefile

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"
)

var errMmapClosed = errors.New("mmap: closed")

// mmapFile wraps a memory-mapped file. This is similar to
// golang.org/x/exp/mmap.ReaderAt, but unlike mmap.ReaderAt,
// mmapFile allows creating []byte slices that refer directly
// to the underlying mmap'd memory segment.
type mmapFile struct {
	filename string
	data     []byte
	pos      uint64
	writable bool
}

// mmapOpen opens the named file for reading.
// If writable is true, the file is also open for writing.
func mmapOpen(filename string, writable bool) (*mmapFile, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}

	size := st.Size()
	if size == 0 {
		return &mmapFile{filename: filename, data: []byte{}}, nil
	}
	if size < 0 {
		return nil, fmt.Errorf("mmap: file %q has negative size: %d", filename, size)
	}
	if size != int64(int(size)) {
		return nil, fmt.Errorf("mmap: file %q is too large", filename)
	}

	prot := syscall.PROT_READ
	if writable {
		prot |= syscall.PROT_WRITE
	}
	data, err := syscall.Mmap(int(f.Fd()), 0, int(size), prot, syscall.MAP_SHARED)
	if err != nil {
		return nil, err
	}
	return &mmapFile{filename: filename, data: data, writable: writable}, nil
}

// mmapOpenAnonymous creates an anonymous mapping of the given size.
// If writable is true, the mapping is created in writable mode.
func mmapOpenAnonymous(size int, writable bool) (*mmapFile, error) {
	prot := syscall.PROT_READ
	if writable {
		prot |= syscall.PROT_WRITE
	}
	data, err := syscall.Mmap(-1, 0, int(size), prot, syscall.MAP_ANONYMOUS|syscall.MAP_PRIVATE)
	if err != nil {
		return nil, err
	}
	return &mmapFile{filename: "", data: data, writable: writable}, nil
}

// Name returns the name of the file.
func (f *mmapFile) Name() string {
	return f.filename
}

// Size returns the size of the mapped file.
func (f *mmapFile) Size() uint64 {
	return uint64(len(f.data))
}

// Pos returns the current file pointer.
// Pos is updated by Read, ReadByte, and ReadSlice.
func (f *mmapFile) Pos() uint64 {
	return f.pos
}

// Read implements io.Reader.
func (f *mmapFile) Read(p []byte) (int, error) {
	n, err := f.ReadAt(p, int64(f.pos))
	f.pos += uint64(n)
	return n, err
}

// ReadAt implements io.ReaderAt.
func (f *mmapFile) ReadAt(p []byte, offset int64) (int, error) {
	if f.data == nil {
		return 0, errMmapClosed
	}
	if offset < 0 {
		return 0, fmt.Errorf("negative offset: %v", offset)
	}
	if uint64(offset) >= f.Size() {
		return 0, io.EOF
	}
	n := copy(p, f.data[offset:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// ReadByte implements io.ByteReader.
func (f *mmapFile) ReadByte() (byte, error) {
	if f.data == nil {
		return 0, errMmapClosed
	}
	if f.pos >= f.Size() {
		return 0, io.EOF
	}
	b := f.data[f.pos]
	f.pos++
	return b, nil
}

// ReadSlice returns a slice of size n that points directly at the
// underlying mapped file. There is no copying. Fails if it cannot
// read n bytes from the current offset.
func (f *mmapFile) ReadSlice(n uint64) ([]byte, error) {
	if f.data == nil {
		return nil, errMmapClosed
	}
	if f.pos+n >= f.Size() {
		return nil, io.EOF
	}
	first := f.pos
	f.pos += n
	return f.data[first:f.pos:f.pos], nil
}

// ReadSliceAt is like ReadSlice, but reads from a specific offset.
// The file pointer is not used or advanced.
func (f *mmapFile) ReadSliceAt(offset, n uint64) ([]byte, error) {
	if f.data == nil {
		return nil, errMmapClosed
	}
	if offset+n > f.Size() {
		return nil, fmt.Errorf("mmap: out-of-bounds ReadSliceAt(%d, %d), file size is %d", offset, n, f.Size())
	}
	end := offset + n
	return f.data[offset:end:end], nil
}

// Close closes the file.
func (f *mmapFile) Close() error {
	if f.data == nil {
		return nil
	}
	err := syscall.Munmap(f.data)
	*f = mmapFile{}
	return err
}
