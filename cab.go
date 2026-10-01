package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// CAB archive layout (CFHEADER / CFOLDER / CFFILE / CFDATA), as used by the
// Microsoft cabinet format. Only the pieces needed for signature packages
// are implemented; multi-cabinet sets are out of scope.

const (
	cabCompNone  = 0
	cabCompMSZIP = 2
	cabCompLZX   = 3
)

type cabHeader struct {
	numFolders int
	numFiles   int
	flags      uint16
	dataResv   int // per-block reserve (flags & 0x0040)
	folderResv int // per-folder reserve (flags & 0x0020)
	headerResv int // per-cabinet reserve (flags & 0x0010)
}

type cabFolder struct {
	dataOff  int64 // file offset of first CFDATA header
	blocks   int
	compType uint16
}

type cabFileEntry struct {
	name   string
	size   int64
	pos    int64
	folder int
}

// parseCAB reads the header, folder table and file table of the cabinet at
// absolute file offset off. The tables are small (real packages carry a
// handful of entries), so plain reads suffice.
func parseCAB(f *os.File, off int64) (cabHeader, []cabFolder, []cabFileEntry, error) {
	var h [40]byte
	if _, err := f.ReadAt(h[:36], off); err != nil {
		return cabHeader{}, nil, nil, fmt.Errorf("cab header: %w", err)
	}
	hdr := cabHeader{
		numFolders: int(le16(h[:], 26)),
		numFiles:   int(le16(h[:], 28)),
		flags:      le16(h[:], 30),
	}
	if hdr.flags&0x0010 != 0 {
		var r [4]byte
		if _, err := f.ReadAt(r[:], off+36); err != nil {
			return cabHeader{}, nil, nil, err
		}
		n := int(le32(r[:], 0))
		if n > 256 {
			return cabHeader{}, nil, nil, errors.New("unsupported CAB header reserve size")
		}
		hdr.headerResv = 4 + n
	}
	if hdr.flags&0x0020 != 0 {
		var r [2]byte
		if _, err := f.ReadAt(r[:], off+36+int64(hdr.headerResv)); err != nil {
			return cabHeader{}, nil, nil, err
		}
		hdr.folderResv = int(le16(r[:], 0))
	}
	if hdr.flags&0x0040 != 0 {
		var r [1]byte
		if _, err := f.ReadAt(r[:], off+38+int64(hdr.headerResv)); err != nil {
			return cabHeader{}, nil, nil, err
		}
		hdr.dataResv = int(r[0])
	}

	base := off + 36 + int64(hdr.headerResv)
	folders := make([]cabFolder, 0, hdr.numFolders)
	for i := 0; i < hdr.numFolders; i++ {
		var fo [8]byte
		if _, err := f.ReadAt(fo[:], base+int64(i)*(8+int64(hdr.folderResv))); err != nil {
			return cabHeader{}, nil, nil, fmt.Errorf("cab folder %d: %w", i, err)
		}
		folders = append(folders, cabFolder{
			dataOff:  off + int64(le32(fo[:], 0)),
			blocks:   int(le16(fo[:], 4)),
			compType: le16(fo[:], 6),
		})
	}

	files := make([]cabFileEntry, 0, hdr.numFiles)
	p := off + int64(le32(h[:], 16))
	for i := 0; i < hdr.numFiles; i++ {
		var fe [16]byte
		if _, err := f.ReadAt(fe[:], p); err != nil {
			return cabHeader{}, nil, nil, fmt.Errorf("cab file %d: %w", i, err)
		}
		nameBuf := make([]byte, 0, 256)
		for k := 0; ; k++ {
			var b [1]byte
			if _, err := f.ReadAt(b[:], p+16+int64(k)); err != nil {
				return cabHeader{}, nil, nil, fmt.Errorf("cab file %d name: %w", i, err)
			}
			if b[0] == 0 {
				break
			}
			nameBuf = append(nameBuf, b[0])
			if k > 512 {
				return cabHeader{}, nil, nil, errors.New("cab file name too long")
			}
		}
		files = append(files, cabFileEntry{
			name:   string(nameBuf),
			size:   int64(le32(fe[:], 0)),
			pos:    int64(le32(fe[:], 4)),
			folder: int(le16(fe[:], 8)),
		})
		p += 16 + int64(len(nameBuf)) + 1
	}
	return hdr, folders, files, nil
}

// extractPackage extracts the signature files from a downloaded package
// (mpam-fe.exe / mpas-fe.exe / bare .cab) into outDir.
func extractPackage(pkgPath, outDir string) error {
	f, err := os.Open(pkgPath)
	if err != nil {
		return err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return err
	}
	off, _, err := findSignatureCAB(f, st.Size())
	if err != nil {
		return err
	}
	hdr, folders, files, err := parseCAB(f, off)
	if err != nil {
		return err
	}
	for fi := range folders {
		var entries []cabFileEntry
		for _, e := range files {
			if e.folder == fi {
				entries = append(entries, e)
			}
		}
		if len(entries) == 0 {
			continue
		}
		sort.Slice(entries, func(a, b int) bool { return entries[a].pos < entries[b].pos })
		if err := extractFolder(f, hdr, folders[fi], entries, outDir); err != nil {
			return fmt.Errorf("folder %d (%s): %w", fi, compTypeName(folders[fi].compType), err)
		}
	}
	return nil
}

func compTypeName(ct uint16) string {
	switch ct & 0xF {
	case cabCompNone:
		return "stored"
	case cabCompMSZIP:
		return "MSZIP"
	case cabCompLZX:
		return fmt.Sprintf("LZX(w%ds)", (ct>>8)&0x1f)
	default:
		return fmt.Sprintf("0x%04x", ct)
	}
}

// extractFolder decodes one folder and routes its output into per-file
// writers according to each entry's position in the folder stream.
func extractFolder(f *os.File, hdr cabHeader, fo cabFolder, entries []cabFileEntry, outDir string) error {
	if entries[0].pos != 0 {
		return fmt.Errorf("first entry %q starts at %d", entries[0].name, entries[0].pos)
	}
	var total int64
	for _, e := range entries {
		if e.pos != total {
			return fmt.Errorf("entries not contiguous at %q (pos %d, expected %d)", e.name, e.pos, total)
		}
		total += e.size
	}
	sw := newSplitWriter(outDir, entries)
	if _, err := f.Seek(fo.dataOff, io.SeekStart); err != nil {
		return err
	}
	fs := newFolderStream(f, fo.blocks, hdr.dataResv)
	var dec folderDecoder
	switch fo.compType & 0xF {
	case cabCompNone:
		dec = &storedDecoder{}
	case cabCompMSZIP:
		dec = &mszipDecoder{}
	case cabCompLZX:
		d, err := newLZXDecoder(int((fo.compType >> 8) & 0x1f))
		if err != nil {
			return err
		}
		defer d.close()
		dec = d
	default:
		return fmt.Errorf("unsupported compression type 0x%04x", fo.compType)
	}
	if err := dec.decompress(fs, sw, total); err != nil {
		return err
	}
	return sw.finish(total)
}

// folderDecoder decodes a complete folder stream into w.
type folderDecoder interface {
	decompress(fs *folderStream, w io.Writer, total int64) error
}

// storedDecoder passes CFDATA payload bytes straight through (for
// compression type 0 the payload is the output).
type storedDecoder struct{}

func (*storedDecoder) decompress(fs *folderStream, w io.Writer, total int64) error {
	written := int64(0)
	for written < total {
		block, err := fs.nextBlock()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		n := int64(len(block))
		if written+n > total {
			n = total - written
		}
		if _, err := w.Write(block[:n]); err != nil {
			return err
		}
		written += n
	}
	if written != total {
		return fmt.Errorf("stored folder: got %d of %d bytes", written, total)
	}
	return nil
}

// folderStream serves the CFDATA payload bytes of one folder as a single
// continuous stream, skipping the per-block headers.
type folderStream struct {
	rs        io.Reader
	remaining int
	dataResv  int
	cur       []byte
	curPos    int
}

func newFolderStream(rs io.Reader, blocks, dataResv int) *folderStream {
	return &folderStream{rs: rs, remaining: blocks, dataResv: dataResv}
}

func (s *folderStream) Read(p []byte) (int, error) {
	for s.curPos >= len(s.cur) {
		if _, err := s.nextBlock(); err != nil {
			return 0, err
		}
	}
	n := copy(p, s.cur[s.curPos:])
	s.curPos += n
	return n, nil
}

// ReadByte lets decoders consume the folder stream byte-by-byte (the LZX
// bit reader and the MSZIP "CK" scanner both need it).
func (s *folderStream) ReadByte() (byte, error) {
	for s.curPos >= len(s.cur) {
		if _, err := s.nextBlock(); err != nil {
			return 0, err
		}
	}
	b := s.cur[s.curPos]
	s.curPos++
	return b, nil
}

// nextBlock loads the next CFDATA block, skipping its header and reserve
// bytes, and returns its payload. io.EOF is returned after the last block.
// The payload is returned whole (block consumers — stored/MSZIP — always
// process entire blocks), while Read() serves it through curPos.
func (s *folderStream) nextBlock() ([]byte, error) {
	if s.remaining <= 0 {
		return nil, io.EOF
	}
	var hdr [8]byte
	if _, err := io.ReadFull(s.rs, hdr[:]); err != nil {
		return nil, fmt.Errorf("cfdata header: %w", err)
	}
	if s.dataResv > 0 {
		if _, err := io.CopyN(io.Discard, s.rs, int64(s.dataResv)); err != nil {
			return nil, fmt.Errorf("cfdata reserve: %w", err)
		}
	}
	cbComp := int(le16(hdr[:], 4))
	cbUncomp := int(le16(hdr[:], 6))
	if cbComp > 0x8000 || cbUncomp > 0x8000 {
		return nil, fmt.Errorf("cfdata sizes too large: %d/%d", cbComp, cbUncomp)
	}
	data := make([]byte, cbComp)
	if _, err := io.ReadFull(s.rs, data); err != nil {
		return nil, fmt.Errorf("cfdata payload: %w", err)
	}
	s.remaining--
	s.cur = data
	s.curPos = 0
	return s.cur, nil
}

// splitWriter routes a stream of bytes into per-file writers based on each
// entry's offset within the folder output.
type splitWriter struct {
	dir     string
	entries []cabFileEntry
	idx     int
	pos     int64
	handles map[int]*os.File
}

func newSplitWriter(dir string, entries []cabFileEntry) *splitWriter {
	return &splitWriter{dir: dir, entries: entries, handles: make(map[int]*os.File)}
}

func (sw *splitWriter) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		if sw.idx >= len(sw.entries) {
			return written, errors.New("folder output exceeds declared entries")
		}
		e := sw.entries[sw.idx]
		if sw.pos < e.pos {
			return written, fmt.Errorf("gap before %q (at %d, entry starts %d)", e.name, sw.pos, e.pos)
		}
		remain := e.pos + e.size - sw.pos
		if remain <= 0 {
			sw.closeIdx(sw.idx)
			sw.idx++
			continue
		}
		n := remain
		if int64(len(p)) < n {
			n = int64(len(p))
		}
		f, err := sw.handle(sw.idx)
		if err != nil {
			return written, err
		}
		if _, werr := f.Write(p[:n]); werr != nil {
			return written, werr
		}
		sw.pos += n
		p = p[n:]
		written += int(n)
	}
	return written, nil
}

func (sw *splitWriter) handle(idx int) (*os.File, error) {
	if f, ok := sw.handles[idx]; ok {
		return f, nil
	}
	f, err := os.Create(filepath.Join(sw.dir, sw.entries[idx].name))
	if err != nil {
		return nil, err
	}
	sw.handles[idx] = f
	return f, nil
}

func (sw *splitWriter) closeIdx(idx int) {
	if f, ok := sw.handles[idx]; ok {
		f.Close()
		delete(sw.handles, idx)
	}
}

// finish closes all files and verifies the whole folder was written.
func (sw *splitWriter) finish(total int64) error {
	for idx := range sw.handles {
		sw.closeIdx(idx)
	}
	if sw.pos != total {
		return fmt.Errorf("folder output short: %d of %d bytes", sw.pos, total)
	}
	return nil
}
