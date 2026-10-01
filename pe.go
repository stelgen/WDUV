package main

import (
	"bytes"
	"errors"
	"os"
)

// Microsoft signature packages (mpam-fe.exe, mpas-fe.exe) are PE
// executables whose .rsrc section embeds one large CAB archive that holds
// the engine, the signature stub and the definition files. findSignatureCAB
// locates that archive (its file offset and length) inside the package,
// preferring the .rsrc section and falling back to a whole-file scan.
func findSignatureCAB(f *os.File, size int64) (int64, int64, error) {
	if start, n, ok := rsrcSectionRange(f, size); ok {
		if off, cab, err := scanForCAB(f, start, n, size); err == nil {
			return off, cab, nil
		}
	}
	return scanForCAB(f, 0, size, size)
}

// rsrcSectionRange parses the PE headers (MZ-relative, the way the loader
// does it) and returns the raw data range of the .rsrc section.
func rsrcSectionRange(f *os.File, size int64) (int64, int64, bool) {
	head := make([]byte, 4096)
	n, err := f.ReadAt(head, 0)
	if err != nil && n < 0x100 {
		return 0, 0, false
	}
	head = head[:n]
	if len(head) < 0x40 || head[0] != 'M' || head[1] != 'Z' {
		return 0, 0, false
	}
	peOff := int(le32(head, 0x3c))
	if peOff <= 0 || peOff+248 > len(head) {
		return 0, 0, false
	}
	if !bytes.Equal(head[peOff:peOff+4], []byte("PE\x00\x00")) {
		return 0, 0, false
	}
	numSec := int(le16(head, peOff+6))
	optSize := int(le16(head, peOff+20))
	sectab := peOff + 24 + optSize
	if sectab+numSec*40 > len(head) {
		return 0, 0, false
	}
	for i := 0; i < numSec; i++ {
		so := sectab + i*40
		name := string(bytes.TrimRight(head[so:so+8], "\x00"))
		if name == ".rsrc" {
			raddr := int64(le32(head, so+20))
			rsz := int64(le32(head, so+16))
			if raddr+rsz <= size && rsz > 0 {
				return raddr, rsz, true
			}
		}
	}
	return 0, 0, false
}

// scanForCAB scans [start, start+length) for a plausible MSCF cabinet
// header. Scanning is chunked with overlap so a header crossing a chunk
// boundary is still found.
func scanForCAB(f *os.File, start, length, fileSize int64) (int64, int64, error) {
	const chunk = 4 << 20
	if length <= 0 {
		return 0, 0, errors.New("empty scan range")
	}
	buf := make([]byte, chunk+8)
	var pos int64
	for pos < start+length {
		n, err := f.ReadAt(buf, pos)
		if n <= 0 {
			if err != nil && pos > start {
				break
			}
			if err != nil {
				return 0, 0, err
			}
			break
		}
		data := buf[:n]
		i := 0
		for {
			j := bytes.Index(data[i:], mscfMagic)
			if j < 0 {
				break
			}
			abs := pos + int64(i+j)
			if ln, ok := validCABAt(f, abs, fileSize); ok {
				return abs, ln, nil
			}
			i += j + 1
		}
		if n < len(data) || n < 16 {
			break
		}
		pos += int64(n) - 8 // keep overlap for split matches
	}
	return 0, 0, errors.New("CAB (MSCF) not found in package")
}

var mscfMagic = []byte("MSCF")

// validCABAt checks the CFHEADER at offset off and, if plausible, returns
// the total cabinet size (cbCabinet).
func validCABAt(f *os.File, off, fileSize int64) (int64, bool) {
	var h [36]byte
	if _, err := f.ReadAt(h[:], off); err != nil {
		return 0, false
	}
	if !bytes.Equal(h[:4], mscfMagic) {
		return 0, false
	}
	cbCabinet := int64(le32(h[:], 8))
	coffFiles := int64(le32(h[:], 16))
	numFolders := int(le16(h[:], 26))
	numFiles := int(le16(h[:], 28))
	if cbCabinet < 36 || coffFiles < 36 || coffFiles >= cbCabinet {
		return 0, false
	}
	if numFolders == 0 || numFolders > 1024 || numFiles == 0 || numFiles > 65535 {
		return 0, false
	}
	if off+cbCabinet > fileSize {
		return 0, false
	}
	return cbCabinet, true
}

func le16(b []byte, off int) uint16 {
	return uint16(b[off]) | uint16(b[off+1])<<8
}

func le32(b []byte, off int) uint32 {
	return uint32(b[off]) | uint32(b[off+1])<<8 | uint32(b[off+2])<<16 | uint32(b[off+3])<<24
}
