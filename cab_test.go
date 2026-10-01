package main

import (
	"bytes"
	"compress/flate"
	"os"
	"path/filepath"
	"testing"
)

// ---- CAB fixture builders ----

type testFile struct {
	name   string
	body   []byte
	folder int
}

// buildTestCAB assembles a CAB archive with the given files. Folders are
// numbered 0..len(compTypes)-1; each folder's output is chunked into
// <=32 KiB CFDATA blocks (stored or MSZIP payload).
func buildTestCAB(t *testing.T, files []testFile, compTypes []uint16) []byte {
	t.Helper()
	if len(compTypes) == 0 {
		t.Fatal("no folders")
	}
	type folderPlan struct {
		comp    uint16
		chunks  [][]byte // uncompressed chunks (<=32K each)
		payload [][]byte // per-block CFDATA payload
		blocks  int
		dataOff int64
	}
	plans := make([]folderPlan, len(compTypes))
	for i := range plans {
		plans[i].comp = compTypes[i]
	}
	var pos int64
	var entries []cabFileEntry
	last := -1
	for _, tf := range files {
		if tf.folder != last {
			last = tf.folder
			pos = 0
		}
		if tf.folder >= len(plans) {
			t.Fatalf("file %s: folder %d out of range", tf.name, tf.folder)
		}
		entries = append(entries, cabFileEntry{name: tf.name, size: int64(len(tf.body)), pos: pos, folder: tf.folder})
		p := &plans[tf.folder]
		for done := 0; done < len(tf.body); {
			n := len(tf.body) - done
			if n > 32768 {
				n = 32768
			}
			p.chunks = append(p.chunks, tf.body[done:done+n])
			done += n
		}
		if len(tf.body) == 0 {
			p.chunks = append(p.chunks, nil)
		}
		pos += int64(len(tf.body))
	}
	// Encode folder payloads.
	var dataBuf bytes.Buffer
	for i := range plans {
		p := &plans[i]
		plans[i].dataOff = int64(dataBuf.Len())
		for ci, chunk := range p.chunks {
			var pl []byte
			if p.comp == cabCompNone {
				pl = chunk
			} else if p.comp&0xF == cabCompMSZIP {
				var z bytes.Buffer
				zw, _ := flate.NewWriter(&z, flate.DefaultCompression)
				zw.Write(chunk)
				zw.Close()
				pl = append([]byte("CK"), z.Bytes()...)
			} else {
				t.Fatalf("fixture builder: unsupported comp 0x%x", p.comp)
			}
			p.blocks++
			var hdr []byte
			hdr = append(hdr, 0, 0, 0, 0) // no checksum
			hdr = append(hdr, byte(len(pl)), byte(len(pl)>>8))
			hdr = append(hdr, byte(len(chunk)), byte(len(chunk)>>8))
			dataBuf.Write(hdr)
			dataBuf.Write(pl)
			_ = ci
		}
	}
	// File table.
	var fileBuf bytes.Buffer
	for _, e := range entries {
		var fe []byte
		fe = append(fe, byte(e.size), byte(e.size>>8), byte(e.size>>16), byte(e.size>>24))
		fe = append(fe, byte(e.pos), byte(e.pos>>8), byte(e.pos>>16), byte(e.pos>>24))
		fe = append(fe, byte(e.folder), byte(e.folder>>8))
		fe = append(fe, 0, 0, 0, 0) // date, time
		fe = append(fe, 0x20, 0)    // attributes
		fe = append(fe, e.name...)
		fe = append(fe, 0)
		fileBuf.Write(fe)
	}
	coffFiles := 36 + len(compTypes)*8
	cabLen := int64(coffFiles) + int64(fileBuf.Len()) + int64(dataBuf.Len())
	var out bytes.Buffer
	out.WriteString("MSCF")
	out.Write([]byte{0, 0, 0, 0}) // reserved1
	cb := cabLen
	out.Write([]byte{byte(cb), byte(cb >> 8), byte(cb >> 16), byte(cb >> 24)})
	out.Write([]byte{0, 0, 0, 0}) // reserved2
	coff := coffFiles
	out.Write([]byte{byte(coff), byte(coff >> 8), byte(coff >> 16), byte(coff >> 24)})
	out.Write([]byte{0, 0, 0, 0}) // reserved3
	out.WriteByte(1)              // version minor
	out.WriteByte(3)              // version major
	nf := len(compTypes)
	out.Write([]byte{byte(nf), byte(nf >> 8)})
	nfiles := len(entries)
	out.Write([]byte{byte(nfiles), byte(nfiles >> 8)})
	out.Write([]byte{0, 0}) // flags
	out.Write([]byte{1, 0}) // setID
	out.Write([]byte{0, 0}) // iCabinet
	for i := range plans {
		coffCab := int64(coffFiles) + int64(fileBuf.Len()) + plans[i].dataOff
		out.Write([]byte{
			byte(coffCab), byte(coffCab >> 8), byte(coffCab >> 16), byte(coffCab >> 24),
			byte(plans[i].blocks), byte(plans[i].blocks >> 8),
			byte(plans[i].comp), byte(plans[i].comp >> 8),
		})
	}
	out.Write(fileBuf.Bytes())
	out.Write(dataBuf.Bytes())
	if int64(out.Len()) != cabLen {
		t.Fatalf("fixture size mismatch: %d != %d", out.Len(), cabLen)
	}
	return out.Bytes()
}

func writeTemp(t *testing.T, dir, name string, body []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func mustExtract(t *testing.T, pkgPath, outDir string) {
	t.Helper()
	if err := extractPackage(pkgPath, outDir); err != nil {
		t.Fatalf("extractPackage: %v", err)
	}
}

func checkExtracted(t *testing.T, outDir string, files []testFile) {
	t.Helper()
	for _, tf := range files {
		got, err := os.ReadFile(filepath.Join(outDir, tf.name))
		if err != nil {
			t.Fatalf("%s: %v", tf.name, err)
		}
		if !bytes.Equal(got, tf.body) {
			t.Fatalf("%s: content mismatch (%d vs %d bytes)", tf.name, len(got), len(tf.body))
		}
	}
}

func TestExtractStoredMultiFolderMultiFile(t *testing.T) {
	files := []testFile{
		{name: "mpengine.dll", body: bytes.Repeat([]byte{0xAA, 0xBB, 0xCC}, 30000), folder: 0},
		{name: "MpSigStub.exe", body: bytes.Repeat([]byte{0x11}, 40000), folder: 1},
		{name: "mpasdlta.vdm", body: bytes.Repeat([]byte{0x22}, 5000), folder: 1},
	}
	cab := buildTestCAB(t, files, []uint16{cabCompNone, cabCompNone})
	dir := t.TempDir()
	pkg := writeTemp(t, dir, "pkg.cab", cab)
	out := filepath.Join(dir, "out")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	mustExtract(t, pkg, out)
	checkExtracted(t, out, files)
}

func TestExtractMSZIP(t *testing.T) {
	files := []testFile{
		{name: "mpasbase.vdm", body: bytes.Repeat([]byte("vdm-data-"), 9000), folder: 0},
		{name: "mpavbase.vdm", body: []byte("small"), folder: 0},
	}
	cab := buildTestCAB(t, files, []uint16{cabCompMSZIP})
	dir := t.TempDir()
	pkg := writeTemp(t, dir, "pkg.cab", cab)
	out := filepath.Join(dir, "out")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	mustExtract(t, pkg, out)
	checkExtracted(t, out, files)
}

// wrapInPE builds a minimal PE32 executable whose .rsrc section starts at
// the CAB payload (mimicking mpam-fe.exe packaging).
func wrapInPE(t *testing.T, cab []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	// DOS header: MZ + e_lfanew = 0x80
	b.WriteString("MZ")
	b.Write(bytes.Repeat([]byte{0}, 0x3A))
	b.Write([]byte{0x80, 0, 0, 0})
	// pad to 0x80
	b.Write(bytes.Repeat([]byte{0}, 0x80-0x40))
	b.WriteString("PE\x00\x00")
	// COFF header
	b.Write([]byte{0x4C, 0x01}) // machine i386
	b.Write([]byte{1, 0})       // 1 section
	b.Write([]byte{0, 0, 0, 0}) // timestamp
	b.Write([]byte{0, 0, 0, 0}) // symtab
	b.Write([]byte{0, 0, 0, 0}) // numsym
	b.Write([]byte{224, 0})     // SizeOfOptionalHeader
	b.Write([]byte{0x02, 0x01}) // characteristics
	// Optional header (224 bytes, minimal)
	opt := make([]byte, 224)
	opt[0] = 0x0B
	opt[1] = 0x01 // PE32
	rsrcRVA := uint32(0x1000)
	raddr := uint32(0x400) // file offset of .rsrc payload
	rsz := uint32(len(cab))
	// SizeOfImage/SizeOfHeaders minimal
	opt[56] = 0x00
	// section table follows optional header
	sec := make([]byte, 40)
	copy(sec[:8], ".rsrc")
	put32(sec, 8, rsz)      // VirtualSize
	put32(sec, 12, rsrcRVA) // VirtualAddress
	put32(sec, 16, rsz)     // SizeOfRawData
	put32(sec, 20, raddr)   // PointerToRawData
	b.Write(opt)
	b.Write(sec)
	// pad to raddr
	for b.Len() < int(raddr) {
		b.WriteByte(0)
	}
	b.Write(cab)
	return b.Bytes()
}

func put32(b []byte, off int, v uint32) {
	b[off] = byte(v)
	b[off+1] = byte(v >> 8)
	b[off+2] = byte(v >> 16)
	b[off+3] = byte(v >> 24)
}

func TestExtractFromPEWrapper(t *testing.T) {
	files := []testFile{
		{name: "mpengine.dll", body: bytes.Repeat([]byte{7, 8, 9}, 20000), folder: 0},
	}
	cab := buildTestCAB(t, files, []uint16{cabCompNone})
	exe := wrapInPE(t, cab)
	dir := t.TempDir()
	pkg := writeTemp(t, dir, "mpam-fe.exe", exe)
	out := filepath.Join(dir, "out")
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	mustExtract(t, pkg, out)
	checkExtracted(t, out, files)
}

func TestScanForCABBareFile(t *testing.T) {
	cab := buildTestCAB(t, []testFile{{name: "a.bin", body: []byte("x"), folder: 0}}, []uint16{cabCompNone})
	f, err := os.Open(writeTemp(t, t.TempDir(), "bare.cab", cab))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	off, n, err := scanForCAB(f, 0, int64(len(cab)), int64(len(cab)))
	if err != nil {
		t.Fatalf("scanForCAB: %v", err)
	}
	if off != 0 || n != int64(len(cab)) {
		t.Fatalf("off=%d n=%d", off, n)
	}
}

func TestScanForCABNotPresent(t *testing.T) {
	f, err := os.Open(writeTemp(t, t.TempDir(), "no.cab", bytes.Repeat([]byte{0x42}, 70000)))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, _, err := scanForCAB(f, 0, 70000, 70000); err == nil {
		t.Fatal("expected not-found error")
	}
}

func TestSplitWriterGap(t *testing.T) {
	dir := t.TempDir()
	sw := newSplitWriter(dir, []cabFileEntry{{name: "a", size: 4, pos: 2}})
	if _, err := sw.Write([]byte("abcd")); err == nil {
		t.Fatal("expected gap error")
	}
}
