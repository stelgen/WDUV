package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
)

// ---- bit stream fixture helpers ----
//
// The CAB LZX bitstream groups bits into 16-bit little-endian words that
// are consumed MSB-first: word value = bytes[b] | bytes[b+1]<<8, bits read
// from bit15 down to bit0. bitWriter collects stream bits (MSB-first) and
// packs them into that layout.

type bitWriter struct {
	bits []byte // one byte per bit, values 0/1
}

func (w *bitWriter) put(v uint32, n int) {
	for i := n - 1; i >= 0; i-- {
		w.bits = append(w.bits, byte((v>>uint(i))&1))
	}
}

func (w *bitWriter) align16() {
	for len(w.bits)%16 != 0 {
		w.bits = append(w.bits, 0)
	}
}

// pack renders the collected bits; bit regions must be padded to the
// 16-bit boundary (the decoder discards to a word boundary before raw
// regions).
func (w *bitWriter) pack() []byte {
	w.align16()
	out := make([]byte, len(w.bits)/8) // 16 bits per 2-byte LE word
	for g := 0; g*16 < len(w.bits); g++ {
		var word uint16
		for k := 0; k < 16; k++ {
			word = word<<1 | uint16(w.bits[g*16+k])
		}
		out[g*2] = byte(word & 0xFF) // low byte: last 8 stream bits
		out[g*2+1] = byte(word >> 8) // high byte: first 8 stream bits
	}
	return out
}

// wrapBlock wraps a bitstream payload into CFDATA blocks (compressed size
// never exceeds the 32 KiB CAB limit) served by a single-folder reader;
// the uncompressed sizes drive lzx.setLength on the last block.
func wrapBlock(payload []byte, uncomp int) *folderStream {
	var buf bytes.Buffer
	remaining := uncomp
	blocks := 0
	for off := 0; off < len(payload) || blocks == 0; {
		n := len(payload) - off
		if n > 32768 {
			n = 32768
		}
		u := remaining
		if u > 32768 {
			u = 32768
		}
		remaining -= u
		var hdr []byte
		hdr = append(hdr, 0, 0, 0, 0)
		hdr = append(hdr, byte(n), byte(n>>8))
		hdr = append(hdr, byte(u), byte(u>>8))
		buf.Write(hdr)
		buf.Write(payload[off : off+n])
		off += n
		blocks++
	}
	return newFolderStream(bytes.NewReader(buf.Bytes()), blocks, 0)
}

// ---- fixtures: canonical trees used by the handcrafted streams ----

// simplePretreeLens: symbols 0..15 have length 4 (complete tree),
// 16..19 unused. Canonical code of symbol k (k<16) is k.
func simplePretreeLens() [20]byte {
	var p [20]byte
	for i := 0; i < 16; i++ {
		p[i] = 4
	}
	return p
}

// emitPretree writes the raw 4-bit code lengths of the pre-tree.
func (w *bitWriter) emitPretree(p [20]byte) {
	for _, l := range p {
		w.put(uint32(l), 4)
	}
}

// emitMainTree writes the delta-coded main-tree lengths for a complete
// tree of `n` symbols each with length `l` (n*2^-l == 1). For a fresh
// (all-zero) state the delta that produces length l is (17-l)%17.
func (w *bitWriter) emitMainTree(n, l int) {
	delta := uint32((17 - l) % 17)
	for x := 0; x < n; x++ {
		w.put(delta, 4)
	}
}

// emitEmptyLengthTree: 250 zero deltas → LENGTH tree stays empty.
func (w *bitWriter) emitEmptyLengthTree() {
	for x := 0; x < lzxNumSecondaryLengths; x++ {
		w.put(0, 4)
	}
}

func newTestLZX() *lzxDecoder {
	d, err := newLZXDecoder(16) // 64 KiB window, 32 position slots → 512 main symbols
	if err != nil {
		panic(err)
	}
	return d
}

// literalsBlock writes a verbatim block that decodes to the given
// literals. Main tree: 512 symbols × 2^-9 == 1 → codes equal symbol
// indices, so literal b is emitted as its 9-bit value. readLens is called
// three times (main 0..256, main 256..512, length); each call reads its
// own pre-tree first.
func (w *bitWriter) literalsBlock(lits []byte) {
	w.put(blockVerbatim, 3)
	n := len(lits)
	w.put(uint32(n>>16)&0xFF, 8)
	w.put(uint32(n>>8)&0xFF, 8)
	w.put(uint32(n)&0xFF, 8)
	w.emitPretree(simplePretreeLens())
	for x := 0; x < 256; x++ {
		w.put(8, 4) // delta 8 → length 9
	}
	w.emitPretree(simplePretreeLens())
	for x := 256; x < 512; x++ {
		w.put(8, 4)
	}
	w.emitPretree(simplePretreeLens())
	w.emitEmptyLengthTree()
	for _, b := range lits {
		w.put(uint32(b), 9)
	}
}

func decodeLZXFixture(t *testing.T, payload []byte, total int) []byte {
	t.Helper()
	d := newTestLZX()
	defer d.close()
	fs := wrapBlock(payload, total)
	out := &bytes.Buffer{}
	if err := d.decompress(fs, out, int64(total)); err != nil {
		t.Fatalf("lzx decompress: %v", err)
	}
	return out.Bytes()
}

func TestBitReaderOrder(t *testing.T) {
	d := newTestLZX()
	defer d.close()
	d.in = bytes.NewReader([]byte{0x01, 0x02, 0x03, 0x04})
	// Word 0 = 0x0201 consumed MSB-first: 00000010 00000001
	cases := []struct {
		n    int
		want uint32
	}{
		{3, 0b000}, {5, 0b00010}, {2, 0b00}, {6, 0b000001}, {16, 0x0403},
	}
	for _, c := range cases {
		got, err := d.readBits(c.n)
		if err != nil {
			t.Fatalf("readBits(%d): %v", c.n, err)
		}
		if got != c.want {
			t.Fatalf("readBits(%d) = %#x, want %#x", c.n, got, c.want)
		}
	}
}

func TestMakeDecodeTableRoundTrip(t *testing.T) {
	lens := []byte{2, 2, 2, 2}
	table := make([]uint16, (1<<2)+2*4)
	if !makeDecodeTable(4, 2, lens, table) {
		t.Fatal("makeDecodeTable failed")
	}
	d := newTestLZX()
	defer d.close()
	// bits: 1,0 then zeros → code '10' = symbol 2
	d.in = bytes.NewReader([]byte{0x00, 0x80})
	sym, err := d.readSym(table, 2, lens, 4)
	if err != nil {
		t.Fatalf("readSym: %v", err)
	}
	if sym != 2 {
		t.Fatalf("sym = %d, want 2", sym)
	}
}

func TestMakeDecodeTableIncomplete(t *testing.T) {
	lens := []byte{2, 2, 2, 0} // Kraft sum 0.75 → incomplete
	table := make([]uint16, (1<<2)+2*4)
	if makeDecodeTable(4, 2, lens, table) {
		t.Fatal("expected failure for incomplete tree")
	}
}

func TestReadLensRuns(t *testing.T) {
	d := newTestLZX()
	defer d.close()
	w := &bitWriter{}
	// Pre-tree: 16 symbols with length 4 (complete: 16×2^-4 = 1).
	// Needed: deltas 1..13 plus run symbols 17/18/19. Canonical codes go to
	// symbols in ascending order: sym 1..13 → codes 0..12,
	// sym 17/18/19 → codes 13/14/15.
	pre := [20]byte{}
	for i := 1; i <= 13; i++ {
		pre[i] = 4
	}
	pre[17], pre[18], pre[19] = 4, 4, 4
	w.emitPretree(pre)
	code := func(sym int) uint32 {
		if sym <= 13 {
			return uint32(sym - 1)
		}
		return uint32(sym - 4) // 17→13, 18→14, 19→15
	}
	// lens[0] = 4 via delta 13
	w.put(code(13), 4)
	// symbol 17: 8 zeros (4-bit payload 4 → 4+4)
	w.put(code(17), 4)
	w.put(4, 4)
	// symbol 18: 22 zeros (5-bit payload 2 → 20+2)
	w.put(code(18), 4)
	w.put(2, 5)
	// symbol 19: 5 copies of (0 - 12 mod 17 = 5)
	w.put(code(19), 4)
	w.put(1, 1)
	w.put(code(12), 4)
	d.in = bytes.NewReader(w.pack())
	lens := make([]byte, 36)
	if err := d.readLens(lens, 0, 36); err != nil {
		t.Fatalf("readLens: %v", err)
	}
	want := make([]byte, 36)
	want[0] = 4
	for i := 31; i < 36; i++ {
		want[i] = 5
	}
	for i := range lens {
		if lens[i] != want[i] {
			t.Fatalf("lens[%d] = %d, want %d", i, lens[i], want[i])
		}
	}
}

func TestLZXLiteralsOnly(t *testing.T) {
	total := lzxFrameSize
	lits := make([]byte, total)
	for i := range lits {
		lits[i] = byte(i * 7)
	}
	w := &bitWriter{}
	w.put(0, 1) // intel filesize = 0 (no E8 translation)
	w.literalsBlock(lits)
	got := decodeLZXFixture(t, w.pack(), total)
	if !bytes.Equal(got, lits) {
		for i := range got {
			if got[i] != lits[i] {
				t.Fatalf("mismatch at %d: got %#x want %#x", i, got[i], lits[i])
			}
		}
	}
}

func TestLZXE8Translation(t *testing.T) {
	total := lzxFrameSize
	filesize := uint32(65536)
	lits := make([]byte, total)
	for i := range lits {
		lits[i] = 0x41
	}
	copy(lits[100:], []byte{0xE8, 0x00, 0x10, 0x00, 0x00}) // abs = 4096
	copy(lits[200:], []byte{0xE8, 0xCE, 0xFF, 0xFF, 0xFF}) // abs = -50
	copy(lits[300:], []byte{0xE8, 0x70, 0x11, 0x01, 0x00}) // abs = 70000 ≥ filesize
	copy(lits[310:], []byte{0xE8, 0xF0, 0x9D, 0xFE, 0xFF}) // abs = -70000
	w := &bitWriter{}
	w.put(1, 1) // intel filesize present
	w.put(filesize>>16, 16)
	w.put(filesize&0xFFFF, 16)
	w.literalsBlock(lits)
	got := decodeLZXFixture(t, w.pack(), total)
	want := append([]byte(nil), lits...)
	put32le := func(off int, v uint32) {
		want[off] = byte(v)
		want[off+1] = byte(v >> 8)
		want[off+2] = byte(v >> 16)
		want[off+3] = byte(v >> 24)
	}
	put32le(101, 4096-100)  // translated: abs - curpos
	put32le(201, -50+65536) // translated: abs + filesize
	// 300 and 310 stay unchanged (abs out of range)
	if !bytes.Equal(got, want) {
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("mismatch at %d: got %#x want %#x", i, got[i], want[i])
			}
		}
	}
}

func TestLZXUncompressedOddSkip(t *testing.T) {
	total := lzxFrameSize
	w := &bitWriter{}
	w.put(0, 1)                 // intel header: no filesize
	w.put(blockUncompressed, 3) // block type 3
	w.put(0, 8)                 // block length (24 bits) = 1
	w.put(0, 8)
	w.put(1, 8)
	w.align16() // raw region starts at a word boundary
	raw := bytes.Buffer{}
	raw.Write([]byte{0x11, 0x11, 0x11, 0x11}) // R0
	raw.Write([]byte{0x22, 0x22, 0x22, 0x22}) // R1
	raw.Write([]byte{0x33, 0x33, 0x33, 0x33}) // R2
	raw.WriteByte(0xAB)                       // one data byte (odd length!)
	raw.WriteByte(0xEE)                       // padding byte the decoder skips
	// Second block: verbatim, 32767 zero literals (finishes the frame).
	w2 := &bitWriter{}
	w2.literalsBlock(make([]byte, total-1))
	stream := append(w.pack(), raw.Bytes()...)
	stream = append(stream, w2.pack()...)
	got := decodeLZXFixture(t, stream, total)
	if got[0] != 0xAB {
		t.Fatalf("first byte = %#x, want 0xAB", got[0])
	}
	for i := 1; i < total; i++ {
		if got[i] != 0 {
			t.Fatalf("byte %d = %#x, want 0", i, got[i])
		}
	}
}

func TestLZXOutOfInput(t *testing.T) {
	d := newTestLZX()
	defer d.close()
	d.in = bytes.NewReader([]byte{0x00}) // 1 real byte; its pair is faked once
	if _, err := d.readBits(16); err != nil {
		t.Fatalf("first readBits: %v", err)
	}
	if _, err := d.readBits(16); err == nil {
		t.Fatal("expected error after input exhausted")
	}
}

func TestLZXZeroLength(t *testing.T) {
	d := newTestLZX()
	defer d.close()
	out := &bytes.Buffer{}
	if err := d.decompress(newFolderStream(bytes.NewReader(nil), 0, 0), out, 0); err != nil {
		t.Fatalf("zero-length decode: %v", err)
	}
	if out.Len() != 0 {
		t.Fatal("expected no output")
	}
}

// TestRealPackageExtraction validates the full pipeline (PE → CAB →
// LZX/stored) against a real Microsoft package. Set VDU_TEST_MPAM to the
// package path to enable; hashes pin package version 1.459.497.0
// (engine 1.1.26080.3, fwlink 121721 redirect of 01.10.2026).
func TestRealPackageExtraction(t *testing.T) {
	pkg := os.Getenv("VDU_TEST_MPAM")
	if pkg == "" {
		t.Skip("VDU_TEST_MPAM not set")
	}
	golden := map[string]string{
		"mpengine.dll":  "0654a5902b3b15d36e48b034e7c75c253b7504a60434bc37d930b3b0a858f079",
		"MpSigStub.exe": "5c3ac01540725e22ca9b7b46a7c21602fdc8dc0f203cc7537962ef7e136685a0",
		"mpasbase.vdm":  "a1eaee9a04019f82dcfeb85337adbb5e2df773b3c5b040639cf6e682f1a47b9f",
		"mpasdlta.vdm":  "56903c941da2ce51a2fecb45956fe7906cde51773ebab8faa48f2b0303c85bc3",
		"mpavbase.vdm":  "38cb628daff54e1dfe83470cd413df0f0c53912fe7b17460826056f4c73a7345",
		"mpavdlta.vdm":  "90298bb2ff05f44633bd4ca5c9e6e993b7b8bce9f673fc754e354ebbed5c91c3",
	}
	out := t.TempDir()
	if err := extractPackage(pkg, out); err != nil {
		t.Fatalf("extractPackage: %v", err)
	}
	for name := range golden {
		data, err := os.ReadFile(fmt.Sprintf("%s/%s", out, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		sum := sha256.Sum256(data)
		t.Logf("%s: %d bytes sha256=%s", name, len(data), hex.EncodeToString(sum[:]))
		if golden[name] != "" && hex.EncodeToString(sum[:]) != golden[name] {
			t.Errorf("%s: sha256 mismatch", name)
		}
	}
}
