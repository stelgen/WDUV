package main

import (
	"errors"
	"fmt"
	"io"
)

// lzxDecoder is a faithful Go port of libmspack's LZX decompressor
// (mspack/lzxd.c, LGPL 2.1 — see docs/ANALYSIS.md for provenance notes).
// It handles the exact bitstream Microsoft's CAB LZX variant produces:
// 16-bit little-endian words read MSB-first, three block types (verbatim,
// aligned-offset, uncompressed), repeated-offset LRU, per-frame E8/E9
// translation and a final short frame sized by setLength().
//
// Regular CAB LZX supports windows of 2^15 .. 2^21 bytes.

const (
	lzxNumChars            = 256
	lzxNumPrimaryLengths   = 7
	lzxNumSecondaryLengths = 249
	lzxMinMatch            = 2
	lzxFrameSize           = 32768
	lzxMaxCodeLength       = 16

	blockVerbatim     = 1
	blockAligned      = 2
	blockUncompressed = 3
)

// Static tables from lzxd.c. position_slots[window_bits-15] gives the
// number of position slots for the window; extra_bits/position_base are
// indexed by slot (slot >= 36 uses extra_bits == 17).
var positionSlots = [11]int{30, 32, 34, 36, 38, 42, 50, 66, 98, 162, 290}

var extraBits = [36]byte{
	0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6,
	7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13, 14, 14,
	15, 15, 16, 16,
}

var positionBase = [290]uint32{
	0, 1, 2, 3, 4, 6, 8, 12, 16, 24, 32, 48, 64, 96, 128, 192, 256, 384, 512,
	768, 1024, 1536, 2048, 3072, 4096, 6144, 8192, 12288, 16384, 24576, 32768,
	49152, 65536, 98304, 131072, 196608, 262144, 393216, 524288, 655360,
	786432, 917504, 1048576, 1179648, 1310720, 1441792, 1572864, 1703936,
	1835008, 1966080, 2097152, 2228224, 2359296, 2490368, 2621440, 2752512,
	2883584, 3014656, 3145728, 3276800, 3407872, 3538944, 3670016, 3801088,
	3932160, 4063232, 4194304, 4325376, 4456448, 4587520, 4718592, 4849664,
	4980736, 5111808, 5242880, 5373952, 5505024, 5636096, 5767168, 5898240,
	6029312, 6160384, 6291456, 6422528, 6553600, 6684672, 6815744, 6946816,
	7077888, 7208960, 7340032, 7471104, 7602176, 7733248, 7864320, 7995392,
	8126464, 8257536, 8388608, 8519680, 8650752, 8781824, 8912896, 9043968,
	9175040, 9306112, 9437184, 9568256, 9699328, 9830400, 9961472, 10092544,
	10223616, 10354688, 10485760, 10616832, 10747904, 10878976, 11010048,
	11141120, 11272192, 11403264, 11534336, 11665408, 11796480, 11927552,
	12058624, 12189696, 12320768, 12451840, 12582912, 12713984, 12845056,
	12976128, 13107200, 13238272, 13369344, 13500416, 13631488, 13762560,
	13893632, 14024704, 14155776, 14286848, 14417920, 14548992, 14680064,
	14811136, 14942208, 15073280, 15204352, 15335424, 15466496, 15597568,
	15728640, 15859712, 15990784, 16121856, 16252928, 16384000, 16515072,
	16646144, 16777216, 16908288, 17039360, 17170432, 17301504, 17432576,
	17563648, 17694720, 17825792, 17956864, 18087936, 18219008, 18350080,
	18481152, 18612224, 18743296, 18874368, 19005440, 19136512, 19267584,
	19398656, 19529728, 19660800, 19791872, 19922944, 20054016, 20185088,
	20316160, 20447232, 20578304, 20709376, 20840448, 20971520, 21102592,
	21233664, 21364736, 21495808, 21626880, 21757952, 21889024, 22020096,
	22151168, 22282240, 22413312, 22544384, 22675456, 22806528, 22937600,
	23068672, 23199744, 23330816, 23461888, 23592960, 23724032, 23855104,
	23986176, 24117248, 24248320, 24379392, 24510464, 24641536, 24772608,
	24903680, 25034752, 25165824, 25296896, 25427968, 25559040, 25690112,
	25821184, 25952256, 26083328, 26214400, 26345472, 26476544, 26607616,
	26738688, 26869760, 27000832, 27131904, 27262976, 27394048, 27525120,
	27656192, 27787264, 27918336, 28049408, 28180480, 28311552, 28442624,
	28573696, 28704768, 28835840, 28966912, 29097984, 29229056, 29360128,
	29491200, 29622272, 29753344, 29884416, 30015488, 30146560, 30277632,
	30408704, 30539776, 30670848, 30801920, 30932992, 31064064, 31195136,
	31326208, 31457280, 31588352, 31719424, 31850496, 31981568, 32112640,
	32243712, 32374784, 32505856, 32636928, 32768000, 32899072, 33030144,
	33161216, 33292288, 33423360,
}

type lzxDecoder struct {
	in interface {
		io.Reader
		io.ByteReader
	}
	bb         uint32
	bl         int
	fakeEOF    bool
	numOffsets int
	maxSyms    int

	window      []byte
	windowSize  int
	windowPosn  int
	framePosn   int
	frame       int
	offset      int64
	length      int64
	r0, r1, r2  uint32
	headerRead  bool
	intelSize   int64
	intelStart  bool
	blockType   int
	blockRemain int
	blockLen    int
	lenEmpty    bool

	mlens [256 + 290*8]byte
	mtab  []uint16
	llens [lzxNumSecondaryLengths + 1]byte
	ltab  []uint16
	plens [20]byte
	ptab  []uint16
	alens [8]byte
	atab  []uint16

	e8buf [lzxFrameSize]byte
}

func newLZXDecoder(windowBits int) (*lzxDecoder, error) {
	if windowBits < 15 || windowBits > 21 {
		return nil, fmt.Errorf("LZX window %d out of range 15..21", windowBits)
	}
	slots := positionSlots[windowBits-15]
	d := &lzxDecoder{
		numOffsets: slots * 8,
		maxSyms:    lzxNumChars + slots*8,
		windowSize: 1 << windowBits,
		r0:         1,
		r1:         1,
		r2:         1,
		blockType:  -1,
	}
	d.mtab = make([]uint16, (1<<12)+2*len(d.mlens))
	d.ltab = make([]uint16, (1<<12)+2*len(d.llens))
	d.ptab = make([]uint16, (1<<6)+2*len(d.plens))
	d.atab = make([]uint16, (1<<7)+2*len(d.alens))
	d.window = make([]byte, d.windowSize)
	return d, nil
}

func (d *lzxDecoder) close() { d.window = nil }

// ---- bit reader: 16-bit little-endian words, consumed MSB-first ----

func (d *lzxDecoder) ensure(n int) error {
	for d.bl < n {
		b0, err := d.in.ReadByte()
		fake := false
		if err != nil {
			if err != io.EOF {
				return errors.New("lzx: input error")
			}
			if d.fakeEOF {
				return errors.New("lzx: out of input")
			}
			d.fakeEOF = true
			fake = true
			b0 = 0
		}
		b1, err := d.in.ReadByte()
		if err != nil {
			if err == io.EOF && (fake || !d.fakeEOF) {
				if !fake {
					d.fakeEOF = true
				}
				b1 = 0
			} else if err != nil {
				return errors.New("lzx: out of input")
			}
		}
		d.bb |= (uint32(b1)<<8 | uint32(b0)) << uint(16-d.bl)
		d.bl += 16
	}
	return nil
}

func (d *lzxDecoder) peek(n int) uint32 {
	return d.bb >> uint(32-n)
}

func (d *lzxDecoder) remove(n int) {
	d.bb <<= uint(n)
	d.bl -= n
}

func (d *lzxDecoder) readBits(n int) (uint32, error) {
	if err := d.ensure(n); err != nil {
		return 0, err
	}
	v := d.peek(n)
	d.remove(n)
	return v, nil
}

// readSym decodes one Huffman symbol using a canonical lookup table built
// by makeDecodeTable (MSB variant).
func (d *lzxDecoder) readSym(table []uint16, tabBits int, lens []byte, maxSyms int) (int, error) {
	if err := d.ensure(lzxMaxCodeLength); err != nil {
		return 0, err
	}
	sym := table[d.peek(tabBits)]
	if sym >= uint16(maxSyms) {
		if sym == 0xFFFF {
			return 0, errors.New("lzx: invalid huffman code")
		}
		mask := uint32(1) << uint(32-tabBits)
		for {
			mask >>= 1
			if mask == 0 {
				return 0, errors.New("lzx: huffman traversal overrun")
			}
			bit := uint32(0)
			if d.bb&mask != 0 {
				bit = 1
			}
			idx := int(sym)<<1 | int(bit)
			if idx >= len(table) {
				return 0, errors.New("lzx: huffman table overrun")
			}
			sym = table[idx]
			if sym < uint16(maxSyms) {
				break
			}
		}
	}
	ln := int(lens[sym])
	if ln == 0 {
		return 0, errors.New("lzx: zero-length huffman code")
	}
	d.remove(ln)
	return int(sym), nil
}

// makeDecodeTable builds a canonical Huffman lookup table (David
// Tritscher's algorithm, MSB-first variant from readhuff.h).
func makeDecodeTable(nsyms, nbits int, lens []byte, table []uint16) bool {
	pos := 0
	tableMask := 1 << nbits
	bitMask := tableMask >> 1
	for bitNum := 1; bitNum <= nbits; bitNum++ {
		for sym := 0; sym < nsyms; sym++ {
			if lens[sym] != byte(bitNum) {
				continue
			}
			leaf := pos
			pos += bitMask
			if pos > tableMask {
				return false
			}
			for f := bitMask; f > 0; f-- {
				table[leaf] = uint16(sym)
				leaf++
			}
		}
		bitMask >>= 1
	}
	if pos == tableMask {
		return true
	}
	for sym := pos; sym < tableMask; sym++ {
		table[sym] = 0xFFFF
	}
	nextSymbol := tableMask >> 1
	if nsyms > nextSymbol {
		nextSymbol = nsyms
	}
	pos <<= 16
	tableMask <<= 16
	bitMask = 1 << 15
	for bitNum := nbits + 1; bitNum <= lzxMaxCodeLength; bitNum++ {
		for sym := 0; sym < nsyms; sym++ {
			if lens[sym] != byte(bitNum) {
				continue
			}
			if pos >= tableMask {
				return false
			}
			leaf := pos >> 16
			for f := 0; f < bitNum-nbits; f++ {
				if table[leaf] == 0xFFFF {
					table[nextSymbol<<1] = 0xFFFF
					table[nextSymbol<<1+1] = 0xFFFF
					table[leaf] = uint16(nextSymbol)
					nextSymbol++
				}
				leaf = int(table[leaf]) << 1
				if pos>>uint(15-f)&1 != 0 {
					leaf++
				}
			}
			table[leaf] = uint16(sym)
			pos += bitMask
		}
		bitMask >>= 1
	}
	return pos == tableMask
}

// readLens reads LZX delta-encoded code lengths (via the pre-tree) into
// lens[first:last].
func (d *lzxDecoder) readLens(lens []byte, first, last int) error {
	for x := 0; x < 20; x++ {
		v, err := d.readBits(4)
		if err != nil {
			return err
		}
		d.plens[x] = byte(v)
	}
	if !makeDecodeTable(len(d.plens), 6, d.plens[:], d.ptab) {
		return errors.New("lzx: bad pretree")
	}
	for x := first; x < last; {
		z, err := d.readSym(d.ptab, 6, d.plens[:], len(d.plens))
		if err != nil {
			return err
		}
		switch {
		case z == 17:
			y, err := d.readBits(4)
			if err != nil {
				return err
			}
			y += 4
			if x+int(y) > last {
				return errors.New("lzx: length run overrun")
			}
			for ; y > 0; y-- {
				lens[x] = 0
				x++
			}
		case z == 18:
			y, err := d.readBits(5)
			if err != nil {
				return err
			}
			y += 20
			if x+int(y) > last {
				return errors.New("lzx: length run overrun")
			}
			for ; y > 0; y-- {
				lens[x] = 0
				x++
			}
		case z == 19:
			y, err := d.readBits(1)
			if err != nil {
				return err
			}
			y += 4
			z2, err := d.readSym(d.ptab, 6, d.plens[:], len(d.plens))
			if err != nil {
				return err
			}
			nz := int(lens[x]) - int(z2)
			if nz < 0 {
				nz += 17
			}
			if x+int(y) > last {
				return errors.New("lzx: length run overrun")
			}
			for ; y > 0; y-- {
				lens[x] = byte(nz)
				x++
			}
		default:
			nz := int(lens[x]) - z
			if nz < 0 {
				nz += 17
			}
			lens[x] = byte(nz)
			x++
		}
	}
	return nil
}

// decompress decodes the whole folder stream (total bytes) into w.
func (d *lzxDecoder) decompress(fs *folderStream, w io.Writer, total int64) error {
	d.in = fs
	defer func() { d.in = nil }()
	if d.length == 0 {
		// The caller knows the folder's uncompressed size; record it up
		// front so the final frame is sized correctly.
		d.length = total
	}
	return d.decompressN(w, total)
}

func (d *lzxDecoder) decompressN(w io.Writer, outBytes int64) error {
	if outBytes < 0 {
		return errors.New("lzx: negative length")
	}
	if outBytes == 0 {
		return nil
	}
	outRemaining := outBytes
	endFrame := (d.offset+outBytes)/lzxFrameSize + 1
	for int64(d.frame) < endFrame {
		if !d.headerRead {
			i, err := d.readBits(1)
			if err != nil {
				return err
			}
			var lo, hi uint32
			if i == 1 {
				if lo, err = d.readBits(16); err != nil {
					return err
				}
				if hi, err = d.readBits(16); err != nil {
					return err
				}
			}
			d.intelSize = int64(lo<<16 | hi)
			d.headerRead = true
		}
		frameSize := int64(lzxFrameSize)
		if d.length != 0 && d.length-d.offset < frameSize {
			frameSize = d.length - d.offset
		}
		bytesTodo := int64(d.framePosn) + frameSize - int64(d.windowPosn)
		for bytesTodo > 0 {
			if d.blockRemain == 0 {
				if err := d.startBlock(); err != nil {
					return err
				}
			}
			thisRun := int64(d.blockRemain)
			if thisRun > bytesTodo {
				thisRun = bytesTodo
			}
			bytesTodo -= thisRun
			d.blockRemain -= int(thisRun)
			switch d.blockType {
			case blockVerbatim, blockAligned:
				if err := d.decodeCompressed(thisRun); err != nil {
					return err
				}
			case blockUncompressed:
				n := int(thisRun)
				if d.windowPosn+n > d.windowSize {
					return errors.New("lzx: uncompressed block overruns window")
				}
				if _, err := io.ReadFull(d.in, d.window[d.windowPosn:d.windowPosn+n]); err != nil {
					return errors.New("lzx: out of input (uncompressed block)")
				}
				d.windowPosn += n
				d.intelStart = true
			default:
				return errors.New("lzx: bad block type")
			}
		}
		if int64(d.windowPosn-d.framePosn) != frameSize {
			return fmt.Errorf("lzx: frame %d produced %d of %d bytes", d.frame, d.windowPosn-d.framePosn, frameSize)
		}
		if d.bl > 0 {
			if err := d.ensure(16); err != nil {
				return err
			}
		}
		if d.bl&15 != 0 {
			d.remove(d.bl & 15)
		}
		// Frame output: apply E8/E9 translation when needed, then write.
		fsz := int(frameSize)
		out := d.window[d.framePosn : d.framePosn+fsz]
		if d.intelStart && d.intelSize != 0 && d.frame < 32768 && fsz > 10 {
			d.translateFrame(fsz)
			out = d.e8buf[:fsz]
		}
		n := outRemaining
		if n > frameSize {
			n = frameSize
		}
		if _, err := w.Write(out[:int(n)]); err != nil {
			return err
		}
		d.offset += n
		outRemaining -= n
		d.framePosn += int(frameSize)
		d.frame++
		if d.windowPosn == d.windowSize {
			d.windowPosn = 0
		}
		if d.framePosn == d.windowSize {
			d.framePosn = 0
		}
	}
	if outRemaining != 0 {
		return fmt.Errorf("lzx: %d bytes left after final frame", outRemaining)
	}
	return nil
}

// startBlock reads a new block header (type, length, trees).
func (d *lzxDecoder) startBlock() error {
	// Realign after an odd-sized uncompressed block.
	if d.blockType == blockUncompressed && d.blockLen&1 == 1 {
		if _, err := d.in.ReadByte(); err != nil {
			return errors.New("lzx: out of input (align)")
		}
	}
	t, err := d.readBits(3)
	if err != nil {
		return err
	}
	hi, err := d.readBits(16)
	if err != nil {
		return err
	}
	lo, err := d.readBits(8)
	if err != nil {
		return err
	}
	d.blockLen = int(hi)<<8 | int(lo)
	d.blockRemain = d.blockLen
	switch t {
	case blockAligned:
		for i := 0; i < 8; i++ {
			v, err := d.readBits(3)
			if err != nil {
				return err
			}
			d.alens[i] = byte(v)
		}
		if !makeDecodeTable(len(d.alens), 7, d.alens[:], d.atab) {
			return errors.New("lzx: bad aligned tree")
		}
		fallthrough
	case blockVerbatim:
		if err := d.readLens(d.mlens[:], 0, lzxNumChars); err != nil {
			return err
		}
		if err := d.readLens(d.mlens[:], lzxNumChars, d.maxSyms); err != nil {
			return err
		}
		if !makeDecodeTable(len(d.mlens), 12, d.mlens[:], d.mtab) {
			return errors.New("lzx: bad main tree")
		}
		if d.mlens[0xE8] != 0 {
			d.intelStart = true
		}
		if err := d.readLens(d.llens[:], 0, lzxNumSecondaryLengths); err != nil {
			return err
		}
		d.lenEmpty = false
		if !makeDecodeTable(len(d.llens), 12, d.llens[:], d.ltab) {
			empty := true
			for _, l := range d.llens {
				if l != 0 {
					empty = false
					break
				}
			}
			if !empty {
				return errors.New("lzx: bad length tree")
			}
			d.lenEmpty = true
		}
	case blockUncompressed:
		d.intelStart = true
		if d.bl == 0 {
			if err := d.ensure(16); err != nil {
				return err
			}
		}
		d.bl = 0
		d.bb = 0
		var buf [12]byte
		if _, err := io.ReadFull(d.in, buf[:]); err != nil {
			return errors.New("lzx: out of input (R0/R1/R2)")
		}
		d.r0 = le32(buf[:], 0)
		d.r1 = le32(buf[:], 4)
		d.r2 = le32(buf[:], 8)
	default:
		return fmt.Errorf("lzx: bad block type %d", t)
	}
	d.blockType = int(t)
	return nil
}

// decodeCompressed decodes thisRun bytes of a verbatim/aligned block into
// the window. Mirrors lzxd.c's symbol loop, including the window-wrap copy
// semantics (the source can straddle the window's end).
func (d *lzxDecoder) decodeCompressed(thisRun int64) error {
	for thisRun > 0 {
		mainElement, err := d.readSym(d.mtab, 12, d.mlens[:], len(d.mlens))
		if err != nil {
			return err
		}
		if mainElement < lzxNumChars {
			d.window[d.windowPosn] = byte(mainElement)
			d.windowPosn++
			thisRun--
			continue
		}
		e := mainElement - lzxNumChars
		matchLength := e & lzxNumPrimaryLengths
		if matchLength == lzxNumPrimaryLengths {
			if d.lenEmpty {
				return errors.New("lzx: LENGTH symbol needed but tree is empty")
			}
			footer, err := d.readSym(d.ltab, 12, d.llens[:], len(d.llens))
			if err != nil {
				return err
			}
			matchLength += footer
		}
		matchLength += lzxMinMatch

		slot := e >> 3
		var matchOffset uint32
		switch slot {
		case 0:
			matchOffset = d.r0
		case 1:
			matchOffset = d.r1
			d.r1 = d.r0
			d.r0 = matchOffset
		case 2:
			matchOffset = d.r2
			d.r2 = d.r0
			d.r0 = matchOffset
		default:
			extra := 17
			if slot < 36 {
				extra = int(extraBits[slot])
			}
			matchOffset = positionBase[slot] - 2
			if extra >= 3 && d.blockType == blockAligned {
				if extra > 3 {
					vb, err := d.readBits(extra - 3)
					if err != nil {
						return err
					}
					matchOffset += vb << 3
				}
				ab, err := d.readSym(d.atab, 7, d.alens[:], len(d.alens))
				if err != nil {
					return err
				}
				matchOffset += uint32(ab)
			} else if extra > 0 {
				vb, err := d.readBits(extra)
				if err != nil {
					return err
				}
				matchOffset += vb
			}
			d.r2 = d.r1
			d.r1 = d.r0
			d.r0 = matchOffset
		}

		if d.windowPosn+matchLength > d.windowSize {
			return errors.New("lzx: match overruns window")
		}
		i := matchLength
		if matchOffset > uint32(d.windowPosn) {
			// Source is (virtually) before the window start: copy runs across
			// the wrap. libmspack checks the distance against the total output
			// here (reference data is not supported for regular LZX).
			if int64(matchOffset) > d.offset {
				return errors.New("lzx: match offset beyond stream")
			}
			j := int(matchOffset - uint32(d.windowPosn))
			if j > d.windowSize {
				return errors.New("lzx: match offset beyond window")
			}
			runsrc := d.windowSize - j
			if j < i {
				i -= j
				for k := 0; k < j; k++ {
					d.window[d.windowPosn+k] = d.window[runsrc+k]
				}
				d.windowPosn += j
				runsrc = 0
			}
			for k := 0; k < i; k++ {
				d.window[d.windowPosn+k] = d.window[runsrc+k]
			}
			d.windowPosn += i
		} else {
			runsrc := d.windowPosn - int(matchOffset)
			for k := 0; k < i; k++ {
				d.window[d.windowPosn+k] = d.window[runsrc+k]
			}
			d.windowPosn += i
		}
		thisRun -= int64(matchLength)
	}
	if thisRun < 0 {
		if -thisRun > int64(d.blockRemain) {
			return errors.New("lzx: match overrun past end of block")
		}
		d.blockRemain -= int(-thisRun)
	}
	return nil
}

// translateFrame applies the E8/E9 call-transform to one frame of decoded
// output (in place in d.e8buf), exactly as lzxd.c does.
func (d *lzxDecoder) translateFrame(frameSize int) {
	copy(d.e8buf[:frameSize], d.window[d.framePosn:d.framePosn+frameSize])
	curpos := int32(d.offset)
	filesize := int32(d.intelSize)
	data := 0
	dataend := frameSize - 10
	for data < dataend {
		if d.e8buf[data] != 0xE8 {
			data++
			curpos++
			continue
		}
		absOff := int32(le32(d.e8buf[:], data+1))
		if absOff >= -curpos && absOff < filesize {
			var relOff int32
			if absOff >= 0 {
				relOff = absOff - curpos
			} else {
				relOff = absOff + filesize
			}
			d.e8buf[data+1] = byte(relOff)
			d.e8buf[data+2] = byte(relOff >> 8)
			d.e8buf[data+3] = byte(relOff >> 16)
			d.e8buf[data+4] = byte(relOff >> 24)
		}
		data += 5
		curpos += 5
	}
}
