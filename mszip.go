package main

import (
	"bytes"
	"compress/flate"
	"fmt"
	"io"
)

// mszipDecoder decodes MSZIP folders. Each CFDATA block carries an
// independent deflate stream (prefixed by the two-byte "CK" marker) whose
// uncompressed size never exceeds 32 KiB. Blocks are processed one at a
// time from the raw payload so the deflate reader can never bleed into the
// following block.
type mszipDecoder struct{}

func (*mszipDecoder) decompress(fs *folderStream, w io.Writer, total int64) error {
	written := int64(0)
	buf := make([]byte, 32*1024)
	for written < total {
		block, err := fs.nextBlock()
		if err != nil {
			return fmt.Errorf("mszip: %w", err)
		}
		ck := bytes.Index(block, []byte("CK"))
		if ck < 0 {
			return fmt.Errorf("mszip: CK marker not found in %d-byte block", len(block))
		}
		zr := flate.NewReader(bytes.NewReader(block[ck+2:]))
		n, rerr := io.ReadFull(zr, buf)
		zr.Close()
		if rerr != nil && rerr != io.EOF && rerr != io.ErrUnexpectedEOF {
			return fmt.Errorf("mszip: inflate: %w", rerr)
		}
		if n > 32*1024 {
			return fmt.Errorf("mszip: block output %d exceeds 32 KiB", n)
		}
		nn := int64(n)
		if written+nn > total {
			nn = total - written
		}
		if _, werr := w.Write(buf[:nn]); werr != nil {
			return werr
		}
		written += nn
	}
	return nil
}
