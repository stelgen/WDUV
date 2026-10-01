// lzx.h — LZX decompressor (C port of libmspack mspack/lzxd.c, LGPL-2.1).
#ifndef VDU_LZX_H
#define VDU_LZX_H

#include <stddef.h>
#include <stdint.h>

typedef struct lzx_decoder lzx_decoder;

typedef struct {
    int (*read_byte)(void *ud);
    void *ud;
} lzx_in;

typedef struct {
    int (*write)(void *ud, const uint8_t *p, size_t n);
    void *ud;
} lzx_out;

// window_bits: 15..21.
lzx_decoder *lzx_new(int window_bits);
void         lzx_free(lzx_decoder *d);
void         lzx_set_io(lzx_decoder *d, lzx_in in);
// Decompress exactly `total` bytes into the writer. 0 = success.
int          lzx_decompress(lzx_decoder *d, lzx_in in, lzx_out out, int64_t total);

// test accessors
int vdu_read_bits(lzx_decoder *d, int n, uint32_t *out);
int vdu_read_sym(lzx_decoder *d, const uint16_t *table, size_t table_cap,
                 int tab_bits, const uint8_t *lens, int max_syms, int *sym_out);
int vdu_read_lens(lzx_decoder *d, uint8_t *lens, int first, int last);
int vdu_make_decode_table(int nsyms, int nbits, const uint8_t *lens, uint16_t *table, size_t cap);

#endif
