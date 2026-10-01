// fixtures.c — test fixture builders (ports of the verified Go test helpers).
#define _CRT_SECURE_NO_WARNINGS
#include "fixtures.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>

#define BLOCK_VERBATIM_CONST 1

// ---- bit writer ----
void bw_init(bitwriter *w) { w->bits = NULL; w->len = w->cap = 0; }
void bw_free(bitwriter *w) { free(w->bits); w->bits = NULL; w->len = w->cap = 0; }
static void bw_bit(bitwriter *w, uint8_t b) {
    if (w->len == w->cap) {
        w->cap = w->cap ? w->cap * 2 : 256;
        w->bits = realloc(w->bits, w->cap);
    }
    w->bits[w->len++] = b;
}
void bw_put(bitwriter *w, uint32_t v, int n) {
    for (int i = n - 1; i >= 0; i--) bw_bit(w, (uint8_t)((v >> i) & 1));
}
void bw_align16(bitwriter *w) {
    while (w->len % 16 != 0) bw_bit(w, 0);
}
uint8_t *bw_pack(bitwriter *w, size_t *out_len) {
    bw_align16(w);
    uint8_t *out = xmalloc(w->len / 8 + 1);
    for (size_t g = 0; g * 16 < w->len; g++) {
        uint16_t word = 0;
        for (int k = 0; k < 16; k++) word = (uint16_t)(word << 1 | w->bits[g * 16 + k]);
        out[g * 2] = (uint8_t)(word & 0xFF);      // low byte: last 8 stream bits
        out[g * 2 + 1] = (uint8_t)(word >> 8);    // high byte: first 8 stream bits
    }
    *out_len = w->len / 8;
    return out;
}

void simple_pretree(uint8_t out[20]) {
    memset(out, 0, 20);
    for (int i = 0; i < 16; i++) out[i] = 4;
}
void bw_emit_pretree(bitwriter *w, const uint8_t lens[20]) {
    for (int i = 0; i < 20; i++) bw_put(w, lens[i], 4);
}

// verbatim block with a complete 512-symbol main tree (all lengths 9) and an
// empty length tree; literal b is emitted as its 9-bit value.
void bw_literals_block(bitwriter *w, const uint8_t *lits, size_t n) {
    bw_put(w, BLOCK_VERBATIM_CONST, 3);
    bw_put(w, (uint32_t)(n >> 16) & 0xFF, 8);
    bw_put(w, (uint32_t)(n >> 8) & 0xFF, 8);
    bw_put(w, (uint32_t)n & 0xFF, 8);
    uint8_t pre[20];
    simple_pretree(pre);
    bw_emit_pretree(w, pre);                       // readLens #1 (main 0..256)
    for (int x = 0; x < 256; x++) bw_put(w, 8, 4); // delta 8 -> length 9
    bw_emit_pretree(w, pre);                       // readLens #2 (main 256..512)
    for (int x = 256; x < 512; x++) bw_put(w, 8, 4);
    bw_emit_pretree(w, pre);                       // readLens #3 (length tree)
    for (int x = 0; x < 249; x++) bw_put(w, 0, 4); // all zero -> empty
    for (size_t i = 0; i < n; i++) bw_put(w, lits[i], 9);
}

// ---- CAB builder: single folder, stored payload, one file ----
int write_test_cab_stored(const char *path, const uint8_t *payload, size_t plen, int uncomp) {
    (void)uncomp;
    // chunks of <= 32768
    size_t n_blocks = (plen + 32767) / 32768;
    if (n_blocks == 0) n_blocks = 1;

    size_t data_len = 0;
    size_t coff_files = 36 + 8;
    size_t ft_len = strlen("payload.bin") + 1 + 16;
    size_t data_cap = plen + n_blocks * 8 + 64;
    uint8_t *data = xmalloc(data_cap);

    size_t off = 0;
    if (plen == 0) {
        memset(data, 0, 8);
        data_len = 8;
    } else {
        while (off < plen) {
            size_t take = plen - off;
            if (take > 32768) take = 32768;
            uint8_t hdr[8];
            memset(hdr, 0, 4);
            hdr[4] = (uint8_t)take;
            hdr[5] = (uint8_t)(take >> 8);
            hdr[6] = (uint8_t)take;
            hdr[7] = (uint8_t)(take >> 8);
            memcpy(data + data_len, hdr, 8);
            data_len += 8;
            memcpy(data + data_len, payload + off, take);
            data_len += take;
            off += take;
        }
    }

    size_t cab_len = coff_files + ft_len + data_len;
    uint8_t *cab = xmalloc(cab_len);
    size_t o = 0;
    memcpy(cab + o, "MSCF", 4); o += 4;
    memset(cab + o, 0, 4); o += 4;                       // reserved1
    cab[o] = (uint8_t)cab_len; cab[o+1] = (uint8_t)(cab_len >> 8);
    cab[o+2] = (uint8_t)(cab_len >> 16); cab[o+3] = (uint8_t)(cab_len >> 24); o += 4;
    memset(cab + o, 0, 4); o += 4;                       // reserved2
    uint32_t cf = (uint32_t)coff_files;
    cab[o] = (uint8_t)cf; cab[o+1] = (uint8_t)(cf >> 8);
    cab[o+2] = (uint8_t)(cf >> 16); cab[o+3] = (uint8_t)(cf >> 24); o += 4;
    memset(cab + o, 0, 4); o += 4;                       // reserved3
    cab[o++] = 1; cab[o++] = 3;                          // version 1.3
    cab[o++] = 1; cab[o++] = 0;                          // 1 folder
    cab[o++] = 1; cab[o++] = 0;                          // 1 file
    cab[o++] = 0; cab[o++] = 0;                          // flags
    cab[o++] = 1; cab[o++] = 0;                          // setID
    cab[o++] = 0; cab[o++] = 0;                          // iCabinet
    // folder: coffCabStart (rel to cab start) = coff_files + ft_len
    uint32_t coff_cab = (uint32_t)(coff_files + ft_len);
    cab[o] = (uint8_t)coff_cab; cab[o+1] = (uint8_t)(coff_cab >> 8);
    cab[o+2] = (uint8_t)(coff_cab >> 16); cab[o+3] = (uint8_t)(coff_cab >> 24); o += 4;
    cab[o++] = (uint8_t)n_blocks; cab[o++] = (uint8_t)(n_blocks >> 8);
    cab[o++] = 0; cab[o++] = 0;                          // compType = stored
    // file entry
    uint32_t sz = (uint32_t)plen;
    cab[o] = (uint8_t)sz; cab[o+1] = (uint8_t)(sz >> 8);
    cab[o+2] = (uint8_t)(sz >> 16); cab[o+3] = (uint8_t)(sz >> 24); o += 4;
    cab[o++] = 0; cab[o++] = 0; cab[o++] = 0; cab[o++] = 0; // pos = 0
    cab[o++] = 0; cab[o++] = 0;                          // folder 0
    cab[o++] = 0; cab[o++] = 0;                          // date
    cab[o++] = 0; cab[o++] = 0;                          // time
    cab[o++] = 0x20; cab[o++] = 0;                       // attrs
    memcpy(cab + o, "payload.bin", 11); o += 11;
    cab[o++] = 0;
    memcpy(cab + o, data, data_len); o += data_len;

    int rc = write_file(path, cab, cab_len);
    free(cab);
    free(data);
    return rc;
}

int write_test_cab_mszip(const char *path, const uint8_t *payload, size_t plen, int uncomp) {
    // same layout but compType = MSZIP; the extractor must reject it
    int rc = write_test_cab_stored(path, payload, plen, uncomp);
    if (rc != 0) return rc;
    // patch the folder compType (offset 36+8+4+2 = 50)
    size_t n;
    uint8_t *d = read_file(path, &n);
    if (!d) return -1;
    d[50] = 2; d[51] = 0;
    rc = write_file(path, d, n);
    free(d);
    return rc;
}

int write_test_cab_pe(const char *path, const uint8_t *cab, size_t cab_len) {
    size_t total = 0x400 + cab_len;
    uint8_t *b = xmalloc(total);
    memset(b, 0, total);
    b[0] = 'M'; b[1] = 'Z';
    uint8_t *pep = b + 0x3c;
    pep[0] = 0x80; pep[1] = 0; pep[2] = 0; pep[3] = 0;
    memcpy(b + 0x80, "PE\0\0", 4);
    b[0x84] = 0x4c; b[0x85] = 0x01;      // machine i386
    b[0x86] = 1; b[0x87] = 0;            // 1 section
    b[0x94] = 224; b[0x95] = 0;          // SizeOfOptionalHeader
    b[0x96] = 0x02; b[0x97] = 0x01;      // characteristics
    b[0x98] = 0x0B; b[0x99] = 0x01;      // PE32 magic
    uint8_t *sec = b + 0x98 + 224;
    memcpy(sec, ".rsrc", 5);
    uint8_t *p32 = sec + 8;
    for (int i = 0; i < 4; i++) p32[i] = (uint8_t)(cab_len >> (8 * i));
    for (int i = 0; i < 4; i++) p32[4 + i] = (uint8_t)(0x1000 >> (8 * i));
    for (int i = 0; i < 4; i++) p32[8 + i] = (uint8_t)(cab_len >> (8 * i));
    for (int i = 0; i < 4; i++) p32[12 + i] = (uint8_t)(0x400 >> (8 * i));
    memcpy(b + 0x400, cab, cab_len);
    int rc = write_file(path, b, total);
    free(b);
    return rc;
}

int write_test_versioninfo(const char *path, const char *version) {
    const char *key = "FileVersion";
    size_t vl = strlen(version), kl = strlen(key) + 1;
    size_t total = 0x400 + 512;
    uint8_t *b = xmalloc(total);
    memset(b, 0, total);
    b[0] = 'M'; b[1] = 'Z';
    b[0x3c] = 0x80; b[0x3d] = 0; b[0x3e] = 0; b[0x3f] = 0;
    memcpy(b + 0x80, "PE\0\0", 4);
    b[0x84] = 0x4c; b[0x85] = 0x01;
    b[0x86] = 1; b[0x87] = 0;
    b[0x94] = 224; b[0x95] = 0;
    b[0x96] = 0x02; b[0x97] = 0x01;

    uint8_t *v = b + 0x400;
    // VS_VERSION_INFO header
    size_t p = 0;
    v[p++] = 0; v[p++] = 0; // wLength patched later (u16)
    size_t wlen_pos = 0;
    (void)wlen_pos;
    v[p++] = 52; v[p++] = 0; // wValueLength
    v[p++] = 0; v[p++] = 0;  // wType
    const char *sig = "VS_VERSION_INFO";
    for (size_t i = 0; i <= strlen(sig); i++) { v[p++] = (uint8_t)sig[i]; v[p++] = 0; }
    while (p % 4) p++;
    p += 52; // VS_FIXEDFILEINFO
    // String block
    uint8_t *s = v + p;
    size_t q = 0;
    s[q++] = 0; s[q++] = 0; // wLength (unused by parser)
    s[q++] = (uint8_t)((vl + 1) * 2); s[q++] = 0; // wValueLength
    s[q++] = 1; s[q++] = 0; // wType = text
    for (size_t i = 0; i < kl; i++) { s[q++] = (uint8_t)key[i]; s[q++] = 0; }
    while (q % 4) q++;
    for (size_t i = 0; i <= vl; i++) { s[q++] = (uint8_t)version[i]; s[q++] = 0; }
    return write_file(path, b, total);
}
