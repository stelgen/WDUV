// fixtures.h — shared test fixture builders (bit writer, pretree, CAB).
#ifndef VDU_FIXTURES_H
#define VDU_FIXTURES_H

#include <stddef.h>
#include <stdint.h>

// bit writer: stream bits MSB-first, packed into 16-bit LE words
typedef struct { uint8_t *bits; size_t len, cap; } bitwriter;
void bw_init(bitwriter *w);
void bw_free(bitwriter *w);
void bw_put(bitwriter *w, uint32_t v, int n);
void bw_align16(bitwriter *w);
uint8_t *bw_pack(bitwriter *w, size_t *out_len);

// pretree used by the literal fixtures: symbols 0..15 length 4
void simple_pretree(uint8_t out[20]);
void bw_emit_pretree(bitwriter *w, const uint8_t lens[20]);

// verbatim block of `lits` (window 16 → 512 main symbols @9, empty length tree)
void bw_literals_block(bitwriter *w, const uint8_t *lits, size_t n);

// CAB fixtures
int write_test_cab_stored(const char *path, const uint8_t *payload, size_t plen, int uncomp);
int write_test_cab_mszip(const char *path, const uint8_t *payload, size_t plen, int uncomp);
int write_test_cab_pe(const char *path, const uint8_t *cab, size_t cab_len);
int write_test_versioninfo(const char *path, const char *version);

#endif
