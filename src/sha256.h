// sha256.h — FIPS 180-4 SHA-256 (compact implementation).
#ifndef VDU_SHA256_H
#define VDU_SHA256_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t h[8];
    uint64_t bits;
    uint8_t  buf[64];
    size_t   buflen;
} vdu_sha256;

void vdu_sha256_init(vdu_sha256 *c);
void vdu_sha256_update(vdu_sha256 *c, const void *data, size_t len);
void vdu_sha256_final(vdu_sha256 *c, uint8_t out[32]);
void vdu_sha256_buf(const void *data, size_t len, uint8_t out[32]);

#endif
