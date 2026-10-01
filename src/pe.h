// pe.h — minimal PE parsing: locate the embedded CAB inside .rsrc and read
// VS_VERSIONINFO FileVersion (for engine/definition version reporting).
#ifndef VDU_PE_H
#define VDU_PE_H

#include <stdint.h>
#include <stdio.h>

// Find the MSCF cabinet inside the package: prefers the .rsrc section,
// falls back to a whole-file scan. Returns 0 and fills cab_off/cab_len.
int pe_find_cab(FILE *f, int64_t file_size, int64_t *cab_off, int64_t *cab_len);

// Parse VS_VERSIONINFO in a PE image buffer; copy the FileVersion string
// (e.g. "1.2.1009.0") into out (truncated to outsz). Returns 0 on success.
int pe_file_version(const uint8_t *data, size_t len, char *out, size_t outsz);

uint16_t vdu_le16(const uint8_t *b, size_t off);
uint32_t vdu_le32(const uint8_t *b, size_t off);

#endif
