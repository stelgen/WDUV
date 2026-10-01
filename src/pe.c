#include "pe.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>

uint16_t vdu_le16(const uint8_t *b, size_t off) {
    return (uint16_t)(b[off] | b[off + 1] << 8);
}

uint32_t vdu_le32(const uint8_t *b, size_t off) {
    return (uint32_t)b[off] | (uint32_t)b[off + 1] << 8 |
           (uint32_t)b[off + 2] << 16 | (uint32_t)b[off + 3] << 24;
}

static const uint8_t MSCF[4] = { 'M', 'S', 'C', 'F' };

// Validate the CFHEADER at absolute offset `off`; on success set *out_len.
static int valid_cab_at(FILE *f, int64_t off, int64_t file_size, int64_t *out_len) {
    uint8_t h[36];
    if (off < 0) return 0;
    if (fseek(f, (long)off, SEEK_SET) != 0) return 0;
    if (fread(h, 1, 36, f) != 36) return 0;
    if (memcmp(h, MSCF, 4) != 0) return 0;
    int64_t cb_cabinet = (int64_t)vdu_le32(h, 8);
    int64_t coff_files = (int64_t)vdu_le32(h, 16);
    int num_folders = vdu_le16(h, 26);
    int num_files = vdu_le16(h, 28);
    if (cb_cabinet < 36 || coff_files < 36 || coff_files >= cb_cabinet) return 0;
    if (num_folders == 0 || num_folders > 1024 || num_files == 0 || num_files > 65535) return 0;
    if (off + cb_cabinet > file_size) return 0;
    *out_len = cb_cabinet;
    return 1;
}

int pe_find_cab(FILE *f, int64_t file_size, int64_t *cab_off, int64_t *cab_len) {
    // try the .rsrc section first
    uint8_t head[4096];
    long headn = (long)(file_size < (int64_t)sizeof(head) ? file_size : (int64_t)sizeof(head));
    int have_rsrc = 0;
    int64_t rs_start = 0, rs_len = 0;
    if (headn >= 0x100 && fseek(f, 0, SEEK_SET) == 0 && fread(head, 1, (size_t)headn, f) == (size_t)headn) {
        if (head[0] == 'M' && head[1] == 'Z') {
            int32_t pe_off = (int32_t)vdu_le32(head, 0x3c);
            if (pe_off > 0 && pe_off + 248 <= headn && memcmp(head + pe_off, "PE\0\0", 4) == 0) {
                int nsec = vdu_le16(head, pe_off + 6);
                int optsize = vdu_le16(head, pe_off + 20);
                int64_t sectab = pe_off + 24 + optsize;
                if (sectab + (int64_t)nsec * 40 <= headn) {
                    for (int i = 0; i < nsec; i++) {
                        const uint8_t *so = head + sectab + (size_t)i * 40;
                        char name[9];
                        memcpy(name, so, 8);
                        name[8] = 0;
                        if (strncmp(name, ".rsrc", 5) == 0) {
                            int64_t raddr = (int64_t)vdu_le32(so, 20);
                            int64_t rsz = (int64_t)vdu_le32(so, 16);
                            if (rsz > 0 && raddr + rsz <= file_size) {
                                rs_start = raddr;
                                rs_len = rsz;
                                have_rsrc = 1;
                            }
                            break;
                        }
                    }
                }
            }
        }
    }

    for (int pass = 0; pass < 2; pass++) {
        int64_t start, length;
        if (pass == 0 && !have_rsrc) continue;
        if (pass == 0) { start = rs_start; length = rs_len; }
        else { start = 0; length = file_size; }

        const int64_t chunk = 4 << 20;
        uint8_t *buf = xmalloc((size_t)chunk + 8);
        int64_t pos = start;
        while (pos < start + length) {
            long want = (long)(start + length - pos);
            if (want > chunk + 8) want = (long)(chunk + 8);
            if (fseek(f, (long)pos, SEEK_SET) != 0) break;
            long n = (long)fread(buf, 1, (size_t)want, f);
            if (n <= 0) break;
            for (long i = 0; i + 4 <= n; i++) {
                if (memcmp(buf + i, MSCF, 4) == 0) {
                    int64_t ln;
                    if (valid_cab_at(f, pos + i, file_size, &ln)) {
                        free(buf);
                        *cab_off = pos + i;
                        *cab_len = ln;
                        return 0;
                    }
                }
            }
            if (n < chunk + 8) break;
            pos += n - 8; // overlap so headers crossing chunks are found
        }
        free(buf);
    }
    return -1;
}

// VS_VERSIONINFO: find the block, then locate the "FileVersion" string pair
// inside it. Layout per string block:
//   { wLength, wValueLength, wType, "Key\0", pad4, "Value\0", pad4 }
int pe_file_version(const uint8_t *data, size_t len, char *out, size_t outsz) {
    out[0] = 0;
    static const char sig[] = "VS_VERSION_INFO";
    uint8_t sig16[64];
    size_t sigw = 0;
    for (size_t i = 0; sig[i] || 1; i++) {
        if (!sig[i]) { sig16[sigw++] = 0; sig16[sigw++] = 0; break; }
        sig16[sigw++] = (uint8_t)sig[i];
        sig16[sigw++] = 0;
    }

    size_t pos = 0;
    // find the utf-16 needle
    while (pos + sigw <= len) {
        if (memcmp(data + pos, sig16, sigw) == 0) break;
        pos += 2; // utf-16 alignment
    }
    if (pos + sigw > len) return -1;

    size_t block_start = pos - 6; // { wLength, wValueLength, wType }
    if (block_start > len) return -1;
    size_t w_length = vdu_le16(data, block_start);
    size_t block_end;
    if (w_length >= 40 && block_start + w_length <= len)
        block_end = block_start + w_length;
    else
        block_end = len; // tolerate a missing/odd wLength (scan to EOF)

    // search "FileVersion" (utf-16, with nul) inside the block
    static const char key[] = "FileVersion";
    uint8_t key16[32];
    size_t keyw = 0;
    for (size_t i = 0; ; i++) {
        if (!key[i]) { key16[keyw++] = 0; key16[keyw++] = 0; break; }
        key16[keyw++] = (uint8_t)key[i];
        key16[keyw++] = 0;
    }

    for (size_t p = block_start; p + keyw <= block_end; p += 2) {
        if (memcmp(data + p, key16, keyw) != 0) continue;
        // sanity: preceding wValueLength>0 and wType==1
        if (p >= block_start + 6) {
            size_t vlen = vdu_le16(data, p - 4);
            size_t wtype = vdu_le16(data, p - 2);
            if (vlen == 0 || wtype != 1) continue;
        }
        size_t val = p + keyw; // key includes its nul terminator
        val = (val + 3) & ~(size_t)3;
        if (val >= block_end) continue;
        // read utf-16 value until nul
        size_t o = 0;
        while (val + 1 < block_end && o + 1 < outsz) {
            uint16_t ch = vdu_le16(data, val);
            if (ch == 0) break;
            out[o++] = (char)ch;
            val += 2;
        }
        out[o] = 0;
        return o ? 0 : -1;
    }
    return -1;
}
