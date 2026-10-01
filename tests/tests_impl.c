// tests_impl.c — all test bodies.
#define _CRT_SECURE_NO_WARNINGS
#include "fixtures.h"
#include "apply.h"
#include "cab.h"
#include "defs.h"
#include "lzx.h"
#include "pe.h"
#include "platform.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ---- shared byte reader ----
static uint8_t g_rbuf[1 << 20];
static size_t g_rlen, g_rpos;
static int reader_byte(void *ud) {
    (void)ud;
    if (g_rpos >= g_rlen) return -1;
    return g_rbuf[g_rpos++];
}
static void reader_set(const uint8_t *d, size_t n) {
    if (n > sizeof(g_rbuf)) n = sizeof(g_rbuf);
    memcpy(g_rbuf, d, n);
    g_rlen = n;
    g_rpos = 0;
}

// CFDATA-aware reader: serves payload bytes, skipping block headers
static size_t g_fs_len, g_fs_pos;
static int g_fs_remaining;
static uint8_t g_blk[32768];
static int g_blk_len, g_blk_pos;
static int fs_test_read_byte(void *ud) {
    (void)ud;
    while (g_blk_pos >= g_blk_len) {
        if (g_fs_remaining <= 0 || g_fs_pos + 8 > g_fs_len) return -1;
        int cb_comp = g_rbuf[g_fs_pos + 4] | (g_rbuf[g_fs_pos + 5] << 8);
        g_fs_pos += 8;
        if (g_fs_pos + (size_t)cb_comp > g_fs_len) return -1;
        memcpy(g_blk, g_rbuf + g_fs_pos, (size_t)cb_comp);
        g_fs_pos += (size_t)cb_comp;
        g_blk_len = cb_comp;
        g_blk_pos = 0;
        g_fs_remaining--;
    }
    return g_blk[g_blk_pos++];
}
static void fs_test_set(const uint8_t *wrapped, size_t n, int blocks) {
    memcpy(g_rbuf, wrapped, n);
    g_fs_len = n;
    g_fs_pos = 0;
    g_fs_remaining = blocks;
    g_blk_len = g_blk_pos = 0;
}

static uint8_t g_out[1 << 21];
static size_t g_out_len;
static int test_out_write(void *ud, const uint8_t *p, size_t n) {
    (void)ud;
    if (g_out_len + n > sizeof(g_out)) return -1;
    memcpy(g_out + g_out_len, p, n);
    g_out_len += n;
    return 0;
}

// wrap payload into CFDATA blocks (<=32K compressed each)
static size_t wrap_block(const uint8_t *payload, size_t plen, int uncomp, uint8_t *out, size_t out_cap) {
    size_t o = 0, off = 0;
    int remaining = uncomp;
    while (off < plen || (off == 0 && plen == 0)) {
        size_t n = plen - off;
        if (n > 32768) n = 32768;
        int u = remaining > 32768 ? 32768 : remaining;
        remaining -= u;
        if (o + 8 + n + 1 > out_cap) return 0;
        memset(out + o, 0, 4);
        out[o + 4] = (uint8_t)n; out[o + 5] = (uint8_t)(n >> 8);
        out[o + 6] = (uint8_t)u; out[o + 7] = (uint8_t)(u >> 8);
        memcpy(out + o + 8, payload + off, n);
        o += 8 + n;
        off += n;
        if (n == 0 && u == 0) break;
        if (off >= plen && remaining <= 0) break;
    }
    return o;
}

// ---- 1. bit reader word order ----
int test_bitio(void) {
    lzx_decoder *d = lzx_new(16);
    if (!d) return 1;
    reader_set((const uint8_t *)"\x01\x02\x03\x04", 4);
    lzx_set_io(d, (lzx_in){ reader_byte, NULL });
    struct { int n; uint32_t want; } cases[] = {
        { 3, 0b000 }, { 5, 0b00010 }, { 2, 0b00 }, { 6, 0b000001 }, { 16, 0x0403 },
    };
    int rc = 0;
    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        uint32_t got = 0;
        if (vdu_read_bits(d, cases[i].n, &got) != 0 || got != cases[i].want) {
            fprintf(stderr, "bitio: case %zu got %u want %u\n", i, got, cases[i].want);
            rc = 1;
        }
    }
    lzx_free(d);
    return rc;
}

// ---- 2. huffman table round trip ----
int test_huffman(void) {
    uint8_t lens[4] = { 2, 2, 2, 2 };
    uint16_t table[(1 << 2) + 2 * 4];
    if (!vdu_make_decode_table(4, 2, lens, table, sizeof(table) / sizeof(table[0])))
        return 1;
    lzx_decoder *d = lzx_new(16);
    if (!d) return 1;
    reader_set((const uint8_t *)"\x00\x80", 2);
    lzx_set_io(d, (lzx_in){ reader_byte, NULL });
    int sym = -1;
    int rc = vdu_read_sym(d, table, sizeof(table) / sizeof(table[0]), 2, lens, 4, &sym);
    lzx_free(d);
    if (rc != 0 || sym != 2) {
        fprintf(stderr, "huffman: rc=%d sym=%d\n", rc, sym);
        return 1;
    }
    return 0;
}

// ---- 3. readLens runs (17/18/19) ----
int test_read_lens_runs(void) {
    lzx_decoder *d = lzx_new(16);
    if (!d) return 1;
    bitwriter w;
    bw_init(&w);
    uint8_t pre[20];
    memset(pre, 0, 20);
    for (int i = 1; i <= 13; i++) pre[i] = 4;
    pre[17] = pre[18] = pre[19] = 4;
    bw_emit_pretree(&w, pre);
    bw_put(&w, 12, 4);  // sym 13 → lens[0] = 4
    bw_put(&w, 13, 4);  // sym 17 (run)
    bw_put(&w, 4, 4);
    bw_put(&w, 14, 4);  // sym 18 (run)
    bw_put(&w, 2, 5);
    bw_put(&w, 15, 4);  // sym 19 (run)
    bw_put(&w, 1, 1);
    bw_put(&w, 11, 4);  // sym 12
    size_t plen;
    uint8_t *packed = bw_pack(&w, &plen);
    reader_set(packed, plen);
    lzx_set_io(d, (lzx_in){ reader_byte, NULL });
    uint8_t lens[36];
    memset(lens, 0, sizeof(lens)); // deltas are relative to previous state
    int rc = vdu_read_lens(d, lens, 0, 36);
    lzx_free(d);
    free(packed);
    if (rc != 0) { fprintf(stderr, "read_lens: rc=%d\n", rc); return 1; }
    for (int i = 0; i < 36; i++) {
        uint8_t want = (i == 0) ? 4 : (i >= 31 && i < 36) ? 5 : 0;
        if (lens[i] != want) {
            fprintf(stderr, "read_lens: lens[%d]=%d want %d\n", i, lens[i], want);
            return 1;
        }
    }
    return 0;
}

// ---- 4. literals-only frame ----
int test_lzx_literals(void) {
    int total = 32768;
    uint8_t *lits = xmalloc((size_t)total);
    for (int i = 0; i < total; i++) lits[i] = (uint8_t)(i * 7);
    bitwriter w;
    bw_init(&w);
    bw_put(&w, 0, 1); // intel filesize = 0
    bw_literals_block(&w, lits, (size_t)total);
    fprintf(stderr, "DBG first 40 bits: ");
    for (int i = 0; i < 40; i++) fprintf(stderr, "%d", w.bits[i]);
    fprintf(stderr, " (total %zu bits)\n", w.len);
    size_t plen;
    uint8_t *payload = bw_pack(&w, &plen);
    static uint8_t stream[1 << 20];
    size_t slen = wrap_block(payload, plen, total, stream, sizeof(stream));
    if (slen == 0) { free(payload); free(lits); return 1; }
    fprintf(stderr, "DBG stream head: %02x %02x %02x %02x %02x %02x %02x %02x (len %zu)\n",
            stream[0], stream[1], stream[2], stream[3], stream[4], stream[5], stream[6], stream[7], slen);

    lzx_decoder *d = lzx_new(16);
    fs_test_set(stream, slen, 2);
    g_out_len = 0;
    int rc = lzx_decompress(d, (lzx_in){ fs_test_read_byte, NULL }, (lzx_out){ test_out_write, NULL }, total);
    lzx_free(d);
    if (rc != 0) fprintf(stderr, "literals: rc=%d out=%zu\n", rc, g_out_len);
    int bad = rc != 0 || g_out_len != (size_t)total;
    for (int i = 0; !bad && i < total; i++)
        if (g_out[i] != lits[i]) { fprintf(stderr, "literals: mismatch at %d (got %02x want %02x)\n", i, g_out[i], lits[i]); bad = 1; }
    free(payload);
    free(lits);
    return bad;
}

// ---- 5. E8 translation ----
int test_lzx_e8(void) {
    int total = 32768;
    uint32_t filesize = 65536;
    uint8_t *lits = xmalloc((size_t)total);
    memset(lits, 0x41, (size_t)total);
    memcpy(lits + 100, "\xE8\x00\x10\x00\x00", 5); // abs = 4096
    memcpy(lits + 200, "\xE8\xCE\xFF\xFF\xFF", 5); // abs = -50
    memcpy(lits + 300, "\xE8\x70\x11\x01\x00", 5); // abs = 70000 >= filesize
    memcpy(lits + 310, "\xE8\xF0\x9D\xFE\xFF", 5); // abs = -70000
    bitwriter w;
    bw_init(&w);
    bw_put(&w, 1, 1);
    bw_put(&w, filesize >> 16, 16);
    bw_put(&w, filesize & 0xFFFF, 16);
    bw_literals_block(&w, lits, (size_t)total);
    size_t plen;
    uint8_t *payload = bw_pack(&w, &plen);
    static uint8_t stream[1 << 20];
    size_t slen = wrap_block(payload, plen, total, stream, sizeof(stream));

    lzx_decoder *d = lzx_new(16);
    fs_test_set(stream, slen, 2);
    g_out_len = 0;
    int rc = lzx_decompress(d, (lzx_in){ fs_test_read_byte, NULL }, (lzx_out){ test_out_write, NULL }, total);
    lzx_free(d);
    if (rc != 0) { fprintf(stderr, "e8: rc=%d out=%zu\n", rc, g_out_len); free(payload); free(lits); return 1; }
    uint8_t want[5];
    uint32_t rel = 4096 - 100;
    memcpy(want, lits + 100, 5);
    want[1] = (uint8_t)rel; want[2] = (uint8_t)(rel >> 8); want[3] = (uint8_t)(rel >> 16); want[4] = (uint8_t)(rel >> 24);
    if (memcmp(g_out + 100, want, 5) != 0) { fprintf(stderr, "e8: pos100\n"); return 1; }
    rel = 65536 - 50;
    memcpy(want, lits + 200, 5);
    want[1] = (uint8_t)rel; want[2] = (uint8_t)(rel >> 8); want[3] = (uint8_t)(rel >> 16); want[4] = (uint8_t)(rel >> 24);
    if (memcmp(g_out + 200, want, 5) != 0) { fprintf(stderr, "e8: pos200\n"); return 1; }
    if (memcmp(g_out + 300, lits + 300, 5) != 0) { fprintf(stderr, "e8: pos300 must stay\n"); return 1; }
    if (memcmp(g_out + 310, lits + 310, 5) != 0) { fprintf(stderr, "e8: pos310 must stay\n"); return 1; }
    free(payload);
    free(lits);
    return 0;
}

// ---- 6. uncompressed block, odd length + skip ----
int test_lzx_uncompressed_odd(void) {
    int total = 32768;
    bitwriter w;
    bw_init(&w);
    bw_put(&w, 0, 1);
    bw_put(&w, 3, 3); // uncompressed block
    bw_put(&w, 0, 8);
    bw_put(&w, 0, 8);
    bw_put(&w, 1, 8); // block length = 1 (odd!)
    bw_align16(&w);
    size_t plen;
    uint8_t *p1 = bw_pack(&w, &plen);
    static uint8_t raw[14];
    memset(raw, 0x11, 4);
    memset(raw + 4, 0x22, 4);
    memset(raw + 8, 0x33, 4);
    raw[12] = 0xAB;
    raw[13] = 0xEE; // must be skipped by the decoder
    bitwriter w2;
    bw_init(&w2);
    uint8_t *zeros = xmalloc((size_t)total - 1);
    memset(zeros, 0, (size_t)total - 1);
    bw_literals_block(&w2, zeros, (size_t)total - 1);
    size_t plen2;
    uint8_t *p2 = bw_pack(&w2, &plen2);
    static uint8_t stream[1 << 20];
    size_t o = 0;
    memcpy(stream + o, p1, plen); o += plen;
    memcpy(stream + o, raw, sizeof(raw)); o += sizeof(raw);
    memcpy(stream + o, p2, plen2); o += plen2;

    lzx_decoder *d = lzx_new(16);
    reader_set(stream, o);
    g_out_len = 0;
    int rc = lzx_decompress(d, (lzx_in){ reader_byte, NULL }, (lzx_out){ test_out_write, NULL }, total);
    lzx_free(d);
    int bad = rc != 0 || g_out_len != (size_t)total;
    if (!bad && g_out[0] != 0xAB) { fprintf(stderr, "uncompressed: first byte %#x\n", g_out[0]); bad = 1; }
    for (int i = 1; !bad && i < total; i++)
        if (g_out[i] != 0) { fprintf(stderr, "uncompressed: byte %d not zero\n", i); bad = 1; }
    free(p1);
    free(p2);
    free(zeros);
    return bad;
}

// ---- 7. CAB stored round-trip ----
int test_cab_stored(void) {
    char dir[1024];
    snprintf(dir, sizeof(dir), "%s/cab_stored", getenv("VDU_TMP") ? getenv("VDU_TMP") : "/tmp");
    mkdir_p(dir);
    uint8_t body[90000];
    for (size_t i = 0; i < sizeof(body); i++) body[i] = (uint8_t)(i * 3);
    char *pkg = path_join(dir, "pkg.cab");
    if (write_test_cab_stored(pkg, body, sizeof(body), (int)sizeof(body)) != 0) return 1;
    char *out = path_join(dir, "out");
    mkdir_p(out);
    if (cab_extract_package(pkg, out) != 0) { fprintf(stderr, "cab: extract failed\n"); return 1; }
    char *got = path_join(out, "payload.bin");
    size_t n;
    uint8_t *d = read_file(got, &n);
    int bad = (!d || n != sizeof(body) || memcmp(d, body, sizeof(body)) != 0);
    free(d);
    free(pkg); free(out); free(got);
    return bad;
}

// ---- 8. unsupported compression is rejected ----
int test_cab_unsupported(void) {
    char dir[1024];
    snprintf(dir, sizeof(dir), "%s/cab_unsup", getenv("VDU_TMP") ? getenv("VDU_TMP") : "/tmp");
    mkdir_p(dir);
    uint8_t body[100];
    memset(body, 7, sizeof(body));
    char *pkg = path_join(dir, "pkg.cab");
    if (write_test_cab_mszip(pkg, body, sizeof(body), (int)sizeof(body)) != 0) return 1;
    char *out = path_join(dir, "out");
    mkdir_p(out);
    int rc = cab_extract_package(pkg, out);
    free(pkg); free(out);
    return rc == 0 ? 1 : 0;
}

// ---- 9. PE wrapper (.rsrc) ----
int test_cab_pe_wrapper(void) {
    char dir[1024];
    snprintf(dir, sizeof(dir), "%s/cab_pe", getenv("VDU_TMP") ? getenv("VDU_TMP") : "/tmp");
    mkdir_p(dir);
    uint8_t body[60000];
    for (size_t i = 0; i < sizeof(body); i++) body[i] = (uint8_t)(i * 5 + 1);
    char *cabp = path_join(dir, "inner.cab");
    if (write_test_cab_stored(cabp, body, sizeof(body), (int)sizeof(body)) != 0) return 1;
    size_t cab_len;
    uint8_t *cab = read_file(cabp, &cab_len);
    char *exep = path_join(dir, "mpam-fake.exe");
    if (write_test_cab_pe(exep, cab, cab_len) != 0) return 1;
    char *out = path_join(dir, "out");
    mkdir_p(out);
    FILE *f = fopen(exep, "rb");
    if (!f) return 1;
    fseek(f, 0, SEEK_END);
    long fsz = ftell(f);
    fclose(f);
    f = fopen(exep, "rb");
    int64_t off, len;
    if (pe_find_cab(f, fsz, &off, &len) != 0) { fprintf(stderr, "pe: cab not found\n"); return 1; }
    fclose(f);
    if (cab_extract_package(exep, out) != 0) { fprintf(stderr, "pe: extract failed\n"); return 1; }
    char *got = path_join(out, "payload.bin");
    size_t n;
    uint8_t *d = read_file(got, &n);
    int bad = (!d || n != sizeof(body) || memcmp(d, body, sizeof(body)) != 0);
    free(d);
    free(cabp); free(exep); free(out); free(got); free(cab);
    return bad;
}

// ---- 10. versioninfo parsing ----
int test_versioninfo(void) {
    char dir[1024];
    snprintf(dir, sizeof(dir), "%s/vinfo", getenv("VDU_TMP") ? getenv("VDU_TMP") : "/tmp");
    mkdir_p(dir);
    char *p = path_join(dir, "mpengine.dll");
    if (write_test_versioninfo(p, "1.2.1009.0") != 0) return 1;
    size_t n;
    uint8_t *d = read_file(p, &n);
    char ver[128];
    int rc = pe_file_version(d, n, ver, sizeof(ver));
    free(d);
    if (rc != 0 || strcmp(ver, "1.2.1009.0") != 0) {
        fprintf(stderr, "versioninfo: rc=%d ver=%s\n", rc, ver);
        return 1;
    }
    return 0;
}

// ---- fake environment for e2e ----
static char fake_reg_av[512] = "";
static char fake_reg_as[512] = "";
static int fake_service_running_state = 0;
static int fake_service_start_fails = 0;
static int dead_service_mode = 0;

static int fake_reg_read(const char *value, char *out, size_t outsz) {
    const char *v = strcmp(value, DEF_REG_AV) == 0 ? fake_reg_av : fake_reg_as;
    snprintf(out, outsz, "%s", v);
    return v[0] ? 1 : 0;
}
static int fake_reg_write(const char *av, const char *as) {
    snprintf(fake_reg_av, sizeof(fake_reg_av), "%s", av);
    snprintf(fake_reg_as, sizeof(fake_reg_as), "%s", as);
    return 0;
}
static int fake_reg_dump(void *f) { (void)f; return -1; }
static int fake_svc_installed(void) { return 1; }
static int fake_svc_stop(void) { fake_service_running_state = 0; return 0; }
static int fake_svc_start(void) {
    if (fake_service_start_fails) return -1;
    fake_service_running_state = 1;
    return 0;
}
static int fake_svc_running(void) {
    return dead_service_mode ? 0 : fake_service_running_state;
}
static int fake_guid(char *out, size_t outsz) {
    static int counter = 0;
    snprintf(out, outsz, "{FAKE-%04d}", ++counter);
    return 0;
}
static void install_fake_hooks(void) {
    plt.reg_read = fake_reg_read;
    plt.reg_write = fake_reg_write;
    plt.reg_dump = fake_reg_dump;
    plt.service_installed = fake_svc_installed;
    plt.service_stop = fake_svc_stop;
    plt.service_start = fake_svc_start;
    plt.service_running = fake_svc_running;
    plt.guid_new = fake_guid;
}

// ---- 11. e2e apply ----
int test_e2e_apply_rollback(void) {
    install_fake_hooks();
    char root[1024];
    snprintf(root, sizeof(root), "%s/e2e1", getenv("VDU_TMP") ? getenv("VDU_TMP") : "/tmp");
    mkdir_p(root);
    char defs[1024];
    snprintf(defs, sizeof(defs), "%s/Definition Updates", root);
    char *oldf = path_join(defs, "{OLD}");
    mkdir_p(oldf);
    write_file(path_join(oldf, FILE_MPAS_BASE), "OLD-BASE", 8);
    write_file(path_join(oldf, FILE_MPAS_DELTA), "OLD-DELTA", 9);
    fake_reg_write("{OLD}", "{OLD}");

    char *newsig = path_join(root, "newsig");
    mkdir_p(newsig);
    write_file(path_join(newsig, FILE_MPAS_BASE), "NEW-BASE", 8);
    write_file(path_join(newsig, FILE_MPAS_DELTA), "NEW-DELTA", 9);

    apply_opts o = { newsig, defs, 0, 0 };
    int rc = apply_signatures(&o);
    if (rc != 0) { fprintf(stderr, "e2e: apply failed\n"); return 1; }
    if (strcmp(fake_reg_as, "{FAKE-0001}") != 0) {
        fprintf(stderr, "e2e: pointer = %s\n", fake_reg_as);
        return 1;
    }
    char *nf = path_join(defs, "{FAKE-0001}");
    size_t n;
    uint8_t *d = read_file(path_join(nf, FILE_MPAS_BASE), &n);
    int bad = (!d || n != 8 || memcmp(d, "NEW-BASE", 8) != 0);
    free(d);
    if (bad) { fprintf(stderr, "e2e: files not staged\n"); return 1; }
    if (!fake_service_running_state) { fprintf(stderr, "e2e: service not running\n"); return 1; }
    return 0;
}

// ---- 12. e2e: engine rejects definitions → auto-rollback ----
int test_e2e_rollback_on_dead_service(void) {
    install_fake_hooks();
    char root[1024];
    snprintf(root, sizeof(root), "%s/e2e2", getenv("VDU_TMP") ? getenv("VDU_TMP") : "/tmp");
    mkdir_p(root);
    char defs[1024];
    snprintf(defs, sizeof(defs), "%s/Definition Updates", root);
    char *oldf = path_join(defs, "{OLD}");
    mkdir_p(oldf);
    write_file(path_join(oldf, FILE_MPAS_BASE), "OLD-BASE", 8);
    write_file(path_join(oldf, FILE_MPAS_DELTA), "OLD-DELTA", 9);
    fake_reg_write("{OLD}", "{OLD}");

    char *newsig = path_join(root, "newsig");
    mkdir_p(newsig);
    write_file(path_join(newsig, FILE_MPAS_BASE), "BAD-BASE", 8);
    write_file(path_join(newsig, FILE_MPAS_DELTA), "BAD-DELTA", 9);

    dead_service_mode = 1; // service reports not-running right after start
    apply_opts o = { newsig, defs, 0, 0 };
    int rc = apply_signatures(&o);
    dead_service_mode = 0;
    if (rc == 0) { fprintf(stderr, "e2e2: expected failure\n"); return 1; }
    if (strcmp(fake_reg_as, "{OLD}") != 0) {
        fprintf(stderr, "e2e2: pointer not restored (%s)\n", fake_reg_as);
        return 1;
    }
    size_t n;
    uint8_t *d = read_file(path_join(oldf, FILE_MPAS_BASE), &n);
    int bad = (!d || n != 8 || memcmp(d, "OLD-BASE", 8) != 0);
    free(d);
    if (bad) { fprintf(stderr, "e2e2: old files not restored\n"); return 1; }
    return 0;
}
