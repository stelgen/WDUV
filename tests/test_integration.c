// test_integration.c — full-cycle check against real Microsoft packages.
// Enabled by env vars (kept out of CI by default — the fixtures are large):
//   VDU_TEST_MPAM  path to a modern mpam-fe.exe (2026, fwlink current)
//   VDU_TEST_VISTA path to mpam-fe_vista_x86.exe (archive.org, 2019)
//   VDU_TEST_WIN7  path to mpam-fe-w7x86.exe (archive.org, 2018)
// Verifies the C extractor (stored + LZX) byte-for-byte against cabextract.
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#include "cab.h"
#include "defs.h"
#include "pe.h"
#include "sha256.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int check_pkg(const char *env, const char *tag,
                     const char *want_base, const char *want_delta,
                     const char *want_engine) {
    const char *pkg = getenv(env);
    if (!pkg || !pkg[0]) {
        printf("%-14s SKIP (%s not set)\n", tag, env);
        return 0;
    }
    char dir[1024];
    snprintf(dir, sizeof(dir), "%s/%s-ref", getenv("VDU_TMP") ? getenv("VDU_TMP") : "/tmp", tag);
    mkdir_p(dir);
    if (cab_extract_package(pkg, dir) != 0) {
        fprintf(stderr, "%s: extraction FAILED\n", tag);
        return 1;
    }
    int rc = 0;
    struct { const char *file; const char *want; } checks[] = {
        { FILE_MPAS_BASE, want_base },
        { FILE_MPAS_DELTA, want_delta },
        { FILE_ENGINE, want_engine },
    };
    for (size_t i = 0; i < sizeof(checks) / sizeof(checks[0]); i++) {
        if (!checks[i].want) continue;
        char *p = path_join(dir, checks[i].file);
        size_t n;
        uint8_t *d = read_file(p, &n);
        uint8_t hash[32];
        char hex[65];
        vdu_sha256_buf(d, n, hash);
        to_hex(hash, 32, hex);
        if (!str_ieq(hex, checks[i].want)) {
            fprintf(stderr, "%s: %s sha256 mismatch: got %s want %s\n", tag, checks[i].file, hex, checks[i].want);
            rc = 1;
        } else {
            printf("%-14s %-14s %10zu bytes  sha256 OK\n", tag, checks[i].file, n);
        }
        free(d);
        free(p);
    }
    // version reporting sanity
    char *eng = path_join(dir, FILE_ENGINE);
    size_t n;
    uint8_t *d = read_file(eng, &n);
    char ver[128];
    if (d && pe_file_version(d, n, ver, sizeof(ver)) == 0)
        printf("%-14s engine version: %s\n", tag, ver);
    free(d);
    free(eng);
    return rc;
}

int test_integration_real_packages(void) {
    int rc = 0;
    rc |= check_pkg("VDU_TEST_MPAM", "2026",
                    "a1eaee9a04019f82dcfeb85337adbb5e2df773b3c5b040639cf6e682f1a47b9f",
                    "56903c941da2ce51a2fecb45956fe7906cde51773ebab8faa48f2b0303c85bc3",
                    "0654a5902b3b15d36e48b034e7c75c253b7504a60434bc37d930b3b0a858f079");
    rc |= check_pkg("VDU_TEST_VISTA", "vista-2019",
                    "f438ec5241aa51cee49fce51268d3756eef3799af1d169582af35afbc3f67188",
                    "51042a11e100ab2db8cbd2e472b1e090ff225b44249661184c2b58f0d2f74ae9",
                    "8b24d2ef44889a3e145e3ad12e0608334be7bb5e2ecd7457df9f5d961d1af314");
    rc |= check_pkg("VDU_TEST_WIN7", "win7-2018",
                    "7958f8dd85b6aa253ece30f7d7f594b3d6722cd5b0cba5a58832b0f2cd86a4f1",
                    "40c3ca8cea3d29845b6a4e3153801d8f5a5ff7c9732c5d961164408498198b8e",
                    NULL);
    return rc;
}
