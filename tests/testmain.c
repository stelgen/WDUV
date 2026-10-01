// testmain.c — tiny test harness.
#ifndef _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#endif
#include "fixtures.h"
#include "util.h"

int test_bitio(void);
int test_huffman(void);
int test_read_lens_runs(void);
int test_lzx_literals(void);
int test_lzx_e8(void);
int test_lzx_uncompressed_odd(void);
int test_cab_stored(void);
int test_cab_unsupported(void);
int test_cab_pe_wrapper(void);
int test_versioninfo(void);
int test_e2e_apply_rollback(void);
int test_e2e_rollback_on_dead_service(void);
int test_integration_real_packages(void);

int main(void) {
    struct { const char *name; int (*fn)(void); } tests[] = {
        { "bitio", test_bitio },
        { "huffman", test_huffman },
        { "read_lens_runs", test_read_lens_runs },
        { "lzx_literals", test_lzx_literals },
        { "lzx_e8", test_lzx_e8 },
        { "lzx_uncompressed_odd", test_lzx_uncompressed_odd },
        { "cab_stored", test_cab_stored },
        { "cab_unsupported", test_cab_unsupported },
        { "cab_pe_wrapper", test_cab_pe_wrapper },
        { "versioninfo", test_versioninfo },
        { "e2e_apply", test_e2e_apply_rollback },
        { "e2e_rollback_on_dead_service", test_e2e_rollback_on_dead_service },
        { "integration_real_packages", test_integration_real_packages },
    };
    int failed = 0;
    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
        int rc = tests[i].fn();
        printf("%-30s %s\n", tests[i].name, rc == 0 ? "PASS" : "FAIL");
        if (rc != 0) failed++;
    }
    printf("%d/%zu passed\n", (int)(sizeof(tests) / sizeof(tests[0])) - failed,
           sizeof(tests) / sizeof(tests[0]));
    return failed ? 1 : 0;
}
