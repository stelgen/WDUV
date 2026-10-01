// platform_stub.c — non-Windows build: everything reports "unsupported".
// Tests replace the plt hooks with fakes, so the whole apply/fetch pipeline
// is exercised on Linux without Windows.
#include "platform.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

vdu_hooks plt = { 0 };

static int unsupported(void) { return -1; }
static int unsupported0(void) { return 0; }

static int stub_reg_read(const char *value, char *out, size_t outsz) {
    (void)value; (void)out; (void)outsz;
    return 0;
}
static int stub_dump(void *f) { (void)f; return -1; }
static int stub_guid(char *out, size_t outsz) {
    static int counter = 0;
    snprintf(out, outsz, "{TEST-GUID-%04d}", ++counter);
    return 0;
}
static int stub_appdata(char *out, size_t outsz) {
    const char *env = getenv("VDU_APPDATA");
    snprintf(out, outsz, "%s", env ? env : "/tmp/vdu-appdata");
    return 0;
}
static int stub_arch(void) { return 0; }

__attribute__((constructor)) static void plt_init(void) {
    plt.reg_read = stub_reg_read;
    plt.reg_write = (int (*)(const char *, const char *))unsupported;
    plt.reg_dump = stub_dump;
    plt.service_installed = (int (*)(void))unsupported0;
    plt.service_stop = (int (*)(void))unsupported;
    plt.service_start = (int (*)(void))unsupported;
    plt.service_running = (int (*)(void))unsupported0;
    plt.guid_new = stub_guid;
    plt.common_appdata = stub_appdata;
    plt.download = (int (*)(const char *, const char *))unsupported;
    plt.arch = stub_arch;
}
