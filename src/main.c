// main.c — WDUV CLI: status, sources, fetch, update, apply, backup,
// rollback, verify (and the GUI entry point on Windows). Every mutating
// operation delegates to ops.c — the single implementation shared with the
// GUI worker, so CLI and GUI behave identically.
#define _CRT_SECURE_NO_WARNINGS
#include "apply.h"
#include "cab.h"
#include "defs.h"
#include "ops.h"
#include "pe.h"
#include "platform.h"
#include "util.h"

#ifdef _WIN32
#include "gui.h"
#endif

#include <stdlib.h>
#include <string.h>

static int g_dry_run = 0;
static int g_strict = 0;

static void cli_log(void *ud, const char *line) {
    (void)ud;
    printf("%s\n", line);
}

static void usage(void) {
    printf("%s v%s — signature updater for the built-in Windows Defender (Vista)\n\n", APP_NAME, APP_VERSION);
    printf("Commands:\n");
    printf("  status                     engine/definition versions, registry, folders\n");
    printf("  sources                    known definition packages + compatibility notes\n");
    printf("  fetch <name|current>       download + unpack a package (use on a modern PC)\n");
    printf("  update [-source N]         download + apply ladder, health-checked, auto-rollback\n");
    printf("  apply -package <pkg|dir>   apply extracted signatures (signatures-only)\n");
    printf("  backup                     back up the current definition set\n");
    printf("  rollback                   restore the last backup\n");
    printf("  verify <pkg>               hash + structure + version report\n\n");
    printf("Flags: -dry-run, -force, -strict, -no-health, -out <dir>\n");
    printf("Env:   VDU_DEFS_ROOT (override Definition Updates root; tests)\n\n");
    printf("update walks the whole ladder freshest-first: an engine-family mismatch\n");
    printf("is informational for signatures-only apply; -strict turns it into a refusal.\n");
    printf("The tool never replaces the engine: it applies only\n");
    printf("%s + %s, exactly what the built-in Vista Defender consumes.\n", FILE_MPAS_BASE, FILE_MPAS_DELTA);
}

static void defs_root(char *out, size_t outsz) {
    const char *env = getenv("VDU_DEFS_ROOT");
    if (env && env[0]) {
        snprintf(out, outsz, "%s", env);
        return;
    }
    char appdata[1024] = "C:\\ProgramData";
    plt.common_appdata(appdata, sizeof(appdata));
    snprintf(out, outsz, "%s\\Microsoft\\Windows Defender\\Definition Updates", appdata);
}

static void local_engine_path(char *out, size_t outsz) {
    const char *pf = getenv("ProgramFiles");
    snprintf(out, outsz, "%s\\Windows Defender\\" FILE_ENGINE, pf ? pf : "C:\\Program Files");
}

static int cmd_status(void) {
    char defs[1024];
    defs_root(defs, sizeof(defs));
    printf("=== %s v%s ===\n\n", APP_NAME, APP_VERSION);
    printf("Definition Updates root: %s\n", defs);

    char engp[1024];
    local_engine_path(engp, sizeof(engp));
    size_t n;
    uint8_t *d = read_file(engp, &n);
    if (d) {
        char ver[128];
        if (pe_file_version(d, n, ver, sizeof(ver)) == 0)
            printf("Local engine (%s): %s\n", engp, ver);
        else
            printf("Local engine (%s): (version unknown)\n", engp);
        free(d);
    } else {
        printf("Local engine: not found at %s\n", engp);
    }

    if (plt.reg_dump(stderr) != 0)
        printf("  [registry] not available on this platform (run on Windows)\n");

    // current pointed definition folder + its version
    char guid[512] = "";
    if (plt.reg_read(DEF_REG_AS, guid, sizeof(guid)) && guid[0]) {
        char *folder = path_join(defs, guid);
        char *ab = path_join(folder, FILE_MPAS_BASE);
        size_t ln;
        uint8_t *dd = read_file(ab, &ln);
        if (dd) {
            char ver[128];
            if (pe_file_version(dd, ln, ver, sizeof(ver)) == 0)
                printf("Current definitions (%s): %s\n", guid, ver);
            free(dd);
        } else {
            printf("Current definition folder %s: %s missing\n", guid, FILE_MPAS_BASE);
        }
        free(folder); free(ab);
    }
    printf("\nKnown sources (freshest first):\n");
    for (size_t i = 0; i < VDU_SOURCE_COUNT; i++)
        printf("  [%zu] %-14s engine %-14s mpas %-12s (%d) %s\n",
               i, VDU_SOURCES[i].name, VDU_SOURCES[i].engine, VDU_SOURCES[i].mpas,
               VDU_SOURCES[i].year, VDU_SOURCES[i].note);
    return 0;
}

static int cmd_sources(void) {
    for (size_t i = 0; i < VDU_SOURCE_COUNT; i++) {
        printf("[%zu] %s\n    url:   %s\n    sha256: %s\n    engine: %s  mpas: %s  (%d)\n    %s\n",
               i, VDU_SOURCES[i].name, VDU_SOURCES[i].url,
               VDU_SOURCES[i].sha256 ? VDU_SOURCES[i].sha256 : "(unpinned — changes daily)",
               VDU_SOURCES[i].engine, VDU_SOURCES[i].mpas, VDU_SOURCES[i].year, VDU_SOURCES[i].note);
    }
    return 0;
}

static int cmd_verify(const char *arg) {
    int src_rc = vdu_ops_verify_source(arg, cli_log, NULL);
    if (src_rc >= 0) return src_rc;

    // treat as a path
    if (!file_exists(arg)) { vdu_log("no such file: %s", arg); return 1; }
    int64_t off, len;
    FILE *f = fopen(arg, "rb");
    if (!f) return 1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return 1; }
    int64_t fsize = ftell(f);
    fclose(f);
    if (pe_find_cab(fopen(arg, "rb"), fsize, &off, &len) != 0) {
        vdu_log("no CAB found in %s", arg);
        return 1;
    }
    printf("CAB found: offset %lld, length %lld\n", (long long)off, (long long)len);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { usage(); return 0; }
    const char *cmd = argv[1];

#ifdef _WIN32
    if (str_ieq(cmd, "gui")) return vdu_gui_run();
#endif
    if (str_ieq(cmd, "status")) return cmd_status();
    if (str_ieq(cmd, "sources")) return cmd_sources();
    if (str_ieq(cmd, "backup")) return vdu_ops_backup(cli_log, NULL) == 0 ? 0 : 1;
    if (str_ieq(cmd, "rollback")) return vdu_ops_rollback(cli_log, NULL) == 0 ? 0 : 1;

    const char *source_arg = NULL, *pkg = NULL, *out = NULL;
    int no_health = 0, force = 0;
    for (int i = 2; i < argc; i++) {
        if (str_ieq(argv[i], "-dry-run")) g_dry_run = 1;
        else if (str_ieq(argv[i], "-no-health")) no_health = 1;
        else if (str_ieq(argv[i], "-force")) force = 1;
        else if (str_ieq(argv[i], "-strict")) g_strict = 1;
        else if (str_ieq(argv[i], "-source") && i + 1 < argc) source_arg = argv[++i];
        else if (str_ieq(argv[i], "-package") && i + 1 < argc) pkg = argv[++i];
        else if (str_ieq(argv[i], "-out") && i + 1 < argc) out = argv[++i];
    }

    if (str_ieq(cmd, "fetch")) {
        if (argc < 3) { vdu_log("usage: fetch <name|current> [-out dir]"); return 1; }
        return vdu_ops_fetch(argv[2], out, cli_log, NULL) == 0 ? 0 : 1;
    }
    if (str_ieq(cmd, "update"))
        return vdu_ops_update(source_arg, no_health, force, g_strict, g_dry_run, cli_log, NULL) == 0 ? 0 : 1;
    if (str_ieq(cmd, "apply")) {
        if (!pkg) { vdu_log("usage: apply -package <pkg|dir> [-force] [-dry-run]"); return 1; }
        return vdu_ops_apply(pkg, force, g_dry_run, cli_log, NULL) == 0 ? 0 : 1;
    }
    if (str_ieq(cmd, "verify")) {
        if (argc < 3) { vdu_log("usage: verify <name|file>"); return 1; }
        return cmd_verify(argv[2]);
    }
    usage();
    return 1;
}