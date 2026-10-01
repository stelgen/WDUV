// main.c — WDUV v2 CLI: status, sources, fetch, update, apply, backup,
// rollback, verify. The tool keeps the original Windows Defender engine and
// only swaps the antispyware signature files (mpasbase.vdm / mpasdlta.vdm),
// following Vista's own update model (new GUID folder + registry flip).
#define _CRT_SECURE_NO_WARNINGS
#include "apply.h"
#include "cab.h"
#include "defs.h"
#include "pe.h"
#include "platform.h"
#include "sha256.h"

#ifdef _WIN32
#include "gui.h"
#endif
#include "util.h"

#include <stdlib.h>
#include <string.h>

static int g_dry_run = 0;

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
    printf("Flags: -dry-run, -force, -no-health, -out <dir>\n");
    printf("Env:   VDU_DEFS_ROOT (override Definition Updates root; tests)\n\n");
    printf("The tool never replaces the engine in default mode: it applies only\n");
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

static int report_pkg_versions(const char *dir) {
    char *eng = path_join(dir, FILE_ENGINE);
    char *ab = path_join(dir, FILE_MPAS_BASE);
    char *ad = path_join(dir, FILE_MPAS_DELTA);
    size_t n;
    uint8_t *d;
    char ver[128];
    if ((d = read_file(eng, &n)) != NULL) {
        if (pe_file_version(d, n, ver, sizeof(ver)) == 0)
            printf("  package engine:        %s\n", ver);
        else
            printf("  package engine:        (unknown)\n");
        free(d);
    }
    if ((d = read_file(ab, &n)) != NULL) {
        if (pe_file_version(d, n, ver, sizeof(ver)) == 0)
            printf("  package %s:  %s\n", FILE_MPAS_BASE, ver);
        free(d);
    }
    if ((d = read_file(ad, &n)) != NULL) {
        if (pe_file_version(d, n, ver, sizeof(ver)) == 0)
            printf("  package %s: %s\n", FILE_MPAS_DELTA, ver);
        free(d);
    }
    free(eng); free(ab); free(ad);
    return 0;
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

// resolve -source arg (index or name) or default ladder order
static int resolve_sources(const char *arg, int *order, int *order_n) {
    if (!arg) {
        for (size_t i = 0; i < VDU_SOURCE_COUNT; i++) order[i] = (int)i;
        *order_n = (int)VDU_SOURCE_COUNT;
        return 0;
    }
    for (size_t i = 0; i < VDU_SOURCE_COUNT; i++) {
        if (str_ieq(VDU_SOURCES[i].name, arg)) { order[0] = (int)i; *order_n = 1; return 0; }
    }
    char *end = NULL;
    long idx = strtol(arg, &end, 10);
    if (end && *end == 0 && idx >= 0 && idx < (long)VDU_SOURCE_COUNT) {
        order[0] = (int)idx;
        *order_n = 1;
        return 0;
    }
    vdu_log("unknown source '%s' (see 'sources')", arg);
    return -1;
}

static int verify_package_hash(const vdu_source *src, const char *path) {
    if (!src->sha256) return 0; // unpinned (fwlink changes daily)
    size_t n;
    uint8_t *d = read_file(path, &n);
    if (!d) return -1;
    uint8_t hash[32];
    vdu_sha256_buf(d, n, hash);
    char hex[65];
    to_hex(hash, 32, hex);
    free(d);
    if (!str_ieq(hex, src->sha256)) {
        vdu_log("SHA-256 mismatch for %s:\n  got      %s\n  expected %s", path, hex, src->sha256);
        return -1;
    }
    vdu_log("  sha256 ok: %s", hex);
    return 0;
}

// download (if needed) + hash check + extract into workdir/extracted
static int prepare_source(const vdu_source *src, const char *workdir, char *out_dir, size_t outsz) {
    char *pkg = path_join(workdir, "package.exe");
    if (!file_exists(pkg)) {
        vdu_log("  downloading %s ...", src->url);
        if (plt.download(src->url, pkg) != 0) {
            vdu_log("  download failed (%s)", src->url);
            free(pkg);
            return -1;
        }
    } else {
        vdu_log("  reusing cached %s", pkg);
    }
    if (verify_package_hash(src, pkg) != 0) { free(pkg); return -1; }
    char *ex = path_join(workdir, "extracted");
    mkdir_p(ex);
    if (cab_extract_package(pkg, ex) != 0) {
        vdu_log("  extraction failed");
        free(pkg); free(ex);
        return -1;
    }
    snprintf(out_dir, outsz, "%s", ex);
    free(pkg);
    free(ex);
    return 0;
}

static int cmd_fetch(const char *arg, const char *out) {
    int order[8], order_n = 0;
    if (resolve_sources(arg, order, &order_n) != 0) return 1;
    const vdu_source *src = &VDU_SOURCES[order[0]];
    char workdir[1024];
    snprintf(workdir, sizeof(workdir), "%s", out ? out : ".");
    char exdir[1024];
    if (prepare_source(src, workdir, exdir, sizeof(exdir)) != 0) return 1;
    printf("Package '%s' prepared in %s\n", src->name, exdir);
    report_pkg_versions(exdir);
    printf("Carry this folder to the Vista machine and run:\n"
           "  vdu apply -package \"%s\"\n", exdir);
    return 0;
}

static int files_ok_dir(const char *dir);

static int compat_note(const char *workdir) {
    // report package engine vs local engine; the caller decides (-force)
    char *pkg_eng = path_join(workdir, FILE_ENGINE);
    size_t n;
    uint8_t *d = read_file(pkg_eng, &n);
    free(pkg_eng);
    if (!d) return 0;
    char pv[128] = "", lv[128] = "";
    pe_file_version(d, n, pv, sizeof(pv));
    free(d);
    char engp[1024];
    local_engine_path(engp, sizeof(engp));
    d = read_file(engp, &n);
    if (d) pe_file_version(d, n, lv, sizeof(lv));
    else snprintf(lv, sizeof(lv), "(none)");
    if (!d) { vdu_log("  local engine not found; engine-family gate skipped"); return 0; }
    vdu_log("  package engine %s vs local engine %s", pv, lv);
    // family = first two components
    int fam_ok = 0;
    if (strncmp(pv, lv, 5) == 0 && pv[4] == '.') fam_ok = 1; // "1.1." prefix match
    if (strncmp(pv, "1.1.", 4) == 0 && strncmp(lv, "1.1.", 4) == 0) fam_ok = 1;
    if (!fam_ok) {
        vdu_log("  ENGINE FAMILY MISMATCH: the package was built for a different engine line.");
        vdu_log("  Signature files of another engine family may be rejected by your Defender.");
        return -1;
    }
    return 0;
}

static int cmd_update(const char *source_arg, int no_health, int force) {
    int order[8], order_n = 0;
    if (resolve_sources(source_arg, order, &order_n) != 0) return 1;
    char defs[1024];
    defs_root(defs, sizeof(defs));

    for (int oi = 0; oi < order_n; oi++) {
        const vdu_source *src = &VDU_SOURCES[order[oi]];
        printf("=== source '%s' (%d, mpas %s) ===\n", src->name, src->year, src->mpas);
        char workdir[1024];
        snprintf(workdir, sizeof(workdir), "vdu-work\\%s", src->name);
        mkdir_p(workdir);
        char exdir[1024];
        if (prepare_source(src, workdir, exdir, sizeof(exdir)) != 0) {
            printf("  source failed, trying next...\n");
            continue;
        }
        report_pkg_versions(exdir);
        if (!force && compat_note(exdir) != 0) {
            printf("  refusing without -force; trying next source...\n");
            continue;
        }
        apply_opts o = { exdir, defs, g_dry_run, no_health };
        if (apply_signatures(&o) == 0) {
            printf("SUCCESS with source '%s'.\n", src->name);
            return 0;
        }
        printf("  apply failed (auto-rollback done), trying next source...\n");
    }
    printf("All sources exhausted. Your current definitions are untouched.\n");
    return 1;
}

static int cmd_apply_pkg(const char *pkg, int force) {
    char defs[1024];
    defs_root(defs, sizeof(defs));
    char exdir[1024];
    if (file_exists(pkg) && str_ends_with(pkg, ".vdm") == 0 && file_exists(pkg)) {
        // could be a package exe or a directory with extracted files
        if (file_exists(pkg) && !str_ends_with(pkg, ".exe")) {
            snprintf(exdir, sizeof(exdir), "%s", pkg);
            if (files_ok_dir(exdir)) {
                apply_opts o = { exdir, defs, g_dry_run, 0 };
                if (!force) compat_note(exdir);
                return apply_signatures(&o) == 0 ? 0 : 1;
            }
        }
    }
    snprintf(exdir, sizeof(exdir), "vdu-work\\apply");
    mkdir_p(exdir);
    if (cab_extract_package(pkg, exdir) != 0) {
        vdu_log("extraction failed");
        return 1;
    }
    report_pkg_versions(exdir);
    if (!force) compat_note(exdir);
    apply_opts o = { exdir, defs, g_dry_run, 0 };
    return apply_signatures(&o) == 0 ? 0 : 1;
}

static int files_ok_dir(const char *dir) {
    char *p1 = path_join(dir, FILE_MPAS_BASE);
    char *p2 = path_join(dir, FILE_MPAS_DELTA);
    int ok = file_exists(p1) && file_exists(p2);
    free(p1); free(p2);
    return ok;
}

static int cmd_verify(const char *arg) {
    for (size_t i = 0; i < VDU_SOURCE_COUNT; i++) {
        if (str_ieq(VDU_SOURCES[i].name, arg)) {
            if (!VDU_SOURCES[i].sha256) {
                printf("source '%s' is unpinned (fwlink — changes daily); verify after download.\n", arg);
                return 0;
            }
            char wd[1024];
            snprintf(wd, sizeof(wd), "vdu-work\\%s", VDU_SOURCES[i].name);
            char *pkg = path_join(wd, "package.exe");
            int rc = verify_package_hash(&VDU_SOURCES[i], pkg);
            free(pkg);
            return rc == 0 ? 0 : 1;
        }
    }
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
    if (str_ieq(cmd, "backup")) {
        char defs[1024];
        defs_root(defs, sizeof(defs));
        char dir[1024];
        return backup_current(defs, dir, sizeof(dir)) == 0 ? 0 : 1;
    }
    if (str_ieq(cmd, "rollback")) {
        char defs[1024];
        defs_root(defs, sizeof(defs));
        return rollback_last(defs) == 0 ? 0 : 1;
    }

    const char *source_arg = NULL, *pkg = NULL, *out = NULL;
    int no_health = 0, force = 0;
    for (int i = 2; i < argc; i++) {
        if (str_ieq(argv[i], "-dry-run")) g_dry_run = 1;
        else if (str_ieq(argv[i], "-no-health")) no_health = 1;
        else if (str_ieq(argv[i], "-force")) force = 1;
        else if (str_ieq(argv[i], "-source") && i + 1 < argc) source_arg = argv[++i];
        else if (str_ieq(argv[i], "-package") && i + 1 < argc) pkg = argv[++i];
        else if (str_ieq(argv[i], "-out") && i + 1 < argc) out = argv[++i];
    }

    if (str_ieq(cmd, "fetch")) {
        if (argc < 3) { vdu_log("usage: fetch <name|current> [-out dir]"); return 1; }
        return cmd_fetch(argv[2], out);
    }
    if (str_ieq(cmd, "update")) return cmd_update(source_arg, no_health, force);
    if (str_ieq(cmd, "apply")) {
        if (!pkg) { vdu_log("usage: apply -package <pkg|dir> [-force] [-dry-run]"); return 1; }
        return cmd_apply_pkg(pkg, force);
    }
    if (str_ieq(cmd, "verify")) {
        if (argc < 3) { vdu_log("usage: verify <name|file>"); return 1; }
        return cmd_verify(argv[2]);
    }
    usage();
    return 1;
}
