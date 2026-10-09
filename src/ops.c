#define _CRT_SECURE_NO_WARNINGS
#include "ops.h"
#include "apply.h"
#include "cab.h"
#include "defs.h"
#include "pe.h"
#include "platform.h"
#include "sha256.h"
#include "status.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void defs_root_of(char *out, size_t outsz) {
    const char *env = getenv("VDU_DEFS_ROOT");
    if (env && env[0]) {
        snprintf(out, outsz, "%s", env);
        return;
    }
    char appdata[1024] = "C:\\ProgramData";
    plt.common_appdata(appdata, sizeof(appdata));
    snprintf(out, outsz, "%s\\Microsoft\\Windows Defender\\Definition Updates", appdata);
}

void vdu_ops_defs_root(char *out, size_t outsz) { defs_root_of(out, outsz); }

size_t vdu_ops_source_count(void) { return VDU_SOURCE_COUNT; }
const char *vdu_ops_source_name(size_t i)  { return i < VDU_SOURCE_COUNT ? VDU_SOURCES[i].name  : ""; }
const char *vdu_ops_source_engine(size_t i){ return i < VDU_SOURCE_COUNT ? VDU_SOURCES[i].engine : ""; }
const char *vdu_ops_source_mpas(size_t i)  { return i < VDU_SOURCE_COUNT ? VDU_SOURCES[i].mpas   : ""; }
const char *vdu_ops_source_note(size_t i)  { return i < VDU_SOURCE_COUNT ? VDU_SOURCES[i].note   : ""; }

// Resolve -source arg (name or index) into the default ladder order.
// order must have room for VDU_SOURCE_COUNT entries.
static int resolve_sources(const char *arg, int *order, int *order_n, vdu_log_fn log, void *ud) {
    if (!arg) {
        for (size_t i = 0; i < VDU_SOURCE_COUNT; i++) order[i] = (int)i;
        *order_n = (int)VDU_SOURCE_COUNT;
        return 0;
    }
    for (size_t i = 0; i < VDU_SOURCE_COUNT; i++) {
        if (str_ieq(VDU_SOURCES[i].name, arg)) {
            order[0] = (int)i;
            *order_n = 1;
            return 0;
        }
    }
    char *end = NULL;
    long idx = strtol(arg, &end, 10);
    if (end && *end == 0 && idx >= 0 && idx < (long)VDU_SOURCE_COUNT) {
        order[0] = (int)idx;
        *order_n = 1;
        return 0;
    }
    char line[256];
    snprintf(line, sizeof(line), "unknown source '%s' (see 'sources')", arg);
    log(ud, line);
    return -1;
}

int vdu_ops_verify_hash(const vdu_source *src, const char *path, vdu_log_fn log, void *ud) {
    if (!src->sha256) return 0; // unpinned (fwlink changes daily)
    size_t n;
    uint8_t *d = read_file(path, &n);
    if (!d) return -1;
    uint8_t hash[32];
    char hex[65], line[256];
    vdu_sha256_buf(d, n, hash);
    to_hex(hash, 32, hex);
    free(d);
    if (!str_ieq(hex, src->sha256)) {
        snprintf(line, sizeof(line), "SHA-256 mismatch: got %s", hex);
        log(ud, line);
        return -1;
    }
    snprintf(line, sizeof(line), "sha256 ok: %s", hex);
    log(ud, line);
    return 0;
}

static int prepare_source(const vdu_source *src, const char *workdir, char *out_dir, size_t outsz,
                          vdu_log_fn log, void *ud) {
    char *pkg = path_join(workdir, "package.exe");
    if (!file_exists(pkg)) {
        char line[512];
        snprintf(line, sizeof(line), "downloading %s ...", src->url);
        log(ud, line);
        if (plt.download(src->url, pkg) != 0) {
            snprintf(line, sizeof(line), "download failed (%s)", src->url);
            log(ud, line);
            free(pkg);
            return -1;
        }
    } else {
        char line[512];
        snprintf(line, sizeof(line), "reusing cached %s", pkg);
        log(ud, line);
    }
    if (vdu_ops_verify_hash(src, pkg, log, ud) != 0) { free(pkg); return -1; }
    char *ex = path_join(workdir, "extracted");
    mkdir_p(ex);
    if (cab_extract_package(pkg, ex) != 0) {
        log(ud, "extraction failed");
        free(pkg); free(ex);
        return -1;
    }
    snprintf(out_dir, outsz, "%s", ex);
    free(pkg);
    free(ex);
    return 0;
}

// Report package engine vs local engine family.
//
// An update installs ONLY the signature files (mpasbase/mpasdlta.vdm) — never
// the package engine. Definition generations share one time scale across
// engine lines (docs/ANALYSIS.md §1), so a package built for the MSE-era
// 1.2.x line is normally loadable by the built-in 1.1.x engine. By default a
// mismatch is therefore informational; the service health check plus the
// automatic rollback remain the actual safety gate. -strict restores the old
// refusal-on-mismatch behaviour.
static int compat_note(const char *workdir, int strict, vdu_log_fn log, void *ud) {
    char *pkg_eng = path_join(workdir, FILE_ENGINE);
    size_t n;
    uint8_t *d = read_file(pkg_eng, &n);
    free(pkg_eng);
    if (!d) { log(ud, "package engine unknown; family check skipped"); return 0; }
    char pv[128] = "";
    pe_file_version(d, n, pv, sizeof(pv));
    free(d);

    char engp[1024];
    const char *pf = getenv("ProgramFiles");
    snprintf(engp, sizeof(engp), "%s\\Windows Defender\\" FILE_ENGINE, pf ? pf : "C:\\Program Files");
    d = read_file(engp, &n);
    char lv[128] = "(none)";
    if (d) { pe_file_version(d, n, lv, sizeof(lv)); free(d); }

    char line[512];
    snprintf(line, sizeof(line), "package engine %s vs local engine %s", pv, lv);
    log(ud, line);
    if (lv[0] == '(') { log(ud, "local engine not found; family gate skipped"); return 0; }
    if (strncmp(pv, lv, 4) == 0) return 0; // same engine line

    if (strict) {
        log(ud, "ENGINE FAMILY MISMATCH (strict mode): refusing this source.");
        log(ud, "without -strict, signatures-only apply would proceed (guarded by health check + rollback)");
        return -1;
    }
    log(ud, "engine line differs from the package line; signatures-only apply proceeds");
    log(ud, "(guarded by the service health check and automatic rollback)");
    return 0;
}

int vdu_ops_update(const char *source_arg, int no_health, int force, int strict, int dry_run,
                   vdu_log_fn log, void *ud) {
    (void)force; // retained for CLI/API compatibility; the ladder self-guards
    int order[VDU_SOURCE_COUNT], order_n = 0;
    if (resolve_sources(source_arg, order, &order_n, log, ud) != 0) return 1;
    char defs[1024];
    defs_root_of(defs, sizeof(defs));

    for (int oi = 0; oi < order_n; oi++) {
        const vdu_source *src = &VDU_SOURCES[order[oi]];
        char line[512];
        snprintf(line, sizeof(line), "=== source '%s' (%d, mpas %s) ===", src->name, src->year, src->mpas);
        log(ud, line);
        char workdir[1024];
        snprintf(workdir, sizeof(workdir), "vdu-work\\%s", src->name);
        mkdir_p(workdir);
        char exdir[1024];
        if (prepare_source(src, workdir, exdir, sizeof(exdir), log, ud) != 0) {
            log(ud, "source failed, trying next...");
            continue;
        }
        char bver[128], dver[128], vline[256];
        vdu_status_pkg_defs(exdir, bver, sizeof(bver), dver, sizeof(dver));
        snprintf(vline, sizeof(vline), "package: engine %s, mpas %s",
                 vdu_status_pkg_engine(exdir, bver, sizeof(bver)) == 0 ? bver : "?", dver);
        log(ud, vline);
        if (compat_note(exdir, strict, log, ud) != 0) {
            log(ud, "refusing (strict); trying next source...");
            continue;
        }
        apply_opts o = { exdir, defs, dry_run, no_health };
        if (apply_signatures(&o) == 0) {
            snprintf(line, sizeof(line), "SUCCESS with source '%s'.", src->name);
            log(ud, line);
            return 0;
        }
        log(ud, "apply failed (auto-rollback done), trying next source...");
    }
    log(ud, "All sources exhausted. Your current definitions are untouched.");
    return 1;
}

int vdu_ops_apply(const char *pkg, int force, int dry_run, vdu_log_fn log, void *ud) {
    char defs[1024];
    defs_root_of(defs, sizeof(defs));
    char exdir[1024];

    // directory with extracted signatures?
    char *p1 = path_join(pkg, FILE_MPAS_BASE);
    char *p2 = path_join(pkg, FILE_MPAS_DELTA);
    int is_dir = file_exists(p1) && file_exists(p2);
    free(p1); free(p2);
    if (is_dir) {
        snprintf(exdir, sizeof(exdir), "%s", pkg);
    } else {
        snprintf(exdir, sizeof(exdir), "vdu-work\\apply");
        mkdir_p(exdir);
        if (cab_extract_package(pkg, exdir) != 0) {
            log(ud, "extraction failed");
            return 1;
        }
    }
    char bver[128], dver[128], vline[256];
    vdu_status_pkg_defs(exdir, bver, sizeof(bver), dver, sizeof(dver));
    snprintf(vline, sizeof(vline), "package: mpas base %s, delta %s",
             bver[0] ? bver : "?", dver[0] ? dver : "?");
    log(ud, vline);
    (void)force;
    compat_note(exdir, 0, log, ud); // informational for signatures-only apply
    apply_opts o = { exdir, defs, dry_run, 0 };
    return apply_signatures(&o) == 0 ? 0 : 1;
}

int vdu_ops_fetch(const char *name_arg, const char *out, vdu_log_fn log, void *ud) {
    int order[VDU_SOURCE_COUNT], order_n = 0;
    if (resolve_sources(name_arg, order, &order_n, log, ud) != 0) return 1;
    const vdu_source *src = &VDU_SOURCES[order[0]];
    char workdir[1024];
    snprintf(workdir, sizeof(workdir), "%s", out ? out : ".");
    char exdir[1024];
    if (prepare_source(src, workdir, exdir, sizeof(exdir), log, ud) != 0) return 1;
    char bver[128], dver[128], line[1152];
    vdu_status_pkg_defs(exdir, bver, sizeof(bver), dver, sizeof(dver));
    snprintf(line, sizeof(line), "Package '%s' prepared in %s", src->name, exdir);
    log(ud, line);
    char ever[128];
    if (vdu_status_pkg_engine(exdir, ever, sizeof(ever)) == 0) {
        snprintf(line, sizeof(line), "package engine: %s", ever);
        log(ud, line);
    }
    snprintf(line, sizeof(line), "package %s: %s", FILE_MPAS_BASE, bver[0] ? bver : "?");
    log(ud, line);
    snprintf(line, sizeof(line), "package %s: %s", FILE_MPAS_DELTA, dver[0] ? dver : "?");
    log(ud, line);
    snprintf(line, sizeof(line),
             "Carry this folder to the Vista machine and run: vdu apply -package \"%s\"", exdir);
    log(ud, line);
    return 0;
}

// Verify the pinned hash of a cached source package. Returns 0 = verified,
// 1 = failed, -1 = 'arg' is not a source name (caller may try a file path).
int vdu_ops_verify_source(const char *name_arg, vdu_log_fn log, void *ud) {
    for (size_t i = 0; i < VDU_SOURCE_COUNT; i++) {
        if (str_ieq(VDU_SOURCES[i].name, name_arg)) {
            if (!VDU_SOURCES[i].sha256) {
                log(ud, "source is unpinned (fwlink — changes daily); verify after download.");
                return 0;
            }
            char wd[1024];
            snprintf(wd, sizeof(wd), "vdu-work\\%s", VDU_SOURCES[i].name);
            char *pkg = path_join(wd, "package.exe");
            int rc = vdu_ops_verify_hash(&VDU_SOURCES[i], pkg, log, ud);
            free(pkg);
            return rc == 0 ? 0 : 1;
        }
    }
    return -1;
}

int vdu_ops_backup(vdu_log_fn log, void *ud) {
    char defs[1024];
    defs_root_of(defs, sizeof(defs));
    char dir[1024];
    if (backup_current(defs, dir, sizeof(dir)) == 0) {
        char line[1152];
        snprintf(line, sizeof(line), "backup written: %s", dir);
        log(ud, line);
        return 0;
    }
    log(ud, "backup failed (no current definition set found?)");
    return 1;
}

int vdu_ops_rollback(vdu_log_fn log, void *ud) {
    (void)log; (void)ud;
    char defs[1024];
    defs_root_of(defs, sizeof(defs));
    return rollback_last(defs) == 0 ? 0 : 1;
}