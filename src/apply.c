#define _CRT_SECURE_NO_WARNINGS
#if !defined(_WIN32)
#define _POSIX_C_SOURCE 200809L
#endif
#include "apply.h"
#include "defs.h"

#ifdef _WIN32
#include <windows.h>
#endif
#include "platform.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>
#include <time.h>

static void defs_paths(const char *defs_root, strbuf *updates, strbuf *backup_root) {
    // defs_root = <ProgramData>\Microsoft\Windows Defender\Definition Updates
    // backup_root = <ProgramData>\Microsoft\Windows Defender\vdu-backup
    sb_init(updates);
    sb_init(backup_root);
    sb_puts(updates, defs_root);
    const char *slash = strrchr(defs_root, '/');
    const char *bslash = strrchr(defs_root, '\\');
    const char *last = slash > bslash ? slash : bslash;
    sb_puts(backup_root, defs_root);
    if (last) backup_root->data[last - defs_root] = 0;
    sb_puts(backup_root, "\\");
    sb_puts(backup_root, BACKUP_NAME);
}

static int copy_file(const char *src, const char *dst) {
    FILE *in = fopen(src, "rb");
    if (!in) return -1;
    FILE *out = fopen(dst, "wb");
    if (!out) { fclose(in); return -1; }
    char buf[65536];
    size_t n;
    int rc = 0;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) { rc = -1; break; }
    }
    fclose(in);
    if (fclose(out) != 0) rc = -1;
    return rc;
}

static void now_stamp(char *out, size_t outsz) {
    time_t t = time(NULL);
    struct tm *tm = localtime(&t);
    strftime(out, outsz, "%Y-%m-%dT%H-%M-%S", tm);
}

static void write_manifest(const char *path, const char *ts, const char *backup_dir,
                           const char *prev_av, const char *prev_as, const char *new_guid) {
    FILE *f = fopen(path, "wb");
    if (!f) return;
    fprintf(f,
        "{\n"
        "  \"tool\": \"" APP_NAME " " APP_VERSION "\",\n"
        "  \"timestamp\": \"%s\",\n"
        "  \"backupDir\": \"%s\",\n"
        "  \"prevAntivirus\": \"%s\",\n"
        "  \"prevAntiSpyware\": \"%s\",\n"
        "  \"newGuid\": \"%s\",\n"
        "  \"mode\": \"signatures-only\"\n"
        "}\n",
        ts, backup_dir, prev_av, prev_as, new_guid);
    fclose(f);
}

static int read_manifest(const char *path, char *backup_dir, size_t bdsz,
                         char *prev_av, size_t avs, char *prev_as, size_t ass,
                         char *new_guid, size_t gsz) {
    (void)bdsz; (void)avs; (void)ass; (void)gsz;
    size_t n;
    uint8_t *d = read_file(path, &n);
    if (!d) return -1;
    d[n] = 0;
    int ok = -1;
    char *p;
    backup_dir[0] = prev_av[0] = prev_as[0] = new_guid[0] = 0;
    if ((p = strstr((char *)d, "\"backupDir\": \"")) != NULL)
        { sscanf(p + 14, "%255[^\"]", backup_dir); ok = 0; }
    if ((p = strstr((char *)d, "\"prevAntivirus\": \"")) != NULL)
        sscanf(p + 18, "%255[^\"]", prev_av);
    if ((p = strstr((char *)d, "\"prevAntiSpyware\": \"")) != NULL)
        sscanf(p + 20, "%255[^\"]", prev_as);
    if ((p = strstr((char *)d, "\"newGuid\": \"")) != NULL)
        sscanf(p + 12, "%255[^\"]", new_guid);
    free(d);
    return ok;
}

// Read the current pointer folder (from AntiSpyware/Antivirus values) and
// copy its mpas files into backup_dir. Returns 0 if a folder was backed up.
static int backup_pointed_folder(const char *defs_root, const char *backup_dir) {
    char cur[512];
    char *base = NULL;
    if (plt.reg_read(DEF_REG_AS, cur, sizeof(cur)) && cur[0])
        base = cur;
    else if (plt.reg_read(DEF_REG_AV, cur, sizeof(cur)) && cur[0])
        base = cur;
    if (!base) {
        vdu_log("  no current definition pointer in registry (nothing to back up)");
        return -1;
    }
    char *src = path_join(defs_root, base);
    int rc = -1;
    for (int i = 0; i < 2; i++) {
        const char *fn = i == 0 ? FILE_MPAS_BASE : FILE_MPAS_DELTA;
        char *s = path_join(src, fn);
        char *d = path_join(backup_dir, fn);
        if (file_exists(s)) {
            if (copy_file(s, d) == 0) rc = 0;
        }
        free(s);
        free(d);
    }
    free(src);
    return rc;
}

int backup_current(const char *defs_root, char *out_backup_dir, size_t outsz) {
    strbuf updates, backup_root;
    defs_paths(defs_root, &updates, &backup_root);
    char ts[64];
    now_stamp(ts, sizeof(ts));
    char *dir = path_join(backup_root.data, ts);
    mkdir_p(dir);
    int rc = backup_pointed_folder(defs_root, dir);
    if (rc == 0) {
        char *mf = path_join(backup_root.data, BACKUP_MANIFEST);
        // a full manifest (with prev pointers) is written by apply; here store basic
        write_manifest(mf, ts, dir, "", "", "");
        free(mf);
        snprintf(out_backup_dir, outsz, "%s", dir);
        vdu_log("  backup: %s", dir);
    }
    free(dir);
    sb_free(&updates);
    sb_free(&backup_root);
    return rc;
}

int rollback_last(const char *defs_root) {
    strbuf updates, backup_root;
    defs_paths(defs_root, &updates, &backup_root);
    char *mf_path = path_join(backup_root.data, BACKUP_MANIFEST);
    char backup_dir[1024] = "", prev_av[512] = "", prev_as[512] = "", guid[512] = "";
    int rc = read_manifest(mf_path, backup_dir, sizeof(backup_dir), prev_av, sizeof(prev_av),
                           prev_as, sizeof(prev_as), guid, sizeof(guid));
    free(mf_path);
    if (rc != 0 || !backup_dir[0]) {
        vdu_log("no backup manifest found under %s", backup_root.data);
        sb_free(&updates);
        sb_free(&backup_root);
        return -1;
    }

    int stopped = 0;
    if (plt.service_installed()) {
        if (plt.service_stop() == 0) stopped = 1;
        else vdu_log("  warning: service stop failed; continuing");
    }

    char *src = path_join(backup_dir, FILE_MPAS_BASE);
    char *dst_folder = path_join(defs_root, prev_as[0] ? prev_as : prev_av);
    char *dst = path_join(dst_folder, FILE_MPAS_BASE);
    if (file_exists(src) && dst_folder[0]) {
        mkdir_p(dst_folder);
        if (copy_file(src, dst) == 0) vdu_log("  restored %s", FILE_MPAS_BASE);
        else vdu_log("  restore %s failed", FILE_MPAS_BASE);
    }
    free(src); free(dst_folder); free(dst);

    if (prev_av[0] || prev_as[0]) {
        if (plt.reg_write(prev_av, prev_as) == 0)
            vdu_log("  registry pointers restored (%s / %s)", prev_av, prev_as);
    }
    // remove the failed GUID folder
    if (guid[0]) {
        char *bad = path_join(defs_root, guid);
        char *cmd = xmalloc(strlen(bad) + 64);
#ifdef _WIN32
        sprintf(cmd, "rd /s /q \"%s\"", bad);
        system(cmd);
#else
        sprintf(cmd, "rm -rf \"%s\"", bad);
        system(cmd);
#endif
        free(cmd);
        free(bad);
        vdu_log("  removed failed definition folder %s", guid);
    }

    if (stopped) {
        if (plt.service_start() != 0) vdu_log("  warning: service start failed");
    }
    vdu_log("Rolled back.");
    sb_free(&updates);
    sb_free(&backup_root);
    return 0;
}

static int files_ok(const char *dir) {
    char *p1 = path_join(dir, FILE_MPAS_BASE);
    char *p2 = path_join(dir, FILE_MPAS_DELTA);
    int ok = file_exists(p1) && file_exists(p2);
    free(p1);
    free(p2);
    return ok;
}

int apply_signatures(const apply_opts *o) {
    if (!files_ok(o->sig_dir)) {
        vdu_log("signature files missing in %s (need %s + %s)",
                o->sig_dir, FILE_MPAS_BASE, FILE_MPAS_DELTA);
        return -1;
    }

    strbuf updates, backup_root;
    defs_paths(o->defs_root, &updates, &backup_root);

    char prev_av[512] = "", prev_as[512] = "";
    plt.reg_read(DEF_REG_AV, prev_av, sizeof(prev_av));
    plt.reg_read(DEF_REG_AS, prev_as, sizeof(prev_as));

    char ts[64];
    now_stamp(ts, sizeof(ts));

    if (o->dry_run) {
        vdu_log("[DRY RUN] would create %s\\{GUID} with %s + %s and flip registry pointers",
                o->defs_root, FILE_MPAS_BASE, FILE_MPAS_DELTA);
        vdu_log("[DRY RUN] current pointers: Antivirus='%s' AntiSpyware='%s'", prev_av, prev_as);
        sb_free(&updates);
        sb_free(&backup_root);
        return 0;
    }

    char guid[128];
    if (plt.guid_new(guid, sizeof(guid)) != 0) {
        sb_free(&updates);
        sb_free(&backup_root);
        return -1;
    }
    char *new_folder = path_join(o->defs_root, guid);

    // stop the service first (files may be locked)
    int stopped = 0;
    if (plt.service_installed()) {
        vdu_log("  stopping " DEF_SERVICE "...");
        if (plt.service_stop() == 0) stopped = 1;
        else vdu_log("  warning: stop failed; continuing");
    }

    // backup current pointed folder
    mkdir_p(backup_root.data);
    char *bk_dir = path_join(backup_root.data, ts);
    mkdir_p(bk_dir);
    backup_pointed_folder(o->defs_root, bk_dir);

    // write new files
    int rc = 0;
    mkdir_p(new_folder);
    for (int i = 0; i < 2 && rc == 0; i++) {
        const char *fn = i == 0 ? FILE_MPAS_BASE : FILE_MPAS_DELTA;
        char *s = path_join(o->sig_dir, fn);
        char *d = path_join(new_folder, fn);
        if (copy_file(s, d) != 0) { vdu_log("copy %s failed", fn); rc = -1; }
        else vdu_log("  staged %s -> %s\\%s", fn, guid, fn);
        free(s);
        free(d);
    }

    if (rc == 0) {
        if (plt.reg_write(guid, guid) != 0) {
            vdu_log("registry write failed");
            rc = -1;
        } else {
            vdu_log("  registry pointers -> %s", guid);
        }
    }

    // manifest (points at the NEW guid so rollback can clean up)
    char *mf = path_join(backup_root.data, BACKUP_MANIFEST);
    write_manifest(mf, ts, bk_dir, prev_av, prev_as, guid);
    free(mf);

    if (rc != 0) {
        if (stopped) plt.service_start();
        sb_free(&updates);
        sb_free(&backup_root);
        free(new_folder);
        free(bk_dir);
        return -1;
    }

    // start + health check
    vdu_log("  starting " DEF_SERVICE "...");
    int health_ok = 1;
    if (plt.service_start() != 0) {
        health_ok = 0;
        vdu_log("  service failed to start");
    } else {
        // give the engine a moment, then confirm it is still running
        for (int i = 0; i < 10 && plt.service_running(); i++) {
#ifdef _WIN32
            Sleep(500);
#else
            struct timespec ts2 = { 0, 500 * 1000 * 1000 };
            nanosleep(&ts2, NULL);
#endif
        }
        if (!plt.service_running()) {
            health_ok = 0;
            vdu_log("  service died after start — engine rejected the definitions");
        }
    }

    if (!health_ok && !o->no_health) {
        vdu_log("  health check failed — auto-rollback");
        rollback_last(o->defs_root);
        sb_free(&updates);
        sb_free(&backup_root);
        free(new_folder);
        free(bk_dir);
        return -1;
    }
    if (!health_ok && o->no_health)
        vdu_log("  health check failed, but auto-rollback is disabled");

    vdu_log("Applied. Definition folder: %s\\%s", o->defs_root, guid);
    sb_free(&updates);
    sb_free(&backup_root);
    free(new_folder);
    free(bk_dir);
    return 0;
}
