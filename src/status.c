#define _CRT_SECURE_NO_WARNINGS
#include "status.h"
#include "apply.h"
#include "defs.h"
#include "pe.h"
#include "platform.h"
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

int vdu_status_collect(vdu_status *st) {
    memset(st, 0, sizeof(*st));
    snprintf(st->app_ver, sizeof(st->app_ver), "%s", APP_VERSION);
    defs_root_of(st->defs_root, sizeof(st->defs_root));

    // local engine
    {
        const char *pf = getenv("ProgramFiles");
        snprintf(st->engine_path, sizeof(st->engine_path),
                 "%s\\Windows Defender\\" FILE_ENGINE, pf ? pf : "C:\\Program Files");
    }
    size_t n;
    uint8_t *d = read_file(st->engine_path, &n);
    if (d) {
        pe_file_version(d, n, st->engine_ver, sizeof(st->engine_ver));
        free(d);
    }

    // registry pointers
    plt.reg_read(DEF_REG_AV, st->reg_av, sizeof(st->reg_av));
    plt.reg_read(DEF_REG_AS, st->reg_as, sizeof(st->reg_as));
    st->service_installed = plt.service_installed();
    st->service_running = plt.service_running();

    // active definition folder + version
    const char *guid = st->reg_as[0] ? st->reg_as : st->reg_av;
    if (guid[0]) {
        snprintf(st->def_folder, sizeof(st->def_folder), "%s\\%s", st->defs_root, guid);
        char *ab = path_join(st->def_folder, FILE_MPAS_BASE);
        uint8_t *dd = read_file(ab, &n);
        if (dd) {
            pe_file_version(dd, n, st->def_ver, sizeof(st->def_ver));
            free(dd);
        }
        free(ab);
    }
    return 0;
}

int vdu_status_pkg_engine(const char *dir, char *out, size_t outsz) {
    out[0] = 0;
    char *eng = path_join(dir, FILE_ENGINE);
    size_t n;
    uint8_t *d = read_file(eng, &n);
    free(eng);
    if (!d) return -1;
    int rc = pe_file_version(d, n, out, outsz);
    free(d);
    return rc;
}

int vdu_status_pkg_defs(const char *dir, char *out_base, size_t bs, char *out_delta, size_t ds) {
    out_base[0] = out_delta[0] = 0;
    char *ab = path_join(dir, FILE_MPAS_BASE);
    char *ad = path_join(dir, FILE_MPAS_DELTA);
    size_t n;
    uint8_t *d = read_file(ab, &n);
    if (d) { pe_file_version(d, n, out_base, bs); free(d); }
    d = read_file(ad, &n);
    if (d) { pe_file_version(d, n, out_delta, ds); free(d); }
    free(ab);
    free(ad);
    return 0;
}
