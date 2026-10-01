// status.h — shared status collection (CLI + GUI).
#ifndef VDU_STATUS_H
#define VDU_STATUS_H

#include <stddef.h>

typedef struct {
    char engine_ver[128];     // local mpengine.dll FileVersion ("1.1.17020.2")
    char engine_path[1024];
    char def_ver[128];        // definition version from the active vdm
    char def_folder[1024];    // active GUID folder (registry pointer)
    char reg_av[512], reg_as[512];
    char app_ver[64];
    int  service_installed;
    int  service_running;
    char defs_root[1024];
} vdu_status;

// Collect everything; platform hooks decide how much is real. Returns 0.
int vdu_status_collect(vdu_status *st);

// The engine FileVersion of an extracted package dir (mpengine.dll), "" if n/a.
int vdu_status_pkg_engine(const char *dir, char *out, size_t outsz);
int vdu_status_pkg_defs(const char *dir, char *out_base, size_t bs, char *out_delta, size_t ds);

#endif
