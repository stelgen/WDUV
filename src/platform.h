// platform.h — Windows facilities behind overridable hooks so the whole
// tool is testable off-Windows: registry, service, GUIDs, downloads.
#ifndef VDU_PLATFORM_H
#define VDU_PLATFORM_H

#include <stddef.h>
#include <stdint.h>

// --- registry hooks ---------------------------------------------------
// Read Signatures\Antivirus (or AS) value; out filled with the string,
// returns 1 if present, 0 if absent/error.
int plt_reg_read(const char *value, char *out, size_t outsz);
// Write both Antivirus and AntiSpyware values.
int plt_reg_write(const char *av, const char *as);
// Enumerate: write "name = data" lines of the Signatures key into a FILE*.
int plt_reg_dump(void *file_out);

// --- service ----------------------------------------------------------
int plt_service_installed(void);
int plt_service_stop(void);   // best-effort; 0 ok
int plt_service_start(void);  // 0 ok
int plt_service_running(void);

// --- misc -------------------------------------------------------------
// Generate a new GUID string like "{B37BD0A0-...}".
int plt_guid_new(char *out, size_t outsz);
// Get the common appdata root ("C:\ProgramData" / env override).
int plt_common_appdata(char *out, size_t outsz);
// Download url to path (HTTP/HTTPS). Returns 0 on success.
int plt_download(const char *url, const char *path);
// Machine architecture: 0 = x86, 64 = x64 (or the host in tests).
int plt_arch(void);

// Test override struct: non-NULL members replace the real implementations.
typedef struct {
    int  (*reg_read)(const char *value, char *out, size_t outsz);
    int  (*reg_write)(const char *av, const char *as);
    int  (*reg_dump)(void *file_out);
    int  (*service_installed)(void);
    int  (*service_stop)(void);
    int  (*service_start)(void);
    int  (*service_running)(void);
    int  (*guid_new)(char *out, size_t outsz);
    int  (*common_appdata)(char *out, size_t outsz);
    int  (*download)(const char *url, const char *path);
    int  (*arch)(void);
} vdu_hooks;

extern vdu_hooks plt;

#endif
