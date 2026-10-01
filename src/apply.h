// apply.h — the Vista-native application model: signatures-only apply into
// a fresh Definition Updates\{GUID} folder + registry pointer flip, with
// backup / rollback / health-check-with-auto-rollback.
#ifndef VDU_APPLY_H
#define VDU_APPLY_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    const char *sig_dir;   // directory with extracted mpasbase/mpasdlta
    const char *defs_root; // e.g. C:\ProgramData\Microsoft\Windows Defender\Definition Updates
    int  dry_run;
    int  no_health;        // skip service health check / auto-rollback
} apply_opts;

// Returns 0 on success. On health-check failure the previous state is
// restored automatically (unless no_health).
int apply_signatures(const apply_opts *o);

// Backup the current definition set (pointed folder) to <defs_root>\..\vdu-backup\<ts>.
int backup_current(const char *defs_root, char *out_backup_dir, size_t outsz);

// Rollback to the newest backup recorded in the manifest.
int rollback_last(const char *defs_root);

#endif
