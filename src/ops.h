// ops.h — high-level operations shared by the CLI and the GUI.
#ifndef VDU_OPS_H
#define VDU_OPS_H

#include <stddef.h>

typedef void (*vdu_log_fn)(void *ud, const char *line);

int  vdu_ops_update(const char *source_arg, int no_health, int force, int dry_run,
                    vdu_log_fn log, void *ud);
int  vdu_ops_apply(const char *pkg, int force, int dry_run, vdu_log_fn log, void *ud);
int  vdu_ops_backup(vdu_log_fn log, void *ud);
int  vdu_ops_rollback(vdu_log_fn log, void *ud);
void vdu_ops_defs_root(char *out, size_t outsz);

// source table access for UIs
size_t      vdu_ops_source_count(void);
const char *vdu_ops_source_name(size_t i);
const char *vdu_ops_source_engine(size_t i);
const char *vdu_ops_source_mpas(size_t i);
const char *vdu_ops_source_note(size_t i);

#endif
