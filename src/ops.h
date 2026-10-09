// ops.h — high-level operations shared by the CLI and the GUI.
#ifndef VDU_OPS_H
#define VDU_OPS_H

#include <stddef.h>

#include "defs.h"

typedef void (*vdu_log_fn)(void *ud, const char *line);

// update: walk the source ladder freshest-first, download + verify + extract
// + apply signatures-only, health-check, auto-rollback on failure and fall
// through to the next-older source. strict = refuse sources whose package
// engine line differs from the local engine (default: informational).
int  vdu_ops_update(const char *source_arg, int no_health, int force, int strict, int dry_run,
                    vdu_log_fn log, void *ud);
int  vdu_ops_apply(const char *pkg, int force, int dry_run, vdu_log_fn log, void *ud);
int  vdu_ops_fetch(const char *name_arg, const char *out, vdu_log_fn log, void *ud);
int  vdu_ops_verify_hash(const vdu_source *src, const char *path, vdu_log_fn log, void *ud);
// 0 = verified, 1 = failed, -1 = not a source name
int  vdu_ops_verify_source(const char *name_arg, vdu_log_fn log, void *ud);
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