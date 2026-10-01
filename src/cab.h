// cab.h — CAB archive tables, folder streaming and package extraction.
#ifndef VDU_CAB_H
#define VDU_CAB_H

#include <stdint.h>
#include <stdio.h>

#define CAB_COMP_NONE  0
#define CAB_COMP_MSZIP 2
#define CAB_COMP_LZX   3

typedef struct {
    int  num_folders, num_files;
    int  data_resv, folder_resv, header_resv;
} cab_header_info;

typedef struct {
    int64_t  data_off;   // absolute file offset of the first CFDATA header
    int      blocks;
    uint16_t comp_type;
} cab_folder;

typedef struct {
    char    *name;       // malloc'd
    int64_t  size;
    int64_t  pos;
    int      folder;
} cab_file_entry;

// Parse header + folder table + file table of the cabinet at absolute
// offset `off`. Caller frees entries (names) via cab_free_entries.
int cab_parse(FILE *f, int64_t off, cab_header_info *hdr,
              cab_folder **folders, int *n_folders,
              cab_file_entry **files, int *n_files);
void cab_free_entries(cab_file_entry *files, int n);

// Extract every file of the cabinet into out_dir (using the per-folder
// decoders: stored + LZX; MSZIP folders are rejected).
int cab_extract_package(const char *pkg_path, const char *out_dir);

// Extract a bare CAB file (or locate the CAB inside a PE wrapper first).
int cab_extract(const char *pkg_path, const char *out_dir,
                int64_t *out_cab_off, int64_t *out_cab_len);

#endif
