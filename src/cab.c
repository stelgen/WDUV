#include "cab.h"
#include "defs.h"
#include "lzx.h"
#include "pe.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>

int cab_parse(FILE *f, int64_t off, cab_header_info *hdr,
              cab_folder **folders_out, int *n_folders_out,
              cab_file_entry **files_out, int *n_files_out) {
    uint8_t h[40];
    if (fseek(f, (long)off, SEEK_SET) != 0 || fread(h, 1, 36, f) != 36) return -1;
    cab_header_info hi;
    memset(&hi, 0, sizeof(hi));
    hi.num_folders = vdu_le16(h, 26);
    hi.num_files = vdu_le16(h, 28);
    uint16_t flags = vdu_le16(h, 30);
    if (flags & 0x0010) {
        uint8_t r[4];
        if (fseek(f, (long)(off + 36), SEEK_SET) != 0 || fread(r, 1, 4, f) != 4) return -1;
        int n = (int)vdu_le32(r, 0);
        if (n > 256) return -1;
        hi.header_resv = 4 + n;
    }
    if (flags & 0x0020) {
        uint8_t r[2];
        if (fseek(f, (long)(off + 36 + hi.header_resv), SEEK_SET) != 0 || fread(r, 1, 2, f) != 2) return -1;
        hi.folder_resv = vdu_le16(r, 0);
    }
    if (flags & 0x0040) {
        uint8_t r[1];
        if (fseek(f, (long)(off + 38 + hi.header_resv), SEEK_SET) != 0 || fread(r, 1, 1, f) != 1) return -1;
        hi.data_resv = r[0];
    }

    cab_folder *folders = xcalloc((size_t)(hi.num_folders ? hi.num_folders : 1), sizeof(cab_folder));
    int64_t base = off + 36 + hi.header_resv;
    for (int i = 0; i < hi.num_folders; i++) {
        uint8_t fo[8];
        if (fseek(f, (long)(base + (int64_t)i * (8 + hi.folder_resv)), SEEK_SET) != 0 ||
            fread(fo, 1, 8, f) != 8) { free(folders); return -1; }
        folders[i].data_off = off + (int64_t)vdu_le32(fo, 0);
        folders[i].blocks = vdu_le16(fo, 4);
        folders[i].comp_type = vdu_le16(fo, 6);
    }

    cab_file_entry *files = xcalloc((size_t)(hi.num_files ? hi.num_files : 1), sizeof(cab_file_entry));
    int64_t p = off + (int64_t)vdu_le32(h, 16);
    for (int i = 0; i < hi.num_files; i++) {
        uint8_t fe[16];
        if (fseek(f, (long)p, SEEK_SET) != 0 || fread(fe, 1, 16, f) != 16) { goto fail; }
        // name: read bytes until nul (cap 512)
        char name[514];
        size_t nl = 0;
        for (;;) {
            uint8_t b;
            if (fseek(f, (long)(p + 16 + nl), SEEK_SET) != 0 || fread(&b, 1, 1, f) != 1) goto fail;
            if (b == 0) break;
            if (nl >= 512) goto fail;
            name[nl++] = (char)b;
        }
        name[nl] = 0;
        files[i].name = xstrdup(name);
        files[i].size = (int64_t)vdu_le32(fe, 0);
        files[i].pos = (int64_t)vdu_le32(fe, 4);
        files[i].folder = vdu_le16(fe, 8);
        p += 16 + (int64_t)nl + 1;
    }
    *hdr = hi;
    *folders_out = folders;
    *n_folders_out = hi.num_folders;
    *files_out = files;
    *n_files_out = hi.num_files;
    return 0;
fail:
    cab_free_entries(files, hi.num_files);
    free(folders);
    return -1;
}

void cab_free_entries(cab_file_entry *files, int n) {
    for (int i = 0; i < n; i++) free(files[i].name);
    free(files);
}

// ---- folder stream: serve CFDATA payload bytes as one continuous stream ----

typedef struct {
    FILE *f;
    int remaining;
    int data_resv;
    uint8_t *cur;
    int cur_len, cur_pos;
} folder_stream;

static int fs_next_block(folder_stream *s) {
    if (s->remaining <= 0) return -1;
    uint8_t hdr[8];
    if (fread(hdr, 1, 8, s->f) != 8) return -1;
    for (int i = 0; i < s->data_resv; i++) {
        if (fgetc(s->f) == EOF) return -1;
    }
    int cb_comp = vdu_le16(hdr, 4);
    int cb_uncomp = vdu_le16(hdr, 6);
    if (cb_comp > 0x8000 || cb_uncomp > 0x8000) return -1;
    free(s->cur);
    s->cur = xmalloc((size_t)(cb_comp ? cb_comp : 1));
    if (cb_comp && fread(s->cur, 1, (size_t)cb_comp, s->f) != (size_t)cb_comp) return -1;
    s->remaining--;
    s->cur_len = cb_comp;
    s->cur_pos = 0;
    return 0;
}

static int fs_read_byte(void *ud) {
    folder_stream *s = ud;
    while (s->cur_pos >= s->cur_len) {
        if (fs_next_block(s) != 0) return -1;
    }
    return s->cur[s->cur_pos++];
}

// ---- split writer: route the folder output into per-file writers ----

typedef struct {
    const char *dir;
    cab_file_entry *entries;
    int n_entries, idx;
    int64_t pos;
    FILE *handles[8];
    int handle_idx[8];
    int handle_count;
} split_writer;

static FILE *sw_handle(split_writer *sw, int idx) {
    for (int i = 0; i < sw->handle_count; i++)
        if (sw->handle_idx[i] == idx) return sw->handles[i];
    if (sw->handle_count == 8) return NULL;
    char *path = path_join(sw->dir, sw->entries[idx].name);
    FILE *f = fopen(path, "wb");
    free(path);
    if (!f) return NULL;
    sw->handles[sw->handle_count] = f;
    sw->handle_idx[sw->handle_count] = idx;
    sw->handle_count++;
    return f;
}

static void sw_close_all(split_writer *sw) {
    for (int i = 0; i < sw->handle_count; i++) fclose(sw->handles[i]);
    sw->handle_count = 0;
}

static int sw_write(void *ud, const uint8_t *p, size_t n) {
    split_writer *sw = ud;
    size_t done = 0;
    while (done < n) {
        if (sw->idx >= sw->n_entries) return -1;
        cab_file_entry *e = &sw->entries[sw->idx];
        if (sw->pos < e->pos) return -1;
        int64_t remain = e->pos + e->size - sw->pos;
        if (remain <= 0) { sw->idx++; continue; }
        size_t take = (size_t)(e->pos + e->size - sw->pos);
        if (take > n - done) take = n - done;
        FILE *f = sw_handle(sw, sw->idx);
        if (!f) return -1;
        if (fwrite(p + done, 1, take, f) != take) return -1;
        sw->pos += (int64_t)take;
        done += take;
    }
    return 0;
}

// ---- decoders ----

typedef struct {
    folder_stream *fs;
    int64_t total;
    split_writer *sw;
    lzx_decoder *lzx; // set for LZX folders
} decode_ctx;

static int decode_stored(decode_ctx *c) {
    int64_t written = 0;
    uint8_t buf[32768];
    while (written < c->total) {
        if (c->fs->remaining <= 0) break;
        if (fs_next_block(c->fs) != 0) return -1;
        int64_t take = c->fs->cur_len;
        if (written + take > c->total) take = c->total - written;
        if (sw_write(c->sw, c->fs->cur, (size_t)take) != 0) return -1;
        written += take;
        c->fs->cur_pos = c->fs->cur_len; // consumed
        (void)buf;
    }
    return written == c->total ? 0 : -1;
}

static int decode_lzx(decode_ctx *c, int window_bits) {
    lzx_decoder *d = lzx_new(window_bits);
    if (!d) return -1;
    lzx_in lin = { fs_read_byte, c->fs };
    lzx_out lout = { sw_write, c->sw };
    int rc = lzx_decompress(d, lin, lout, c->total);
    lzx_free(d);
    return rc;
}

int cab_extract(const char *pkg_path, const char *out_dir,
                int64_t *out_cab_off, int64_t *out_cab_len) {
    FILE *f = fopen(pkg_path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    int64_t fsize = ftell(f);

    int64_t cab_off = 0, cab_len = 0;
    if (pe_find_cab(f, fsize, &cab_off, &cab_len) != 0) { fclose(f); return -1; }
    if (out_cab_off) *out_cab_off = cab_off;
    if (out_cab_len) *out_cab_len = cab_len;

    cab_header_info hdr;
    cab_folder *folders = NULL;
    cab_file_entry *files = NULL;
    int n_folders = 0, n_files = 0;
    if (cab_parse(f, cab_off, &hdr, &folders, &n_folders, &files, &n_files) != 0) {
        fclose(f);
        return -1;
    }

    int rc = 0;
    for (int fi = 0; fi < n_folders && rc == 0; fi++) {
        // collect + sort entries of this folder by pos
        cab_file_entry *ent = xcalloc((size_t)(n_files ? n_files : 1), sizeof(cab_file_entry));
        int ne = 0;
        for (int i = 0; i < n_files; i++)
            if (files[i].folder == fi) ent[ne++] = files[i];
        if (ne == 0) { free(ent); continue; }
        for (int i = 0; i < ne; i++)
            for (int j = i + 1; j < ne; j++)
                if (ent[j].pos < ent[i].pos) { cab_file_entry t = ent[i]; ent[i] = ent[j]; ent[j] = t; }

        int64_t total = 0;
        for (int i = 0; i < ne; i++) {
            if (ent[i].pos != total) { rc = -1; break; }
            total += ent[i].size;
        }
        if (rc == 0) {
            split_writer sw;
            memset(&sw, 0, sizeof(sw));
            sw.dir = out_dir;
            sw.entries = ent;
            sw.n_entries = ne;
            if (fseek(f, (long)folders[fi].data_off, SEEK_SET) != 0) { rc = -1; }
            else {
                folder_stream fs;
                memset(&fs, 0, sizeof(fs));
                fs.f = f;
                fs.remaining = folders[fi].blocks;
                fs.data_resv = hdr.data_resv;
                decode_ctx c = { &fs, total, &sw, NULL };
                uint16_t ct = folders[fi].comp_type & 0xF;
                if (ct == CAB_COMP_NONE) rc = decode_stored(&c);
                else if (ct == CAB_COMP_LZX) rc = decode_lzx(&c, (int)((folders[fi].comp_type >> 8) & 0x1f));
                else { vdu_log("unsupported CAB compression 0x%04x in folder %d", folders[fi].comp_type, fi); rc = -1; }
                if (sw.pos != total && rc == 0) rc = -1;
            }
            sw_close_all(&sw);
        }
        free(ent);
    }

    cab_free_entries(files, n_files);
    free(folders);
    fclose(f);
    return rc;
}

int cab_extract_package(const char *pkg_path, const char *out_dir) {
    return cab_extract(pkg_path, out_dir, NULL, NULL);
}
