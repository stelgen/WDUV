#define _CRT_SECURE_NO_WARNINGS
#include "util.h"
#include "defs.h"

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <direct.h>
#include <windows.h>
#define VDU_MKDIR(p) _mkdir(p)
#else
#include <sys/stat.h>
#include <sys/types.h>
#define VDU_MKDIR(p) mkdir(p, 0755)
#endif

void *xmalloc(size_t n) {
    void *p = malloc(n ? n : 1);
    if (!p) { vdu_log("out of memory (%zu bytes)", n); exit(2); }
    return p;
}
void *xcalloc(size_t n, size_t m) {
    void *p = calloc(n ? n : 1, m ? m : 1);
    if (!p) { vdu_log("out of memory"); exit(2); }
    return p;
}
char *xstrdup(const char *s) {
    char *p = xmalloc(strlen(s) + 1);
    strcpy(p, s);
    return p;
}

void sb_init(strbuf *sb) { sb->data = xmalloc(64); sb->data[0] = 0; sb->len = 0; sb->cap = 64; }
void sb_free(strbuf *sb) { free(sb->data); sb->data = NULL; sb->len = sb->cap = 0; }
static void sb_grow(strbuf *sb, size_t need) {
    if (sb->len + need + 1 <= sb->cap) return;
    while (sb->cap < sb->len + need + 1) sb->cap *= 2;
    sb->data = realloc(sb->data, sb->cap);
    if (!sb->data) { vdu_log("out of memory"); exit(2); }
}
void sb_puts(strbuf *sb, const char *s) {
    size_t n = strlen(s);
    sb_grow(sb, n);
    memcpy(sb->data + sb->len, s, n);
    sb->len += n;
    sb->data[sb->len] = 0;
}
void sb_putc(strbuf *sb, char c) { sb_grow(sb, 1); sb->data[sb->len++] = c; sb->data[sb->len] = 0; }
void sb_printf(strbuf *sb, const char *fmt, ...) {
    char tmp[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    sb_puts(sb, tmp);
}

uint8_t *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    rewind(f);
    uint8_t *buf = xmalloc((size_t)sz + 1);
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[rd] = 0;
    if (out_len) *out_len = rd;
    return buf;
}

int write_file(const char *path, const void *data, size_t len) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t wr = len ? fwrite(data, 1, len, f) : 0;
    int cl = fclose(f);
    return (wr == len && cl == 0) ? 0 : -1;
}

int file_exists(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    fclose(f);
    return 1;
}

int64_t file_size(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    fclose(f);
    return sz;
}

int mkdir_p(const char *path) {
    char tmp[1024];
    size_t n = strlen(path);
    if (n >= sizeof(tmp)) return -1;
    strcpy(tmp, path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/' || *p == '\\') {
            char c = *p;
            *p = 0;
            VDU_MKDIR(tmp);
            *p = c;
        }
    }
    VDU_MKDIR(tmp);
    return file_exists(tmp) ? 0 : -1;
}

char *path_join(const char *a, const char *b) {
    size_t la = strlen(a), lb = strlen(b);
    int need_sep = la && a[la - 1] != '/' && a[la - 1] != '\\';
    char *out = xmalloc(la + lb + 2);
    memcpy(out, a, la);
    if (need_sep) out[la++] = '/';
    memcpy(out + la, b, lb + 1);
    return out;
}

int str_ieq(const char *a, const char *b) {
    while (*a && *b) {
        char ca = *a, cb = *b;
        if (ca >= 'A' && ca <= 'Z') ca += 32;
        if (cb >= 'A' && cb <= 'Z') cb += 32;
        if (ca != cb) return 0;
        a++; b++;
    }
    return *a == 0 && *b == 0;
}

int str_ends_with(const char *s, const char *suffix) {
    size_t ls = strlen(s), lf = strlen(suffix);
    return ls >= lf && str_ieq(s + ls - lf, suffix);
}

void to_hex(const uint8_t *in, size_t n, char *out) {
    static const char *hexd = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[i * 2] = hexd[in[i] >> 4];
        out[i * 2 + 1] = hexd[in[i] & 15];
    }
    out[n * 2] = 0;
}

void vdu_log(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "[vdu] ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n");
    va_end(ap);
}
