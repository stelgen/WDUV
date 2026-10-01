// util.h — small portable helpers (files, paths, strings, hex).
#ifndef VDU_UTIL_H
#define VDU_UTIL_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef struct { char *data; size_t len, cap; } strbuf;
void  sb_init(strbuf *sb);
void  sb_free(strbuf *sb);
void  sb_puts(strbuf *sb, const char *s);
void  sb_putc(strbuf *sb, char c);
void  sb_printf(strbuf *sb, const char *fmt, ...);

uint8_t *read_file(const char *path, size_t *out_len);       // malloc'd
int      write_file(const char *path, const void *data, size_t len);
int      file_exists(const char *path);
int64_t  file_size(const char *path);
int      mkdir_p(const char *path);                          // 0 = ok
char    *path_join(const char *a, const char *b);            // malloc'd
int      str_ieq(const char *a, const char *b);
int      str_ends_with(const char *s, const char *suffix);
void     to_hex(const uint8_t *in, size_t n, char *out /* 2n+1 */);
void    *xmalloc(size_t n);
void    *xcalloc(size_t n, size_t m);
char    *xstrdup(const char *s);

// best-effort error reporter
void vdu_log(const char *fmt, ...);

#endif
