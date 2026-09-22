#ifndef PM_WRITER_H
#define PM_WRITER_H

#include "pm_ringbuf.h"
#include <stdarg.h>

typedef struct {
  int fd;
  pm_ringbuf rb;
  int last_errno;
  bool error;
  bool eof;
} pm_writer;

void pm_writer_init(pm_writer *w, int fd, size_t capacity);
void pm_writer_free(pm_writer *w);
void pm_writer_reset(pm_writer *w);
void pm_writer_dump(const pm_writer *w);

bool pm_writer_is_empty(const pm_writer *w);
bool pm_writer_is_full(const pm_writer *w);
size_t pm_writer_avail(const pm_writer *w); // free space
size_t pm_writer_size(const pm_writer *w); // used space (pending)

ssize_t pm_writer_flush(pm_writer *w);

ssize_t pm_writer_append_bytes(pm_writer *w, const void *data, size_t size);
// pm_write_result pm_writer_append_cstr(pm_writer *w, const char *s);
// pm_write_result pm_writer_append_strn(pm_writer *w, const char *s, size_t len);
// pm_write_result pm_writer_append_u64(pm_writer *w, uint64_t value);
// pm_write_result pm_writer_append_i64(pm_writer *w, int64_t value);
//
// pm_write_result pm_writer_append_u16_le(pm_writer *w, uint16_t value);
// pm_write_result pm_writer_append_u16_be(pm_writer *w, uint16_t value);
// pm_write_result pm_writer_append_u32_le(pm_writer *w, uint32_t value);
// pm_write_result pm_writer_append_u32_be(pm_writer *w, uint32_t value);
// pm_write_result pm_writer_append_u64_le(pm_writer *w, uint64_t value);
// pm_write_result pm_writer_append_u64_be(pm_writer *w, uint64_t value);
//
ssize_t pm_writer_write_bytes(pm_writer *w, const void *data, size_t size);
// pm_write_result pm_writer_write_cstr(pm_writer *w, const char *s);
// pm_write_result pm_writer_write_strn(pm_writer *w, const char *s, size_t len);
//
// pm_write_result pm_writer_append_printf(pm_writer *w, const char *fmt, ...);
// pm_write_result pm_writer_append_vprintf(pm_writer *w, const char *fmt, va_list ap);
// pm_write_result pm_writer_write_printf(pm_writer *w, const char *fmt, ...);
// pm_write_result pm_writer_write_vprintf(pm_writer *w, const char *fmt, va_list ap);

#endif
