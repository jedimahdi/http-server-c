#ifndef PM_READER_H
#define PM_READER_H

#include "pm_ringbuf.h"
#include <stdbool.h>
#include <stddef.h>

typedef struct {
  int fd;
  pm_ringbuf rb;
  int last_errno;
  bool eof;
  bool error;
} pm_reader;

void pm_reader_init(pm_reader *r, int fd, size_t capacity);
void pm_reader_free(pm_reader *r);
void pm_reader_reset(pm_reader *r);
void pm_reader_dump(const pm_reader *r);

size_t pm_reader_total_avail_data(const pm_reader *r);
size_t pm_reader_total_free_space(const pm_reader *r);
int pm_reader_error(const pm_reader *r);
bool pm_reader_is_eof(const pm_reader *r);
bool pm_reader_is_empty(const pm_reader *r);

ssize_t pm_reader_fill(pm_reader *r);
void pm_reader_skip(pm_reader *r, size_t n);
void pm_reader_compact(pm_reader *r);
const uint8_t *pm_reader_peek(const pm_reader *r, size_t *avail_out);

void pm_reader_peek_split(const pm_reader *r, struct iovec spans[2]);

#endif
