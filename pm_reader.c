#include "pm_reader.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "pm_ringbuf.h"

static inline size_t pm_min(size_t a, size_t b) {
  return a < b ? a : b;
}

void pm_reader_init(pm_reader *r, int fd, size_t capacity) {
  assert(r);
  pm_ringbuf_init(&r->rb, capacity);
  r->fd = fd;
  r->last_errno = 0;
  r->eof = false;
  r->error = false;
}

void pm_reader_free(pm_reader *r) {
  assert(r);
  pm_ringbuf_free(&r->rb);
  memset(r, 0, sizeof(*r));
}

void pm_reader_reset(pm_reader *r) {
  assert(r);
  pm_ringbuf_reset(&r->rb);
  r->eof = false;
  r->error = false;
  r->last_errno = 0;
}

bool pm_reader_is_empty(const pm_reader *r) {
  return pm_ringbuf_is_empty(&r->rb);
}

bool pm_reader_is_eof(const pm_reader *r) {
  return pm_reader_is_empty(r) && r->eof;
}

size_t pm_reader_total_avail_data(const pm_reader *r) {
  return pm_ringbuf_total_used(&r->rb);
}

size_t pm_reader_total_free_space(const pm_reader *r) {
  return pm_ringbuf_total_free(&r->rb);
}

int pm_reader_error(const pm_reader *r) {
  return r->last_errno;
}

ssize_t pm_reader_fill(pm_reader *r) {
  if (r->error) return -1;
  if (r->eof) return 0;

  struct iovec free_spans[2];
  ssize_t total_bytes = 0;
  ssize_t nread;

  while (true) {
    pm_ringbuf_get_free_spans(&r->rb, free_spans);

    if (free_spans[0].iov_len == 0) {
      if (!pm_ringbuf_grow(&r->rb, r->rb.cap * 2)) {
        r->error = true;
        r->last_errno = errno;
        return -1;
      }
      continue;
    }

    if (free_spans[1].iov_len == 0) {
      nread = read(r->fd, free_spans[0].iov_base, free_spans[0].iov_len);
    } else {
      nread = readv(r->fd, free_spans, 2);
    }

    if (nread == 0) {
      r->eof = true;
      if (total_bytes > 0) break;
      return 0;
    }

    if (nread < 0) {
      if (errno == EWOULDBLOCK || errno == EAGAIN) {
        if (total_bytes > 0) break;
        return -1;
      }

      if (errno == EINTR) continue;

      r->error = true;
      r->last_errno = errno;
      return -1;
    }

    pm_ringbuf_advance_tail(&r->rb, nread);
    total_bytes += nread;
  }

  return total_bytes;
}

const uint8_t *pm_reader_peek(const pm_reader *r, size_t *avail_out) {
  struct iovec used_spans[2];
  pm_ringbuf_get_used_spans(&r->rb, used_spans);
  if (avail_out) *avail_out = used_spans[0].iov_len;
  return used_spans[0].iov_len == 0 ? NULL : used_spans[0].iov_base;
}

void pm_reader_peek_split(const pm_reader *r, struct iovec spans[2]) {
  pm_ringbuf_get_used_spans(&r->rb, spans);
}

void pm_reader_skip(pm_reader *r, size_t n) {
  struct iovec used_spans[2];
  pm_ringbuf_get_used_spans(&r->rb, used_spans);

  size_t to_take = pm_min(n, used_spans[0].iov_len);
  pm_ringbuf_advance_head(&r->rb, to_take);

  if (to_take < n && used_spans[1].iov_len > 0) {
    pm_ringbuf_advance_head(&r->rb, n - to_take);
  }
}

void pm_reader_compact(pm_reader *r) {
  pm_ringbuf_compact(&r->rb);
}

void pm_reader_dump(const pm_reader *r) {
  printf("\n");
  printf("pm_reader:\n");
  printf("  cap: %zu\n", r->rb.cap);
  printf("  head: %zu\n", r->rb.head);
  printf("  tail: %zu\n", r->rb.tail);
  printf("  eof: %s\n", r->eof ? "true" : "false");
  size_t avail;
  const uint8_t *s = pm_reader_peek(r, &avail);
  printf("  avail: %zu\n", avail);
  if (s) {
    printf("  peek: `%.*s`\n", (int)avail, (const char *)s);
    printf("  peek hex:");
    for (size_t i = 0; i < avail; i++) {
      printf(" %02X", s[i]);
    }
    printf("\n");

  } else {
    printf("  peek: <empty>\n");
  }
  printf("\n");
}
