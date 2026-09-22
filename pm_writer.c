#include "pm_writer.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include "pm_ringbuf.h"
#include <assert.h>
#include <unistd.h>

static inline size_t pm_min(size_t a, size_t b) {
  return a < b ? a : b;
}

void pm_writer_init(pm_writer *w, int fd, size_t capacity) {
  assert(w);
  pm_ringbuf_init(&w->rb, capacity);
  w->fd = fd;
  w->error = false;
  w->last_errno = 0;
}

void pm_writer_reset(pm_writer *w) {
  pm_ringbuf_reset(&w->rb);
  w->error = false;
  w->last_errno = 0;
}

void pm_writer_free(pm_writer *w) {
  pm_ringbuf_free(&w->rb);
  memset(w, 0, sizeof(*w));
}

ssize_t pm_writer_flush(pm_writer *w) {
  if (w->error) return -1;
  if (w->eof) return -1;

  struct iovec used_spans[2];
  ssize_t total_bytes = 0;
  ssize_t nwrite;

  while (true) {
    pm_ringbuf_get_used_spans(&w->rb, used_spans);
    if (used_spans[0].iov_len == 0) return total_bytes;

    if (used_spans[1].iov_len == 0) {
      nwrite = write(w->fd, used_spans[0].iov_base, used_spans[0].iov_len);
    } else {
      nwrite = writev(w->fd, used_spans, 2);
    }

    if (nwrite == 0) {
      w->eof = true;
      if (total_bytes > 0) break;
      return 0;
    }

    if (nwrite < 0) {
      if (errno == EWOULDBLOCK || errno == EAGAIN) {
        if (total_bytes > 0) break;
        return -1;
      }

      if (errno == EINTR) continue;

      w->error = true;
      w->last_errno = errno;
      return -1;
    }

    pm_ringbuf_advance_head(&w->rb, nwrite);
    total_bytes += nwrite;
  }

  return total_bytes;
}

ssize_t pm_writer_append_bytes(pm_writer *w, const void *data, size_t size) {
  assert(w && w->rb.cap > 0);
  if (w->error) return -1;
  if (size == 0) return 0;

  size_t used = pm_ringbuf_total_used(&w->rb);
  size_t needed_cap = used + size;

  if (w->rb.cap < needed_cap) {
    size_t min_new_cap = w->rb.cap;
    while (min_new_cap < needed_cap) {
      min_new_cap *= 2;
    }

    if (!pm_ringbuf_grow(&w->rb, min_new_cap)) {
      w->error = true;
      w->last_errno = ENOMEM;
      return -1;
    }
  }

  struct iovec free_spans[2];
  pm_ringbuf_get_free_spans(&w->rb, free_spans);

  size_t first_copy = pm_min(size, free_spans[0].iov_len);
  memcpy(free_spans[0].iov_base, data, first_copy);
  pm_ringbuf_advance_tail(&w->rb, first_copy);

  size_t remaining = size - first_copy;
  if (remaining > 0) {
    memcpy(free_spans[1].iov_base, (const uint8_t *)data + first_copy, remaining);
    pm_ringbuf_advance_tail(&w->rb, remaining);
  }

  return size;
}

ssize_t pm_writer_write_bytes(pm_writer *w, const void *data, size_t size) {
  if (w->error) return -1;
  if (size == 0) return 0;

  struct iovec used_spans[2];
  size_t buffered = pm_ringbuf_total_used(&w->rb);

  ssize_t nwrite;
  ssize_t total_bytes = 0;

  while (true) {
    pm_ringbuf_get_used_spans(&w->rb, used_spans);

    if (used_spans[0].iov_len == 0) {
      nwrite = write(w->fd, data, size);
    } else if (used_spans[1].iov_len == 0) {
      struct iovec spans[2] = {0};
      spans[0] = used_spans[0];
      spans[1].iov_base = (void *)data;
      spans[1].iov_len = size;
      nwrite = writev(w->fd, spans, 2);
    } else {
      struct iovec spans[3] = {0};
      spans[0] = used_spans[0];
      spans[1] = used_spans[1];
      spans[2].iov_base = (void *)data;
      spans[2].iov_len = size;
      nwrite = writev(w->fd, spans, 3);
    }

    if (nwrite == 0) {
      w->eof = true;
      if (total_bytes > 0) break;
      return 0;
    }

    if (nwrite < 0) {
      if (errno == EWOULDBLOCK || errno == EAGAIN) {
        if (total_bytes > 0) break;
        return -1;
      }

      if (errno == EINTR) continue;

      w->error = true;
      w->last_errno = errno;
      return -1;
    }

    pm_ringbuf_advance_head(&w->rb, pm_min(nwrite, used_spans[0].iov_len + used_spans[1].iov_len));
    total_bytes += nwrite;
  }

  size_t consumed_from_input = 0;
  if (total_bytes > buffered) {
    consumed_from_input = total_bytes - buffered;
    assert(consumed_from_input <= size);
  }

  size_t remaining = size - consumed_from_input;
  if (remaining == 0) return total_bytes;

  ssize_t aw = pm_writer_append_bytes(w, (const uint8_t *)data + consumed_from_input, remaining);
  if (aw < 0) return -1;

  return total_bytes + aw;
}

ssize_t pm_writer_write_cstr(pm_writer *w, const char *s) {
  return pm_writer_write_bytes(w, s, strlen(s));
}

ssize_t pm_writer_append_cstr(pm_writer *w, const char *s) {
  return pm_writer_append_bytes(w, s, strlen(s));
}

ssize_t pm_writer_write_strn(pm_writer *w, const char *s, size_t len) {
  return pm_writer_write_bytes(w, s, len);
}

bool pm_writer_is_empty(const pm_writer *w) {
  return pm_ringbuf_is_empty(&w->rb);
}

bool pm_writer_is_full(const pm_writer *w) {
  return pm_ringbuf_is_full(&w->rb);
}

size_t pm_writer_avail(const pm_writer *w) {
  return pm_ringbuf_total_free(&w->rb);
}

size_t pm_writer_size(const pm_writer *w) {
  return pm_ringbuf_total_used(&w->rb);
}

void pm_writer_dump(const pm_writer *w) {
  printf("\n");
  printf("pm_writer:\n");
  printf("  cap: %zu\n", w->rb.cap);
  printf("  head: %zu\n", w->rb.head);
  printf("  tail: %zu\n", w->rb.tail);
  printf("  eof: %s\n", w->eof ? "true" : "false");
  printf("\n");
}
