#include "pm_ringbuf.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static inline size_t rb_mask(const pm_ringbuf *rb, size_t idx) {
  return idx & (rb->cap - 1);
}

static inline size_t rb_cap(const pm_ringbuf *rb) {
  return rb->cap;
}

static inline size_t rb_used(const pm_ringbuf *rb) {
  return rb->tail - rb->head;
}

static inline size_t rb_free(const pm_ringbuf *rb) {
  return rb_cap(rb) - rb_used(rb);
}

static size_t next_pow2(size_t v) {
  if (v == 0) return 1;
  v--;
  v |= v >> 1;
  v |= v >> 2;
  v |= v >> 4;
  v |= v >> 8;
  v |= v >> 16;
#if SIZE_MAX > 0xFFFFFFFF
  v |= v >> 32;
#endif
  return v + 1;
}

bool pm_ringbuf_init(pm_ringbuf *rb, size_t capacity) {
  assert(capacity > 0);
  size_t cap = next_pow2(capacity);
  rb->buf = malloc(cap);
  if (!rb->buf) return false;

  rb->cap = cap;
  rb->head = 0;
  rb->tail = 0;
  return true;
}

void pm_ringbuf_free(pm_ringbuf *rb) {
  assert(rb->buf);
  free(rb->buf);
  *rb = (pm_ringbuf){0};
}

void pm_ringbuf_reset(pm_ringbuf *rb) {
  rb->head = 0;
  rb->tail = 0;
}

size_t pm_ringbuf_capacity(const pm_ringbuf *rb) {
  return rb_cap(rb);
}

bool pm_ringbuf_is_empty(const pm_ringbuf *rb) {
  return rb->head == rb->tail;
}

bool pm_ringbuf_is_full(const pm_ringbuf *rb) {
  return rb_used(rb) == rb_cap(rb);
}

size_t pm_ringbuf_total_used(const pm_ringbuf *rb) {
  return rb_used(rb);
}

size_t pm_ringbuf_total_free(const pm_ringbuf *rb) {
  return rb_free(rb);
}

size_t pm_ringbuf_contig_used(const pm_ringbuf *rb) {
  size_t used = rb_used(rb);
  size_t h = rb_mask(rb, rb->head);
  size_t to_end = rb_cap(rb) - h;

  return used <= to_end ? used : to_end;
}

size_t pm_ringbuf_contig_free(const pm_ringbuf *rb) {
  size_t free_count = rb_free(rb);
  size_t t = rb_mask(rb, rb->tail);
  size_t to_end = rb_cap(rb) - t;

  return free_count <= to_end ? free_count : to_end;
}

void pm_ringbuf_advance_head(pm_ringbuf *rb, size_t n) {
  assert(n <= rb_used(rb));
  rb->head += n;
}

void pm_ringbuf_advance_tail(pm_ringbuf *rb, size_t n) {
  assert(n <= rb_free(rb));
  rb->tail += n;
}

void pm_ringbuf_get_used_spans(const pm_ringbuf *rb, struct iovec out[2]) {
  out[0].iov_base = NULL;
  out[0].iov_len = 0;
  out[1].iov_base = NULL;
  out[1].iov_len = 0;

  size_t used = rb_used(rb);
  if (used == 0) return;

  size_t h = rb_mask(rb, rb->head);
  size_t to_end = rb_cap(rb) - h;

  if (used <= to_end) {
    out[0].iov_base = rb->buf + h;
    out[0].iov_len = used;
  } else {
    out[0].iov_base = rb->buf + h;
    out[0].iov_len = to_end;
    out[1].iov_base = rb->buf;
    out[1].iov_len = used - to_end;
  }
}

void pm_ringbuf_get_free_spans(const pm_ringbuf *rb, struct iovec out[2]) {
  out[0].iov_base = NULL;
  out[0].iov_len = 0;
  out[1].iov_base = NULL;
  out[1].iov_len = 0;

  size_t free_count = rb_free(rb);
  if (free_count == 0) return;

  size_t t = rb_mask(rb, rb->tail);
  size_t to_end = rb_cap(rb) - t;

  if (free_count <= to_end) {
    out[0].iov_base = rb->buf + t;
    out[0].iov_len = free_count;
  } else {
    out[0].iov_base = rb->buf + t;
    out[0].iov_len = to_end;
    out[1].iov_base = rb->buf;
    out[1].iov_len = free_count - to_end;
  }
}

void pm_ringbuf_compact(pm_ringbuf *rb) {
  size_t used = rb_used(rb);
  if (used == 0) {
    rb->head = 0;
    rb->tail = 0;
    return;
  }

  size_t h = rb_mask(rb, rb->head);
  if (h == 0) {
    rb->head = 0;
    rb->tail = used;
    return;
  }

  size_t cap = rb_cap(rb);
  size_t to_end = cap - h;

  if (used <= to_end) {
    memmove(rb->buf, rb->buf + h, used);
  } else {
    size_t first = to_end;
    size_t second = used - to_end;

    if (first <= second) {
      uint8_t stack[4096];
      uint8_t *tmp = (first <= sizeof(stack)) ? stack : malloc(first);
      assert(tmp);

      memcpy(tmp, rb->buf + h, first);
      memmove(rb->buf + first, rb->buf, second);
      memcpy(rb->buf, tmp, first);

      if (tmp != stack) free(tmp);
    } else {
      uint8_t stack[4096];
      uint8_t *tmp = (second <= sizeof(stack)) ? stack : malloc(second);
      assert(tmp);

      memcpy(tmp, rb->buf, second);
      memmove(rb->buf, rb->buf + h, first);
      memcpy(rb->buf + first, tmp, second);

      if (tmp != stack) free(tmp);
    }
  }

  rb->head = 0;
  rb->tail = used;
}

bool pm_ringbuf_grow(pm_ringbuf *rb, size_t min_needed_cap) {
  assert(rb->cap > 0);

  size_t old_cap = rb_cap(rb);
  size_t used = rb_used(rb);
  size_t new_cap = old_cap * 2;
  size_t min_cap = next_pow2(min_needed_cap);
  if (new_cap < min_cap)
    new_cap = min_cap;

  if (used > 0 && rb_mask(rb, rb->head) != 0) {
    pm_ringbuf_compact(rb);
  }

  uint8_t *new_buf = realloc(rb->buf, new_cap);
  if (!new_buf) {
    return false;
  }

  rb->buf = new_buf;
  rb->cap = new_cap;

  return true;
}

void pm_ringbuf_compact_when_half(pm_ringbuf *rb) {
  size_t used = rb_used(rb);
  if (used == 0) {
    rb->head = 0;
    rb->tail = 0;
    return;
  }

  size_t h = rb_mask(rb, rb->head);
  if (h == 0) {
    rb->head = 0;
    rb->tail = used;
    return;
  }

  size_t cap = rb_cap(rb);
  size_t to_end = cap - h;

  if (used <= to_end) {
    memmove(rb->buf, rb->buf + h, used);
  } else {
    size_t first = to_end;
    size_t second = used - to_end;

    if (first <= second) {
      uint8_t stack[4096];
      uint8_t *tmp = (first <= sizeof(stack)) ? stack : malloc(first);
      assert(tmp);

      memcpy(tmp, rb->buf + h, first);
      memmove(rb->buf + first, rb->buf, second);
      memcpy(rb->buf, tmp, first);

      if (tmp != stack) free(tmp);
    } else {
      uint8_t stack[4096];
      uint8_t *tmp = (second <= sizeof(stack)) ? stack : malloc(second);
      assert(tmp);

      memcpy(tmp, rb->buf, second);
      memmove(rb->buf, rb->buf + h, first);
      memcpy(rb->buf + first, tmp, second);

      if (tmp != stack) free(tmp);
    }
  }

  rb->head = 0;
  rb->tail = used;
}
