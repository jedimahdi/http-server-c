#ifndef PM_RINGBUF_H
#define PM_RINGBUF_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/uio.h>

typedef struct {
  uint8_t *buf;
  size_t head, tail, cap;
} pm_ringbuf;

bool pm_ringbuf_init(pm_ringbuf *rb, size_t capacity);
void pm_ringbuf_free(pm_ringbuf *rb);
void pm_ringbuf_reset(pm_ringbuf *rb);

size_t pm_ringbuf_capacity(const pm_ringbuf *rb);
size_t pm_ringbuf_total_used(const pm_ringbuf *rb);
size_t pm_ringbuf_total_free(const pm_ringbuf *rb);
size_t pm_ringbuf_contig_used(const pm_ringbuf *rb);
size_t pm_ringbuf_contig_free(const pm_ringbuf *rb);
bool pm_ringbuf_is_empty(const pm_ringbuf *rb);
bool pm_ringbuf_is_full(const pm_ringbuf *rb);

void pm_ringbuf_get_free_spans(const pm_ringbuf *rb, struct iovec out[2]);
void pm_ringbuf_get_used_spans(const pm_ringbuf *rb, struct iovec out[2]);

void pm_ringbuf_advance_head(pm_ringbuf *rb, size_t n);
void pm_ringbuf_advance_tail(pm_ringbuf *rb, size_t n);

void pm_ringbuf_compact(pm_ringbuf *rb);
bool pm_ringbuf_grow(pm_ringbuf *rb, size_t min_needed_cap);

#endif
