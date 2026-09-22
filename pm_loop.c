#include "pm_loop.h"
#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/epoll.h>

#define MAX_EVENTS 128

#define PM_LOG_ERROR(fmt, ...) fprintf(stderr, "[ERROR] [PM] " fmt "\n", ##__VA_ARGS__)

void pm_loop_init(pm_loop *l) {
  l->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
  if (l->epoll_fd < 0) {
    PM_LOG_ERROR("epoll_create1: %s", strerror(errno));
    return;
  }
  l->fd_table_cap = 4096;
  l->fd_table = malloc(l->fd_table_cap * sizeof(*l->fd_table));
  if (!l->fd_table) {
    close(l->epoll_fd);
    return;
  }
  for (int i = 0; i < l->fd_table_cap; i++)
    l->fd_table[i].fd = -1;

  l->running = false;
}

void pm_loop_free(pm_loop *l) {
  free(l->fd_table);
  l->fd_table = NULL;
  l->fd_table_cap = 0;

  if (l->epoll_fd >= 0) {
    close(l->epoll_fd);
    l->epoll_fd = -1;
  }
}

static uint32_t pm_mask_to_epoll(pm_event_mask mask) {
  uint32_t ev = 0;
  if (mask & PM_EVENT_READABLE) ev |= EPOLLIN;
  if (mask & PM_EVENT_WRITABLE) ev |= EPOLLOUT;
  if (mask & PM_EVENT_POLLET) ev |= EPOLLET;
  if (mask & PM_EVENT_ERROR) ev |= EPOLLERR;
  if (mask & PM_EVENT_HANGUP) ev |= EPOLLHUP;
  return ev;
}

static pm_event_mask epoll_to_pm_mask(uint32_t ev) {
  pm_event_mask mask = 0;
  if (ev & EPOLLIN) mask |= PM_EVENT_READABLE;
  if (ev & EPOLLOUT) mask |= PM_EVENT_WRITABLE;
  if (ev & EPOLLERR) mask |= PM_EVENT_ERROR;
  if (ev & EPOLLHUP) mask |= PM_EVENT_HANGUP;
  return mask;
}

void pm_loop_add(pm_loop *l, int fd, pm_event_mask mask, pm_loop_cb cb, void *cb_user_data) {
  assert(fd >= 0);

  if (fd >= l->fd_table_cap) {
    int old_cap = l->fd_table_cap;
    while (fd >= l->fd_table_cap) l->fd_table_cap *= 2;
    pm_loop_entry *new_table = realloc(l->fd_table, l->fd_table_cap * sizeof(*l->fd_table));
    if (!new_table) return;
    l->fd_table = new_table;
    for (int i = old_cap; i < l->fd_table_cap; i++)
      l->fd_table[i].fd = -1;
  }

  pm_loop_entry *entry = &l->fd_table[fd];
  entry->fd = fd;
  entry->cb_user_data = cb_user_data;
  entry->cb = cb;

  struct epoll_event ev = {0};
  ev.events = pm_mask_to_epoll(mask);
  ev.data.fd = fd;

  if (epoll_ctl(l->epoll_fd, EPOLL_CTL_ADD, fd, &ev) < 0) {
    PM_LOG_ERROR("epoll_ctl ADD: %s", strerror(errno));
    entry->fd = -1;
    return;
  }
}

void pm_loop_del(pm_loop *l, int fd) {
  assert(fd >= 0 && fd < l->fd_table_cap);

  pm_loop_entry *e = &l->fd_table[fd];
  if (e->fd == fd) {
    if (epoll_ctl(l->epoll_fd, EPOLL_CTL_DEL, fd, NULL) < 0) {
      PM_LOG_ERROR("epoll_ctl DEL: %s", strerror(errno));
      return;
    }
    e->fd = -1;
  }
}

void pm_loop_mod(pm_loop *l, int fd, pm_event_mask mask) {
  assert(fd >= 0 && fd < l->fd_table_cap);

  pm_loop_entry *e = &l->fd_table[fd];
  if (e->fd == fd) {
    struct epoll_event ev = {0};
    ev.events = pm_mask_to_epoll(mask);
    ev.data.fd = fd;
    if (epoll_ctl(l->epoll_fd, EPOLL_CTL_MOD, fd, &ev) < 0) {
      PM_LOG_ERROR("epoll_ctl MOD: %s", strerror(errno));
      return;
    }
  }
}

void pm_loop_once_epoll(pm_loop *l, int timeout_ms, struct epoll_event *events, int events_count) {
  int n;
  do {
    n = epoll_wait(l->epoll_fd, events, events_count, timeout_ms);
  } while (n < 0 && errno == EINTR);

  if (n < 0) {
    PM_LOG_ERROR("epoll_wait: %s", strerror(errno));
    return;
  }

  for (int i = 0; i < n; ++i) {
    int fd = events[i].data.fd;
    pm_loop_entry *entry = &l->fd_table[fd];
    if (entry->fd < 0) continue;
    pm_event_mask mask = epoll_to_pm_mask(events[i].events);
    entry->cb(entry->fd, l, mask, entry->cb_user_data);
  }
}

void pm_loop_once(pm_loop *l, int timeout_ms) {
  struct epoll_event events[MAX_EVENTS];
  pm_loop_once_epoll(l, timeout_ms, events, MAX_EVENTS);
}

void pm_loop_run(pm_loop *l, int timeout_ms) {
  struct epoll_event events[MAX_EVENTS];
  l->running = true;

  while (l->running) {
    pm_loop_once_epoll(l, timeout_ms, events, MAX_EVENTS);
  }
}

void pm_loop_stop(pm_loop *l) {
  l->running = false;
}
