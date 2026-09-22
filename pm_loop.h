#ifndef PM_LOOP_H
#define PM_LOOP_H

#include <stdbool.h>

typedef enum {
  PM_EVENT_READABLE = 1 << 0,
  PM_EVENT_WRITABLE = 1 << 1,
  PM_EVENT_POLLET = 1 << 2,
  PM_EVENT_ERROR = 1 << 3,
  PM_EVENT_HANGUP = 1 << 4
} pm_event_mask;

typedef struct pm_loop pm_loop;

typedef void (*pm_loop_cb)(int fd, pm_loop *l, pm_event_mask events, void *user_data);

typedef struct {
  int fd;
  pm_loop_cb cb;
  void *cb_user_data;
} pm_loop_entry;

struct pm_loop {
  int epoll_fd;
  pm_loop_entry *fd_table;
  int fd_table_cap;
  bool running;
};

void pm_loop_init(pm_loop *l);
void pm_loop_free(pm_loop *l);

void pm_loop_add(pm_loop *l, int fd, pm_event_mask mask, pm_loop_cb cb, void *cb_user_data);
void pm_loop_del(pm_loop *l, int fd);
void pm_loop_mod(pm_loop *l, int fd, pm_event_mask mask);

void pm_loop_once(pm_loop *l, int timeout_ms);
void pm_loop_run(pm_loop *l, int timeout_ms);
void pm_loop_stop(pm_loop *l);

#endif
