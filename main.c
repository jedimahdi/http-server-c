#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <errno.h>
#include <net/if.h>
#include <signal.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_packet.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <liburing.h>
#include <llhttp.h>

#include "pm_ringbuf.h"
#include "utils.h"

typedef enum {
  HP_ERROR = 0,
  HP_METHOD,
  HP_URI,
  HP_VERSION,
  HP_HEADER_NAME,
  HP_HEADER_VALUE,
  HP_HEADERS_DONE,
  HP_BODY,
  HP_DONE,
} Http_Parser_State;

typedef struct {
  Http_Parser_State state;

  char method[16];
  char uri[2048];
  char version[16];
  char header_name[256];
  char header_value[4096];

  int method_idx;
  int uri_idx;
  int version_idx;
  int header_name_idx;
  int header_value_idx;

  long content_length;
  long body_read;
  bool keep_alive;
  bool has_content_length;
} Http_Parser;

void hp_init(Http_Parser *p);
ssize_t hp_execute(Http_Parser *p, const char *data, size_t len);
void hp_reset(Http_Parser *p);

void hp_init(Http_Parser *p) {
  memset(p, 0, sizeof(*p));
  p->state = HP_METHOD;
  p->content_length = -1;
  p->has_content_length = false;
  p->keep_alive = true;
}

void hp_reset(Http_Parser *p) {
  hp_init(p);
}

static void hp_on_header_done(Http_Parser *p) {
  if (strcasecmp(p->header_name, "Content-Length") == 0) {
    p->content_length = strtol(p->header_value, NULL, 10);
    p->has_content_length = true;
  }

  if (strcasecmp(p->header_name, "Connection") == 0) {
    if (strcasecmp(p->header_value, "close") == 0)
      p->keep_alive = false;
    else if (strcasecmp(p->header_value, "keep-alive") == 0)
      p->keep_alive = true;
  }

  if (strcmp(p->version, "HTTP/1.0") == 0 && strcasecmp(p->header_name, "Connection") != 0) {
    p->keep_alive = false;
  }
}

ssize_t hp_execute(Http_Parser *p, const char *data, size_t len) {
  size_t i = 0;
  while (i < len && p->state != HP_DONE && p->state != HP_ERROR) {
    char c = data[i++];

    switch (p->state) {
      case HP_METHOD:
        if (c == ' ') {
          p->method[p->method_idx] = '\0';
          p->state = HP_URI;
        } else if (p->method_idx < (int)sizeof(p->method) - 1) {
          p->method[p->method_idx++] = c;
        } else {
          p->state = HP_ERROR;
        }
        break;

      case HP_URI:
        if (c == ' ') {
          p->uri[p->uri_idx] = '\0';
          p->state = HP_VERSION;
        } else if (p->uri_idx < (int)sizeof(p->uri) - 1) {
          p->uri[p->uri_idx++] = c;
        } else {
          p->state = HP_ERROR;
        }
        break;

      case HP_VERSION:
        if (c == '\r') {
          p->version[p->version_idx] = '\0';
        } else if (c == '\n') {
          p->state = HP_HEADER_NAME;
        } else if (p->version_idx < (int)sizeof(p->version) - 1) {
          p->version[p->version_idx++] = c;
        } else {
          p->state = HP_ERROR;
        }
        break;

      case HP_HEADER_NAME:
        if (c == '\r') {
          p->state = HP_HEADERS_DONE;
        } else if (c == ':') {
          p->header_name[p->header_name_idx] = '\0';
          p->header_value_idx = 0;
          p->state = HP_HEADER_VALUE;
        } else if (p->header_name_idx < (int)sizeof(p->header_name) - 1) {
          p->header_name[p->header_name_idx++] = c;
        } else {
          p->state = HP_ERROR;
        }
        break;

      case HP_HEADERS_DONE:
        if (c == '\n') {
          if (p->has_content_length && p->content_length > 0) {
            p->state = HP_BODY;
          } else {
            p->state = HP_DONE;
          }
        } else {
          p->state = HP_ERROR;
        }
        break;

      case HP_HEADER_VALUE:
        if (c == '\r') {
          p->header_value[p->header_value_idx] = '\0';
          hp_on_header_done(p);
          p->header_name_idx = 0;
          p->header_value_idx = 0;
        } else if (c == '\n') {
          p->state = HP_HEADER_NAME;
        } else if (p->header_value_idx == 0 && (c == ' ' || c == '\t'))
          break;
        else if (p->header_value_idx < (int)sizeof(p->header_value) - 1) {
          p->header_value[p->header_value_idx++] = c;
        } else {
          p->state = HP_ERROR;
        }
        break;

      case HP_BODY:
        p->body_read++;
        if (p->body_read >= p->content_length) p->state = HP_DONE;
        break;

      case HP_DONE:
      case HP_ERROR:
        break;
    }
  }

  return i;
}

typedef struct {
  int client_sock;
  pm_ringbuf read_buf;
  pm_ringbuf write_buf;
  Http_Parser parser;
  bool close_after_flush;
} Conn;

void on_read(struct io_uring *ring, struct io_uring_cqe *cqe, void *ud);
void on_write(struct io_uring *ring, struct io_uring_cqe *cqe, void *ud);

void conn_close(Conn *conn) {
  LOG_INFO("[Client] fd=%d closing", conn->client_sock);

  pm_ringbuf_free(&conn->read_buf);
  pm_ringbuf_free(&conn->write_buf);
  close(conn->client_sock);
  free(conn);
}

void conn_submit_read(struct io_uring *ring, Conn *conn) {
  int client_sock = conn->client_sock;
  struct iovec spans[2];
  pm_ringbuf_get_free_spans(&conn->read_buf, spans);

  if (spans[1].iov_len == 0) {
    io_uring_prep_read(sqe_with_cb(ring, on_read, conn), client_sock, spans[0].iov_base, spans[0].iov_len, 0);
  } else {
    io_uring_prep_readv(sqe_with_cb(ring, on_read, conn), client_sock, spans, 2, 0);
  }
}

void conn_submit_write(struct io_uring *ring, Conn *conn) {
  int client_sock = conn->client_sock;
  struct iovec spans[2];
  pm_ringbuf_get_used_spans(&conn->write_buf, spans);

  if (spans[1].iov_len == 0) {
    io_uring_prep_write(sqe_with_cb(ring, on_write, conn), client_sock, spans[0].iov_base, spans[0].iov_len, 0);
  } else {
    io_uring_prep_writev(sqe_with_cb(ring, on_write, conn), client_sock, spans, 2, 0);
  }
}

void append_ringbuf(pm_ringbuf *rb, const char *data, size_t size) {
  size_t used = pm_ringbuf_total_used(rb);
  size_t needed_cap = used + size;

  if (rb->cap < needed_cap) {
    size_t min_new_cap = rb->cap;
    while (min_new_cap < needed_cap) {
      min_new_cap *= 2;
    }

    if (!pm_ringbuf_grow(rb, min_new_cap)) {
      LOG_ERROR("realloc failed");
      exit(1);
    }
  }

  struct iovec free_spans[2];
  pm_ringbuf_get_free_spans(rb, free_spans);

  size_t first_copy = size < free_spans[0].iov_len ? size : free_spans[0].iov_len;
  memcpy(free_spans[0].iov_base, data, first_copy);
  pm_ringbuf_advance_tail(rb, first_copy);

  size_t remaining = size - first_copy;
  if (remaining > 0) {
    memcpy(free_spans[1].iov_base, (const uint8_t *)data + first_copy, remaining);
    pm_ringbuf_advance_tail(rb, remaining);
  }
}

void send_response(struct io_uring *ring, Conn *conn, int status, const char *reason, const char *body, size_t body_len, bool keep_alive) {
  char hdr[512];
  int n = snprintf(hdr, sizeof(hdr),
                   "HTTP/1.1 %d %s\r\n"
                   "Content-Length: %zu\r\n"
                   "Content-Type: text/plain\r\n"
                   "Connection: %s\r\n"
                   "\r\n",
                   status, reason, body_len,
                   keep_alive ? "keep-alive" : "close");

  append_ringbuf(&conn->write_buf, hdr, n);
  if (body_len > 0) append_ringbuf(&conn->write_buf, body, body_len);
  conn_submit_write(ring, conn);
}

void dispatch(struct io_uring *ring, Conn *conn) {
  Http_Parser *p = &conn->parser;

  LOG_INFO("method = %s, uri = %s", p->method, p->uri);

  if (strcmp(p->method, "GET") == 0 && strcmp(p->uri, "/") == 0) {
    const char *body = "hello, world!\n";
    send_response(ring, conn, 200, "OK", body, strlen(body), p->keep_alive);
  } else {
    const char *body = "not found\n";
    send_response(ring, conn, 404, "Not Found", body, strlen(body), p->keep_alive);
  }
}

void process_client(struct io_uring *ring, Conn *conn) {
  struct iovec spans[2];
  pm_ringbuf_get_used_spans(&conn->read_buf, spans);

  ssize_t nparse = hp_execute(&conn->parser, spans[0].iov_base, spans[0].iov_len);
  ssize_t nparse2 = 0;
  if (spans[1].iov_len > 0 && conn->parser.state != HP_DONE) {
    nparse2 = hp_execute(&conn->parser, spans[1].iov_base, spans[1].iov_len);
  }
  pm_ringbuf_advance_head(&conn->read_buf, nparse + nparse2);

  if (conn->parser.state == HP_ERROR) {
    LOG_ERROR("invalid request");
    send_response(ring, conn, 400, "Bad Request", "bad request\n", 12, false);
    //
    conn_close(conn);
    return;
  } else if (conn->parser.state != HP_DONE) {
    LOG_INFO("need more");
    conn_submit_read(ring, conn);
    return;
  }

  dispatch(ring, conn);
  hp_reset(&conn->parser);

  size_t used = pm_ringbuf_total_used(&conn->read_buf);
  if (used > 0)
    return process_client(ring, conn);

  if (conn->parser.keep_alive) {
    conn_submit_read(ring, conn);
  } else {
    conn->close_after_flush = true;
  }
}

void on_read(struct io_uring *ring, struct io_uring_cqe *cqe, void *ud) {
  Conn *conn = ud;
  int client_sock = conn->client_sock;
  ssize_t nread = cqe->res;
  if (nread < 0) {
    conn_close(conn);
    LOG_ERROR("read error: %s", strerror(-nread));
    return;
  }
  if (nread == 0) {
    conn->close_after_flush = true;
    LOG_INFO("read eof");
    return;
  }

  pm_ringbuf_advance_tail(&conn->read_buf, nread);
  process_client(ring, conn);
}

void on_write(struct io_uring *ring, struct io_uring_cqe *cqe, void *ud) {
  Conn *conn = ud;
  int client_sock = conn->client_sock;
  ssize_t nwrite = cqe->res;
  if (nwrite < 0) {
    LOG_ERROR("write error: %s", strerror(-nwrite));
    conn_close(conn);
    return;
  }
  if (nwrite == 0) {
    LOG_ERROR("write eof");
    conn_close(conn);
    return;
  }

  pm_ringbuf_advance_head(&conn->write_buf, nwrite);

  size_t used = pm_ringbuf_total_used(&conn->write_buf);
  if (used > 0) {
    conn_submit_write(ring, conn);
  }
}

void on_accept(struct io_uring *ring, struct io_uring_cqe *cqe, void *ud) {
  LOG_INFO("on_accept");
  (void)ud;

  int client_sock = cqe->res;

  Conn *conn = malloc(sizeof(*conn));
  conn->client_sock = client_sock;
  pm_ringbuf_init(&conn->read_buf, 4096);
  pm_ringbuf_init(&conn->write_buf, 4096);
  hp_init(&conn->parser);

  conn_submit_read(ring, conn);
}

int main() {
  signal(SIGPIPE, SIG_IGN);
  char *hostname = "127.0.0.1";
  char *port = "8000";
  int server_sock = listen_tcp(hostname, port);

  LOG_WARN("Listening on %s:%s...", hostname, port);

  struct io_uring ring;
  io_uring_queue_init(256, &ring, 0);

  io_uring_prep_multishot_accept(sqe_with_cb(&ring, on_accept, NULL), server_sock, NULL, NULL, 0);

  while (true) {
    io_uring_submit_and_wait(&ring, 1);

    struct io_uring_cqe *cqe;
    unsigned head, count = 0;
    io_uring_for_each_cqe(&ring, head, cqe) {
      struct cb_ctx *ctx = io_uring_cqe_get_data(cqe);
      ctx->cb(ctx->ring, cqe, ctx->ud);
      if (!(cqe->flags & IORING_CQE_F_MORE))
        free(ctx);
      count++;
    }

    io_uring_cq_advance(&ring, count);
  }

  return 0;
}
