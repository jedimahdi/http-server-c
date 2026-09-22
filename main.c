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
#include "pm_loop.h"
#include "utils.h"
#include "pm_reader.h"
#include "pm_writer.h"

typedef enum {
  HP_METHOD,
  HP_URI,
  HP_VERSION,
  HP_HEADER_NAME,
  HP_HEADER_VALUE,
  HP_HEADERS_DONE,
  HP_BODY,
  HP_DONE,
  HP_ERROR
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
  printf("execute: '%.*s'\n", len, data);
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

void send_response(pm_writer *w, int status, const char *reason, const char *body, size_t body_len, bool keep_alive) {
  char hdr[512];
  int n = snprintf(hdr, sizeof(hdr),
                   "HTTP/1.1 %d %s\r\n"
                   "Content-Length: %zu\r\n"
                   "Content-Type: text/plain\r\n"
                   "Connection: %s\r\n"
                   "\r\n",
                   status, reason, body_len,
                   keep_alive ? "keep-alive" : "close");

  pm_writer_append_bytes(w, hdr, n);
  if (body_len > 0) pm_writer_append_bytes(w, body, body_len);
  pm_writer_flush(w);
}

typedef struct {
  int client_sock;
  pm_reader reader;
  pm_writer writer;
  Http_Parser parser;
  bool close_after_flush;
} Conn;

static Conn *new_connection(int client_sock) {
  Conn *conn = malloc(sizeof(*conn));
  conn->client_sock = client_sock;
  pm_reader_init(&conn->reader, conn->client_sock, 4096);
  pm_writer_init(&conn->writer, conn->client_sock, 4096);
  hp_init(&conn->parser);
  return conn;
}

static void close_connection(Conn *conn, pm_loop *l) {
  LOG_INFO("[Client] fd=%d closing", conn->client_sock);

  pm_reader_free(&conn->reader);
  pm_writer_free(&conn->writer);
  pm_loop_del(l, conn->client_sock);
  close(conn->client_sock);
  free(conn);
}

void update_events(Conn *conn, pm_loop *l) {
  pm_event_mask mask = PM_EVENT_READABLE;
  if (!pm_writer_is_empty(&conn->writer)) mask |= PM_EVENT_WRITABLE;
  pm_loop_mod(l, conn->client_sock, mask);
}

void handle_client(int client_sock, pm_loop *l, pm_event_mask events, void *ud) {
  Conn *conn = ud;

  if (events & (PM_EVENT_HANGUP | PM_EVENT_ERROR)) {
    LOG_WARN("[Client] hangup | err");
    close_connection(conn, l);
    return;
  }

  if (events & PM_EVENT_READABLE) {
    ssize_t nread = pm_reader_fill(&conn->reader);

    size_t avail = 0;
    char *buf = (char *)pm_reader_peek(&conn->reader, &avail);

    if (nread < 0) {
      LOG_ERROR("handle_client: read failed: %s", strerror(errno));
      close_connection(conn, l);
      return;
    }
    if (nread == 0 && conn->reader.eof) {
      LOG_INFO("[Client] fd=%d EOF", client_sock);
      close_connection(conn, l);
      return;
    }
  }

  if (events & PM_EVENT_WRITABLE) {
    pm_writer_flush(&conn->writer);
    // pm_writer_dump(&conn->writer);

    if (conn->close_after_flush && pm_writer_is_empty(&conn->writer)) {
      close_connection(conn, l);
      return;
    }
  }

  while (true) {
    struct iovec spans[2];
    pm_reader_peek_split(&conn->reader, spans);

    if (spans[0].iov_len == 0) break;

    ssize_t r1 = hp_execute(&conn->parser, spans[0].iov_base, spans[0].iov_len);
    ssize_t r2 = 0;
    if (r1 == (ssize_t)spans[0].iov_len && spans[1].iov_len > 0) {
      r2 = hp_execute(&conn->parser, spans[1].iov_base, spans[1].iov_len);
    }
    pm_reader_skip(&conn->reader, r1 + r2);

    if (conn->parser.state == HP_ERROR) {
      send_response(&conn->writer, 400, "Bad Request", "bad request\n", 12, false);
      close_connection(conn, l);
      return;
    }

    if (conn->parser.state == HP_DONE) {
      Http_Parser *p = &conn->parser;

      printf("method = %s, uri = %s\n", p->method, p->uri);

      if (strcmp(p->method, "GET") == 0 && strcmp(p->uri, "/") == 0) {
        const char *body = "hello, world!\n";
        send_response(&conn->writer, 200, "OK", body, strlen(body), p->keep_alive);
      } else {
        const char *body = "not found\n";
        send_response(&conn->writer, 404, "Not Found", body, strlen(body), p->keep_alive);
      }

      if (p->keep_alive) {
        hp_reset(p);
        LOG_INFO("keep alive is on");
      } else {
        conn->close_after_flush = true;
        break;
      }
    } else {
      break;
    }
  }

  update_events(conn, l);
}

void on_accept(int server_sock, pm_loop *l, pm_event_mask events, void *ud) {
  (void)ud;
  (void)events;

  while (true) {
    int client_sock = accept4(server_sock, NULL, NULL, SOCK_CLOEXEC | SOCK_NONBLOCK);
    if (client_sock < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) break;
      if (errno == EINTR) continue;
      LOG_ERROR("accept4: %s", strerror(errno));
      exit(1);
    }

    Conn *conn = new_connection(client_sock);
    pm_loop_add(l, client_sock, PM_EVENT_READABLE, handle_client, conn);
  }
}

int main() {
  signal(SIGPIPE, SIG_IGN);
  char *hostname = "127.0.0.1";
  char *port = "8000";
  int server_sock = listen_tcp(hostname, port);
  set_nonblocking(server_sock);

  LOG_WARN("Listening on %s:%s...", hostname, port);

  pm_loop l;
  pm_loop_init(&l);
  pm_loop_add(&l, server_sock, PM_EVENT_READABLE, on_accept, NULL);
  pm_loop_run(&l, -1);
  pm_loop_free(&l);

  return 0;
}
