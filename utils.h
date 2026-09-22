#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>

#define FORMAT_CHECK(fmt_pos, args_pos) __attribute__((format(printf, fmt_pos, args_pos)))

typedef enum {
  LOG_LEVEL_INFO = 0,
  LOG_LEVEL_WARN,
  LOG_LEVEL_ERROR,
  LOG_LEVEL_PANIC,
} LogLevel;

void _log(LogLevel level, const char *fmt, ...) FORMAT_CHECK(2, 3);

#define LOG_INFO(...) _log(LOG_LEVEL_INFO, __VA_ARGS__)
#define LOG_WARN(...) _log(LOG_LEVEL_WARN, __VA_ARGS__)
#define LOG_ERROR(...) _log(LOG_LEVEL_ERROR, __VA_ARGS__)

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef ptrdiff_t isize;

int listen_tcp(const char *hostname, const char *port);
void die(const char *fmt, ...);
void set_nonblocking(int fd);
bool get_local_iface(const char *target_ip, char *local_ip, size_t local_ip_len, char *iface_name, size_t iface_len, int *iface_index);
int rawsocket(int iface_index);

#define CLIENT_HELLO_SIZE 517
void build_client_hello(const char *sni, uint8_t *out_buffer);

void build_fake_frame(const uint8_t *template_frame, size_t template_len, uint32_t client_isn, const uint8_t *fake_payload, size_t fake_len, uint8_t *out, size_t *out_len);
