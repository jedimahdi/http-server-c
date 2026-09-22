#include "utils.h"
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <fcntl.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <time.h>
#include <assert.h>
#include <ifaddrs.h>

void _log(LogLevel level, const char *fmt, ...) {
  char *level_string[] = {
      [LOG_LEVEL_INFO] = "INFO",
      [LOG_LEVEL_WARN] = "WARN",
      [LOG_LEVEL_ERROR] = "ERROR",
      [LOG_LEVEL_PANIC] = "PANIC",
  };

  fprintf(stderr, "%s: ", level_string[level]);
  va_list args;
  va_start(args, fmt);
  vfprintf(stderr, fmt, args);
  va_end(args);
  fprintf(stderr, "\n");
}

int listen_tcp(const char *hostname, const char *port) {
  int sfd = -1;
  int yes = 1;

  struct addrinfo *result, *rp;
  struct addrinfo hints = {0};
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  int s = getaddrinfo(hostname, port, &hints, &result);
  if (s != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
    exit(1);
  }

  for (rp = result; rp != NULL; rp = rp->ai_next) {
    sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sfd == -1) continue;

    if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
      perror("setsockopt");
      close(sfd);
      continue;
    }

    if (bind(sfd, rp->ai_addr, rp->ai_addrlen) == 0)
      break;
    close(sfd);
  }

  freeaddrinfo(result);

  if (rp == NULL || sfd == -1) {
    fprintf(stderr, "Could not bind to %s:%s\n", hostname, port);
    exit(1);
  }

  if (listen(sfd, SOMAXCONN) != 0) {
    perror("listen");
    close(sfd);
    exit(1);
  }

  return sfd;
}

void die(const char *fmt, ...) {
  va_list ap;
  int saved_errno;

  saved_errno = errno;

  va_start(ap, fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);

  if (fmt[0] && fmt[strlen(fmt) - 1] == ':')
    fprintf(stderr, " %s", strerror(saved_errno));
  fputc('\n', stderr);

  exit(1);
}

void set_nonblocking(int fd) {
  int flags = fcntl(fd, F_GETFL);
  if (flags == -1) die("fcntl:");
  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) die("fcntl:");
}

bool get_local_iface(const char *target_ip, char *local_ip, size_t local_ip_len, char *iface_name, size_t iface_len, int *iface_index) {
  assert(local_ip_len >= INET_ADDRSTRLEN);
  assert(iface_len >= IFNAMSIZ);

  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) {
    perror("socket");
    return false;
  }
  struct sockaddr_in remote = {0};
  remote.sin_family = AF_INET;
  remote.sin_port = htons(53);
  inet_pton(AF_INET, target_ip, &remote.sin_addr);

  if (connect(sock, (struct sockaddr *)&remote, sizeof(remote)) < 0) {
    perror("connect");
    close(sock);
    return false;
  }

  struct sockaddr_in local = {0};
  socklen_t len = sizeof(local);

  if (getsockname(sock, (struct sockaddr *)&local, &len) < 0) {
    perror("getsockname");
    close(sock);
    return false;
  }

  inet_ntop(AF_INET, &local.sin_addr, local_ip, local_ip_len);
  close(sock);

  struct ifaddrs *ifa;
  struct ifaddrs *p;
  if (getifaddrs(&ifa) != 0) {
    perror("getifaddrs");
    return false;
  }

  for (p = ifa; p != NULL; p = p->ifa_next) {
    if (p->ifa_addr == NULL || p->ifa_addr->sa_family != AF_INET)
      continue;

    struct sockaddr_in *sin = (struct sockaddr_in *)p->ifa_addr;
    if (memcmp(&sin->sin_addr, &local.sin_addr, sizeof(struct in_addr)) == 0) {
      strcpy(iface_name, p->ifa_name);
      *iface_index = if_nametoindex(p->ifa_name);
      freeifaddrs(ifa);
      return true;
    }
  }

  fprintf(stderr, "No interface found for local IP %s. Available IPv4 interfaces:\n", local_ip);
  for (struct ifaddrs *p = ifa; p != NULL; p = p->ifa_next) {
    if (p->ifa_addr && p->ifa_addr->sa_family == AF_INET) {
      struct sockaddr_in *sin = (struct sockaddr_in *)p->ifa_addr;
      char ip[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &sin->sin_addr, ip, sizeof(ip));
      printf("  %s -> %s\n", p->ifa_name, ip);
    }
  }

  freeifaddrs(ifa);
  return false;
}

void apply_bpf_filter(int raw_fd) {
  struct sock_filter code[] = {
      // Load EtherType (bytes 12-13)
      BPF_STMT(BPF_LD | BPF_H | BPF_ABS, offsetof(struct ethhdr, h_proto)),
      // If it's not IPv4 (0x0800), jump to end (drop)
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETH_P_IP, 0, 3),
      // Load IP Protocol (byte 23, which is 14 + 9)
      BPF_STMT(BPF_LD | BPF_B | BPF_ABS, sizeof(struct ethhdr) + offsetof(struct iphdr, protocol)),
      // If it's not TCP (6), jump to end (drop)
      BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_TCP, 0, 1),
      // Keep the packet
      BPF_STMT(BPF_RET | BPF_K, 65535),
      // Drop the packet
      BPF_STMT(BPF_RET | BPF_K, 0)};

  struct sock_fprog bpf = {
      .len = sizeof(code) / sizeof(code[0]),
      .filter = code};

  if (setsockopt(raw_fd, SOL_SOCKET, SO_ATTACH_FILTER, &bpf, sizeof(bpf)) < 0) {
    perror("setsockopt SO_ATTACH_FILTER");
  }
}

int rawsocket(int iface_index) {
  int raw_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (raw_sock < 0) {
    perror("socket(AF_PACKET)");
    return -1;
  }

  apply_bpf_filter(raw_sock);

  struct sockaddr_ll sll = {0};
  sll.sll_family = AF_PACKET;
  sll.sll_ifindex = iface_index;
  sll.sll_protocol = htons(ETH_P_ALL);

  if (bind(raw_sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
    perror("bind");
    close(raw_sock);
    return -1;
  }

  return raw_sock;
}

#define MAX_SNI_LEN 219

#define OFFSET_SNI_EXT_LEN 120
#define OFFSET_SNI_LIST_LEN 123
#define OFFSET_SNI_TYPE 126
#define OFFSET_SNI_LEN 127
#define OFFSET_SNI_DATA 129

static const uint8_t TEMPLATE_BYTES[CLIENT_HELLO_SIZE] = {
    0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 0x00, 0x01, 0xfc, 0x03, 0x03, 0x41, 0xd5, 0xb5, 0x49, 0xd9,
    0xcd, 0x1a, 0xdf, 0xa7, 0x29, 0x6c, 0x84, 0x18, 0xd1, 0x57, 0xdc, 0x7b, 0x62, 0x4c, 0x84, 0x28,
    0x24, 0xff, 0x49, 0x3b, 0x93, 0x75, 0xbb, 0x48, 0xd3, 0x4f, 0x2b, 0x20, 0xbf, 0x01, 0x8b, 0xcc,
    0x90, 0xa7, 0xc8, 0x9a, 0x23, 0x00, 0x94, 0x81, 0x5a, 0xd0, 0xc1, 0x5b, 0x73, 0x6e, 0x38, 0xc0,
    0x12, 0x09, 0xd7, 0x2d, 0x28, 0x2c, 0xb5, 0xe2, 0x10, 0x53, 0x28, 0x15, 0x00, 0x24, 0x13, 0x02,
    0x13, 0x03, 0x13, 0x01, 0xc0, 0x2c, 0xc0, 0x30, 0xc0, 0x2b, 0xc0, 0x2f, 0xcc, 0xa9, 0xcc, 0xa8,
    0xc0, 0x24, 0xc0, 0x28, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x9f, 0x00, 0x9e, 0x00, 0x6b, 0x00, 0x67,
    0x00, 0xff, 0x01, 0x00, 0x01, 0x8f, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x09, 0x00, 0x00, 0x06, 0x6d,
    0x63, 0x69, 0x2e, 0x69, 0x72, 0x00, 0x0b, 0x00, 0x04, 0x03, 0x00, 0x01, 0x02, 0x00, 0x0a, 0x00,
    0x16, 0x00, 0x14, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x1e, 0x00, 0x19, 0x00, 0x18, 0x01, 0x00, 0x01,
    0x01, 0x01, 0x02, 0x01, 0x03, 0x01, 0x04, 0x00, 0x23, 0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00,
    0x0c, 0x02, 0x68, 0x32, 0x08, 0x68, 0x74, 0x74, 0x70, 0x2f, 0x31, 0x2e, 0x31, 0x00, 0x16, 0x00,
    0x00, 0x00, 0x17, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x2a, 0x00, 0x28, 0x04, 0x03, 0x05, 0x03, 0x06,
    0x03, 0x08, 0x07, 0x08, 0x08, 0x08, 0x09, 0x08, 0x0a, 0x08, 0x0b, 0x08, 0x04, 0x08, 0x05, 0x08,
    0x06, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x03, 0x03, 0x03, 0x01, 0x03, 0x02, 0x04, 0x02, 0x05,
    0x02, 0x06, 0x02, 0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03, 0x00, 0x2d, 0x00, 0x02,
    0x01, 0x01, 0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, 0x43, 0x5b, 0xac, 0xc4,
    0xd0, 0x5f, 0x9d, 0x41, 0xfe, 0xf4, 0x4a, 0xb3, 0xad, 0x55, 0x61, 0x6c, 0x36, 0xe0, 0x61, 0x34,
    0x73, 0xe2, 0x33, 0x87, 0x70, 0xef, 0xda, 0xa9, 0x86, 0x93, 0xd2, 0x17, 0x00, 0x15, 0x00, 0xd5};

static void get_random_bytes(uint8_t *buf, size_t len) {
  static int seeded = 0;
  if (!seeded) {
    seeded = 1;
    srand(time(NULL) ^ (uint32_t)getpid());
  }
  for (size_t i = 0; i < len; i++) {
    buf[i] = rand() % 256;
  }
}

uint16_t checksum(uint16_t *buf, int len) {
  uint32_t sum = 0;

  while (len > 1) {
    sum += *buf++;
    len -= 2;
  }

  if (len == 1) {
    sum += *(uint8_t *)buf;
  }

  sum = (sum >> 16) + (sum & 0xFFFF);
  sum += (sum >> 16);

  return (uint16_t)~sum;
}

uint16_t tcp_checksum(const uint8_t *ip_hdr, const uint8_t *tcp_hdr, size_t tcp_len) {
  uint32_t sum = 0;

  // Pseudo Header (Source IP, Dest IP, Protocol, TCP Len)
  sum += (ip_hdr[12] << 8) | ip_hdr[13];
  sum += (ip_hdr[14] << 8) | ip_hdr[15];
  sum += (ip_hdr[16] << 8) | ip_hdr[17];
  sum += (ip_hdr[18] << 8) | ip_hdr[19];
  sum += htons(0x0006); // Protocol TCP
  sum += htons((uint16_t)tcp_len);

  // TCP Header + Data
  // Loop carefully to avoid OOB read on odd lengths
  size_t i;
  for (i = 0; i + 1 < tcp_len; i += 2) {
    uint16_t word = (tcp_hdr[i] << 8) | tcp_hdr[i + 1];
    sum += word;
  }

  // Handle trailing odd byte
  if (tcp_len & 1) {
    sum += tcp_hdr[tcp_len - 1] << 8;
  }

  while (sum >> 16) {
    sum = (sum & 0xFFFF) + (sum >> 16);
  }

  return (uint16_t)~sum;
}

// --- Main Builders ---

void build_client_hello(const char *sni, uint8_t *out_buffer) {
  assert(sni != NULL);
  assert(out_buffer != NULL);
  assert(strlen(sni) <= MAX_SNI_LEN);

  size_t sni_len = strlen(sni);

  memcpy(out_buffer, TEMPLATE_BYTES, CLIENT_HELLO_SIZE);

  get_random_bytes(out_buffer + 11, 32); // Client Random
  get_random_bytes(out_buffer + 44, 32); // Session ID

  // === SNI Extension ===
  uint16_t sni_ext_len = (uint16_t)(sni_len + 5);
  uint16_t sni_list_len = (uint16_t)(sni_len + 3);

  out_buffer[OFFSET_SNI_EXT_LEN] = (sni_ext_len >> 8) & 0xFF;
  out_buffer[OFFSET_SNI_EXT_LEN + 1] = sni_ext_len & 0xFF;

  out_buffer[OFFSET_SNI_LIST_LEN] = (sni_list_len >> 8) & 0xFF;
  out_buffer[OFFSET_SNI_LIST_LEN + 1] = sni_list_len & 0xFF;

  out_buffer[OFFSET_SNI_TYPE] = 0x00; // host_name

  out_buffer[OFFSET_SNI_LEN] = (sni_len >> 8) & 0xFF;
  out_buffer[OFFSET_SNI_LEN + 1] = sni_len & 0xFF;

  memcpy(out_buffer + OFFSET_SNI_DATA, sni, sni_len);

  // === Key Share ===
  size_t key_share_pos = OFFSET_SNI_DATA + sni_len + 133;
  assert(key_share_pos + 32 <= CLIENT_HELLO_SIZE);

  get_random_bytes(out_buffer + key_share_pos, 32);

  // === Padding Extension ===
  size_t pad_header_pos = key_share_pos + 32;
  assert(pad_header_pos + 4 <= CLIENT_HELLO_SIZE);

  uint16_t pad_len = (uint16_t)(CLIENT_HELLO_SIZE - (pad_header_pos + 4));

  out_buffer[pad_header_pos] = 0x00;
  out_buffer[pad_header_pos + 1] = 0x15; // padding extension type
  out_buffer[pad_header_pos + 2] = (pad_len >> 8) & 0xFF;
  out_buffer[pad_header_pos + 3] = pad_len & 0xFF;

  // Fill remaining bytes with zeros
  memset(out_buffer + pad_header_pos + 4, 0, pad_len);
}

void build_fake_frame(const uint8_t *template_frame, size_t template_len,
                      uint32_t client_isn, // Original ISN from SYN
                      const uint8_t *fake_payload, size_t fake_len,
                      uint8_t *out, size_t *out_len) {

  const size_t ETH_HDR_LEN = 14;
  const size_t IP_HDR_LEN = 20;
  const size_t IP_OFF = ETH_HDR_LEN;
  const size_t TCP_OFF = ETH_HDR_LEN + IP_HDR_LEN;

  assert(template_frame != NULL);
  assert(out != NULL);
  assert(out_len != NULL);
  assert(fake_payload != NULL);
  assert(fake_len > 0 && fake_len <= 1400);
  assert(template_len >= TCP_OFF + 20);

  *out_len = 0;

  // Get real TCP header length from the template
  uint8_t tcp_data_offset = (template_frame[TCP_OFF + 12] >> 4) * 4;
  assert(tcp_data_offset >= 20 && tcp_data_offset <= 60);

  size_t tcp_hdr_end = TCP_OFF + tcp_data_offset;

  // Copy headers + fake payload
  memcpy(out, template_frame, tcp_hdr_end);
  memcpy(out + tcp_hdr_end, fake_payload, fake_len);

  size_t total_len = tcp_hdr_end + fake_len;
  *out_len = total_len;

  // === IP Header ===
  uint8_t *ip_hdr = out + IP_OFF;

  uint16_t ip_total_len = (uint16_t)(IP_HDR_LEN + tcp_data_offset + fake_len);
  ip_hdr[2] = (ip_total_len >> 8) & 0xFF;
  ip_hdr[3] = ip_total_len & 0xFF;

  // Increment IP ID
  uint16_t ip_id = (ip_hdr[4] << 8) | ip_hdr[5];
  ip_id++;
  ip_hdr[4] = (ip_id >> 8) & 0xFF;
  ip_hdr[5] = ip_id & 0xFF;

  // Recompute IP checksum
  ip_hdr[10] = 0;
  ip_hdr[11] = 0;
  uint16_t ip_cksum = checksum((uint16_t *)ip_hdr, IP_HDR_LEN);
  ip_hdr[10] = (ip_cksum >> 8) & 0xFF;
  ip_hdr[11] = ip_cksum & 0xFF;

  // === TCP Header ===
  uint8_t *tcp_hdr = out + TCP_OFF;

  // Set PSH flag
  tcp_hdr[13] |= 0x08;

  // Calculate out-of-window fake sequence number
  uint32_t fake_seq = client_isn + 1 - (uint32_t)fake_len;

  tcp_hdr[4] = (fake_seq >> 24) & 0xFF;
  tcp_hdr[5] = (fake_seq >> 16) & 0xFF;
  tcp_hdr[6] = (fake_seq >> 8) & 0xFF;
  tcp_hdr[7] = fake_seq & 0xFF;

  // Acknowledgment number (usually server_isn + 1)
  // We can leave it from the template or set it explicitly if you pass it

  // Recompute TCP checksum
  tcp_hdr[16] = 0;
  tcp_hdr[17] = 0;
  uint16_t tcp_cksum = tcp_checksum(ip_hdr, tcp_hdr, tcp_data_offset + fake_len);
  tcp_hdr[16] = (tcp_cksum >> 8) & 0xFF;
  tcp_hdr[17] = tcp_cksum & 0xFF;
}
