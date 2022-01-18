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

#include "constants.h"

#define PAYLOAD_HEADER "If-None-Match: "
#define HTTP_PORT 80
#define MESSAGE_QUEQUE_SIZE 16
#define CLIENT_IP_OFFSET 22
#define EXTRA_HEADER_SIZE 30
#define CONTROL_CHAR_SIZE 4
#define IP_BUF_SIZE 16

struct hdr_cursor
{
  void *pos;
};

struct message_details
{
  unsigned char message[MESSAGE_BUF_SIZE];
  unsigned char ip[IP_BUF_SIZE];
};

struct bpf_map_def SEC("maps") message_map_array = {
  .type        = BPF_MAP_TYPE_ARRAY,
  .key_size    = sizeof(__u32),
  .value_size  = sizeof(struct message_details),
  .max_entries = MESSAGE_QUEQUE_SIZE,
};

#endif