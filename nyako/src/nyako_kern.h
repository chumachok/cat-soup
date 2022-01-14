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

#include "crypto.h"

#define BUF_SIZE 64

struct hdr_cursor
{
  void *pos;
};

struct
{
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, __u32);
  __type(value, long);
  __uint(max_entries, 1);
} rxcnt SEC(".maps");

// #ifndef memcpy
// #define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
// #endif

#endif