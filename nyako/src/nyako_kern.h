#ifndef NYAKO_KERN_H
#define NYAKO_KERN_H

#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

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

#endif