#ifndef PACKET_PROCESSOR_H
#define PACKET_PROCESSOR_H

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

#endif