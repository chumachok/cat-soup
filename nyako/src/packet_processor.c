#include "packet_processor.h"

// clang -O2 -g -Wall -target bpf -c src/packet_processor.c -o packet_processor.o

static __always_inline int parse_ethhdr(struct hdr_cursor *header, void *data_end, struct ethhdr **ethhdr)
{
  struct ethhdr *eth = header->pos;
  int hdrsize = sizeof(*eth);

  // bound-check
  if (header->pos + hdrsize > data_end)
    return -1;

  header->pos += hdrsize;
  *ethhdr = eth;

  // network byte order
  return eth->h_proto;
}

// struct xdp_md {
//  __u32 data;
//  __u32 data_end;
//  __u32 data_meta;
//  __u32 ingress_ifindex; // rxq->dev->ifindex
//  __u32 rx_queue_index; // rxq->queue_index
//  __u32 egress_ifindex; // txq->dev->ifindex
// };
SEC("packet_processor")
int process_packet(struct xdp_md *ctx)
{
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth;

  struct hdr_cursor header;
  int header_type;

  __u32 key = 0;
  long *value;

  // start next header cursor position at data start
  header.pos = data;

  header_type = parse_ethhdr(&header, data_end, &eth);
  if (header_type == bpf_htons(ETH_P_IP))
  {
    value = bpf_map_lookup_elem(&rxcnt, &key);

    // increase packet count for debugging and development purposes
    if (value)
    {
      *value += 1;
    }
  }

  return XDP_PASS;
}

char _license[] SEC("license") = "MIT";
