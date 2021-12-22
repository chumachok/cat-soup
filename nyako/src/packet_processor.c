#include "packet_processor.h"

// clang -O2 -g -Wall -target bpf -c nyako/src/packet_processor.c -o packet_processor.o
// ip link add veth0 type veth peer name veth1
// ip link set veth1 xdpgeneric obj packet_processor.o sec packet_processor

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

SEC("packet_processor")
int process_packet(struct xdp_md *ctx)
{
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth;

  struct hdr_cursor header;
  int header_type;

  // start next header cursor position at data start
  header.pos = data;

  header_type = parse_ethhdr(&header, data_end, &eth);
  if (header_type == bpf_htons(ETH_P_IPV6))
  {
    return XDP_DROP;
  }

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
