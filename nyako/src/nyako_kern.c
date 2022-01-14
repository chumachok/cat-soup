#include "nyako_kern.h"

// struct xdp_md {
//  __u32 data;
//  __u32 data_end;
//  __u32 data_meta;
//  __u32 ingress_ifindex; // rxq->dev->ifindex
//  __u32 rx_queue_index; // rxq->queue_index
//  __u32 egress_ifindex; // txq->dev->ifindex
// };

SEC("nyako_kern")
int process_packet(struct xdp_md *ctx)
{
  int action = XDP_PASS;

  struct ethhdr *ethh;
  struct iphdr *iph;
  struct tcphdr *tcph;

  struct hdr_cursor header;

  int hlen;

  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  // start next header cursor position at data start
  header.pos = data;

  // parse eth header
  ethh = header.pos;
  hlen = ETH_HLEN;
  if (header.pos + hlen > data_end)
    goto out;

  header.pos += hlen;

  if (ethh->h_proto < 0)
  {
    action = XDP_ABORTED;
    goto out;
  }

  if (ethh->h_proto != bpf_htons(ETH_P_IP))
  {
    goto out;
  }

  // parse ip header
  if (header.pos + sizeof(*iph) > data_end)
    goto out;

  iph = header.pos;

  hlen = iph->ihl * 4;

  if (hlen < sizeof(*iph))
  {
    action = XDP_ABORTED;
    goto out;
  }

  header.pos += hlen;

  if (iph->protocol != IPPROTO_TCP)
  {
    goto out;
  }

  // parse tcp header
  if ((header.pos + sizeof(*tcph)) > data_end)
  {
    goto out;
  }

  tcph = header.pos;
  hlen = tcph->doff * 4;

  if (hlen < sizeof(*tcph))
  {
    goto out;
  }

  bpf_printk("%li", bpf_ntohs(tcph->dest));

out:
  return action;
}

char _license[] SEC("license") = "Dual MIT/GPL";
