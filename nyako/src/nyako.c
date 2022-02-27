#include "nyako.h"

static void get_map_value(int fd, __u32 key, struct message_details *value)
{
  if ((bpf_map_lookup_elem(fd, &key, value)) != 0)
  {
    fprintf(stderr, "ERROR: bpf_map_lookup_elem failed key:0x%X\n", key);
  }
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

static void message_poll(int map_fd, __u32 key, int interval)
{
  struct message_details prev, message_details;

  // get initial reading
  get_map_value(map_fd, key, &message_details);
  usleep(1000000 / 4);

  while (true)
  {
    prev = message_details;
    get_map_value(map_fd, key, &message_details);
    printf("%s\n", message_details.message);

    sleep(interval);
  }
}

int main()
{
  struct bpf_object *bpf_obj;
  int message_queque_map_fd;
  int interval = 2;

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

  message_queque_map_fd = find_map_fd(bpf_obj, "message_queque_map");
  if (message_queque_map_fd < 0)
  {
    xdp_link_detach(cfg.ifindex, cfg.xdp_flags, 0);
    log_error("find_map_fd");
    return -1;
  }

  message_poll(message_queque_map_fd, 0, interval);

  return 0;
}

