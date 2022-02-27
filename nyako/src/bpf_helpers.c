#include "bpf_helpers.h"

static inline bool IS_ERR_OR_NULL(const void *ptr)
{
  return (!ptr) || IS_ERR_VALUE((unsigned long)ptr);
}

static inline long PTR_ERR(const void *ptr)
{
  return (long) ptr;
}

static struct bpf_object *open_bpf_object(const char *file, int ifindex)
{
  int err;
  struct bpf_object *obj;
  struct bpf_map *map;
  struct bpf_program *prog, *first_prog = NULL;

  struct bpf_object_open_attr open_attr = {
    .file = file,
    .prog_type = BPF_PROG_TYPE_XDP,
  };

  obj = bpf_object__open_xattr(&open_attr);
  if (IS_ERR_OR_NULL(obj))
  {
    err = -PTR_ERR(obj);
    fprintf(stderr, "ERROR: opening BPF-OBJ file(%s) (%d): %s\n", file, err, strerror(-err));
    return NULL;
  }

  bpf_object__for_each_program(prog, obj)
  {
    bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);
    bpf_program__set_ifindex(prog, ifindex);

    if (!first_prog)
      first_prog = prog;
  }

  bpf_object__for_each_map(map, obj)
  {

    if (!bpf_map__is_offload_neutral(map))
      bpf_map__set_ifindex(map, ifindex);
  }

  if (!first_prog)
  {
    fprintf(stderr, "ERROR: file %s contains no programs\n", file);
    return NULL;
  }

  return obj;
  }

static int reuse_maps(struct bpf_object *obj, const char *path)
{
  struct bpf_map *map;

  if (!obj)
    return -ENOENT;

  if (!path)
    return -EINVAL;

  bpf_object__for_each_map(map, obj)
  {
    int len, err;
    int pinned_map_fd;
    char buf[BUF_SIZE];

    len = snprintf(buf, BUF_SIZE, "%s/%s", path, bpf_map__name(map));
    if (len < 0)
    {
      return -EINVAL;
    } else if (len >= BUF_SIZE)
    {
      return -ENAMETOOLONG;
    }

    pinned_map_fd = bpf_obj_get(buf);
    if (pinned_map_fd < 0)
      return pinned_map_fd;

    err = bpf_map__reuse_fd(map, pinned_map_fd);
    if (err)
      return err;
  }

  return 0;
}

static struct bpf_object *load_bpf_object_file(const char *filename, int ifindex)
{
  int first_prog_fd = -1;
  struct bpf_object *obj;
  int err;

  struct bpf_prog_load_attr prog_load_attr = {
    .prog_type = BPF_PROG_TYPE_XDP,
    .ifindex = ifindex,
  };
  prog_load_attr.file = filename;

  err = bpf_prog_load_xattr(&prog_load_attr, &obj, &first_prog_fd);
  if (err)
  {
    fprintf(stderr, "ERROR: loading BPF-OBJ file(%s) (%d): %s\n", filename, err, strerror(-err));
    return NULL;
  }

  return obj;
}

static struct bpf_object *load_bpf_object_file_reuse_maps(const char *file, int ifindex, const char *pin_dir)
{
  int err;
  struct bpf_object *obj;

  obj = open_bpf_object(file, ifindex);
  if (!obj)
  {
    fprintf(stderr, "ERROR: failed to open object %s\n", file);
    return NULL;
  }

  err = reuse_maps(obj, pin_dir);
  if (err)
  {
    fprintf(stderr, "ERROR: failed to reuse maps for object %s, pin_dir=%s\n", file, pin_dir);
    return NULL;
  }

  err = bpf_object__load(obj);
  if (err)
  {
    fprintf(stderr, "ERROR: loading BPF-OBJ file(%s) (%d): %s\n", file, err, strerror(-err));
    return NULL;
  }

  return obj;
}

static int xdp_link_attach(int ifindex, __u32 xdp_flags, int prog_fd)
{
  int err;

  // libbpf provide the XDP net_device link-level hook attach helper
  err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
  if (err == -EEXIST && !(xdp_flags & XDP_FLAGS_UPDATE_IF_NOEXIST))
  {
    // force mode didn't work, probably because a program of the opposite type is loaded. Let's unload that and try loading again.
    __u32 old_flags = xdp_flags;

    xdp_flags &= ~XDP_FLAGS_MODES;
    xdp_flags |= (old_flags & XDP_FLAGS_SKB_MODE) ? XDP_FLAGS_DRV_MODE : XDP_FLAGS_SKB_MODE;
    err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
    if (!err)
      err = bpf_set_link_xdp_fd(ifindex, prog_fd, old_flags);
  }
  if (err < 0)
  {
    fprintf(stderr, "ERROR: ifindex(%d) link set xdp fd failed (%d): %s\n", ifindex, -err, strerror(-err));

    switch (-err)
    {
      case EBUSY:
      case EEXIST:
        fprintf(stderr, "NOTE: XDP already loaded on device use --force to swap/replace\n");
        break;
      case EOPNOTSUPP:
        fprintf(stderr, "NOTE: native-XDP not supported use --skb-mode or --auto-mode\n");
        break;
      default:
        break;
    }
    return -1;
  }

  return 0;
}

struct bpf_object *load_bpf_and_xdp_attach(struct config *cfg)
{
  struct bpf_program *bpf_prog;
  struct bpf_object *bpf_obj;
  int offload_ifindex = 0;
  int prog_fd = -1;
  int err;

  // if flags indicate hardware offload, supply ifindex
  if (cfg->xdp_flags & XDP_FLAGS_HW_MODE)
    offload_ifindex = cfg->ifindex;

  // load the BPF-ELF object file and get back libbpf bpf_object
  if (cfg->reuse_maps)
    bpf_obj = load_bpf_object_file_reuse_maps(cfg->filename, offload_ifindex, cfg->pin_dir);
  else
    bpf_obj = load_bpf_object_file(cfg->filename, offload_ifindex);
  if (!bpf_obj)
  {
    fprintf(stderr, "ERROR: loading file: %s\n", cfg->filename);
    exit(EXIT_FAILURE);
  }

  if (cfg->progsec[0])
    // find a matching BPF prog section name
    bpf_prog = bpf_object__find_program_by_title(bpf_obj, cfg->progsec);
  else
    // find the first program
    bpf_prog = bpf_program__next(NULL, bpf_obj);

  if (!bpf_prog)
  {
    fprintf(stderr, "ERROR: couldn't find a program in ELF section '%s'\n", cfg->progsec);
    exit(EXIT_FAILURE);
  }

  strncpy(cfg->progsec, bpf_program__section_name(bpf_prog), sizeof(cfg->progsec));

  prog_fd = bpf_program__fd(bpf_prog);
  if (prog_fd <= 0)
  {
    fprintf(stderr, "ERROR: bpf_program__fd failed\n");
    exit(EXIT_FAILURE);
  }

  err = xdp_link_attach(cfg->ifindex, cfg->xdp_flags, prog_fd);
  if (err)
    exit(err);

  return bpf_obj;
}

int xdp_link_detach(int ifindex, __u32 xdp_flags, __u32 expected_prog_id)
{
  __u32 curr_prog_id;
  int err;

  err = bpf_get_link_xdp_id(ifindex, &curr_prog_id, xdp_flags);
  if (err)
  {
    fprintf(stderr, "ERR: get link xdp id failed (err=%d): %s\n", -err, strerror(-err));
    return -1;
  }

  if (!curr_prog_id)
  {
    return 0;
  }

  if (expected_prog_id && curr_prog_id != expected_prog_id)
  {
    fprintf(stderr, "ERR: %s() expected prog ID(%d) no match(%d), not removing\n", __func__, expected_prog_id, curr_prog_id);
    return -1;
  }

  if ((err = bpf_set_link_xdp_fd(ifindex, -1, xdp_flags)) < 0)
  {
    fprintf(stderr, "ERR: %s() link set xdp failed (err=%d): %s\n", __func__, err, strerror(-err));
    return -1;
  }

  return 0;
}