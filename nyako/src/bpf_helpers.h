#ifndef BPF_HELPERS_H
#define BPF_HELPERS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/if_link.h>

#include "constants.h"

#define MAX_ERRNO 4095

#define IS_ERR_VALUE(x) ((x) >= (unsigned long)-MAX_ERRNO)

struct config {
  __u32 xdp_flags;
  int ifindex;
  bool reuse_maps;
  char pin_dir[BUF_SIZE];
  char filename[BUF_SIZE];
  char progsec[32];
};

struct bpf_object *load_bpf_and_xdp_attach(struct config *cfg);
int xdp_link_detach(int ifindex, __u32 xdp_flags, __u32 expected_prog_id);

#endif