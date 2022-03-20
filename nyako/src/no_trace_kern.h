#ifndef NO_TRACE_KERN_H
#define NO_TRACE_KERN_H

#include "event.h"
#include "kern_common.h"

#define SIGKILL 9

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

#endif