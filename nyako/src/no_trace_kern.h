#ifndef NO_TRACE_KERN_H
#define NO_TRACE_KERN_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <string.h>

#include "event.h"

#define SIGKILL 9

struct trace_entry {
  short unsigned int type;
  unsigned char flags;
  unsigned char preempt_count;
  int pid;
};

struct trace_event_raw_sys_enter {
  struct trace_entry ent;
  long int id;
  long unsigned int args[6];
  char __data[0];
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

#endif