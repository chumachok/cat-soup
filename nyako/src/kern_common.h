#ifndef KERN_COMMON_H
#define KERN_COMMON_H

#include <stdbool.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <string.h>

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

struct trace_event_raw_sys_exit {
  struct trace_entry ent;
  long int id;
  long int ret;
  char __data[0];
};

typedef __s64 s64;
typedef __u64 u64;

struct linux_dirent64 {
  u64 d_ino;
  s64 d_off;
  short unsigned int d_reclen;
  unsigned char d_type;
  char d_name[0];
};

#endif