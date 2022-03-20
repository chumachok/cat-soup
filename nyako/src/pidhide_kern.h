#ifndef PIDHIDE_KERN_H
#define PIDHIDE_KERN_H

#include "kern_common.h"
#include "event.h"
#include "constants.h"

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// map to fold the dents buffer addresses
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, size_t);
  __type(value, long unsigned int);
} map_buffs SEC(".maps");

// map used to enable searching through the data in a loop
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, size_t);
  __type(value, int);
} map_bytes_read SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 8192);
  __type(key, size_t);
  __type(value, long unsigned int);
} map_to_patch SEC(".maps");

// map to hold program tail calls
struct {
  __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
  __uint(max_entries, 5);
  __type(key, __u32);
  __type(value, __u32);
} map_prog_array SEC(".maps");

#endif