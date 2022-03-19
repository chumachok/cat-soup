#include "no_trace_kern.h"

SEC("tp/syscalls/sys_enter_ptrace")
int no_trace(struct trace_event_raw_sys_enter *ctx)
{
  long ret = 0;
  size_t pid_tgid = bpf_get_current_pid_tgid();
  int pid = pid_tgid >> 32;

  ret = bpf_send_signal(SIGKILL);

  struct event *event;
  event = bpf_ringbuf_reserve(&rb, sizeof(*event), 0);
  if (event)
  {
    event->success = (ret == 0);
    event->pid = pid;
    bpf_get_current_comm(&event->comm, sizeof(event->comm));
    bpf_ringbuf_submit(event, 0);
  }

  return 0;
}

char _license[] SEC("license") = "Dual MIT/GPL";