#include "no_trace.h"

static int handle_event(void *ctx, void *data, size_t data_sz)
{
  const struct event *event = data;
  if (event->success)
    fprintf(stdout, "killed PID %d (%s)\n", event->pid, event->comm);
  else
    fprintf(stderr, "failed to kill PID %d (%s)\n", event->pid, event->comm);
  return 0;
}

void destroy_no_trace(struct no_trace_kern *skel)
{
  no_trace_kern__destroy(skel);
}

int setup_no_trace(struct no_trace_kern *skel)
{
  struct ring_buffer *rb = NULL;
  int err;

  if (!skel)
  {
    fprintf(stderr, "failed to open BPF program: %s\n", strerror(errno));
    return -1;
  }

  // verify and load program
  err = no_trace_kern__load(skel);
  if (err)
  {
    fprintf(stderr, "failed to load and verify bpf program\n");
    destroy_no_trace(skel);
    return -1;
  }

  // attach tracepoint handler
  err = no_trace_kern__attach(skel);
  if (err)
  {
    fprintf(stderr, "failed to attach bpf program: %s\n", strerror(errno));
    destroy_no_trace(skel);
    return -1;
  }

  rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
  if (!rb)
  {
    fprintf(stderr, "failed to create ring buffer\n");
    destroy_no_trace(skel);
    return -1;
  }

  printf("sending SIGKILL to any program using the ptrace syscall\n");
  while (true)
  {
    // timeout in ms
    err = ring_buffer__poll(rb, 100);
    // ctrl-c
    if (err == -EINTR)
    {
      err = 0;
      break;
    }
    if (err < 0)
    {
      fprintf(stderr, "error polling perf buffer: %d\n", err);
      break;
    }
  }

  return 0;
}
