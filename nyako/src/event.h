#ifndef EVENT_H
#define EVENT_H

#include <stdbool.h>

#define TASK_COMM_LEN 16

struct event {
  int pid;
  char comm[TASK_COMM_LEN];
  bool success;
};

#endif