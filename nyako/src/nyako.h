#ifndef NYAKO_H
#define NYAKO_H

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>

#include "logger.h"
#include "bpf_helpers.h"
#include "message.h"
#include "command.h"
#include "network.h"
#include "utils.h"
#include "crypto.h"
#include "constants.h"
#include "no_trace.h"
#include "pidhide.h"

#define NYAKO_KERN_FILENAME "nyako_kern.o"
#define NYAKO_KERN_PROGSEC "nyako_kern"
#define IFINDEX 3
#define NYAKO_KERN_PROG_ID 0

#endif