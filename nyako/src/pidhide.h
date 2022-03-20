#ifndef PIDHIDE_H
#define PIDHIDE_H

#include <stdio.h>
#include <bpf/bpf.h>

#include "config.h"
#include "event.h"
#include "constants.h"
#include "pidhide_skeleton.h"

int setup_pidhide(struct pidhide_kern *skel, int target_pid);
void destroy_pidhide(struct pidhide_kern *skel);

#endif