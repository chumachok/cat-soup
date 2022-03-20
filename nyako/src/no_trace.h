#ifndef NO_TRACE_H
#define NO_TRACE_H

#include "no_trace_skeleton.h"
#include "event.h"
#include "logger.h"

int setup_no_trace(struct no_trace_kern *skel);
void destroy_no_trace(struct no_trace_kern *skel);

#endif