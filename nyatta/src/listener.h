
#ifndef LISTENER_H
#define LISTENER_H

#include <pcap.h>
#include <string.h>

#include "config.h"
#include "logger.h"

void setup_network_listener(int num_packets, char *filter, pcap_handler callback, unsigned char *params);

#endif