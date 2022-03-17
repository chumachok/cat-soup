#ifndef NYATTA_H
#define NYATTA_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <curl/curl.h>
#include <pcap.h>
#include <libnet.h>
#include <pthread.h>

#include "config.h"
#include "constants.h"
#include "logger.h"
#include "crypto.h"
#include "network.h"
#include "message.h"
#include "listener.h"

#define ETHER_IP_TCP_LEN 54

struct hdr_cursor
{
  void *pos;
};

#endif