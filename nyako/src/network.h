#ifndef NETWORK_H
#define NETWORK_H

#include <curl/curl.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "config.h"
#include "constants.h"
#include "logger.h"

#define PAYLOAD_HEADER "If-None-Match: "

int send_request(const unsigned char *payload, const unsigned char *ip);
int saddr_to_str(unsigned char *buf, unsigned int saddr);

#endif