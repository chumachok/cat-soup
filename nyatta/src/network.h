#ifndef NETWORK_H
#define NETWORK_H

#include <curl/curl.h>
#include <string.h>

#include "config.h"
#include "constants.h"
#include "logger.h"

#define PAYLOAD_HEADER "If-None-Match: "
#define PAYLOAD_HEADER_LEN 15

int send_request(const unsigned char *payload);

#endif