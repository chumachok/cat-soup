#ifndef MESSAGE_H
#define MESSAGE_H

#include "constants.h"

#define IP_BUF_SIZE 16

struct message_details
{
  unsigned char message[MESSAGE_BUF_SIZE];
  unsigned char ip[IP_BUF_SIZE];
};

#endif