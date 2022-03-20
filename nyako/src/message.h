#ifndef MESSAGE_H
#define MESSAGE_H

#include <stdio.h>
#include <string.h>
#include <sodium.h>

#include "constants.h"
#include "command.h"
#include "utils.h"

#define IP_BUF_SIZE 16

struct message_details
{
  unsigned char message[MESSAGE_BUF_SIZE];
  unsigned int ip_saddr;
};

struct message
{
  unsigned char auth_header[AUTH_HEADER_SIZE + 1];
  unsigned long id;
  int type;
  int ciphertext_len;
  unsigned char ciphertext[MESSAGE_BUF_SIZE];
  unsigned char nonce[crypto_secretbox_NONCEBYTES];
};

void to_hex(unsigned char* input, int len, unsigned char* output);
void to_ascii(unsigned char *dest, const unsigned char *data);
int craft_message(unsigned char *message, unsigned char *auth_header, unsigned long id, int type, int ciphertext_len, unsigned char *ciphertext, unsigned char *nonce);
int parse_message(unsigned char *message_in, struct message *message_out);

#endif