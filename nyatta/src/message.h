#ifndef MESSAGE_H
#define MESSAGE_H

#include <stdio.h>
#include <string.h>

#include "constants.h"
#include "command.h"
#include "utils.h"

void to_hex(unsigned char* input, int len, unsigned char* output);
void to_ascii(unsigned char *dest, const unsigned char *data);
int get_command_type(const char* command);
int craft_message(unsigned char *message, unsigned char *auth_header, unsigned long id, int type, int ciphertext_len, unsigned char *ciphertext, unsigned char *nonce);

#endif