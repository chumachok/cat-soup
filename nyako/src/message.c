#include "message.h"

void to_hex(unsigned char *input, int len, unsigned char *output)
{
  int j;

  j = 0;
  for (int i = 0; i < len; i++)
  {
    sprintf((char *)(output + j),"%02x", input[i]);
    j += 2;
  }

  // null terminate
  output[j++] = '\0';
}

void to_ascii(unsigned char *dest, const unsigned char *data)
{
  unsigned int ch;
  for(; sscanf((char *)data, "%02X", &ch) == 1; data += 2)
  {
    *dest++ = ch;
  }

  // null-terminate
  *dest = 0;
}

int craft_message(unsigned char *message, unsigned char *auth_header, unsigned long id, int type, int ciphertext_len, unsigned char *ciphertext, unsigned char *nonce)
{
  int n, padding;
  unsigned char padding_buf[MESSAGE_BUF_SIZE];
  n = snprintf((char *) message, MESSAGE_BUF_SIZE, "%s.%li.%i.%i.%s.%s", auth_header, id, type, ciphertext_len, ciphertext, nonce);
  padding = MESSAGE_BUF_SIZE - n;

  if (padding > 0)
  {
    generate_rand_string(padding_buf, padding - 1);
    snprintf((char *)message + n, padding, ".%s", (char *)padding_buf);
  }

  return n;
}

int parse_message(unsigned char *message_in, struct message *message_out)
{
  int i;
  unsigned char copy[MESSAGE_BUF_SIZE];
  char delim[] = ".";

  snprintf((char *)copy, sizeof(copy), "%s", message_in);
  char *ptr = strtok((char *)copy, delim);
  i = 0;
  while(ptr != NULL)
  {
    switch (i)
    {
    case 0:
      snprintf((char *)message_out->auth_header, AUTH_HEADER_SIZE + 1, "%s", ptr);
      break;
    case 1:
      message_out->id = atoi(ptr);
      break;
    case 2:
      message_out->type = atoi(ptr);
      break;
    case 3:
      message_out->ciphertext_len = atoi(ptr);
      break;
    case 4:
      to_ascii(message_out->ciphertext, (unsigned char *)ptr);
      break;
    case 5:
      to_ascii(message_out->nonce, (unsigned char *)ptr);
      break;
    default:
      break;
    }
    i++;
    ptr = strtok(NULL, delim);
  }

  return 0;
}