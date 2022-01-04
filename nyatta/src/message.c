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

int get_command_type(const char* command)
{
  if (strcmp(command, ADD_WATCHER_CMD) == 0)
    return TYPE_ADD_WATCHER;
  else if (strcmp(command, REMOVE_WATCHER_CMD) == 0)
    return TYPE_REMOVE_WATCHER;

  // default command
  return TYPE_EXECUTE_CMD;
}

int craft_message(unsigned char *message, unsigned char *auth_header, int id, int type, unsigned char *ciphertext, int ciphertext_len)
{
  int n;
  n = snprintf((char *) message, BUF_SIZE, "%s.%i.%i.%i.%s", auth_header, id, type, ciphertext_len, ciphertext);

  return n;
}
