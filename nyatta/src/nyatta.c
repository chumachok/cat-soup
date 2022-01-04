#include "nyatta.h"

static char *line = NULL;

static void cleanup()
{
  free(line);
  curl_global_cleanup();
  exit(EXIT_SUCCESS);
}

int main()
{
  ssize_t n;
  size_t len = 0;
  int ciphertext_len, message_id, command_type;
  // TODO: calculate proper buffer sizes
  unsigned char ciphertext_hex[BUF_SIZE], ciphertext[BUF_SIZE], message[BUF_SIZE];
  curl_global_init(CURL_GLOBAL_DEFAULT);

  signal(SIGINT, cleanup);

  message_id = 0;
  while ((n = getline(&line, &len, stdin)) != -1)
  {
    // remove newline
    line[n - 1] = 0;
    if ((ciphertext_len = encrypt((unsigned char *)line, len, PRIVATE_KEY_PATH, PUBLIC_KEY_PATH, ciphertext)) < 0)
    {
      log_error("encrypt");
      continue;
    }

    to_hex(ciphertext, ciphertext_len, ciphertext_hex);
    command_type = get_command_type(line);
    if (craft_message(message, AUTH_HEADER, message_id, command_type, ciphertext_hex, ciphertext_len) < 0)
    {
      log_error("craft_message");
      continue;
    }

    send_request(message);
    message_id++;
  }

  cleanup();

  return 0;
}