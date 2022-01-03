#include "nyatta.h"

static char *line = NULL;

static void cleanup()
{
  free(line);
  exit(EXIT_SUCCESS);
}

int main()
{
  ssize_t n;
  size_t len = 0;
  unsigned char ciphertext[BUF_SIZE];

  signal(SIGINT, cleanup);

  while ((n = getline(&line, &len, stdin)) != -1)
  {
    // remove newline
    line[n - 1] = 0;
    encrypt((unsigned char *)line, len, PRIVATE_KEY_PATH, PUBLIC_KEY_PATH, ciphertext);
    printf("%s\n", ciphertext);

    // send http get request with "If-None-Match"
  }

  cleanup();

  return 0;
}