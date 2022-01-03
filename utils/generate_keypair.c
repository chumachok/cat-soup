#include <stdio.h>
#include <sodium.h>
#include <getopt.h>

// gcc -Wall -o generate_keypair.o ./utils/generate_keypair.c -lsodium
// ./generate_keypair.o -p secrets/server/
// ./generate_keypair.o -p secrets/client/

static void print_usage(char *progname)
{
  fprintf(stdout, "usage: %s -p <path>", progname);
}

static void write_file(const char* path, unsigned char *data, size_t nwrite)
{
  FILE *fp;
  size_t n;
  fp = fopen(path, "w");
  if (fp == NULL)
  {
    perror("fopen");
    exit(EXIT_FAILURE);
  }
  if ((n = fwrite(data, nwrite, 1, fp)) != 1)
  {
    perror("fwrite");
    exit(EXIT_FAILURE);
  }
  fclose(fp);
}

static void generate_keypair(const char *path)
{
  unsigned char publickey[crypto_box_PUBLICKEYBYTES];
  unsigned char secretkey[crypto_box_SECRETKEYBYTES];
  int bufsize = 256;
  char publickey_path[bufsize];
  char secretkey_path[bufsize];

  if (sodium_init() == -1)
  {
    perror("sodium_init");
    exit(EXIT_FAILURE);
  }

  crypto_box_keypair(publickey, secretkey);

  if (snprintf(secretkey_path, bufsize, "%s/private.bin", path) < 0)
  {
    perror("snprintf");
    exit(EXIT_FAILURE);
  }

  if (snprintf(publickey_path, bufsize, "%s/public.bin", path) < 0)
  {
    perror("snprintf");
    exit(EXIT_FAILURE);
  }

  write_file(secretkey_path, secretkey, crypto_box_SECRETKEYBYTES);
  write_file(publickey_path, publickey, crypto_box_PUBLICKEYBYTES);
}


int main(int argc, char *argv[])
{
  int opt;

  while ((opt = getopt(argc, argv, "p:h:")) != -1)
  {
    switch (opt)
    {
      case 'p':
        generate_keypair(optarg);
        break;
      case 'h':
        print_usage(argv[0]);
        break;
      default:
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }
  }

  return 0;
}