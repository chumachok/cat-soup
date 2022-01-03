#include "crypto.h"

size_t encrypt(const unsigned char *data, size_t len, const char *private_key_path, const char *public_key_path, unsigned char *ciphertext)
{
  unsigned char nonce[crypto_secretbox_NONCEBYTES];
  unsigned char publickey[crypto_box_PUBLICKEYBYTES];
  unsigned char secretkey[crypto_box_SECRETKEYBYTES];

  size_t ciphertext_len = crypto_secretbox_MACBYTES + len;

  if (ciphertext_len > BUF_SIZE)
  {
    log_error("ciphertext_len invalid");
    exit(EXIT_FAILURE);
  }

  if (read_file(private_key_path, secretkey) < 0)
  {
    log_error("read_file");
    exit(EXIT_FAILURE);
  }

  if(read_file(public_key_path, publickey) < 0)
  {
    log_error("read_file");
    exit(EXIT_FAILURE);
  }

  randombytes_buf(nonce, sizeof(nonce));
  if (crypto_box_easy(ciphertext, data, len, nonce, publickey, secretkey) != 0)
  {
    log_error("crypto_box_easy");
    exit(EXIT_FAILURE);
  }

  return ciphertext_len;
}