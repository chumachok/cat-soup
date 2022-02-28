#include "crypto.h"

int encrypt(unsigned char *ciphertext, const unsigned char *data, size_t len, const unsigned char *nonce, const char *private_key_path, const char *public_key_path)
{
  unsigned char publickey[crypto_box_PUBLICKEYBYTES];
  unsigned char secretkey[crypto_box_SECRETKEYBYTES];

  size_t ciphertext_len = crypto_secretbox_MACBYTES + len;

  if (ciphertext_len > BUF_SIZE)
  {
    log_error("ciphertext_len invalid");
    return -1;
  }

  if (read_file(private_key_path, secretkey) < 0)
  {
    log_error("read_file");
    return -1;
  }

  if (read_file(public_key_path, publickey) < 0)
  {
    log_error("read_file");
    return -1;
  }

  if (sodium_init() == -1)
  {
    log_error("sodium_init");
    return -1;
  }

  if (crypto_box_easy(ciphertext, data, len, nonce, publickey, secretkey) != 0)
  {
    log_error("crypto_box_easy");
    return -1;
  }

  return (int)ciphertext_len;
}

int decrypt(unsigned char *decrypted, const unsigned char *ciphertext, size_t ciphertext_len, unsigned char *nonce, const char *private_key_path, const char *public_key_path)
{
  unsigned char publickey[crypto_box_PUBLICKEYBYTES], secretkey[crypto_box_SECRETKEYBYTES];

  if (read_file(private_key_path, secretkey) < 0)
  {
    log_error("read_file");
    return -1;
  }

  if (read_file(public_key_path, publickey) < 0)
  {
    log_error("read_file");
    return -1;
  }

  if (crypto_box_open_easy(decrypted, ciphertext, ciphertext_len, nonce, publickey, secretkey) != 0)
  {
    log_error("crypto_box_open_easy");
    return -1;
  }

  return 0;
}