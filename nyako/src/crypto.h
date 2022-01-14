#ifndef CRYPTO_H
#define CRYPTO_H

#define CRYPTO_KEY "IuUWptZcxmJXuVAHMAZ8TvBQdc3n0RBW"

int xor_cipher(unsigned char *output, unsigned char *data, __u32 datalen, unsigned char *key, __u32 keylen)
{
  for (__u32 i = 0; i < datalen; i++)
  {
    output[i] = data[i] ^ key[i % keylen];
  }

  return 0;
}

#endif