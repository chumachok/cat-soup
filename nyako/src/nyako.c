#include <string.h>
#include <stdio.h>

int main()
{
  // test encryption
  unsigned char crypto_key[32];
  unsigned char plaintext[128], cipher[128], decrypted[128];

  memcpy(crypto_key, "IuUWptZcxmJXuVAHMAZ8TvBQdc3n0RBW", sizeof(crypto_key));
  memcpy(plaintext, "qsVNEpZsTqLrwjOdEcw5buoCQNijTHuNi63uG7B2wjNkj3AVj9Bmzlua2jJH4Q9ll03ldWtzezcXTZbDO3Nfmq7Ppe32LU2DF7BQZILyFRvk8Hubcjb27VkPvakPEjb", sizeof(plaintext) - 1);

  plaintext[127] = '\0';

  for(int i = 0; i < sizeof(plaintext) - 1; i++)
  {
    cipher[i] = plaintext[i] ^ crypto_key[i % sizeof(crypto_key)];
  }

  for(int i = 0; i < sizeof(cipher) - 1; i++)
  {
    decrypted[i] = cipher[i] ^ crypto_key[i % sizeof(crypto_key)];
  }

  decrypted[127] = '\0';

  printf("%s\n", plaintext);
  printf("%s\n", decrypted);

  return 0;
}

