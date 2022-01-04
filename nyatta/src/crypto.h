#ifndef CRYPTO_H
#define CRYPTO_H

#include <sodium.h>
#include <stdint.h>

#include "constants.h"
#include "utils.h"
#include "logger.h"

int encrypt(unsigned char *ciphertext, const unsigned char *data, size_t len, const unsigned char *nonce, const char *private_key_path, const char *public_key_path);
int decrypt(unsigned char *decrypted, const unsigned char *ciphertext, size_t ciphertext_len, unsigned char *nonce, const char *private_key_path, const char *public_key_path);

#endif