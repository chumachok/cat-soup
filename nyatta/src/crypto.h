#ifndef CRYPTO_H
#define CRYPTO_H

#include <sodium.h>
#include <stdint.h>

#include "constants.h"
#include "utils.h"
#include "logger.h"

size_t encrypt(const unsigned char *data, size_t len, const char *private_key_path, const char *public_key_path, unsigned char *ciphertext);

#endif