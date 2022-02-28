#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>
#include <stdlib.h>

int read_file(const char *path, unsigned char *buf);
void generate_rand_string(unsigned char *str, int size);

#endif