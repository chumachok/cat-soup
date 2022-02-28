#include "utils.h"

void generate_rand_string(unsigned char *str, int size)
{
  const char charset[] = "abcdefghijklmnopqrstuvwxyz";
  if (size)
  {
    --size;
    for (int n = 0; n < size; n++)
    {
      int key = rand() % (int) (sizeof charset - 1);
      str[n] = charset[key];
    }
    str[size] = '\0';
  }

  return;
}

int read_file(const char *path, unsigned char *buf)
{
  FILE *fp;
  long filelen;
  int n;

  fp = fopen(path, "r");
  if (fp == NULL)
  {
    return -1;
  }

  fseek(fp, 0, SEEK_END);
  filelen = ftell(fp);
  rewind(fp);

  if ((n = fread(buf, filelen, 1, fp)) != 1)
  {
    return -1;
  }

  fclose(fp);
  return 0;
}