#include "utils.h"

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