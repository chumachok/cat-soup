#include "logger.h"

void log_error(const char *msg)
{
  fprintf(stderr, "ERROR: %s\n", msg);
}

void log_info(const char *msg)
{
  fprintf(stdout, "INFO: %s\n", msg);
}

void log_pcap_error(const char *msg, const char *errbuf)
{
  fprintf(stderr, "%s: %s\n", msg, errbuf);
}