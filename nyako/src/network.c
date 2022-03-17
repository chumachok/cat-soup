#include "network.h"

static void log_request_error(CURLcode res, char *errbuf)
{
  size_t len;

  len = strlen(errbuf);
  fprintf(stderr, "ERROR: (%d) ", res);
  if (len)
  {
    fprintf(stderr, "%s%s", errbuf, ((errbuf[len - 1] != '\n') ? "\n" : ""));
  }
  else
  {
    fprintf(stderr, "%s\n", curl_easy_strerror(res));
  }
}

static size_t no_write(void *buffer, size_t size, size_t nmemb, void *userp)
{
  return size * nmemb;
}

int send_request(const unsigned char *payload, const unsigned char *ip)
{
  CURL *curl;
  CURLcode res;
  struct curl_slist *headers = NULL;
  char errbuf[CURL_ERROR_SIZE];
  char data[DATA_BUF_SIZE];

  curl = curl_easy_init();

  if (curl == NULL)
  {
    log_error("curl_easy_init");
    return -1;
  }

  // set debugging options
  if (DEBUG_ENABLED)
  {
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  }

  curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, no_write);

  if (snprintf(data, sizeof(data), "%s%s", PAYLOAD_HEADER, payload) < 0)
  {
    log_error("snprintf");
    return -1;
  }

  curl_easy_setopt(curl, CURLOPT_URL, ip);
  curl_easy_setopt(curl, CURLOPT_PORT, CLIENT_PORT);

  headers = curl_slist_append(headers, data);
  curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

  res = curl_easy_perform(curl);

  if (res != CURLE_OK)
  {
    log_request_error(res, errbuf);
    return -1;
  }

  curl_slist_free_all(headers);
  curl_easy_cleanup(curl);

  return 0;
}