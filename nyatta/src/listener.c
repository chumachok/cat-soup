#include "listener.h"

void setup_network_listener(int num_packets, char *filter, pcap_handler callback, unsigned char *params)
{
  pcap_if_t *devs, *current_dev;
  char pcap_errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* sniff_session;
  struct bpf_program fp;

  if (pcap_findalldevs(&devs, pcap_errbuf) == PCAP_ERROR || devs == NULL)
  {
    log_pcap_error("pcap_findalldevs", pcap_errbuf);
    return;
  }

  current_dev = devs;

  if (LOCAL)
  {
    for (; current_dev != NULL; current_dev = current_dev->next)
    {
      if (current_dev->flags & PCAP_IF_LOOPBACK)
      {
        break;
      }
    }
  }
  else
  {
    for (; current_dev != NULL; current_dev = current_dev->next)
    {
      if (strcmp(current_dev->name, DEV) == 0)
      {
        break;
      }
    }
  }

  sniff_session = pcap_open_live(current_dev->name, BUFSIZ, 0, -1, pcap_errbuf);
  if (sniff_session == NULL)
  {
    log_pcap_error("pcap_open_live", pcap_errbuf);
    return;
  }

  pcap_freealldevs(devs);

  if (pcap_compile(sniff_session, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1)
  {
    log_pcap_error("pcap_compile", pcap_errbuf);
    return;
  }

  if (pcap_setfilter(sniff_session, &fp) == -1)
  {
    log_pcap_error("pcap_setfilter", pcap_errbuf);
    return;
  }

  pcap_loop(sniff_session, num_packets, callback, params);
}