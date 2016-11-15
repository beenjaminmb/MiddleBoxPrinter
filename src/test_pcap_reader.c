#include <assert.h>
#include "sniffer.h"
#include "dtable.h"
#include <pcap.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#define PCAP_FILE_NAME "test-launch.pcap"

int test_parse_pcap()
{
  pcap_t *pcap;
  const unsigned char *packet;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct pcap_pkthdr header;

  dict_t *q_r = new_dict_size(QR_DICT_SIZE);

  pcap = pcap_open_offline(PCAP_FILE_NAME, errbuf);
  assert( pcap );
  
  while ( (packet = pcap_next(pcap, &header)) != NULL ) {
    process_packet(&q_r, packet, header.ts, header.capture_len);
  }
  return 0;
}

int test_split_query_response()
{
  dict_t *dict = split_query_response();
  return 0;
}

int main(void)
{
  assert( (test_parse_pcap() == 0));
  
  return 0;
}
