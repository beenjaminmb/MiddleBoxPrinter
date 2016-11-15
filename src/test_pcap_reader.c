/**
 * @author: Ben Mixon-Baca
 * @email: bmixonb1@cs.unm.edu
 */

#include "scanner.h"
#include "dtable.h"

#include <assert.h>
#include <pcap.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#define PCAP_FILE_NAME "capnext.pcap"
#define TS_SPOOF_IP "64.106.82.6" /* IP address tonysoprano 
				     uses to spoof ip addresses. */
#define QR_DICT_SIZEp 2

int test_parse_pcap()
{

  dict_t *q_r = new_dict_size(QR_DICT_SIZEp);

  pcap = pcap_open_offline(PCAP_FILE_NAME, errbuf);
  assert( pcap );
  
  printf("%s %d\n", __func__, __LINE__);

  while ( (packet = pcap_next(pcap, &header)) != NULL ) {
    process_packet(&q_r, packet, header.ts, header.caplen);    
  }
  dict_destroy_fn(q_r, (free_fn)free);
  free((void*)pcap);
  free((void*)packet);

  printf("%s %d: According to valgrind, there are "
	 "there are two missing free's here\n", __func__, __LINE__);

  return 0;
}


int test_split_qr()
{
  dict_t *qr = splot_query_response(PCAP_FILE_NAME);
  dict_destroy_fn(qr, (free_fn)free);
}

int main(void)
{
  //assert( (test_parse_pcap() == 0) );
  assert( (test_split_qr() == 0) );

  return 0;
}
