/**
 * @author: Ben Mixon-Baca
 * @email: bmixonb1@cs.unm.edu
 */

#include "scanner.h"
#include "dtable.h"
#include "packet.h"
#include "blacklist.h"

#include <assert.h>
#include <pcap.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#define PCAP_FILE_NAME "/vagrant/2016-11-20 5:36:27.pcap"
//#define PCAP_FILE_NAME "capnext.pcap"
#define TS_SPOOF_IP "64.106.82.6" /* IP address tonysoprano 
				     uses to spoof ip addresses. */

#define BLACKLIST_FILE "/vagrant/blacklist.conf"
#define QR_DICT_SIZEp 1024
static char filename[1024];

int test_parse_pcap()
{
  phase_stats_t phase_stats = {
    .total_probes = 0,
    .total_unique_probes = 0,
    .total_responses = 0,
    .total_unique_responses = 0,
    .total_responses_with_retransmissions = 0
  };
  
  dict_t *q_r = new_dict_size(QR_DICT_SIZEp);
  const unsigned char *packet;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct pcap_pkthdr header;
  pcap_t *pcap = pcap_open_offline(filename, errbuf);
  assert( pcap );
  
  printf("%s %d\n", __func__, __LINE__);

  while ( (packet = pcap_next(pcap, &header)) != NULL ) {
    process_packet(&q_r, packet, &phase_stats,
		   header.ts, header.caplen);
  }

  dict_destroy_fn(q_r, (free_fn)free);
  free((void*)pcap);
  free((void*)packet);

  printf("%s %d: According to valgrind, there are "
	 "there are two missing free's here\n", __func__, __LINE__);

  return 0;
}

void print_qr_dict(dict_t *d)
{
  int size = d->size;
  list_t *element_list = NULL;
  int avgsize = 0;
  char *str = malloc(MTU * sizeof(char));
  int nzeros = 0;
  int nones = 0;
  int ngolt = 0;
  int ngtlh = 0;
  int nghlt = 0;
  int other = 0;
  for (int i = 0; i < size; i++) {
    element_list = d->elements[i];
    list_node_t *node = element_list->list;
    while ( node ) {
      list_node_t *tmp = node->next;
      struct hash_args *harg = node->value;
      list_t *l = (list_t*)harg->value;
      avgsize += l->size;
      if ( l->size == 0 ) {
	nzeros += 1;
      }
      if (l->size == 1) {
	nones += 1;
      }
      if (l->size > 1 && l->size <= 10) {
	ngolt += 1;
      }
      
      if (l->size > 10 && l->size <= 100) {
	ngtlh += 1;
      }
      
      if (l->size > 100 && l->size <= 100) {
	nghlt += 1;
      }
      else if (l->size > 1000){
	printf("\tsize!!! %d\n", l->size);
	other += 1;
      }

      list_node_t *pkt_node = l->list;
      while ( pkt_node ) {
	list_node_t *pkt_tmp = pkt_node->next;
	stringify_node(&str, pkt_node->value, 0);
	printf("%s %d %s\n", __func__, __LINE__, str);
	pkt_node = pkt_tmp;
      }
      node = tmp;
    } 
  }
  free(str);
  printf("dict size:                                        %d\n", 
	 d->size);
  printf("dict elements:                                    %d\n", 
	 d->N);
  printf("avg size:                                         %f\n", 
	 ((float)avgsize / ((float) d->N)));
  printf("number zeros:                                     %d\n",
	 nzeros); 
  printf("number ones:                                      %d\n",
	 nones);
  printf("number greater than 1 less than 10:               %d\n",
	 ngolt);
  printf("number greater than 10 less than 100:             %d\n",
	 ngtlh);
  printf("number greater than 100 less than 1000:           %d\n",
	 nghlt);
  printf("Major problems!!!!!:                              %d\n",
	 other);
}

int test_split_qr()
{
  phase_stats_t phase_stats = {
    .total_probes = 0,
    .total_unique_probes = 0,
    .total_responses = 0,
    .total_unique_responses = 0,
    .total_responses_with_retransmissions = 0
  };

  printf("%s %d: Test Starting\n",__func__, __LINE__);
  double time;
  START_TIMER(time);
  dict_t *qr = split_query_response(filename, &phase_stats);
  STOP_TIMER(time);
  printf("%s %d %f: Test Ending\n",__func__, __LINE__, time);
  //print_qr_dict(qr);
  dict_destroy_fn(qr, (free_fn)free_list);
  
  print_phase_statistics(&phase_stats);

  return 0;
}


int test_response_reply()
{
  phase_stats_t phase_stats = {
    .total_probes = 0,
    .total_unique_probes = 0,
    .total_responses = 0,
    .total_unique_responses = 0,
    .total_responses_with_retransmissions = 0
  };

  dict_t *qr = split_query_response(filename, &phase_stats);

  double time;
  START_TIMER(time);
  response_replay(&qr, &phase_stats);
  STOP_TIMER(time);
  printf("%s %d running time %f: Test Ending\n",
	 __func__, __LINE__, time);

  //print_qr_dict(qr);
  dict_destroy_fn(qr, (free_fn)free_list);
  print_phase_statistics(&phase_stats);
  return 0;
}


int test_copy_query_response_to_scanner()
{
  phase_stats_t phase_stats = {
    .total_probes = 0,
    .total_unique_probes = 0,
    .total_responses = 0,
    .total_unique_responses = 0,
    .total_responses_with_retransmissions = 0
  };

  dict_t *qr = split_query_response(filename, &phase_stats);

  double time;
  START_TIMER(time);
  response_replay(&qr, &phase_stats);
  STOP_TIMER(time);
  printf("%s %d running time %f: Test Ending\n",
	 __func__, __LINE__, time);

  //print_qr_dict(qr);
  copy_query_response_to_scanner(qr, &phase_stats);
  dict_destroy_fn(qr, (free_fn)free_list);
  print_phase_statistics(&phase_stats);
  return 0;
}


void split_addr(char *s)
{
  return;
}

int main(int argc, char *argv[])
{
  if (argc == 1) {
    memcpy(filename, PCAP_FILE_NAME, strlen(PCAP_FILE_NAME));
  }
  else {
    memcpy(filename, argv[1], strlen(argv[1]));
    printf("%s %s\n", argv[1], filename);
  }
  new_scanner_singleton();
  init_blacklist(BLACKLIST_FILE);

  //int nallowed = blacklist_count_not_allowed();
  //printf("not allowed %d\n", nallowed);
  // assert( (test_parse_pcap() == 0) );
  // assert( (test_split_qr() == 0) );

  //assert( (test_response_reply() == 0) );
  assert( (test_copy_query_response_to_scanner()) == 0);

  return 0;
}
