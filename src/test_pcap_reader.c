/**
 * @author: Ben Mixon-Baca
 * @email: bmixonb1@cs.unm.edu
 */

#include "scanner.h"
#include "dtable.h"
#include "packet.h"
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

#define PCAP_FILE_NAME "capnext.pcap"
#define TS_SPOOF_IP "64.106.82.6" /* IP address tonysoprano 
				     uses to spoof ip addresses. */
#define QR_DICT_SIZEp 2

int test_parse_pcap()
{

  dict_t *q_r = new_dict_size(QR_DICT_SIZEp);
  const unsigned char *packet;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct pcap_pkthdr header;  
  pcap_t *pcap = pcap_open_offline(PCAP_FILE_NAME, errbuf);
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
    avgsize += element_list->size;
    if ( element_list->size == 0 ) {
      nzeros += 1;
    }
    if (element_list->size == 1) {
      nones += 1;
    }
    if (element_list->size > 1 && element_list->size <= 10) {
      ngolt += 1;
    }

    if (element_list->size > 10 && element_list->size <= 100) {
      ngtlh += 1;
    }

    if (element_list->size > 100 && element_list->size <= 100) {
      nghlt += 1;
    }
    else if (element_list->size > 1000){
      printf("\tsize!!! %d\n", element_list->size);
      other += 1;
    }
    while (  node ) {
      list_node_t *tmp = node->next;
      list_t *l = node->value;
      stringify_node(&str, l->list->value);
      printf("%s %d %s\n", __func__, __LINE__, str);
      node = tmp;
    }
  }
  free(str);
  printf("dict size:                                        %d\n", d->size);
  printf("dict elements:                                    %d\n", d->N);
  printf("avg size:                                         %f\n", ((float)avgsize / ((float) d->N)));
  printf("number zeros:                                     %d\n", nzeros); 
  printf("number ones:                                      %d\n", nones);
  printf("number greater than 1 less than 10:               %d\n", ngolt);
  printf("number greater than 10 less than 100:             %d\n", ngtlh);
  printf("number greater than 100 less than 1000:           %d\n", nghlt);
  printf("Major problems!!!!!:                              %d\n", other);
}

int test_split_qr()
{
  dict_t *qr = split_query_response(PCAP_FILE_NAME);
  printf("%s %d %p: Test Starting\n",__func__, __LINE__, qr);
  

  printf("%s %d %p: Test Ending\n",__func__, __LINE__, qr);  
  print_qr_dict(qr);
  dict_destroy_fn(qr, (free_fn)free_list);

  return 0;
}

int test_response_reply()
{
  printf("%s %d: Test starting\n", __func__, __LINE__);
  dict_t *qr = split_query_response(PCAP_FILE_NAME);
  printf("%s %d %p size = %d, N = %d\n", __func__, __LINE__, 
	 qr, qr->size, qr->N);

  response_replay(&qr);
  print_qr_dict(qr);

  printf("%s %d %p size = %d, N = %d\n", __func__, __LINE__, 
	 qr, qr->size, qr->N);
  
  dict_destroy_fn(qr, (free_fn)free_list);
  printf("%s %d: Test Ending\n",__func__, __LINE__);
  return 0;
}
int main(void)
{
  // assert( (test_parse_pcap() == 0) );
  // assert( (test_split_qr() == 0) );
  assert( (test_response_reply() == 0) );
  return 0;
}
