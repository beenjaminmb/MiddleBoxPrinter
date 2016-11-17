/**
 * @author: Ben Mixon-Baca
 * @email: bmixonb1@cs.unm.edu
 */

#include "scanner.h"
#include "dtable.h"

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

void stringify_node( char **str, void *vnode)
{
  char *s = *str;
  unsigned char *packet = (unsigned char*)vnode;
  unsigned char src_addr[32];
  unsigned char dst_addr[32];
  
  struct ether_header *eth = (struct ether_header*)packet;
  packet += sizeof(struct ether_header);
  struct ip *ip = (struct ip*)packet;

  char *addr = inet_ntoa(ip->ip_src);

  int len = strlen(addr);
  memset((void*)src_addr, 0, sizeof(src_addr));
  memcpy((void*)src_addr, (void*)addr, len);

  addr = inet_ntoa(ip->ip_dst);
  len = strlen(addr);
  memset((void*)dst_addr, 0, sizeof(dst_addr));
  memcpy((void*)dst_addr, (void*)addr, len);

  struct tcphdr *tcp;
  unsigned short sport = 0;
  unsigned short dport = 0;

  int IP_header_len = ip->ip_hl * 4;

  switch( ip->ip_p ) {
  case IPPROTO_TCP:
    tcp = (struct tcphdr*)(ip + IP_header_len);
    sport = tcp->th_sport;
    dport = tcp->th_dport;

    printf("TCP %s %d %s %s %d %d\n", __func__, __LINE__,
	   (char *)src_addr, (char *)dst_addr, sport, dport);
    break;
  case IPPROTO_UDP:
    printf("UDP %s %d %s %s\n", __func__, __LINE__,
	   (char *)src_addr, (char *)dst_addr);
    break;
  case IPPROTO_ICMP:
    printf("ICMP %s %d %s %s\n", __func__, __LINE__,
	   (char *)src_addr, (char *)dst_addr);
    break;
  default:
    printf("Other %s %d %s %s\n", __func__, __LINE__,
	   (char *)src_addr, (char *)dst_addr);
    break ;
  }

  sprintf((char*)s, "%s %s %d %d", (char*)src_addr,
	  (char*)dst_addr, sport, dport);
  return ;
}

void print_qr_dict(dict_t *d)
{
  int size = d->size;
  list_t *element_list = NULL;
  list_node_t *node = NULL;
  
  char *str = malloc(MTU * sizeof(char));
  for (int i = 0; i < size; i++) {
    element_list = d->elements[i];
    node = element_list->list;
    while ( element_list->size && node ) {
      list_node_t *tmp = node->next;
      
      list_t *l = node->value;

      stringify_node(&str, l->list->value);
      printf("%s %d %s\n", __func__, __LINE__, str);

      node = tmp;
    }
  }
}

unsigned long free_list(void *list)
{
  list_t *l = list;
  list_node_t *current = l->list;  
  while( current ) {
    list_node_t *tmp = current->next; 
    free(current->value);
    free(current);
    current = tmp;
  }
  free(list);
  return 0;
}

int test_split_qr()
{
  printf("%s %d: Test Starting\n",__func__, __LINE__);
  dict_t *qr = split_query_response(PCAP_FILE_NAME);

  print_qr_dict(qr);

  dict_destroy_fn(qr, (free_fn)free_list);
  printf("%s %d: Test Ending\n",__func__, __LINE__);
  return 0;
}

int main(void)
{
  //assert( (test_parse_pcap() == 0) );
  assert( (test_split_qr() == 0) );
  
  return 0;
}
