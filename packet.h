/**
 * @author: Ben Mixon-Baca
 * @email: bmixonb1@cs.unm.edu
 *  
 * packet header code and checksum from:
 * http://www.tenouk.com/Module43a.html
 */
#ifndef _PACKET_
#define _PACKET_

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "worker.h"
#include "util.h"


#define PERFORMANCE_DEBUG 1


#define PACKET_LEN 2048
#define START_TTL 2
#if PERFORMANCE_DEBUG == 1
  #define END_TTL 3
#else
  #define END_TTL 128
#endif
#define TTL_MODULATION_COUNT 3
#define TEST_IP "192.168.0.1"
#define SRC_IP "192.168.0.3"
#define TEST_DATA_LEN 0

#ifdef DEBUG
static const char *test_ips[] =
  { "192.168.0.1",
      "192.168.0.2",
      "192.168.0.4",
      "192.168.0.5",
      "192.168.0.6",
      "192.168.0.7",
      "192.168.0.8",
      "192.168.0.9",
      "192.168.0.10",
      "192.168.0.11"};
#endif 

typedef struct iphdr iphdr;
typedef struct udphdr udphdr;
typedef struct tcphdr tcphdr;
typedef struct icmphdr icmphdr;

typedef struct pseudo_header
{
  u_int32_t source_address;
  u_int32_t dest_address;
  u_int8_t placeholder;
  u_int8_t protocol;
  u_int16_t total_length;
} pseudo_header;

/* Simple checksum function, may use others such as Cyclic Redundancy 
   Check, CRC */
static inline unsigned short csum(unsigned short *ptr, int nbytes)
  __attribute__((always_inline));

static inline int make_packet(unsigned char *restrict packet_buffer,
			      scanner_worker_t *restrict worker,
			      int packet_idx)
  __attribute__((always_inline));

static inline tcphdr *make_tcpheader(unsigned char *restrict buffer, 
				     scanner_worker_t *restrict worker,
				     int probe_idx) 
  __attribute__((always_inline));

static inline void 
generate_random_destination_ip(char *restrict dst_ip, 
			       scanner_worker_t *restrict worker)
  __attribute__((always_inline));


static inline icmphdr *make_icmpheader(unsigned char *restrict buffer, 
				       scanner_worker_t 
				       *restrict worker, 
				       int datalen)
  __attribute__((always_inline));


static inline udphdr *make_udpheader(unsigned char *buffer, 
				     int datalen)
  __attribute__((always_inline));


static inline iphdr *make_ipheader(unsigned char *restrict buffer, 
				   struct sockaddr_in *restrict sin, 
				   int datalen)
  __attribute__((always_inline));


static inline unsigned short csum(unsigned short *ptr, int nbytes)
{
  register long sum = 0;
  unsigned short oddbyte;
  register short answer = 0; 
  while(nbytes>1) {
    sum+=*ptr++;
    nbytes-=2;
  }
  if(nbytes==1) {
    oddbyte=0;
    *((u_char*)&oddbyte)=*(u_char*)ptr;
    sum+=oddbyte;
  }
  sum = (sum>>16)+(sum & 0xffff);
  sum = sum + (sum>>16);
  answer=(short)~sum;
  return(answer);
}

/**
 * Generates a random IP address. This will be changed later so that
 * Workers only generate IP's in some given range,e.g. 2^32/MAX_WORKERS
 *
 * Worker 1           = [0, 2^32/MAX_WORKERS]
 * Worker 2           = [2^32/MAX_WORKERS, ]
 *    .
 *    .
 *    .
 * Worker MAX_WORKERS = [2^32/MAX_WORKERS, ]
 *
 */
static inline void 
generate_random_destination_ip(char *restrict dst_ip, 
			       scanner_worker_t *restrict worker)
{
  int r1, r2, r3, r4;
  sprintf(dst_ip, "%d.%d.%d.%d", 
	  (unsigned int)range_random(255, worker->random_data, &r1), 
	  (unsigned int)range_random(255, worker->random_data, &r2), 
	  (unsigned int)range_random(255, worker->random_data, &r3),
	  (unsigned int)range_random(255, worker->random_data, &r4));
  return ;
}

static inline icmphdr *make_icmpheader(unsigned char *restrict buffer, 
				       scanner_worker_t 
				       *restrict worker, 
				       int datalen)
{
  icmphdr *icmph = (icmphdr *)(buffer + + sizeof(struct ip));
  icmph->type = ICMP_ECHOREPLY; // make random later.
  icmph->code = 0;
  icmph->un.echo.id = 0;
  icmph->un.echo.sequence = 0;
  icmph->checksum = 0;
  return icmph;
}

static inline udphdr *make_udpheader(unsigned char *buffer, 
				     int datalen)
{
  udphdr *udph = (udphdr *)(buffer + sizeof(struct ip));
  udph->source = htons (6666);
  udph->dest = htons (8622);
  udph->len = htons(8 + datalen);
  udph->check = 0;
  return udph;
}

static inline tcphdr *make_tcpheader(unsigned char *restrict buffer, 
				     scanner_worker_t *restrict worker,
				     int probe_idx)
{
  int result;
  struct tcphdr *tcph = (tcphdr *)(buffer + sizeof(struct ip));
  tcph->source = htons(1234);

  tcph->dest = htons(80);
  worker->probe_list[probe_idx].sin->sin_port = htons(80);

  tcph->seq = range_random(RAND_MAX, worker->random_data, &result);
  tcph->ack_seq = range_random(RAND_MAX, worker->random_data,
			       &result);
  tcph->doff = 5;
  /*
     #define TH_FIN 0x01
     #define TH_SYN 0x02
     #define TH_RST 0x04
     #define TH_PUSH        0x08
     #define TH_ACK 0x10
     #define TH_URG 0x20
   */
  tcph->fin=0;
  tcph->syn=1;
  tcph->rst=0;
  tcph->psh=0;
  tcph->ack=0;

  tcph->window = htons(5840);
  tcph->urg_ptr = 0;
  tcph->urg=0;
  tcph->check = 0;
  tcph->res1 = 0;
  tcph->res2 = 0;

  if (range_random(100, worker->random_data, &result) < 10) {
    tcph->urg=1;
    tcph->th_urp = 1;
    tcph->urg_ptr = range_random(65535, worker->random_data,
				 &result);
    tcph->th_urp = tcph->urg_ptr;
  }
  if (range_random(100, worker->random_data, &result) < 50) {
    tcph->res1 = range_random(16, worker->random_data, &result);
    tcph->res2 = range_random(16, worker->random_data, &result);
  }
  return tcph;
}

static inline iphdr *make_ipheader(unsigned char *restrict buffer, 
				   struct sockaddr_in *restrict sin, 
				   int datalen)
{
  iphdr *iph = (iphdr *)buffer;
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->id = htonl(1);
  iph->frag_off = 0;
  iph->ttl = START_TTL;
  iph->check = 0;
  iph->saddr = inet_addr( SRC_IP );
  iph->daddr = sin->sin_addr.s_addr;
  return iph;
}

/*
While (1)
    Create a random IPv4 packet
    For length, checksum, etc. make it correct 90% of the time,
    incorrect in a random way 10%

    For protocol, TCP 50% of the time, UDP 25%, random 25%
    Dest address random, source address our own (not bound to an
    interface)

    10% of the time have a randomly generated options field
    
    if (TCP) fill in TCP header as below
    
    if (UDP or other) fill in rest of IP packet with random junk
       Send it in a TTL-limited fashion

    for TCP packets:
    50% chance of random dest port, 50% chance of common (22, 80, 
    etc.)
  
    seq and ack numbers random
    Flags random but biased towards usually only 1 or 2 bits set
    with 10% chance add randomly generated options
    Reserved 0 50% of the time and random 50% of the time
    Window random
    Checksum correct 90% of the time, random 10%
    Urgent pointer not there 90% of the time, random 10% of the time

Then we just send out this kind of traffic at 1 Gbps or so and take a
pcap of all outgoing and incoming packets for that source IP, and 
store that on the NFS mount for later analysis
*/
static inline int make_packet(unsigned char *restrict packet_buffer, 
			      scanner_worker_t *restrict worker,
			      int packet_idx)
{
  int datalen = 0;
  char *src_ip = SRC_IP;
  int result = 0;
  long prand = range_random(100, worker->random_data, &result);
  pseudo_header *psh = malloc(sizeof(pseudo_header));
  char *pseudogram = NULL, source_ip[32], dst_ip[32];
  generate_random_destination_ip((char*)dst_ip, worker);
  strcpy(source_ip, src_ip); // This can be optimized at some point.
  memset(packet_buffer, 0, MTU);
  worker->probe_list[packet_idx].sin->sin_addr.s_addr = 
    inet_addr(dst_ip);
  worker->probe_list[packet_idx].sin->sin_family = AF_INET;
  iphdr *ip = make_ipheader(packet_buffer, 
			    worker->probe_list[packet_idx].sin, 
			    datalen);

  psh->source_address = inet_addr(source_ip);
  psh->dest_address = 
    worker->probe_list[packet_idx].sin->sin_addr.s_addr;
  psh->placeholder = 0;
  if ( DO_TCP(prand) ) { /* Make a TCP packet */
    ip->tot_len = sizeof(iphdr) + sizeof(tcphdr) + datalen;
    ip->protocol = IPPROTO_TCP;
    tcphdr *tcph = make_tcpheader(packet_buffer, worker, packet_idx);
    psh->protocol = IPPROTO_TCP;
    psh->total_length = htons(sizeof(tcphdr) + datalen);
    int psize = sizeof(pseudo_header) + sizeof(tcphdr) + datalen;
    pseudogram = malloc(psize);
    memcpy(pseudogram, (char*)psh, sizeof(pseudo_header));
    memcpy(pseudogram + sizeof(pseudo_header), tcph,
	   sizeof(tcphdr) + datalen);
    tcph->check = csum((unsigned short*)pseudogram, psize);
    goto DONE;
  }
  else if ( DO_UDP(prand) ) { /* Make a UDP */
    ip->tot_len = sizeof(iphdr) + sizeof(udphdr) + datalen;
    udphdr *udph = make_udpheader(packet_buffer, 0);
    ip->protocol = IPPROTO_UDP;
    psh->protocol = IPPROTO_UDP;
    psh->total_length = htons(sizeof(udphdr) + datalen);
    int psize = sizeof(pseudo_header) + sizeof(udphdr) + datalen;
    pseudogram = malloc(psize);
    memcpy(pseudogram, (char*)psh, sizeof(pseudo_header));
    memcpy(pseudogram + sizeof(pseudo_header), udph,
	   sizeof(udphdr) + datalen);
    udph->check = csum((unsigned short*) pseudogram, psize);
    goto DONE;
  }
  else if ( DO_ICMP(prand) ) { /* Make ICMP packet */
    ip->tot_len = sizeof(iphdr) + sizeof(icmphdr) + datalen;
    icmphdr *icmph = make_icmpheader(packet_buffer, worker, 0);
    ip->protocol = IPPROTO_ICMP;
    icmph->checksum = csum((unsigned short*) icmph, sizeof(icmphdr));
    goto RETURN;
  }
  else {/* random junk */
  
  }
 DONE:
  free(pseudogram);
  pseudogram = NULL;
 RETURN:
  free(psh);
  psh = NULL;
  return 0;
}
#endif /* _PACKET_ */
