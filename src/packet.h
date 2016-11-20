/**
 * @author: Ben Mixon-Baca
 * @email: bmixonb1@cs.unm.edu
 *  
 * pseudo packet header code and checksum from:
 * http://www.tenouk.com/Module43a.html
 */
#ifndef _PACKET_
#define _PACKET_
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "worker.h"
#include "util.h"
#include "blacklist.h"

//#define PERFORMANCE_DEBUG 1

#define PACKET_LEN 2048
#define START_TTL 64

#if PERFORMANCE_DEBUG == 1
  #define END_TTL 64
  #define START_TIMER(seconds) (seconds = -wall_time())
  #define STOP_TIMER(seconds) (seconds += wall_time())
#else
  #define END_TTL 64
  /* #define START_TIMER(seconds) (seconds = -1) */
  /* #define STOP_TIMER(seconds) (seconds = -1) */
  #define START_TIMER(seconds) (seconds = -wall_time())
  #define STOP_TIMER(seconds) (seconds += wall_time())
#endif
#define TTL_MODULATION_COUNT 3

#ifdef DILLINGER
 #define SRC_IP "64.106.82.6" //Spoofed but on same subnet as tonys.
 #define REAL_SRC_IP "64.106.82.5" 
#else
 #define SRC_IP "64.106.82.6" //Spoofed but on same subnet as tonys.
 #define REAL_SRC_IP "64.106.82.5" 

 /* #define SRC_IP "192.168.0.18"//vboxnet0 interface 64.106.82.5 my comp. */
 /* #define REAL_SRC_IP "192.168.0.5"  */
#endif

typedef struct iphdr iphdr;
typedef struct udphdr udphdr;
typedef struct tcphdr tcphdr;
typedef struct icmphdr icmphdr;


typedef struct packet_value {
  unsigned char *packet;
  int capture_len;
} packet_value_t;


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

static inline unsigned short random_sport(scanner_worker_t *restrict 
					  worker)
  __attribute__((always_inline));

static inline unsigned short random_dport(scanner_worker_t *restrict 
					  worker)
  __attribute__((always_inline));

static inline int make_packet(unsigned char *restrict packet_buffer,
			      scanner_worker_t *restrict worker,
			      int packet_idx)
  __attribute__((always_inline));

static inline int
make_phase1_packet(unsigned char *restrict packet_buffer,
		   scanner_worker_t *restrict worker,
		   int packet_idx)
  __attribute__((always_inline));

static inline tcphdr *make_tcpheader(unsigned char *restrict buffer,
				     scanner_worker_t *restrict worker,
				     int probe_idx)
  __attribute__((always_inline));

static inline void 
generate_destination_ip(char *restrict dst_ip, 
			scanner_worker_t *restrict worker)
  __attribute__((always_inline));

static inline icmphdr *make_icmpheader(unsigned char *restrict buffer, 
				       scanner_worker_t
				       *restrict worker,
				       int datalen)
  __attribute__((always_inline));

static inline udphdr *make_udpheader(unsigned char *buffer,
				     scanner_worker_t *restrict
				     worker,
				     int datalen)
  __attribute__((always_inline));

static inline unsigned char *make_junk_header(unsigned char *buffer,
					      scanner_worker_t
					      *restrict worker,
					      int datalen)
  __attribute__((always_inline));

static inline iphdr *make_ipheader(unsigned char *restrict buffer, 
				   struct sockaddr_in *restrict sin, 
				   int datalen)
  __attribute__((always_inline));


static inline iphdr *set_ip(unsigned char *restrict buffer, 
			    struct sockaddr_in *restrict sin,
			    short ihl, short version, short tos,
			    short id, short frag_off, short ttl,
			    short proto, short check, char *saddr, 
			    int datalen)

  __attribute__((always_inline));



static inline void set_layer_four(unsigned char *restrict packet, 
				  short proto, short sport, 
				  short dport)
  
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
 * Workers only generate IP's in some given range,e.g. 
 * 2^32/MAX_WORKERS
 *
 * Worker 1           = [0, 2^32/MAX_WORKERS]
 * Worker 2           = [2^32/MAX_WORKERS, ]
 *    .
 *    .
 *    .
 * Worker MAX_WORKERS = [2^32/MAX_WORKERS, ]
 */
static inline void 
generate_destination_ip(char *restrict dst_ip, 
			scanner_worker_t *restrict worker)
{
  unsigned int addr;
  while ( 1 ) {
    addr = (unsigned int)range_random(RAND_MAX,
				      worker->random_data,
				      (int *)&addr);

    if ( blacklist_is_allowed( addr ) ) {
      break;
    }
  }

  unsigned char r1 = (unsigned char)(addr & 0x000000ff);
  unsigned char r2 = (unsigned char)((addr >> 8) & 0x000000ff);
  unsigned char r3 = (unsigned char)((addr >> 16) & 0x000000ff);
  unsigned char r4 = (unsigned char)((addr >> 24) & 0x000000ff);

  sprintf(dst_ip, "%d.%d.%d.%d", r4, r3, r2, r1);
  return;
}

static inline unsigned char *make_junk_header(unsigned char *buffer, 
					      scanner_worker_t
					      *restrict worker,
					      int datalen)
{
  int result;
  unsigned char *junk_header = (buffer + sizeof(struct ip));
  for (int i = 0; i < (datalen - sizeof(struct ip)) /sizeof(long); i++) {
    junk_header[i] = range_random(RAND_MAX, worker->random_data,
				  &result);
  }
  return junk_header;
}
static inline icmphdr *make_icmpheader(unsigned char *restrict buffer,
				       scanner_worker_t 
				       *restrict worker, 
				       int datalen)
{
  icmphdr *icmph = (icmphdr *)(buffer + sizeof(struct ip));
  icmph->type = ICMP_ECHOREPLY; // make random later.
  icmph->code = 0;
  icmph->un.echo.id = 0;
  icmph->un.echo.sequence = 0;
  icmph->checksum = 0;
  return icmph;
}


static inline unsigned short random_sport(scanner_worker_t *restrict 
					  worker) {
  int result;
  unsigned short sport = (unsigned short) 
    range_random( (0xffff), worker->random_data, &result);
  return sport;
}


static inline unsigned short random_dport(scanner_worker_t *restrict 
					  worker) {
  int result;
  unsigned short sport;
  if ( range_random( 100, worker->random_data, &result) < 50) {
    sport = (unsigned short) 
      range_random( (0xffff), worker->random_data, &result);
  }
  else {
    int i = range_random( 100, worker->random_data, &result);
    if ( i < 25) {
      sport = 80;
    }
    if ( i < 50) {
      sport = 443;
    }
    else if (i < 75) {
      sport = 22;
    }
    else if (i < 85) {
      sport = 23;
    }
    else if (i < 90) {
      sport = 53;
    }
  }
  return sport;
}

static inline udphdr *make_udpheader(unsigned char *buffer,
				     scanner_worker_t *restrict 
				     worker,
				     int datalen)
{
  udphdr *udph = (udphdr *)(buffer + sizeof(struct ip));
  unsigned short source = 0;
  unsigned short dest = 0;
  while ( (source = random_sport (worker) ) == 0 );
  while ( (dest = random_dport (worker) ) == 0 );

  udph->source = htons (source);
  udph->dest = htons (dest);
  udph->len = htons (8 + datalen);
  udph->check = 0;
  return udph;
}

static inline tcphdr *make_tcpheader(unsigned char *restrict buffer, 
				     scanner_worker_t *restrict
				     worker,
				     int probe_idx)
{
  int result;
  struct tcphdr *tcph = (tcphdr *)(buffer + sizeof(struct ip));
  unsigned short source = 0;
  unsigned short dest = 0;
  while ( (source = random_sport(worker)) == 0 );
  while ( (dest = random_dport(worker)) == 0 );

  tcph->source = htons(source);
  tcph->dest = htons(dest);

  worker->probe_list[probe_idx].sin->sin_port = htons(dest);

  tcph->seq = htonl(range_random(RAND_MAX, worker->random_data, &result));
  tcph->ack_seq = htonl(range_random(RAND_MAX, worker->random_data,
				     &result));
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


static inline void set_layer_four(unsigned char *restrict packet, 
				  short proto, short sport, 
				  short dport)
{
  struct ip* ip = (struct ip*)packet;
  int IP_header_len = ip->ip_hl * 4;
  struct tcphdr *tcp = NULL;
  struct udphdr *udp = NULL;

  switch ( proto ) {
  case IPPROTO_TCP:
    tcp = (struct tcphdr*)(packet + IP_header_len);
    tcp->th_sport = htons(sport);
    tcp->th_dport = htons(dport);
    break;
  case IPPROTO_UDP:
    udp = (struct udphdr*)(packet + IP_header_len);
    udp->uh_sport = htons(sport);
    udp->uh_dport = htons(dport);
    break;
  case IPPROTO_ICMP:
    break;
  default: //Don't change anything.
    
    break; 
  }
  return ;
}


static inline iphdr 
*make_ipheader(unsigned char *restrict buffer, 
	       struct sockaddr_in *restrict sin, 
	       int datalen)
{
  return set_ip(buffer, sin, 5, 4, 0, 1, 0, START_TTL, 0, 0, 
		SRC_IP, datalen);
}

static inline iphdr *set_ip(unsigned char *restrict buffer, 
			    struct sockaddr_in *restrict sin,
			    short ihl, short version, short tos,
			    short id, short frag_off, short ttl,
			    short p, short check, char *saddr,
			    int datalen)
{
  iphdr *iph = (iphdr *)buffer;
  iph->ihl = ihl;
  iph->version = version;
  iph->tos = tos;
  iph->id = htonl(id);
  iph->frag_off = frag_off;
  iph->ttl = ttl;
  iph->check = check;
  iph->protocol = p;
  iph->saddr = inet_addr( saddr );
  iph->daddr = sin->sin_addr.s_addr;
  iph->check = check;
  iph->tot_len = htons(datalen);
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
  int result;
  int data_len = range_random(MTU - 256, worker->random_data, &result);
  char *src_ip = SRC_IP;
  long prand = range_random(100, worker->random_data, &result);
  pseudo_header *psh = smalloc(sizeof(pseudo_header));
  char *pseudogram = NULL, source_ip[32], dst_ip[32];
  generate_destination_ip((char*)dst_ip, worker);
  strcpy(source_ip, src_ip); // This can be optimized at some point.
  memset(packet_buffer, 0, MTU);
  worker->probe_list[packet_idx].sin->sin_addr.s_addr = 
    inet_addr(dst_ip);
  worker->probe_list[packet_idx].sin->sin_family = AF_INET;
  iphdr *ip = make_ipheader(packet_buffer, 
			    worker->probe_list[packet_idx].sin, 
			    data_len);
  
  if (range_random(100, worker->random_data, &result) < 90) {
    worker->probe_list[packet_idx].good_csum = TRUE;
  }
  else {
    worker->probe_list[packet_idx].good_csum = FALSE;
    data_len = (data_len + 
		range_random(MTU - 256, worker->random_data, &result))
      % MTU;
  }
  worker->probe_list[packet_idx].data_len = data_len;
  psh->source_address = inet_addr(source_ip);
  psh->dest_address = 
    worker->probe_list[packet_idx].sin->sin_addr.s_addr;
  psh->placeholder = 0;
  if ( DO_TCP(prand) ) { /* Make a TCP packet */
    worker->probe_list[packet_idx].proto = IPPROTO_TCP; 
    ip->tot_len = htons(sizeof(iphdr) + sizeof(tcphdr) + data_len);
    ip->protocol = IPPROTO_TCP;
    tcphdr *tcph = make_tcpheader(packet_buffer, worker, packet_idx);
    psh->protocol = IPPROTO_TCP;
    psh->total_length = htons(sizeof(tcphdr) + data_len);
    int psize = sizeof(pseudo_header) + sizeof(tcphdr) + data_len;
    pseudogram = smalloc(psize);
    memcpy(pseudogram, (char*)psh, sizeof(pseudo_header));
    memcpy(pseudogram + sizeof(pseudo_header), tcph,
	   sizeof(tcphdr) + data_len);
    tcph->check = csum((unsigned short*)pseudogram, psize);
    goto DONE;
  }
  else if ( DO_UDP(prand) ) { /* Make a UDP */
    ip->tot_len = sizeof(iphdr) + sizeof(udphdr) + data_len;
    ip->protocol = IPPROTO_UDP;
    worker->probe_list[packet_idx].proto = IPPROTO_UDP;
    udphdr *udph = make_udpheader(packet_buffer, worker, data_len);
    psh->protocol = IPPROTO_UDP;
    psh->total_length = htons(sizeof(udphdr) + data_len);
    int psize = sizeof(pseudo_header) + sizeof(udphdr) + data_len;
    pseudogram = smalloc(psize);
    memcpy(pseudogram, (char*)psh, sizeof(pseudo_header));
    memcpy(pseudogram + sizeof(pseudo_header), udph,
	   sizeof(udphdr) + data_len);
    udph->check = htons(csum((unsigned short*) pseudogram, psize));
    goto DONE;
  }
  else if ( DO_ICMP(prand) ) { /* Make ICMP packet */
    ip->tot_len = sizeof (iphdr) + sizeof (icmphdr) + data_len;
    ip->protocol = IPPROTO_ICMP;
    worker->probe_list[packet_idx].proto = IPPROTO_ICMP;
    icmphdr *icmph = make_icmpheader (packet_buffer, worker, 0);
    icmph->checksum = htons (csum((unsigned short*) icmph, sizeof(icmphdr)));
    goto RETURN;
  }
  else {/* random junk */
    worker->probe_list[packet_idx].proto = 0xff;
    make_junk_header (packet_buffer, worker, data_len);
  } 
 DONE:
  free(pseudogram);
  pseudogram = NULL;
 RETURN:
  free(psh);
  psh = NULL;
  return 0;
}


static inline int 
make_phase1_packet(unsigned char *restrict packet_buffer,
		   scanner_worker_t *restrict worker,
		   int packet_idx)
{
  int result;
  int data_len = range_random(MTU - 256, worker->random_data, &result);
  char *src_ip = SRC_IP;
  long prand = range_random(100, worker->random_data, &result);
  pseudo_header *psh = smalloc(sizeof(pseudo_header));
  char *pseudogram = NULL, source_ip[32], dst_ip[32];
  generate_destination_ip((char*)dst_ip, worker);
  strcpy(source_ip, src_ip); // This can be optimized at some point.
  memset(packet_buffer, 0, MTU);
  worker->probe_list[packet_idx].sin->sin_addr.s_addr = 
    inet_addr(dst_ip);
  worker->probe_list[packet_idx].sin->sin_family = AF_INET;
  iphdr *ip = make_ipheader(packet_buffer,
			    worker->probe_list[packet_idx].sin, 
			    data_len);
  
  if (range_random(100, worker->random_data, &result) < 90) {
    worker->probe_list[packet_idx].good_csum = TRUE;
  }
  else {
    worker->probe_list[packet_idx].good_csum = FALSE;
    data_len = (data_len + 
		range_random(MTU - 256, worker->random_data, &result))
      % MTU;
  }
  worker->probe_list[packet_idx].data_len = data_len;
  psh->source_address = inet_addr(source_ip);
  psh->dest_address = 
    worker->probe_list[packet_idx].sin->sin_addr.s_addr;
  psh->placeholder = 0;
  if ( DO_TCP(prand) ) { /* Make a TCP packet */
    worker->probe_list[packet_idx].proto = IPPROTO_TCP; 
    ip->tot_len = sizeof(iphdr) + sizeof(tcphdr) + data_len;
    ip->protocol = IPPROTO_TCP;
    tcphdr *tcph = make_tcpheader(packet_buffer, worker, packet_idx);
    psh->protocol = IPPROTO_TCP;
    psh->total_length = htons(sizeof(tcphdr) + data_len);
    int psize = sizeof(pseudo_header) + sizeof(tcphdr) + data_len;
    pseudogram = smalloc(psize);
    memcpy(pseudogram, (char*)psh, sizeof(pseudo_header));
    memcpy(pseudogram + sizeof(pseudo_header), tcph,
	   sizeof(tcphdr) + data_len);
    tcph->check = csum((unsigned short*)pseudogram, psize);
    goto DONE;
  }
  else if ( DO_UDP(prand) ) { /* Make a UDP */
    ip->tot_len = sizeof(iphdr) + sizeof(udphdr) + data_len;
    ip->protocol = IPPROTO_UDP;
    worker->probe_list[packet_idx].proto = IPPROTO_UDP;
    udphdr *udph = make_udpheader(packet_buffer, worker, data_len);
    psh->protocol = IPPROTO_UDP;
    psh->total_length = htons(sizeof(udphdr) + data_len);
    int psize = sizeof(pseudo_header) + sizeof(udphdr) + data_len;
    pseudogram = smalloc(psize);
    memcpy(pseudogram, (char*)psh, sizeof(pseudo_header));
    memcpy(pseudogram + sizeof(pseudo_header), udph,
	   sizeof(udphdr) + data_len);
    udph->check = csum((unsigned short*) pseudogram, psize);
    goto DONE;
  }
  else if ( DO_ICMP(prand) ) { /* Make ICMP packet */
    ip->tot_len = sizeof(iphdr) + sizeof(icmphdr) + data_len;
    ip->protocol = IPPROTO_ICMP;
    worker->probe_list[packet_idx].proto = IPPROTO_ICMP;
    icmphdr *icmph = make_icmpheader(packet_buffer, worker, 0);
    icmph->checksum = csum((unsigned short*) icmph, sizeof(icmphdr));
    goto RETURN;
  }
  else {/* random junk */
    worker->probe_list[packet_idx].proto = 0xff;
    make_junk_header(packet_buffer, worker, data_len);
  } 
 DONE:
  free(pseudogram);
  pseudogram = NULL;
 RETURN:
  free(psh);
  psh = NULL;

  if ( worker->probe_list[packet_idx].good_csum ) {
    ip->check = csum((unsigned short *)packet_buffer,
		     ip->tot_len);
  }
  else {
    ip->check = range_random(65536, worker->random_data,
			     &result);
  }

  return 0;
}

static void deepcopy_packet(scanner_worker_t *worker, /* The worker */
			    packet_value_t *response,
			    char *wsrc_addr, char* wdst_addr,
			    short wsport, short wdport,
			    int probe_idx /* The specific probe */)
{
  int len = response->capture_len;
  /**
   * Don't overwrite response->value. It is used by all other
   * packets to make custom copies.
   *  
   * Needs to change, src_addr == SRC_ADDR,
   *                  dst_addr == ADDR_ki == address k for worker i.
   *
   *                  sport == srcport. 
   *		      dport == dst_port of
   *
   * Packet length and checksum also needs to be recalculated.
   *
   */
  unsigned char *packet_to_copy = response->packet; 
  probe_t *prev_probe = &worker->probe_list[probe_idx];

  memcpy(&worker->probe_list[probe_idx].probe_buff,
	 (packet_to_copy+sizeof(struct ether_header)),
	 len);
  
  worker->probe_list[probe_idx].sin->sin_addr.s_addr = 
    inet_addr(wdst_addr);

  struct ip *ip = (struct ip*)
    &worker->probe_list[probe_idx].probe_buff;
  
  short ihl = ip->ip_hl;
  short version = ip->ip_v;
  short tos = ip->ip_tos;
  short id = ntohs(ip->ip_id);
  short frag_off = ip->ip_off;
  short ttl = ip->ip_ttl;
  short protocol = ip->ip_p;
  short tot_len = ntohs(ip->ip_len);
  short chk_sum = ip->ip_sum;
  
  set_ip((unsigned char *)worker->probe_list[probe_idx].probe_buff, 
	 worker->probe_list[probe_idx].sin,
	 ihl, version, tos, id, frag_off,
	 ttl, protocol, chk_sum, wsrc_addr, tot_len);

  set_layer_four
    ((unsigned char *)worker->probe_list[probe_idx].probe_buff,
     protocol, wsport, wdport);

  return ;
}

#endif /* _PACKET_ */
