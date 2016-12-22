/**
 * @author: Ben Mixon-Baca
 * @email: bmixonb1@cs.unm.edu
 */
#include <stdlib.h>
#include <pthread.h>
#include <signal.h>
//#include <sys/socket.h>
//#include <sys/types.h>
#include <pcap.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <net/ethernet.h>
#include "scanner.h"
#include "sniffer.h"
#include "worker.h"
#include "packet.h"
#include "util.h"
#include "dtable.h"
#include "ssocket.h"
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>

#define PCAP_TEST_FILE "./capnext.pcap"

static struct scanner_t *scanner = NULL;
static scan_statistics_t scan_stats;
static dict_t *global_qr_dict = NULL;
static FILE *log_file = NULL;

static void inc_phase_counter(scanner_worker_t *worker, int phase);
static void worker_send_packet(scanner_worker_t *worker);



void dec_field(int *field)
{
  int f = *field;
  f++;
  *field = f;
  return;
}

void halve_field(int *field)
{
  int f = *field;
  f /= 2;
  *field = f;
  return;
}

void inc_field(int *field)
{
  int f = *field;
  f++;
  *field = f;
  return;
}

void double_field(int *field)
{
  int f = *field;
  f *= 2;
  *field = f;
  return;
}

int inc_sport(const void *packet)
{
  iphdr *ip = (iphdr*)packet;
  struct tcphdr *tcp = NULL;
  struct udphdr *udp = NULL;
  char *src_addr = smalloc(128);
  char *dst_addr = smalloc(128);
  int IP_header_len = ip->ihl * 4;
  short protocol = ip->protocol;
  char *stringy = smalloc(256);
  struct packet_value pv;
  pv.packet = packet;
  stringify_node((char**)&stringy, &pv, 0);
  unsigned short ssport = 0;
  unsigned short sdport = 0;
  split_stringify(stringy, &src_addr, &dst_addr, &ssport, &sdport);
  unsigned short tot_len = ip->tot_len;
  unsigned short data_len = 0;
  unsigned short check = 0;
  switch (protocol) {
  case IPPROTO_TCP:
    tcp = (struct tcphdr*)(packet + IP_header_len);
    ssport = ntohs(tcp->th_sport);
    inc_field((int*)&ssport);
    tcp->th_sport = htons(ssport);
    check = htons(ntohs(tcp->check) - 1);
    tcp->check = check;
    break;
  case IPPROTO_UDP:
    udp = (struct udphdr*)(packet + IP_header_len);
    ssport = ntohs(udp->uh_sport);
    inc_field((int *)&ssport);
    udp->uh_sport = htons(ssport);
    check = htons(ntohs(udp->check) - 1);
    udp->check = check;
    break;
  default:
    break;
  }

  ip->ttl = START_TTL;
  ip->check = csum((unsigned short *)packet,
		   ip->tot_len);
  sfree(src_addr);
  sfree(dst_addr);
  sfree(stringy);
  return 0;
}

void *per_flow_experiment(void *vworker)
{
  /**
   * 1. Collect some probes via phase 1.
   *  
   * 2. Generate some phase 2 probes. 
   * 
   * 3. Perform a ssendn_fn.
   */
  scanner_worker_t *worker = vworker;
 
  /**
   * 1. Initialize a set of packets to interogate the side-channel
   *    initially.
   */
  for (int i = 0; i < ADDRS_PER_WORKER; i++) {
    make_phase1_packet((unsigned char *)
		       &worker->probe_list[i].probe_buff,
		       worker, i);
  }
  // Internal: Send the phase 1 packets.
  phase1(worker); 

  inc_phase_counter(worker, 1);  
  /* These three lines are internal */
  phase2_wait(worker);

  int nprobes = worker->probe_list_size;
  int sockfd = worker->ssocket->sockfd;
  for (int probe_idx = 0; probe_idx < nprobes; probe_idx++) {
    struct sockaddr *dest_addr =
      (struct sockaddr *)worker->probe_list[probe_idx].sin;
    iphdr *iph = (iphdr *)worker->probe_list[probe_idx].probe_buff;
    int len = iph->tot_len;
    ssendn(sockfd, worker->probe_list[probe_idx].probe_buff,
	   len, 0, dest_addr, sizeof(struct sockaddr),
	   5);
  }

  sleep(120); // Let the targets' side-channels reset. (Hopefully)  

  for (int probe_idx = 0; probe_idx < nprobes; probe_idx++) {
    struct sockaddr *dest_addr =
      (struct sockaddr *)worker->probe_list[probe_idx].sin;
    iphdr *iph = (iphdr *)worker->probe_list[probe_idx].probe_buff;
    short len = iph->tot_len;
    ssendn_fn(sockfd, worker->probe_list[probe_idx].probe_buff,
	      len, 0, dest_addr, sizeof(struct sockaddr),
	      5, inc_sport);
  }

  inc_phase_counter(worker, 2);
  
  /**
   * phase3_wait(worker);
   *
   * phase3(worker);
   * 
   * inc_phase_counter(worker, 3);
   */
  printf("DONE\n");
  return NULL;
}

unsigned long free_list(void *args)
{
  struct hash_args *hargs = args;
  sfree(hargs->keystr);
  list_t *l = (list_t *)hargs->value;
  list_node_t *current = l->list;
  while( current ) {
    list_node_t *tmp = current->next;
    struct packet_value *pv = current->value;
    sfree(pv->packet);
    sfree(current->value);
    sfree(current);
    current = tmp;
  }
  sfree(l);
  sfree(args);
  return 0;
}

static void worker_send_packet(scanner_worker_t *worker)
{
  int nprobes = worker->probe_list_size;
  int sockfd = worker->ssocket->sockfd;
  for (int probe_idx = 0; probe_idx < nprobes; probe_idx++) {
    struct sockaddr *dest_addr =
      (struct sockaddr *)worker->probe_list[probe_idx].sin;
    iphdr *iph = (iphdr *)worker->probe_list[probe_idx].probe_buff;
    int len = ntohs(iph->tot_len);
    ssendto(sockfd, worker->probe_list[probe_idx].probe_buff,
	    len, 0, dest_addr, sizeof(struct sockaddr));
  }
  return ;
}

void split_stringify(char *keystr, char **src_addr, char **dst_addr,
		     short *sport, short *dport)
{
  sscanf(keystr ,"%s %s %hd %hd", 
	 *src_addr, *dst_addr, sport, dport);
  return ;
}

/**
 * This code needs to be refactored with other code so that it 
 * can generalize some of the repeated behavior.
 */
void stringify_node(char **str, void *vnode, int direction)
{
  char *s = *str;
  struct packet_value *pv = vnode;
  unsigned char *packet = (unsigned char *)pv->packet;
  unsigned char src_addr[32];
  unsigned char dst_addr[32];
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
  struct udphdr *udp;
  unsigned short sport = 0;
  unsigned short dport = 0;
  int IP_header_len = ip->ip_hl * 4;
  switch( ip->ip_p ) {
  case IPPROTO_TCP:
    tcp = (struct tcphdr*)(packet + IP_header_len);
    sport = ntohs(tcp->th_sport);
    dport = ntohs(tcp->th_dport);
    break;
  case IPPROTO_UDP:
    udp = (struct udphdr*)(packet + IP_header_len);
    sport = ntohs(udp->uh_sport);
    dport = ntohs(udp->uh_dport);
    break;
  default:
    break ;
  }
  if ( direction == 0 ) {
    sprintf((char*)s, "%s %s %d %d", (char*)src_addr,
	    (char*)dst_addr, sport, dport);
  }
  else {
    sprintf((char*)s, "%s %s %d %d", (char*)dst_addr,
	    (char*)src_addr, dport, sport);    
  }
  return ;
}

unsigned long str_key(void *value, int right, void *args)
{
  struct hash_args *hargs = value;
  char *str = (char*)hargs->keystr;
  unsigned long hash = 5381;
  int c;
  char *tmp = str;
  while ( (c = *tmp++) ) {
    hash = ((hash << 5) + hash) + c;
  }
  if (right) {
    return (unsigned long)(hash % right);
  }
  else {
    return 0;
  }
}

int packet_equal(void *vpack1, void *vpack2)
{
  struct hash_args *harg1 = vpack1;
  struct hash_args *harg2 = vpack2;
  
  int len1 = strlen((char*)(harg1->keystr));
  int len2 = strlen((char*)(harg2->keystr));

  char *str1 = (char*)smalloc(len1+1);
  char *str2 = (char*)smalloc(len2+1);

  memset((void*)str1, 0, len1 + 1);
  memset((void*)str2, 0, len2 + 1);

  memcpy((void*)str1, (void*)harg1->keystr, len1);
  memcpy((void*)str2, (void*)harg2->keystr, len2);

  str1[len1] = '\0';
  str1[len2] = '\0';

  int ret = strcmp((char *)str1, (char *)str2) == 0 ? 1 : 0;

  sfree((void*)str1);
  sfree((void*)str2);
  return ret;
}

unsigned long fourtuple_hash(void *v, int right, void *args)
{
  unsigned long key = make_key(v, right, args);
  return key;
}

unsigned long hash_qr(void *v, int right, void *args)
{
  unsigned long key = str_key(v, right, args);
  return key;
}

unsigned long hash_rq(void *v, int right, void *args)
{
  struct hash_args *hargs = v;
  if ( hargs->value ) {
    char *str = smalloc(256 * sizeof(char));
    memset(str, 0, (sizeof(char)*256));
    stringify_node((char **)&str, hargs->value, 1);
    unsigned long key = str_key((char*)v, right, str);
    sfree(str);
    return key;
  } 
  else {
    unsigned long key = str_key((char*)v, right, NULL);
    return key;
  }
}

void process_packet(dict_t **dictp, const unsigned char *packet,
		    phase_stats_t *phase_stats,
		    struct timeval ts, unsigned int capture_len)
{
  if ( capture_len < sizeof(struct ether_header) ) {
#ifdef UNITTEST
    printf("Capture length not big enough\n");
#endif
    return ;
  }
  struct ether_header *eth = (struct ether_header*)packet;
  int ethtype = ntohs(eth->ether_type);
  if ( ethtype != ETHERTYPE_IP) {
#ifdef UNITTEST
    printf("Datagram is not IPv4\n");
#endif
    return ;
  }
  /*Might be able to replace to block of code below with stringify.*/
  const unsigned char *tmppacket = packet;
  packet += sizeof(struct ether_header);
  struct ip *ip = (struct ip*)packet;
  unsigned char src_addr[32];
  unsigned char dst_addr[32];
  int len;
  int caplen = capture_len;
  char *addr = inet_ntoa(ip->ip_src);
  len = strlen(addr);
  memset((void*)src_addr, 0, sizeof(src_addr));
  memcpy((void*)src_addr, (void*)addr, len);

  addr = inet_ntoa(ip->ip_dst);
  len = strlen(addr);
  memset((void*)dst_addr, 0, sizeof(dst_addr));
  memcpy((void*)dst_addr, (void*)addr, len);

  capture_len -= sizeof(struct ether_header);

  struct packet_value *pv = smalloc(sizeof(struct packet_value));
  char *value = (char *)smalloc(caplen + 1);

  pv->packet = (unsigned char *)value;
  pv->capture_len = caplen;

  memset(value, 0, caplen + 1);
  memcpy(value, (void*)tmppacket, caplen);

  int is_probe = (strcmp((const char*)src_addr, SRC_IP) == 0);
  int is_response = (strcmp((const char*)dst_addr,
			    (const char*)SRC_IP) == 0);
  if ( is_probe ) {

    phase_stats->total_probes += 1;
    char *keystr = smalloc(256 * sizeof(char));
    memset(keystr, 0, 256);
    stringify_node((char**)&keystr, (void *)pv, 0);
    struct hash_args hargs = {.keystr = (unsigned char *)keystr, 
			      .value = NULL};

    if ( !dict_member_fn((*dictp), (void*)&hargs, hash_qr,
			 NULL,  packet_equal ) ) {

      phase_stats->total_unique_probes += 1;

      list_t *l = new_list();
      struct hash_args *hargsp = smalloc(sizeof(struct hash_args));
      hargsp->keystr = smalloc(strlen(keystr) + 1);
      memset(hargsp->keystr, 0, strlen(keystr) + 1);
      memcpy(hargsp->keystr, keystr, strlen(keystr));
      hargsp->value = (unsigned char *)l;
      dict_insert_fn(dictp, (void*)hargsp, hash_qr,
		     NULL,  NULL);
      list_insert(l, pv);
    }
    else {
      sfree(keystr);
      goto FREE_VALUE;
    }
    sfree(keystr);
    goto DONE; /*ATTENTION: normally I wouldn't insert query node
		 however in this case I need to for testing.*/
  }
  else  if ( is_response ) {

    phase_stats->total_responses += 1;

    char *keystr = smalloc(256 * sizeof(char));
    memset(keystr, 0, 256);
    stringify_node((char **)&keystr, (void *)pv, 1);
    struct hash_args hargs = {.keystr=(unsigned char*)keystr,
			      .value=NULL};
    if ( dict_member_fn(*dictp, (void*)&hargs, hash_qr,
			NULL, packet_equal ) ) {

      struct hash_args *h = dict_get_value_fn(*dictp, (void*)&hargs,
					      hash_rq, NULL,
					      packet_equal);
      list_t *l = (list_t *)h->value;
      list_insert(l, pv);
      sfree(keystr);
      goto DONE;
    }
    else {
      sfree(keystr);
      goto FREE_VALUE;
    }
  }
 FREE_VALUE:
  sfree(value);
  sfree(pv);
 DONE:
  return ;
}

dict_t * split_query_response(const char* pcap_fname, 
			      phase_stats_t *phase_stats)
{
  dict_t *q_r = new_dict_size(QR_DICT_SIZE);
  pcap_t *pcap;
  const unsigned char *packet;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct pcap_pkthdr header;
  pcap = pcap_open_offline(pcap_fname, errbuf);
  if (pcap == NULL) {
    printf("%s %d %s %d %s\n",__func__, __LINE__, pcap_fname, errno,
	   strerror(errno) );
    assert( pcap );
  }  
  while ( (packet = pcap_next(pcap, &header)) != NULL ) {
    process_packet(&q_r, packet, phase_stats, 
		   header.ts, header.caplen);
  }
  sfree((void*)pcap);
  pcap = NULL;
  sfree((void*)packet);
  packet = NULL;
  return q_r;    
}

void *copy_packet(void *v)
{
  struct packet_value *pv = v;
  struct packet_value *newpv = smalloc(sizeof(struct packet_value));
  newpv->packet = smalloc(pv->capture_len + 1);  
  memset(newpv->packet, 0, pv->capture_len + 1 );
  memcpy(newpv->packet, pv->packet, pv->capture_len);
  newpv->capture_len = pv->capture_len;
  return (void *) newpv;
}

void response_replay(dict_t **dp, phase_stats_t *phase_stats)
{
  dict_t *d = *dp;
  list_t *element_list = NULL;
  list_node_t *node = NULL;
  int size = d->size;

  dict_t *q_r = new_dict_size(QR_DICT_SIZE);

  for (int i = 0; i < size; i++) {
    element_list = d->elements[i];
    if ( element_list->size >=  1) { 
      node = element_list->list;
      struct hash_args *hargs = (struct hash_args *)node->value;
      list_t *l = (list_t *)hargs->value;
      if ( l->size > 1 ) { /*Cull the probes w/o responses */
#ifdef UNITTEST
	printf("%s %d %s\n", __func__, __LINE__, hargs->keystr);
	printf("size = %d\n", l->size );
#endif /* UNITTEST */
	phase_stats->total_unique_responses += 1;
	if (l->size > 2) {
	  phase_stats->total_responses_with_retransmissions += 1;
	}

	struct hash_args *va = smalloc(sizeof(struct hash_args));
	int len = strlen((char*)hargs->keystr);
	va->keystr = smalloc( len + 1 );
	memcpy(va->keystr, hargs->keystr, len);
	va->keystr[len] = '\0';
	list_t *l2 = clone_list_fn(l, (void*)copy_packet);
	va->value = (unsigned char*)l2;
	dict_insert_fn(&q_r, va, hash_qr, NULL, NULL);
      }
    }
  }
  dict_destroy_fn(d, (free_fn)free_list);
  *dp = q_r;
  return ;
}

static void copy_per_worker_phase2_copy(scanner_worker_t *worker,
					dict_t *qr, int *probe_id,
					char *wsrc_addr,
					char *wdst_addr, int wsport,
					int wdport)
{
  char *packet_to_copy_str = smalloc(256);
  char *psrc_addr = smalloc(256);
  char *pdst_addr = smalloc(256);
  short psport = 0;
  short pdport = 0;
  int n = qr->N;
  int probe_idx = *probe_id;
  for(int k = 0; k < n; k++) {
    list_t *response_list = qr->elements[k];
    list_node_t* current_response = response_list->list;    
    while ( current_response ) {
      struct hash_args *response_args = /*I should call this probe args*/
	current_response->value;
      list_node_t *next_response = current_response->next;
      // This needs to be a check on the string of the hashargs value, not the keystring.
      list_t *pkt_list_to_copy = (list_t*)response_args->value;
      list_node_t *current_packet = pkt_list_to_copy->list;
      char *prev_src_addr = NULL;
      short prev_sport = 0;
      while( current_packet ) {
	list_node_t *next_packet = current_packet->next;
	stringify_node(&packet_to_copy_str,
		       current_packet->value, 0);
	sscanf(packet_to_copy_str, "%s %s %hd %hd",
	       psrc_addr, pdst_addr, &psport, &pdport);
	if ( prev_src_addr == NULL ) {
	  deepcopy_packet(worker, current_packet->value,
			  wsrc_addr, wdst_addr, wsport,
			  wdport, probe_idx);
	  probe_idx++;
	  if (probe_idx >= worker->probe_list_size) {
	    worker->probe_list_size = probe_idx * 2;
	    worker->probe_list =
	      realloc(worker->probe_list,
		      sizeof(probe_t) * probe_idx * 2);
	    assert(worker->probe_list);
	    for (int i = probe_idx; i < (probe_idx * 2); i++){
	      init_probe_t(&worker->probe_list[i]);
	    }
	  }
	}
	else {
	  int not_seen = 
	    (strcmp(prev_src_addr, pdst_addr)) ||
	    (prev_sport != psport) ? 1 : 0; // Logical error here
	  if ( not_seen ) {
	    deepcopy_packet(worker, current_packet->value,
			    wsrc_addr, wdst_addr, wsport,
			    wdport, probe_idx);
	    probe_idx++;
	    if (probe_idx >= worker->probe_list_size) {
	      worker->probe_list = 
		realloc(worker->probe_list, 
			sizeof(probe_t) * probe_idx * 2);

	      assert(worker->probe_list);
	      worker->probe_list_size = probe_idx * 2;
	      for (int i = probe_idx; i < probe_idx * 2; i++) {
		init_probe_t(&worker->probe_list[i]);
	      }
	    }
	  }
	}
	current_packet = next_packet;
	prev_src_addr = psrc_addr;
	prev_sport = psport;
      }
      current_response = next_response;
    }
  }
  worker->probe_list_size = probe_idx; /* It is actually bigger than that but we only have this many probes. */
  *probe_id = probe_idx;
  sfree(packet_to_copy_str);
  sfree(psrc_addr);
  sfree(pdst_addr);
  return;
}

/**
 * 1. Each worker get's n / MAX_WORKERS, IP address to send each of 
 *    the n responding hosts.
 */
void copy_query_response_to_workers(dict_t *qr, 
				    phase_stats_t *phase_stats)
{
  int n = qr->N;
  int probes_per_worker = n / MAX_WORKERS;
  int remainder = n % MAX_WORKERS;
  
  assert((remainder + (probes_per_worker * MAX_WORKERS)) == n);
  scanner_worker_t *worker = &scanner->workers[0];
  char *wsrc_addr = smalloc(256);
  char *wdst_addr = smalloc(256);
  short wsport = 0;
  short wdport = 0;
  int bound = 0;
  for (int i = 0; i < MAX_WORKERS; i++) {
    worker = &scanner->workers[i];
    bound = (i * probes_per_worker);
    int probe_idx = 0;
    for (int j = bound; j < (bound + probes_per_worker); j++) {
      list_t *element_list = qr->elements[j];
      list_node_t* current_element = element_list->list;
      list_node_t *next_element = NULL;
      while ( current_element ) {
	next_element = current_element->next;
	struct hash_args *hargs = current_element->value;
	char *keystr = (char*)hargs->keystr;
	sscanf(keystr, "%s %s %hd %hd", wsrc_addr, wdst_addr,
	       &wsport, &wdport);
	int good = !strcmp(wsrc_addr, SRC_IP);
	assert( good );
	fprintf(log_file, "%s,%d\n", wdst_addr, wdport);
	copy_per_worker_phase2_copy(worker, qr, &probe_idx, 
				    wsrc_addr, wdst_addr, wsport, 
				    wdport);
	current_element = next_element;
      }
    }
  }

  worker = &scanner->workers[0];
  int probe_idx = probes_per_worker;
  for (int j = bound; j < (bound + remainder); j++) {
    list_t *element_list = qr->elements[j];
    list_node_t* current_element = element_list->list;
    list_node_t *next_element = NULL;
    while ( current_element ) {
      next_element = current_element->next;
      struct hash_args *hargs = current_element->value;
      char *keystr = (char*)hargs->keystr;
      sscanf(keystr, "%s %s %hd %hd", wsrc_addr, wdst_addr,
	     &wsport, &wdport);
      int good = !strcmp(wsrc_addr, SRC_IP);
      assert( good );
      copy_per_worker_phase2_copy(worker, qr, &probe_idx, 
				  wsrc_addr, wdst_addr, wsport, 
				  wdport);
      current_element = next_element;
    }
  }
  sfree(wsrc_addr);
  sfree(wdst_addr);
  return ;
}

/** 
 * This needs to be reworked so that the code can be more like a library 
 */
void generate_phase2_packets()
{
  /**
   * 1. Split queries and response
   * 2. Generate response replays.
   *
   *    For each host that responsded, take its response
   *    and reply at back to set how people respond to THESE
   *    packets.
   *
   * 3.
   * 2. For query in :
   * 3.   for response in query[response]
   * 4.
   */
  dict_t *query_response =
    split_query_response(scanner->current_pcap_file_name,
			 &scan_stats.phase1);
  response_replay(&query_response, &scan_stats.phase1);
  copy_query_response_to_workers(query_response, &scan_stats.phase1);
  global_qr_dict = query_response;
  return ;
}

void send_scan_packet(unsigned char *restrict packet_buffer, 
		      int sockfd, scanner_worker_t *restrict worker,
		      int probe_idx, int ttl)
{
  struct sockaddr *dest_addr =
    (struct sockaddr *)worker->probe_list[probe_idx].sin;
  iphdr *iph = (iphdr *)packet_buffer;
  int len = iph->tot_len;
  int result;
  if ( worker->probe_list[probe_idx].good_csum ) {
    iph->check = csum((unsigned short *)packet_buffer,
		      iph->tot_len);
  }
  else {
    iph->check = range_random(65536, worker->random_data,
			      &result);
  }
  ssendto(sockfd, packet_buffer, len, 0, dest_addr, 
	  sizeof(struct sockaddr));
  return ;
}

const char* get_proto(iphdr *ip){
 switch(ip->protocol){
 case IPPROTO_TCP:
   return "TCP";
 case IPPROTO_ICMP:
   return "ICMP";
 case IPPROTO_UDP:
   return "UDP";
 }
 return "Other";
}

void
send_phase1_packet(unsigned char *restrict packet_buffer, 
		   scanner_worker_t *restrict worker, int probe_idx,
		   int sockfd)
{
  struct sockaddr *dest_addr =
    (struct sockaddr *)worker->probe_list[probe_idx].sin;
  iphdr *iph = (iphdr *)packet_buffer;
  int len = iph->tot_len;
#ifdef UNITTEST
  int ret = ssendto(sockfd, packet_buffer, len, 0, dest_addr,
		    sizeof(struct sockaddr));
#else
  ssendto(sockfd, packet_buffer, len, 0, dest_addr,
	  sizeof(struct sockaddr));
#endif

#ifdef UNITTEST
  int localerror = errno;
  if (localerror == EINVAL) {
    printf("FOO: %d %s %d %d %s %d %s\n",
	   __LINE__,__func__, ret, errno,
	   strerror(errno), len, get_proto(iph));
  }
  else if (localerror == EMSGSIZE){
    printf("BAR: %d %s %d %d %s %d %s\n",
	   __LINE__,__func__, ret, errno,
	   strerror(errno), len, get_proto(iph));
  }
  else {
    printf("BAZ: %d %s %d %d %s %d %s\n",
	   __LINE__,__func__, ret, errno, 
	   strerror(errno), len, get_proto(iph));
  }
#endif
  return ;
}

/* This is really a default phase 1 scan. */
void phase1(scanner_worker_t *self) 
{
  for (int probe_idx = 0;
       probe_idx < ADDRS_PER_WORKER; probe_idx++) {
    send_phase1_packet((unsigned char *)
		       &self->probe_list[probe_idx].probe_buff,
		       self, probe_idx, self->ssocket->sockfd);
  }
  return ;
}

static void inc_phase_counter(scanner_worker_t *worker, int phase)
{
  switch(phase) {
  case 1:
    pthread_mutex_lock(worker->scanner->phase1_lock);
    worker->scanner->phase1 += 1;
    pthread_cond_signal(worker->scanner->phase1_cond);
    pthread_mutex_unlock(worker->scanner->phase1_lock);
    break;
  case 2:
    pthread_mutex_lock(worker->scanner->phase2_lock);
    worker->scanner->phase2 += 1;
    pthread_cond_signal(worker->scanner->phase2_cond);
    pthread_mutex_unlock(worker->scanner->phase2_lock);
    break;
  default:
    assert(0);
  }
  return;
}

void phase2(scanner_worker_t *self)
{
  worker_send_packet(self);
  return; 
}

void phase2_wait(scanner_worker_t *self)
{
  pthread_mutex_lock(self->scanner->phase2_wait_lock);
  while( self->scanner->phase2_wait ) {
    pthread_cond_wait(self->scanner->phase2_wait_cond,
		      self->scanner->phase2_wait_lock);
  }
  pthread_mutex_unlock(self->scanner->phase2_wait_lock);
  return;
}

/**
 * @param vself: Generic pointer to a scanner_worker_t.
 * @return: Always return
 *
 * Overview:
 * 
 * 1. Generates packets based on my randomized
 * algorithm for setting fields.
 * 
 * 2. Send packets from (1).
 * 
 * 3. Once finished, find packets that illicited a response.
 * 
 * @note: In the future, this needs to be generalized. 
 * The user should have to register a set of up to three
 * functions that will have some desired effect.
 */
void *basic_experiment(void *vworker)
{
  scanner_worker_t *worker = vworker;

  for (int i = 0; i < ADDRS_PER_WORKER; i++) {
    make_phase1_packet((unsigned char *)
		       &worker->probe_list[i].probe_buff,
		       worker, i);
  }

  for (int i = 0; i < PHASE1_ITERATIONS; i++) {
    phase1(worker);
  }

  inc_phase_counter(worker, 1);

  phase2_wait(worker);

  for (int i = 0; i < PHASE1_ITERATIONS; i++) {
    phase2(worker);
  }
  inc_phase_counter(worker, 2);
  printf("DONE\n");
  return NULL;
}
/**
 * This function is relavant only to the middle-box fingerprinting
 * experiments, not to the expirments for this research.
 */
void *worker_routine(void *vself)
{
  printf("%d %s ",__LINE__, __func__);
  scanner_worker_t *self = vself;
  int scanning = 1;
  // Probably change this so we can make a list of ipaddresses.
  int sockfd = self->ssocket->sockfd;
  double start_time;
  START_TIMER(start_time);
  double end_time;
  while ( scanning ) {
    START_TIMER(end_time);
    if (end_time - start_time > SCAN_DURATION) {
      break;
    }
    for (int i = 0; i < ADDRS_PER_WORKER; i++) {
      make_packet ((unsigned char *)&self->probe_list[i].probe_buff,
		   self, i);
    }

    int ttl = START_TTL;
    self->current_ttl = START_TTL;
    int probe_idx = self->probe_idx;
    for (int j = 0; j < TTL_MODULATION_COUNT; j++) {
      ttl = START_TTL;
      while ( self->current_ttl < END_TTL ) {
	if (probe_idx == ADDRS_PER_WORKER) {
	  ttl++;
	  self->current_ttl = ttl;
	  probe_idx = 0;
	}
	send_scan_packet((unsigned char *)
			 &self->probe_list[probe_idx].probe_buff,
			 sockfd, self, probe_idx, ttl);
	probe_idx += 1;
      }
      self->probe_idx = 0;
    }
  }
  printf("Done scanning. Total scan time %f sec\n",
	 (end_time - start_time));
  return NULL;
}

static void start_workers()
{
  for (int i = 0; i < MAX_WORKERS; i++) {
    if (pthread_create(scanner->workers[i].thread, NULL,
		       per_flow_experiment,
		       (void *)&scanner->workers[i]) < 0) {
      printf("Couldn't initialize thread for worker[%d]\n", i);
      exit(-1);
    }
  }
  return ;
}

/**
 * Main loop for the scanner code. ''main" calls this function.
 */
int scanner_main_loop(scan_args_t *scan_args)
{
  new_scanner_singleton();

  if (signal(SIGCHLD, SIG_IGN) == SIG_ERR) {
    exit(1);
  }

  init_blacklist(scan_args->blacklist);

  pthread_mutex_lock(scanner->continue_lock);
  pthread_mutex_lock(scanner->phase1_lock);
  pthread_mutex_lock(scanner->phase2_lock);
  pthread_mutex_lock(scanner->phase2_wait_lock);
  char *filename = smalloc(MAX_PCAP_NAME_LEN);

  timestamp_filename((char**)&filename, 1);
  scanner->current_pcap_file_name = (char *)filename;
  start_sniffer(scanner->sniffer, filename);

  start_workers();
  
  /* Wait until all workers have finished phase1. */
  while(scanner->phase1 < MAX_WORKERS) {
    pthread_cond_wait(scanner->phase1_cond, scanner->phase1_lock);
  }
  pthread_mutex_unlock(scanner->phase1_lock);

  sleep(120);
  stop_sniffer(scanner->sniffer);

  /* This should be called something else. 
   * Maybe just have this start phase 2 and when that happens, 
   * all of the workers go on to generate their phase 2 packets.
   *
   */
  generate_phase2_packets(); 

  memset(filename, 0, MAX_PCAP_NAME_LEN);
  timestamp_filename((char**)&filename, 2);
  scanner->current_pcap_file_name = (char *)filename;
  start_sniffer(scanner->sniffer, filename);

  scanner->phase2_wait = 0;

  pthread_cond_signal(scanner->phase2_wait_cond);
  pthread_mutex_unlock(scanner->phase2_wait_lock);
  while(scanner->phase2 < MAX_WORKERS) {
    pthread_cond_wait(scanner->phase2_cond, scanner->phase2_lock);
  }
  pthread_mutex_unlock(scanner->phase2_lock);

  sleep(90);
  stop_sniffer(scanner->sniffer);

  //log_phase_statistics(&scan_stats.phase1);
  //response_replay(global_qr_dict, &scan_stats.phase2);
  //log_phase_statistics(&scan_stats.phase2);

  delete_scanner(scanner);
  sfree(scanner);
  free(filename);
  scanner = NULL;
  return 0;
}

/**
 * Creates a new scanner_worker_t and initializes all of its fields.
 * @param: worker. Pointer to the scanner_worker_t to be initialized
 * @param: id. And int that is the worker identifier.
 * 
 * @return: 0 on succes. -1 on failure with an error message printed
 * to the screen..
 */
int new_worker(scanner_worker_t *worker, int id)
{
#ifdef UNITTEST
  printf("%d %s \n", __LINE__, __func__);
#endif

  worker->ssocket = smalloc_msg(sizeof(scanner_socket_t),
			   "Couldn't allocate scanner_socket_t for "
			   "worker[%d]\n", id);

  worker->ssocket->sockfd = socket(AF_INET, SOCK_RAW,
				   IPPROTO_RAW);

  if (worker->ssocket->sockfd < 0) {
    printf("Couldn't open socket fd for worker[%d]\n", id);
    return -1;
  };

  if (setsockopt(worker->ssocket->sockfd, SOL_SOCKET,
		 SO_BINDTODEVICE, CAPTURE_INTERFACE,
		 strlen(CAPTURE_INTERFACE)) ) {
    printf("%s %d %s %d %s\n", __func__, __LINE__,
	   strerror(errno), errno, CAPTURE_INTERFACE);
    printf("getsockopt() for worker[%d]\n", id);
    return -1;
  }

  
  worker->thread = smalloc_msg(sizeof(pthread_t),
			       "Couldn't allocate thread for"
			       " worker[%d]\n", id);

  worker->random_data = malloc(sizeof(struct random_data));

  assert(worker->random_data);

  worker->state_size = STATE_SIZE;
  worker->random_state = smalloc_msg(STATE_SIZE, "Couldn't allocate "
				     "random_state storage for "
				     "worker[%d]\n",
				     id);
  double time = wall_time() + id;
  //  srandom_r((long)time, worker->random_data);
  worker->seed = (long)time;

  if (initstate_r(worker->seed, worker->random_state, STATE_SIZE,
		  worker->random_data) < 0) {
    printf("Couldn't initialize random_state for worker[%d]'s.\n",
	   id);
    assert(0);
  }  
  worker->probe_list = 
    smalloc_msg(sizeof(probe_t) * ADDRS_PER_WORKER,
		"Couldn't allocate space for "
		"address list for worker[%d]\n", id);
  worker->probe_list_size = ADDRS_PER_WORKER;
  for (int i = 0; i < ADDRS_PER_WORKER; i++) {
    worker->probe_list[i].sin = 
      smalloc_msg(sizeof(struct sockaddr_in),
		  "Cannot allocate space for "
		  "probe sockaddr_in for "
		  "worker[%d]\n", id);
  }
  worker->worker_id = id;
  worker->probe_idx = 0;
  worker->current_ttl = START_TTL;
  return id;
}

void init_conds()
{
  scanner->continue_cond = new_cond();
  scanner->phase1_cond = new_cond();
  scanner->phase2_cond = new_cond();
  scanner->phase2_wait_cond = new_cond();
  return;
}

void init_locks()
{
  scanner->continue_lock = new_mutex();
  scanner->phase1_lock = new_mutex();
  scanner->phase2_lock = new_mutex();
  scanner->phase2_wait_lock = new_mutex();
  return;
}

void init_stats()
{
  scan_stats.phase1.total_probes = 0;
  scan_stats.phase1.total_unique_probes = 0;
  scan_stats.phase1.total_unique_responses = 0;
  scan_stats.phase1.total_responses = 0;
  scan_stats.phase1.total_responses_with_retransmissions = 0;

  scan_stats.phase2.total_probes = 0;
  scan_stats.phase2.total_responses = 0;
  scan_stats.phase2.total_unique_responses = 0;
  scan_stats.phase2.total_responses = 0;
  scan_stats.phase2.total_responses_with_retransmissions = 0;

  scan_stats.phase3.total_probes = 0;
  scan_stats.phase3.total_responses = 0;
  scan_stats.phase3.total_unique_responses = 0;
  scan_stats.phase3.total_responses = 0;
  scan_stats.phase3.total_responses_with_retransmissions = 0;
  return;
}

/**
 * @warning: Need to free up all this crap too eventually!!!
 */
static void init_scanner_random()
{
  scanner->random_data = malloc(sizeof(struct random_data) );

  assert( scanner->random_data );

  scanner->state_size = STATE_SIZE;
  scanner->random_state = malloc(STATE_SIZE);

  assert(scanner->random_state);
  double time = wall_time() + LUCKY;
  //srandom_r((long)time, scanner->random_data);
  scanner->seed = (long )time;
  if (initstate_r(scanner->seed, scanner->random_state, STATE_SIZE,
		  scanner->random_data) < 0) {
    printf("Couldn't initialize random_state for scanner.\n");
    assert(0);
  }
  return;
}

static void init_workers()
{
  for (int i = 0 ; i < MAX_WORKERS; i++) {
    if (new_worker(&scanner->workers[i], i) != i) {
      exit(-1);
    }
    scanner->workers[i].scanner = scanner;
  }
  return;
}

static void init_logfile()
{
  char *filename = smalloc(MAX_PCAP_NAME_LEN);
  timestamp_str((char**)&filename, "log-file");
  log_file=fopen(filename, "w");
  free(filename);
}

/** 
 * Either build a scanner singleton or create a completely new one
 *  if we have already built on in the past. This is simply an 
 *  interface
 *  to get at the statically declared one.
 */
scanner_t *new_scanner_singleton()
{
  if ( scanner ) {
    return scanner;
  }
  init_stats();
  scanner = malloc(sizeof(scanner_t));
  assert( scanner );
  scanner->keep_scanning = 1;
  scanner->phase1 = 0;
  scanner->phase2 = 0;
  scanner->phase2_wait = 1;
  scanner->workers = malloc(sizeof(scanner_worker_t) * MAX_WORKERS);
  assert( scanner->workers );
  init_scanner_random();
  init_workers();
  scanner->sniffer = smalloc( sizeof(sniffer_t) );
  init_sniffer(scanner->sniffer);
  init_locks();
  init_conds();
  init_logfile();
  scanner->current_pcap_file_name = NULL;
  return scanner;
}

void delete_conds()
{
  sfree(scanner->continue_cond);
  sfree(scanner->phase1_cond);
  sfree(scanner->phase2_cond);
  sfree(scanner->phase2_wait_cond);
  return;
}

void  delete_locks()
{ 
  sfree(scanner->continue_lock);
  sfree(scanner->phase1_lock);
  sfree(scanner->phase2_lock);
  sfree(scanner->phase2_wait_lock);

  return;
}

void delete_workers(scanner_worker_t *worker)
{
  close(worker->ssocket->sockfd);
  sfree(worker->ssocket);
  worker->ssocket = NULL;

  sfree(worker->thread);
  worker->thread = NULL;

  sfree(worker->random_data);
  worker->random_data = NULL;  

  sfree(worker->random_state);
  worker->random_state = NULL;

  for (int i = 0; i < worker->probe_list_size; i++) {
    sfree(worker->probe_list[i].sin);
  }
  sfree(worker->probe_list);
  worker->probe_list = NULL;
  return;
}

void delete_scanner()
{
  delete_conds();
  delete_locks();
  for(int i = 0; i < MAX_WORKERS; i++) {
    delete_workers(&(scanner->workers[i]));
  }
  sfree(scanner->workers);
  scanner->workers = NULL;
  return ;
}

void print_phase_statistics(phase_stats_t *phase_stats)
{
  printf("Scan statistics: \n");
  printf("\t  total probes sent:                    %d\n",
	 phase_stats->total_probes);
  printf("\t  total unique probes sent:              %d\n",
	 phase_stats->total_unique_probes);
  printf("\t  total unique responses:               %d\n",
	 phase_stats->total_unique_responses);
  printf("\t  total responses:                      %d\n",
	 phase_stats->total_responses);
  printf("\t  total responses with retransmissions: %d\n", 
	 phase_stats->total_responses_with_retransmissions);
  return;
}

void log_phase_statistics(phase_stats_t *phase_stats)
{
  fprintf(log_file, "Scan statistics: \n");
  fprintf(log_file, "\t  total probes sent:                    %d\n",
	  phase_stats->total_probes);
  fprintf(log_file, "\t  total probes sent:                    %d\n",
	  phase_stats->total_unique_probes);
  fprintf(log_file, "\t  total unique responses:               %d\n",
	  phase_stats->total_unique_responses);
  fprintf(log_file, "\t  total responses:                      %d\n",
	  phase_stats->total_responses);
  fprintf(log_file, "\t  total responses with retransmissions: %d\n",
	  phase_stats->total_responses_with_retransmissions);
  return;
}
