/*
  @author: Ben Mixon-Baca
  @email: bmixonb1@cs.unm.edu
 */

#ifndef _SCANNER_
#define _SCANNER_

#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "packet.h"
#include "worker.h"
#include "util.h"
#include <pcap/pcap.h>
#define DEBUG 0
#define MAX_WORKERS 1
#define PACKETS_PER_SECOND 100
#define TEST_SEED 0
#define STATE_SIZE 8
#define MAX_FILTER_SIZE sizeof("host 255.255.255.255") + 1
typedef struct scanner_t {
  scanner_worker_t *workers;  
  pthread_mutex_t *continue_lock;
  pthread_cond_t *continue_cond;
  int keep_scanning;
} scanner_t;



static scanner_t *scanner = NULL;

static inline void send_scan_packet(unsigned char *packet_buffer, 
				    int sockfd, 
				    scanner_worker_t *worker)  
  __attribute__((always_inline));

static inline void *worker_routine(void* vself) 
  __attribute__((always_inline));

static inline int scanner_main_loop() __attribute__((always_inline));

static inline int new_worker(scanner_worker_t *worker, int id)  
  __attribute__((always_inline));

static inline scanner_t *new_scanner_singleton() 
  __attribute__((always_inline));

void got_packet(u_char *args, const struct pcap_pkthdr *header,
		const u_char *packet);



static inline void *sniffer_routine(void *argv)
{
  sniffer_t *sniffer = argv;
  pthread_mutex_lock(sniffer->sniffer_lock);
  while(sniffer->keep_sniffing == 0) {
    pthread_cond_wait(sniffer->sniffer_cond, sniffer->sniffer_lock);
  }
  while(sniffer->keep_sniffing) {
  
  }
  pthread_mutex_unlock(sniffer->sniffer_lock);
  return NULL;
}

static inline void send_scan_packet(unsigned char *packet_buffer, 
				    int sockfd,
				    scanner_worker_t *worker)

{
  struct sockaddr *dest_addr = (struct sockaddr *)worker->sin;
  iphdr *iph = (iphdr *)packet_buffer;
  int len = iph->tot_len;
  char filter_str[MAX_FILTER_SIZE];
  
  int result;
  char *addr = inet_ntoa(worker->sin->sin_addr);
  sprintf(filter_str, "host %s", addr);
  struct bpf_program bpf_prog;

  if (pcap_compile(worker->cap_handle, &bpf_prog, filter_str, 1,
		   PCAP_NETMASK_UNKNOWN) ==  -1){
    pcap_perror(worker->cap_handle, NULL);
    printf("Couldn't compile pcap filter for worker[%d]",
	   worker->worker_id);
  }
  for (int i = START_TTL; i < END_TTL; i++) {
    iph->ttl = i;
    if (DEBUG && MAX_WORKERS == 1)
      printf("ttl = %d\n", i);
    
    for (int j = 0; j < TTL_MODULATION_COUNT; j++) {
      
      if (range_random(100, worker->random_data, &result) < 90) {
	iph->check = csum((unsigned short *)packet_buffer, 
			  iph->tot_len);
      }
      else {
	iph->check = range_random(65536, worker->random_data, 
				  &result);
      }// this might be slow.
      sendto(sockfd, packet_buffer, len, 0,
	     dest_addr, sizeof(struct sockaddr));
    }
  }

}

static inline void *worker_routine(void* vself)
{
  scanner_worker_t *self = vself;
  int scanning = 1;
  // Probably change this so we can make a list of ipaddresses.
  unsigned char packet_buffer[PACKET_LEN];
  int sockfd = self->ssocket->sockfd;
  while ( scanning ) {
    make_packet((unsigned char *)&packet_buffer, self);
    send_scan_packet((unsigned char *)&packet_buffer, sockfd, self);
  }
  
  return NULL;
}

/**
 * Main loop for the scanner code. ''main" calls this function.
 */
static inline int scanner_main_loop()
{
  new_scanner_singleton();
  pthread_mutex_lock(scanner->continue_lock);  
  for (int i = 0; i < MAX_WORKERS; i++) {
    if (pthread_create(scanner->workers[i].thread, NULL,
		       worker_routine,
		       (void *)&scanner->workers[i]) < 0) {
	exit(-1);
      }
  }
  while (scanner->keep_scanning) {
    pthread_cond_wait(scanner->continue_cond, scanner->continue_lock);
  }
  pthread_mutex_unlock(scanner->continue_lock);
  return 0;
}


static inline int new_worker(scanner_worker_t *worker, int id)
{
  worker->ssocket = malloc(sizeof(scanner_socket_t));
  if ((long)worker->ssocket == -1) {
    printf("Couldn't allocate scanner_socket_t for worker[%d]\n", id);
    return -1;
  }

  worker->ssocket->sockfd = socket(AF_INET, SOCK_RAW,
				   IPPROTO_RAW);
  if (worker->ssocket->sockfd < 0) {
    printf("Couldn't open socket fd for worker[%d]\n", id);
    return -1;
  };

  worker->thread = malloc(sizeof(pthread_t));
  if ((long)worker->thread == -1) {
    printf("Couldn't allocate thread for worker[%d]\n", id);
    return -1;
  }

  worker->random_data = malloc(sizeof(struct random_data));
  if ((long)worker->random_data == -1) {
    printf("Couldn't allocate random_data storage for worker[%d]\n", id);
    return -1;
  }

  worker->state_size = STATE_SIZE;
  worker->random_state = malloc(STATE_SIZE);
  if ((long)worker->random_state == -1) {
    printf("Couldn't allocate random_state storage for worker[%d]\n", id);
    return -1;
  }

  worker->cap_errbuf = malloc(PCAP_ERRBUF_SIZE);
  if (worker->cap_errbuf == NULL) {
    printf("Couldn't allocate %d bytes for cap error buffer for worker[%d]'s\n",
	   PCAP_ERRBUF_SIZE, id);
    return -1;
  }

  worker->cap_handle = pcap_create(CAPTURE_IFACE, worker->cap_errbuf);
  if(worker->cap_handle == NULL) {
    printf("Couldn't create a capture handle for worker[%d]'s.\n", id);
    return -1;
  }

  if ( pcap_set_promisc(worker->cap_handle, 1) ) {
    printf("Error opening interface in promiscuous mode for worker[%d]'s\n", id);
    return -1;
  }

  if (initstate_r(TEST_SEED, worker->random_state, STATE_SIZE,
		  worker->random_data) < 0) {
    printf("Couldn't initialize random_state for worker[%d]'s.\n", id);
    return -1;
  }

  worker->sin = malloc(sizeof(struct sockaddr_in));
  if ((long)worker->sin == -1) {
    printf("Couldn't allocate sockaddr_in for worker[%d].\n", id);
    return -1;
  }

  if (pcap_activate(worker->cap_handle) != 0) {
    pcap_perror(worker->cap_handle, NULL);
    printf("Error activating capture interface for worker[%d].\n",
	   worker->worker_id);
    return -1;
  }
  worker->sniffer = malloc(sizeof(sniffer_t));
  
  if (worker->sniffer == NULL) {
    printf("Cannot allocate sniffer for worker[%d]\n", id);
  }
  
  worker->sniffer->sniffer_lock = malloc(sizeof(pthread_mutex_t));
  if (worker->sniffer->sniffer_lock == NULL) {
    printf("Cannot allocate sniffer lock worker[%d]\n", id);
  }
  if (pthread_mutex_init(worker->sniffer->sniffer_lock, NULL) != 0) {
    printf("Cannot initialize sniffer lock worker[%d]\n", id);
    return -1;
  }
  worker->sniffer->sniffer_cond = malloc(sizeof(pthread_cond_t));
  if (worker->sniffer->sniffer_cond == NULL) {
    printf("Cannot allocate sniffer cond worker[%d]\n", id);
  }
  
  if (pthread_cond_init(worker->sniffer->sniffer_cond, NULL) != 0) {
    printf("Cannot initialize sniffer cond worker[%d]\n", id);
    return -1;
  }
  worker->sniffer->sniffer_thread = malloc(sizeof(pthread_t));
  if (worker->sniffer->sniffer_thread == NULL) {
    printf("Cannot allocate space for sniffer thread for worker[%d]",
	   id);
    return -1;
  }
  worker->worker_id = id;
  worker->sniffer->keep_sniffing = 0;
  return id;
}

/** 
 * Either build a scanner singleton or create a completely new one
 *  if we have already built on in the past. This is simply an 
 *  interface
 *  to get at the statically declared one.
 */
//static inline scanner_t *new_scanner_singleton()

static inline scanner_t *new_scanner_singleton()
{
  if ( scanner ) return scanner;
  scanner = malloc(sizeof(scanner_t));
  scanner->keep_scanning = 1;
  scanner->workers = malloc(sizeof(scanner_worker_t) * MAX_WORKERS);
  for (int i = 0 ; i < MAX_WORKERS; i++) {
    if (new_worker(&scanner->workers[i], i) != i) {
      exit(-1);
    }
  }
  scanner->continue_lock = malloc(sizeof(pthread_mutex_t));
  if ((long)scanner->continue_lock == -1) return NULL;
  pthread_mutex_init(scanner->continue_lock, NULL);
  
  scanner->continue_cond = malloc(sizeof(pthread_cond_t));
  if ((long)scanner->continue_cond == -1) return NULL;
  pthread_cond_init(scanner->continue_cond, NULL);
  
  return scanner;
}

#endif /* _SCANNER_ */
