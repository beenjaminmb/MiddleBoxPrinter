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
#include <errno.h>
#include <string.h>
#include <unistd.h>

#define DEBUG 0
#define TEST_SEED 0
#define STATE_SIZE 8
#define SCAN_DURATION 3600.0


typedef struct scanner_t {
  scanner_worker_t *workers;
  pthread_mutex_t *continue_lock;
  pthread_cond_t *continue_cond;

  pthread_mutex_t *phase1_lock;
  pthread_cond_t *phase1_cond;

  pthread_mutex_t *phase2_lock;
  pthread_cond_t *phase2_cond;

  pthread_mutex_t *phase2_wait_lock;
  pthread_cond_t *phase2_wait_cond;


  int keep_scanning;
  int phase1;
  int phase2;
  int phase2_wait;
} scanner_t;

static scanner_t *scanner = NULL;

static inline void send_scan_packet(unsigned char *restrict packet_buffer, 
				    int sockfd, 
				    scanner_worker_t *restrict worker,
				    int probe_idx, int ttl)
  __attribute__((always_inline));

static inline void *worker_routine(void* vself) 
  __attribute__((always_inline));

static inline int scanner_main_loop() __attribute__((always_inline));

static inline int new_worker(scanner_worker_t *worker, int id)  
  __attribute__((always_inline));

static inline scanner_t *new_scanner_singleton()
  __attribute__((always_inline));

static inline void
send_phase1_packet(unsigned char *restrict packet_buffer, 
		   scanner_worker_t *restrict worker, int probe_idx,
		   int sockfd)  __attribute__((always_inline));


static inline void phase1(scanner_worker_t *self)
  __attribute__((always_inline));

static inline void phase2(scanner_worker_t *self)
  __attribute__((always_inline));

void 
got_packet(u_char * restrict args,
	   const struct pcap_pkthdr * restrict header,
	   const u_char *restrict packet);

static inline void
send_scan_packet(unsigned char *restrict packet_buffer, int sockfd, 
		 scanner_worker_t *restrict worker, int probe_idx,
		 int ttl)
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

  sendto(sockfd, packet_buffer, len, 0, dest_addr, 
	 sizeof(struct sockaddr));

  return ;
}

static const char* get_proto(iphdr *ip){
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

static inline void
send_phase1_packet(unsigned char *restrict packet_buffer, 
		   scanner_worker_t *restrict worker, int probe_idx,
		   int sockfd)
{
  struct sockaddr *dest_addr =
    (struct sockaddr *)worker->probe_list[probe_idx].sin;
  iphdr *iph = (iphdr *)packet_buffer;
  int len = iph->tot_len;

  int ret = sendto(sockfd, packet_buffer, len, 0, dest_addr, 
		   sizeof(struct sockaddr));

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
  return ;
}


static inline void phase1(scanner_worker_t *self)
{
  for (int i = 0; i < ADDRS_PER_WORKER; i++) {
    make_phase1_packet((unsigned char *)
		       &self->probe_list[i].probe_buff,
		       self, i);
  }

  for (int probe_idx = 0;
       probe_idx < ADDRS_PER_WORKER; probe_idx++) {
    send_phase1_packet((unsigned char *)
		       &self->probe_list[probe_idx].probe_buff,
		       self, probe_idx, self->ssocket->sockfd);
    sleep(1);
  }  
  pthread_mutex_lock(self->scanner->phase1_lock);
  self->scanner->phase1 += 1;
  pthread_cond_signal(self->scanner->phase1_cond);
  pthread_mutex_unlock(self->scanner->phase1_lock);

  printf("%d %s %d\n",__LINE__,__func__, ADDRS_PER_WORKER);

  return ;
}

static inline void phase2(scanner_worker_t *self)
{
  pthread_mutex_lock(self->scanner->phase2_lock);
  self->scanner->phase2 += 1;
  pthread_cond_signal(self->scanner->phase2_cond);
  pthread_mutex_unlock(self->scanner->phase2_lock);
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
 */
static inline void *find_responses(void *vself)
{
  scanner_worker_t *self = vself;
  phase1(self);

  pthread_mutex_lock(self->scanner->phase2_wait_lock);

  while( self->scanner->phase2_wait ) {
    pthread_cond_wait(self->scanner->phase2_wait_cond,
		      self->scanner->phase2_wait_lock);
  }

  pthread_mutex_unlock(self->scanner->phase2_wait_lock);
  phase2(self);

  printf("DONE\n");
  return NULL;
}


/**
 * This is the worker routine that generates packets with varying 
 * fields. Spins up a sniffer thread with with appropriate 
 * pcap filter and sends the pcap off with modulated TTL.
 * 
 * @param: vself. A void pointer to the worker that is actually
 * sending of packets.
 *
 * @return: Always returns NULL.
 */
static inline void *worker_routine(void *vself)
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
    if (end_time - start_time > SCAN_DURATION){
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

/**
 * Main loop for the scanner code. ''main" calls this function.
 */
static inline int scanner_main_loop()
{
  new_scanner_singleton();
  pthread_mutex_lock(scanner->continue_lock);
  for (int i = 0; i < MAX_WORKERS; i++) {
    if (pthread_create(scanner->workers[i].thread, NULL,
		       find_responses,
		       (void *)&scanner->workers[i]) < 0) {
      printf("Couldn't initialize thread for worker[%d]\n", i);
      exit(-1);
    }
  }
  
  pthread_mutex_lock(scanner->phase1_lock);
  pthread_mutex_lock(scanner->phase2_lock);
  pthread_mutex_lock(scanner->phase2_wait_lock);


  while(scanner->phase1 < MAX_WORKERS) {
    pthread_cond_wait(scanner->phase1_cond, scanner->phase1_lock);
  }
  pthread_mutex_unlock(scanner->phase1_lock);
  
  scanner->phase2_wait = 0;
  pthread_cond_signal(scanner->phase2_wait_cond);
  pthread_mutex_unlock(scanner->phase2_wait_lock);
  while(scanner->phase2 < MAX_WORKERS) {
    pthread_cond_wait(scanner->phase2_cond, scanner->phase2_lock);
  }
  pthread_mutex_unlock(scanner->phase2_lock);
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
static inline int new_worker(scanner_worker_t *worker, int id)
{
  printf("%d %s \n", __LINE__, __func__);
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

  if (setsockopt(worker->ssocket->sockfd, SOL_SOCKET, SO_BINDTODEVICE,
		 CAPTURE_INTERFACE, strlen(CAPTURE_INTERFACE)) ) {
    printf("getsockopt() for worker[%d]\n", id);
    return -1;
  }
  
  worker->thread = malloc(sizeof(pthread_t));
  if ((long)worker->thread == -1) {
    printf("Couldn't allocate thread for worker[%d]\n", id);
    return -1;
  }

  worker->random_data = malloc(sizeof(struct random_data));
  if ((long)worker->random_data == -1) {
    printf("Couldn't allocate random_data storage for worker[%d]\n", 
	   id);
    return -1;
  }

  worker->state_size = STATE_SIZE;
  worker->random_state = malloc(STATE_SIZE);
  if ((long)worker->random_state == -1) {
    printf("Couldn't allocate random_state storage for worker[%d]\n",
	   id);
    return -1;
  }  

  if (initstate_r(TEST_SEED, worker->random_state, STATE_SIZE,
		  worker->random_data) < 0) {
    printf("Couldn't initialize random_state for worker[%d]'s.\n",
	   id);
    return -1;
  }
  
  worker->probe_list = malloc(sizeof(probe_t) * ADDRS_PER_WORKER);
  if (worker->probe_list == NULL) {
    printf("Couldn't allocate space for "
	   "address list for worker[%d]\n", id);
    return -1;
  }

  for (int i = 0; i < ADDRS_PER_WORKER; i++) {
    worker->probe_list[i].sin = malloc(sizeof(struct sockaddr_in));
    if (worker->probe_list[i].sin == NULL) {
      printf("Cannot allocate space for probe sockaddr_in for "
	     "worker[%d]\n", id);
      return -1;
    }
  }
  printf("%d %s \n", __LINE__, __func__);
  double time = wall_time();
  srandom_r((long)time, worker->random_data);
  printf("%d %s \n", __LINE__, __func__);
  worker->worker_id = id;
  worker->probe_idx = 0;
  worker->current_ttl = START_TTL;
  printf("%d %s FUCK\n", __LINE__, __func__);
  return id;
}

static void init_conds(scanner_t *scanner)
{

  scanner->continue_cond = malloc(sizeof(pthread_cond_t));
  if ((long)scanner->continue_cond == -1) {
    exit(-1);
  }
  pthread_cond_init(scanner->continue_cond, NULL);

  scanner->phase1_cond = malloc(sizeof(pthread_cond_t));
  if ((long)scanner->phase1_cond == -1) {
    exit(-1);
  }
  pthread_cond_init(scanner->phase1_cond, NULL);

  scanner->phase2_cond = malloc(sizeof(pthread_cond_t));
  if ((long)scanner->phase2_cond == -1) {
    exit(-1);
  }
  pthread_cond_init(scanner->phase2_cond, NULL);


  scanner->phase2_wait_cond = malloc(sizeof(pthread_cond_t));
  if ((long)scanner->phase2_wait_cond == -1) {
    exit(-1);
  }
  pthread_cond_init(scanner->phase2_wait_cond, NULL);

  return;
}

static void init_locks(scanner_t *scanner)
{
  scanner->continue_lock = malloc(sizeof(pthread_mutex_t));
  if ((long)scanner->continue_lock == -1) {
    exit(-1);
  }
  pthread_mutex_init(scanner->continue_lock, NULL);

  scanner->phase1_lock = malloc(sizeof(pthread_mutex_t));
  if ((long)scanner->phase1_lock == -1) {
    exit(-1);
  }
  pthread_mutex_init(scanner->phase1_lock, NULL);

  scanner->phase2_lock = malloc(sizeof(pthread_mutex_t));
  if ((long)scanner->phase2_lock == -1) {
    exit(-1);
  }
  pthread_mutex_init(scanner->phase2_lock, NULL);

  scanner->phase2_wait_lock = malloc(sizeof(pthread_mutex_t));
  if ((long)scanner->phase2_wait_lock == -1) {
    exit(-1);
  }
  pthread_mutex_init(scanner->phase2_wait_lock, NULL);

  return;
}

/** 
 * Either build a scanner singleton or create a completely new one
 *  if we have already built on in the past. This is simply an 
 *  interface
 *  to get at the statically declared one.
 */
static inline scanner_t *new_scanner_singleton()
{
  if ( scanner ) {
    return scanner;
  }
  scanner = malloc(sizeof(scanner_t));
  scanner->keep_scanning = 1;
  scanner->phase1 = 0;
  scanner->phase2 = 0;
  scanner->phase2_wait = 1;
  scanner->workers = malloc(sizeof(scanner_worker_t) * MAX_WORKERS);
  for (int i = 0 ; i < MAX_WORKERS; i++) {
    if (new_worker(&scanner->workers[i], i) != i) {
      exit(-1);
    }
    scanner->workers[i].scanner = scanner;
  }

  init_locks(scanner);
  
  init_conds(scanner);

  return scanner;
}

#endif /* _SCANNER_ */
