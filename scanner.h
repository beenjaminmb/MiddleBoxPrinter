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

#define MAX_WORKERS 10
#define PACKETS_PER_SECOND 100

typedef struct scanner_socket_t {
  int sockfd;
} scanner_socket_t;

typedef struct scanner_worker_t {
  pthread_t *thread;
  scanner_socket_t *ssocket;
  struct random_data *random_data;
  int worker_id;
  // list_t *addr_list;
} scanner_worker_t;

typedef struct scanner_t {
  scanner_worker_t *workers;  
  pthread_mutex_t *continue_lock;
  pthread_cond_t *continue_cond;
  int keep_scanning;
} scanner_t;

static scanner_t *scanner = NULL;

static inline void send_scan_packet(unsigned char *packet_buffer, 
				    int sockfd,
				    struct sockaddr *dest_addr)
{
  iphdr *ipheader = (iphdr *)&packet_buffer;
  int len = ipheader->tot_len;
  for (int i = START_TTL; i < END_TTL; i++) {
    ipheader->ttl = i;
    for (int j = 0; j < TTL_MODULATION_COUNT; j++) {
      sendto(sockfd, packet_buffer, len, MSG_DONTWAIT | MSG_NOSIGNAL,
	     dest_addr, sizeof(struct sockaddr));
    }
  }
}

static inline void *worker_routine(void* vself)
{
  scanner_worker_t *self = vself;
  int scanning = 1;
  unsigned char packet_buffer[PACKET_LEN];
  int sockfd = self->ssocket->sockfd;
  struct sockaddr_in *dest_addr;
  while ( scanning ) {
    make_packet((unsigned char *)&packet_buffer);
    send_scan_packet((unsigned char *)&packet_buffer, sockfd, 
		     (struct sockaddr *)dest_addr);
  }
  
  return NULL;
}

/**
 * Main loop for the scanner code. ''main" calls this function.
 */

static inline void *worker_routine(void* vself);

static inline int scanner_main_loop()
{
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
  if ((long)worker->ssocket == -1) return -1;

  worker->ssocket->sockfd = socket(AF_INET, SOCK_RAW, 
				   IPPROTO_RAW);  
  if (worker->ssocket->sockfd < 0) return -1;

  worker->thread = malloc(sizeof(pthread_t));
  if ((long)worker->thread == -1) return -1;
  
  worker->random_data = malloc(sizeof(struct random_data));
  if ((long)worker->random_data == -1) return -1;
  
  worker->worker_id = id;
  return id;
}

/** 
 * Either build a scanner singleton or create a completely new one
 *  if we have already built on in the past. This is simply an interfac
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
    if ( new_worker(&scanner->workers[i], i) != i) {
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
