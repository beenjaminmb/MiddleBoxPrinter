/*
  @author: Ben Mixon-Baca
  @email: bmixonb1@cs.unm.edu
 */

#ifndef _SCANNER_
#define _SCANNER_

#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>

#define MAX_WORKERS 10
#define PACKETS_PER_SECOND 100

char *make_random_address();

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

typedef struct scanner_packet_t {} scanner_packet_t;

/**
 * Main loop for the scanner code. ''main" calls this function.
 */
int scanner_main_loop();

/** 
 * Either build a scanner singleton or create a completely new one
 *  if we have already built on in the past. This is simply an interfac
 *  to get at the statically declared one.
 */
scanner_t *new_scanner_singleton();

#endif /* _SCANNER_ */
