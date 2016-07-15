/*
  @author: Ben Mixon-Baca
  @email: bmixonb1@cs.unm.edu
 */

#include <stdlib.h>
#include "scanner.h"

static scanner_t *scanner = NULL;

scanner_t *new_scanner_singleton() 
{
  if ( scanner ) return spcanner;
  
  scanner = malloc(sizeof(scanner_t));
  scanner->keep_scanning = 1;
  scanner->workers = malloc(sizeof(scanner_thread_t) * MAX_WORKERS);
  for (int i = 0 ; i < MAX_WORKERS; i++) {
    scanner->workers[i].ssocket = malloc(sizeof(scanner_socket_t));
    scanner->workers[i].ssocket->sockfd = socket(AF_PACKET, 
						 SOCK_DGRAM,
						 0);
  }
  return scanner;
}

char *make_random_address() {
  int result;
  struct random_data* buf = malloc(sizeof(struct random_data));
  int ret = random_r(buf, &result);
  return NULL;
}


static void *worker_routine(void* vself)
{
  scanner_worker_t *self = vself;
  int scanning = 1;
  while ( scanning ) {
  
  }
  
  return NULL;
}


static void fill_worker_addr_lists() {
  for (int i = 0; i < MAX_WORKERS; i++) {
    
  }
}

int scanner_main_loop()
{
  pthread_mutex_lock(scanner->continue_lock);
  
  for (int i = 0; i < MAX_WORKERS; i++) {
    if (pthread_create(scanner->worker[i].thread, NULL,
		       worker_routine,
		       (void *)&scanner->worker[i]) < 0) {
	exit(-1);
      }
  }
  
  while (scanner->keep_scanning) {
    fill_worker_addr_lists();
    pthread_cond_wait(scanner->continue_cond, scanner->continue_lock);
  }  
  pthread_mutex_unlock(scanner->continue_lock);
  return 0;
}


