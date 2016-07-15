/*
  @author: Ben Mixon-Baca
  @email: bmixonb1@cs.unm.edu
 */

#include <stdlib.h>
#include "spoofer.h"

static spoofer_t *spoofer = NULL;

spoofer_t *new_spoofer_singleton() 
{
  if ( spoofer ) return spoofer;
  
  spoofer = malloc(sizeof(spoofer_t));
  spoofer->keep_spoofing = 1;
  spoofer->workers = malloc(sizeof(spoofer_thread_t) * MAX_WORKERS);
  for (int i = 0 ; i < MAX_WORKERS; i++) {
    spoofer->workers[i].ssocket = malloc(sizeof(spoofer_socket_t));
    spoofer->workers[i].ssocket->sockfd = socket(AF_PACKET, 
						 SOCK_DGRAM,
						 0);
  }
  return spoofer;
}

char *make_random_address() {
  int result;
  struct random_data* buf = malloc(sizeof(struct random_data));
  int ret = random_r(buf, &result);
  return NULL;
}

int spoofer_main_loop()
{
  
  while (spoofer->keep_spoofing) {
    
  }
  
  return 0;
}
