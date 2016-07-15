#ifndef _SPOOFER_
#define _SPOOFER_

#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#define MAX_WORKERS 10
#define PACKETS_PER_SECOND 100

char *make_random_address();

typedef struct spoofer_socket_t {
  int sockfd;
} spoofer_socket_t;

typedef struct spoofer_worker_t {
  pthread_t *thread;
  spoofer_socket_t *ssocket;
  
} spoofer_thread_t;

typedef struct spoofer_t {
  spoofer_thread_t *workers;
  int keep_spoofing;
} spoofer_t;

typedef struct spoofer_packet_t {} spoofer_packet_t;

int spoofer_main_loop();

spoofer_t *new_spoofer_singleton();

spoofer_packet_t *new_packet();


#endif /* _SPOOFER_ */
