#ifndef _WORKER
#define _WORKER
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <pcap/pcap.h>

#define CAPTURE_IFACE "wlan0"
typedef struct scanner_socket_t {
  int sockfd;
} scanner_socket_t;

typedef struct scanner_worker_t {
  pthread_t *thread;
  scanner_socket_t *ssocket;
  struct sockaddr_in *sin;
  struct random_data *random_data;
  char *random_state;
  pcap_t *cap_handle;
  char *cap_errbuf;
  //pthread_mutex_t *cap_lock;
  //pthread_cond_t *cap_cond;
  int state_size;
  int worker_id;
  // list_t *addr_list;
} scanner_worker_t;


#endif