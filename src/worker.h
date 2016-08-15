#ifndef _WORKER
#define _WORKER
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <pcap/pcap.h>



#define CAPTURE_IFACE "wlan0"
#define MAX_ADDR_SIZE sizeof("255.255.255.255\0")
#define MTU 1500 /* Make size for a probe including payload*/
#define NORMAL_MTU 576 /* Official MTU of the Internet. */
#define RATE 10000000.0 /* 1000 packets per second, 1 Gb/sec */
#define PERIOD 60.0 /* Period in seconds == 1 minute */
#define AVG_PACKET_SIZE 6000.0 /* 750 Bytes == 6000bits */

#define UNITTEST 1

#ifdef UNITTEST
  #define ADDRS_PER_WORKER RATE*PERIOD/(MAX_WORKERS*AVG_PACKET_SIZE)
  #define MAX_WORKERS 10
#else
  #define ADDRS_PER_WORKER 5//RATE*PERIOD/(MAX_WORKERS*AVG_PACKET_SIZE)
  #define MAX_WORKERS 1
#endif

typedef struct scanner_socket_t {
  int sockfd;
} scanner_socket_t;

typedef struct sniffer_t {
  pcap_t *cap_handle;
  char *cap_errbuf;
  pthread_t *sniffer_thread;
  pthread_mutex_t *sniffer_lock;
  pthread_cond_t *sniffer_cond;
  int keep_sniffing;
} sniffer_t;

typedef struct probe_t {
  struct sockaddr_in *sin;
  unsigned char probe_buff[MTU];
} probe_t;

typedef struct scanner_worker_t {
  pthread_t *thread;
  sniffer_t *sniffer;
  scanner_socket_t *ssocket;
  struct random_data *random_data;
  char *random_state;
  probe_t *probe_list;
  long probe_idx;
  int current_ttl;
  int state_size;
  int worker_id;
  // list_t *addr_list;
} scanner_worker_t;

#endif
