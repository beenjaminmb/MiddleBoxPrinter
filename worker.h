#ifndef _WORKER
#define _WORKER
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <pcap/pcap.h>

#define MAX_WORKERS 10
#define CAPTURE_IFACE "wlan0"
#define MAX_ADDR_SIZE sizeof("255.255.255.255\0")
#define MTU 1500 /* Make size for a probe including payload*/
#define NORMAL_MTU 576
#define RATE 1000000000.0 /* 1 Gb/sec */
#define PERIOD 60.0 /* Period in seconds == 1 minute */
#define AVG_PACKET_SIZE 6000.0 /* 750 Bytes == 6000bits */
#define ADDRS_PER_WORKER RATE*PERIOD/(MAX_WORKERS*AVG_PACKET_SIZE)
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

typedef char addr_buff_t[MAX_ADDR_SIZE];

typedef struct addr_list_t {
  addr_buff_t *address;
  long addr_idx;
} addr_list_t;

typedef char probe_buff_t[MTU];

typedef struct probe_list_t {}

typedef struct scanner_worker_t {
  pthread_t *thread;
  sniffer_t *sniffer;
  scanner_socket_t *ssocket;
  struct sockaddr_in *sin;
  struct random_data *random_data;
  addr_list_t *addresses;
  char *random_state;
  int state_size;
  int worker_id;
  // list_t *addr_list;
} scanner_worker_t;

#endif
