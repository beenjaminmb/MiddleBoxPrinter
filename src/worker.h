/**
 * @author: Ben Mixon-Baca
 * @email: bmixonb1@cs.unm.edu
 */
#ifndef _WORKER
#define _WORKER
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <pcap/pcap.h>
#include "scanner.h"
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>

#ifdef DILLINGER
 #define CAPTURE_INTERFACE "enp0s8"
#else
 #define CAPTURE_INTERFACE "wlan0"
#endif
//#define CAPTURE_IFACE "eth0"
#define MAX_ADDR_SIZE sizeof("255.255.255.255\0")
#define MTU 1500 /* Make size for a probe including payload*/
#define NORMAL_MTU 576 /* Official MTU of the Internet. */
#define RATE 1000000.0 /* 1000 packets per second, 1 Gb/sec */
#define PERIOD 60.0 /* Period in seconds == 1 minute */
#define AVG_PACKET_SIZE 6000.0 /* 750 Bytes == 6000bits */

#ifdef UNITTEST
  #define ADDRS_PER_WORKER 10 //RATE*PERIOD/(MAX_WORKERS*AVG_PACKET_SIZE)
  #define MAX_WORKERS 1
#else
  #define MAX_WORKERS 10
  #define ADDRS_PER_WORKER RATE*PERIOD/(MAX_WORKERS*AVG_PACKET_SIZE)
#endif

typedef struct scanner_socket_t {
  int sockfd;
} scanner_socket_t;


typedef struct probe_t  { 
  struct sockaddr_in *sin;
  unsigned int data_len;
  unsigned char probe_buff[MTU];
  unsigned char good_csum;
  unsigned char proto;
} probe_t;

typedef struct scanner_worker_t {
  pthread_t *thread;
  scanner_socket_t *ssocket;
  struct random_data *random_data;
  struct scanner_t *scanner;
  char *random_state;
  probe_t *probe_list;
  long probe_list_size;
  long probe_idx; 
  int current_ttl;
  int state_size;
  int worker_id;
  double seed;
// list_t *addr_list;
} scanner_worker_t;

static void init_probe_t(probe_t *probe)
{
  probe->sin = smalloc(sizeof(struct sockaddr_in));
  probe->data_len = 0;
  probe->good_csum = 1;
  probe->proto = 0;
  return ;
}

#endif
