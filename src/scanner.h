/**
 * @author: Ben Mixon-Baca
 * @email: bmixonb1@cs.unm.edu
 */

#ifndef _SCANNER_
#define _SCANNER_

#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "worker.h"
#include "util.h"
#include "sniffer.h"
#include "dtable.h"
#include <pcap.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>

#define DEBUG 0
#define TEST_SEED 0
#define STATE_SIZE 8
#define SCAN_DURATION 3600.0
/* Change back to 128 when we fix the memory leak.*/
// #define QR_DICT_SIZE 2
#define QR_DICT_SIZE 3072

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

  sniffer_t *sniffer;
  
  int keep_scanning;
  int phase1;
  int phase2;
  int phase2_wait;
} scanner_t;

struct hash_args {
  unsigned char *keystr;
  unsigned char *value;
};


struct packet_value {
  unsigned char *packet;
  int capture_len;
};

unsigned long free_list(void *list);

void send_scan_packet(unsigned char *restrict packet_buffer, 
		      int sockfd, 
		      scanner_worker_t *restrict worker,
		      int probe_idx, int ttl);

void *worker_routine(void* vself); 

int scanner_main_loop();

int new_worker(scanner_worker_t *worker, int id);

void send_phase1_packet(unsigned char *restrict packet_buffer, 
		   scanner_worker_t *restrict worker, int probe_idx,
		   int sockfd);

void phase1(scanner_worker_t *self);

void phase2(scanner_worker_t *self);

void delete_conds();

void delete_conds();

void delete_workers(scanner_worker_t *scanner);

void delete_scanner();

void  got_packet(u_char * restrict args,
		 const struct pcap_pkthdr * restrict header,
		 const u_char *restrict packet);

void generate_phase2_packets();

void phase2_wait(scanner_worker_t *self);

void delete_scanner();

int scanner_main_loop();

scanner_t *new_scanner_singleton();

void process_packet(dict_t **dictp, const unsigned char *packetp,
		    struct timeval ts, unsigned int capture_len);


void response_replay(dict_t **dp);

dict_t * split_query_response(const char* pcap_fname);

void stringify_node( char **str, void *vnode, int direction);

#endif
