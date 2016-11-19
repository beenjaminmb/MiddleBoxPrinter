/**
 * @author: Ben Mixon-Baca
 * @email: bmixonb1@cs.unm.edu
 */


#ifndef _SCANNER_
#define _SCANNER_

#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include "util.h"
#include "blacklist.h"
#include "worker.h"
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
#define QR_DICT_SIZE 4096

typedef struct scan_args_t {
  char *blacklist;
} scan_args_t;


typedef struct phase_stats_t {
  int total_probes;
  int total_unique_probes;
  int total_responses;
  int total_unique_responses;
  int total_responses_with_retransmissions;
} phase_stats_t;


typedef struct scan_statistics_t {
  /* Probe space, proper is U_i=k^15002^i. Probes are generated randomly from this space. */
  phase_stats_t phase1;
  /* Responses from phase1 are used as the probes from which this statistics are derived */
  phase_stats_t phase2;
  /**
   * If I'm feeling saucy, phase3 will be to query one hosts,
   * then spoof packets to another host,
   * then require the specified host.
   * 
   * This scanning logic for this will be challanging.
   */
  phase_stats_t phase3;
} scan_statistics_t;

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
  char *current_pcap_file_name;
  struct random_data *random_data;
  char *random_state;

  int keep_scanning;
  int phase1;
  int phase2;
  int phase2_wait;
} scanner_t;

struct hash_args {
  unsigned char *keystr;
  unsigned char *value;
};

unsigned long free_list(void *list);

void send_scan_packet(unsigned char *restrict packet_buffer, 
		      int sockfd, 
		      scanner_worker_t *restrict worker,
		      int probe_idx, int ttl);


/**
 * Used for experiments in this project.
 */
void *find_responses(void *vworker);

/**
 * @warning: NOT CURRENTLY USED
 * This is the worker routine that generates packets with varying 
 * fields. Spins up a sniffer thread with with appropriate 
 * pcap filter and sends the pcap off with modulated TTL.
 * 
 * @param: vself. A void pointer to the worker that is actually
 * sending of packets.
 *
 * @return: Always returns NULL.
 */
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

/**
 * Work horse routing for packet separation.
 */
void process_packet(dict_t **dictp, const unsigned char *packetp,
		    phase_stats_t *phase_stats, 
		    struct timeval ts, unsigned int capture_len);


void response_replay(dict_t **dp, phase_stats_t *phase_stats);

dict_t * split_query_response(const char* pcap_fname,
			      phase_stats_t *phase_stats);

void stringify_node( char **str, void *vnode, int direction);

void print_phase_statistics(phase_stats_t *phase_stats);

void copy_query_response_to_scanner(dict_t *qr);
#endif
