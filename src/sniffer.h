/*
  @author: Ben Mixon-Baca
  @email: bmixonb1@cs.unm.edu
 */
#ifndef _SNIFFER_
#define _SNIFFER_
#include <pthread.h>
#include <pcap/pcap.h>

#ifdef DILLINGER
 #define CAPTURE_FILTER "host 64.106.82.6"
#else
 #define CAPTURE_FILTER "host 192.168.0.6"
#endif

typedef struct sniffer_t {
  int sniff;
  int pid;

  pthread_t *thread;
  pthread_mutex_t *lock;
  pthread_cond_t *cond;

#ifdef USE_PCAP
  pcap_t *cap_handle;
#endif
} sniffer_t;

void start_sniffer(sniffer_t *sniffer, void *args);

void stop_sniffer(sniffer_t *sniffer);

void init_sniffer(sniffer_t *snifferp);

void delete_sniffer(sniffer_t *sniffer);

#endif /* _SNIFFER_*/
