#ifndef _SNIFFER_
#define _SNIFFER_
#include <pthread.h>
#include <pcap/pcap.h>

typedef struct sniffer_t {
  pthread_t *thread;
  pcap_t *cap_handle;
  pthread_mutex_t *lock;
  pthread_cond_t *cond;
  int sniff;
} sniffer_t;


void start_sniffer(sniffer_t *sniffer, void *args);

void stop_sniffer(sniffer_t *sniffer);

void init_sniffer(sniffer_t **snifferp);

void delete_sniffer(sniffer_t *sniffer);

#endif /* _SNIFFER_*/
