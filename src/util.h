/**
 * @author: Ben Mixon-Baca
 * @email: bmixonb1@cs.unm.edu
 */
#ifndef _UTIL_
#define _UTIL_
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "util.h"
#include <errno.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>
#include <pthread.h>
#include "dtable.h"
/*https://stackoverflow.com/questions/2509679/how-to-generate-a-random-number-from-within-a-range */

#define TRUE 1
#define FALSE !TRUE
#define DO_TCP(x) (x < 100) // Change this later
#define DO_UDP(x) ((x >= 50) & (x < 75))
#define DO_ICMP(x) ((x > 74) & (x <= 100))

extern int errno;

static inline double wall_time() __attribute__((always_inline));

static inline long range_random(long, struct random_data *restrict, 
				int *restrict )
  __attribute__((always_inline));

static inline long range_random(long max, 
				struct random_data *restrict buf, 
				int *restrict result) {
  unsigned long
    num_bins = (unsigned long) max + 1,
    num_rand = (unsigned long) RAND_MAX + 1,
    bin_size = num_rand / num_bins,
    defect   = num_rand % num_bins;
  long x;
  do {
    random_r(buf, result);
  }
  while (num_rand - defect <= (unsigned long)*result);
  x = *result/bin_size;
  *result = x;
  return x;
}

static inline double wall_time()
{
  struct timeval t;
  gettimeofday(&t, NULL);
  return 1. * t.tv_sec + 1.e-6 * t.tv_usec;
}


int init_blacklist(char *blacklist);

void *smalloc(int size, char *s, int id);

void sfree(void *ptr);

pthread_cond_t *new_cond();

pthread_mutex_t *new_mutex();

#ifdef EXPERIMENTAL

static char* subnet_prefix(char *ip){
  printf("%s", ip);
  return NULL;
}

static void read_blacklist(dict **d)
{
  char ip_address[256];
  FILE *file = fopen("blacklist.txt", "r");
  while ((fgets(ip_address, 256, file))) {
    int len = strlen(ip_address);
    char *value = malloc(len+1);
    value[len] = '\0';
    strcpy(value, ip_address);
    subnet_prefix(ip_address);
    dict_insert(d, value);
  }
  return;
}
#endif /* EXPERIMENTAL */

#endif /* _UTIL_ */
