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
/*https://stackoverflow.com/questions/2509679/how-to-generate-a-random-number-from-within-a-range */

#define DO_TCP(x) (x < 50)
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

/* #define _RINGBUFFER 0 */

/* #ifdef _RINGBUFFER */
/* #define memory_barrier()    asm volatile("mfence":::"memory") */
/* #define read_barrier()   asm volatile("lfence":::"memory") */
/* #define write_barrier()   asm volatile("sfence" ::: "memory") */

/* typedef struct ringbuffer_cell { */
/*   void *value; */
/* } ringbuffer_cell_t; */

/* typedef struct ringbuffer { */
/*   ringbuffer_cell_t *head, *tail; */
/*   ringbuffer_cell_t *buf, *end; */
/*   pthread_mutex_t *rb_lock; */
/*   pthread_cond_t *rb_empty; */
/*   pthread_cond_t *rb_full; */
/* } ringbuffer_t; */

/* int ringbuffer_init(ringbuffer_t *rb, int len); */
/* int ringbuffer_destroy(ringbuffer_t *rb); */
/* int ringbuffer_append_single(ringbuffer_t *rb, void *item); */
/* int ringbuffer_remove_single(ringbuffer_t *rb, void **item); */
/* int ringbuffer_empty(ringbuffer_t *rb); */
/* int ringbuffer_full(ringbuffer_t *rb); */
/* #endif */

#endif /* _UTIL_ */
