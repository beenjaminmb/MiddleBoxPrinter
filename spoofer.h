#ifndef _SPOOFER_
#define _SPOOFER_

#define MAX_THREADS 10
#define PACKETS_PER_SECOND 100


typedef struct spoofer_thread_t {} spoofer_thread_t;

typedef struct spoofer_t {
  
  spoofer_thread_t *workers;
} spoofer_t;

typedef struct spoofer_packet_t {} spoofer_packet_t;


sint spoofer_main_loop();


spoofer_t *new_spoofer_singleton();

spoofer_packet_t *new_packet();


#endif /* _SPOOFER_ */
