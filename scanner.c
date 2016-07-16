/*
  @author: Ben Mixon-Baca
  @email: bmixonb1@cs.unm.edu
 */

#include <stdlib.h>
#include "scanner.h"

static scanner_t *scanner = NULL;

scanner_t *new_scanner_singleton() 
{
  if ( scanner ) return spcanner;
  
  scanner = malloc(sizeof(scanner_t));
  scanner->keep_scanning = 1;
  scanner->workers = malloc(sizeof(scanner_thread_t) * MAX_WORKERS);
  for (int i = 0 ; i < MAX_WORKERS; i++) {
    scanner->workers[i].ssocket = malloc(sizeof(scanner_socket_t));
    scanner->workers[i].ssocket->sockfd = socket(AF_PACKET, 
						 SOCK_DGRAM,
						 0);
  }
  return scanner;
}

char *make_random_address() {
  int result;
  struct random_data* buf = malloc(sizeof(struct random_data));
  int ret = random_r(buf, &result);
  return NULL;
}

/*
While (1)
   Create a random IPv4 packet
   For length, checksum, etc. make it correct 90% of the time,
   incorrect in a random way 10%
   For protocol, TCP 50% of the time, UDP 25%, random 25%
   Dest address random, source address our own (not bound to an
   interface)
   10% of the time have a randomly generated options field

   if (TCP) 
       fill in TCP header as below
   if (UDP or other) 
       fill in rest of IP packet with random junk
       Send it in a TTL-limited fashion

for TCP packets:
50% chance of random dest port, 50% chance of common (22, 80,
etc.)
seq and ack numbers random
Flags random but biased towards usually only 1 or 2 bits set
with 10% chance add randomly generated options
Reserved 0 50% of the time and random 50% of the time
Window random
Checksum correct 90% of the time, random 10%
Urgent pointer not there 90% of the time, random 10% of the time


Then we just send out this kind of traffic at 1 Gbps or so and take a
pcap of all outgoing and incoming packets for that source IP, and store
that on the NFS mount for later analysis
*/


static void send_scan_packet(unsigned char *packet_buffer, 
			     int sockfd, struct sockaddr *dest_addr)
{
  ipheader_t *iphdr = &packet_buffer;
  int len = iphdr->iph_len;
  for (int i = START_TTL; i < END_TTL; i++) {
    iphdr->iphdr_ttl = i;
    for (int j = 0; j < TTL_MODULATION_COUNT; j++) {
      sendto(sockfd, packet_buffer, len, MSG_DONTWAIT | MSG_NOSIGNAL,
	     dest_addr, sizeof(struct sockaddr));
    }
  }
}


static void *worker_routine(void* vself)
{
  scanner_worker_t *self = vself;
  int scanning = 1;
  unsigned char packet_buffer[PACKET_LEN];
  int sockfd = self->sscoket->sockfd;
  struct sockaddr_in *dest_addr;
  while ( scanning ) {
    make_packet(&packet_buffer);

    send_scan_packet(&packet_buffer, sockfd, 
		     (struct sockaddr *)dest_addr);
  }
  
  return NULL;
}

int scanner_main_loop()
{
  pthread_mutex_lock(scanner->continue_lock);
  
  for (int i = 0; i < MAX_WORKERS; i++) {
    if (pthread_create(scanner->worker[i].thread, NULL,
		       worker_routine,
		       (void *)&scanner->worker[i]) < 0) {
	exit(-1);
      }
  }
  
  while (scanner->keep_scanning) {
    pthread_cond_wait(scanner->continue_cond, scanner->continue_lock);
  }
  pthread_mutex_unlock(scanner->continue_lock);
  return 0;
}


