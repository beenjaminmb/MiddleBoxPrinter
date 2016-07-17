/*
  @author: Ben Mixon-Baca
  @email: bmixonb1@cs.unm.edu
   
  packet header code and checksum from:
  http://www.tenouk.com/Module43a.html
 */
#ifndef _PACKET_
#define _PACKET_

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "worker.h"

#define PACKET_LEN 4096
#define START_TTL 2
#define END_TTL 255
#define TTL_MODULATION_COUNT 3
#define TEST_IP "192.168.0.1"
#define SRC_IP "192.168.0.3"
#define TEST_DATA_LEN 0
typedef struct iphdr iphdr;
typedef struct udphdr udphdr;
typedef struct tcphdr tcphdr;

typedef struct pseudo_header
{
  u_int32_t source_address;
  u_int32_t dest_address;
  u_int8_t placeholder;
  u_int8_t protocol;
  u_int16_t total_length;
} pseudo_header;

/* Simple checksum function, may use others such as Cyclic Redundancy 
   Check, CRC */
unsigned short csum(unsigned short *ptr, int nbytes);

int make_packet(unsigned char *packet_buffer,
		  scanner_worker_t *worker);

#endif /* _PACKET_ */
