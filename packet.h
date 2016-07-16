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

#define PACKET_LEN 8192
#define START_TTL 2
#define END_TTL 255
#define TTL_MODULATION_COUNT 3
typedef struct iphdr iphdr;
typedef struct udphdr udphdr;
typedef struct tcphdr tcphdr;

/* Simple checksum function, may use others such as Cyclic Redundancy 
   Check, CRC */
unsigned short csum(unsigned short *buf, int len);


int make_packet(unsigned char *packet_buffer);

#endif /* _PACKET_ */
