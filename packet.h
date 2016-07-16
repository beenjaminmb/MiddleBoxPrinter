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
#include <netinet/tcp.h>
#include <string.h>

#define PACKET_LEN 8192
#define START_TTL 2
#define END_TTL 255
#define TTL_MODULATION_COUNT 3
typedef struct ipheader_t {
  unsigned char      iph_ihl:5, iph_ver:4;
  unsigned char      iph_tos;
  unsigned short int iph_len;
  unsigned short int iph_ident;
  unsigned char      iph_flag;
  unsigned short int iph_offset;
  unsigned char      iph_ttl;
  unsigned char      iph_protocol;
  unsigned short int iph_chksum;
  unsigned int       iph_sourceip;
  unsigned int       iph_destip;
} ipheader_t;

/* Structure of a TCP header */
struct tcpheader_t {
  unsigned short int tcph_srcport;
  unsigned short int tcph_destport;
  unsigned int       tcph_seqnum;
  unsigned int       tcph_acknum;
  unsigned char      tcph_reserved:4, tcph_offset:4;
  // unsigned char tcph_flags;
  unsigned int
  tcp_res1:4,       /*little-endian*/
    tcph_hlen:4,      /*length of tcp header in 32-bit words*/
    tcph_fin:1,       /*Finish flag "fin"*/
    tcph_syn:1,       /*Synchronize sequence numbers to start a connection*/
    tcph_rst:1,       /*Reset flag */
    tcph_psh:1,       /*Push, sends data to the application*/
    tcph_ack:1,       /*acknowledge*/
    tcph_urg:1,       /*urgent pointer*/
    tcph_res2:2;
  unsigned short int tcph_win;
  unsigned short int tcph_chksum;
  unsigned short int tcph_urgptr;
} tcpheader_t;

// UDP header's structure
typedef struct udpheader_t {
  unsigned short int udph_srcport;
  unsigned short int udph_destport;
  unsigned short int udph_len;
  unsigned short int udph_chksum;
} udpheader_t;

/* Simple checksum function, may use others such as Cyclic Redundancy 
   Check, CRC */
unsigned short csum(unsigned short *buf, int len);


int make_packet(unsigned char *packet_buffer);

#endif /* _PACKET_ */
