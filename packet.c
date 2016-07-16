/*
  @author: Ben Mixon-Baca
  @email: bmixonb1@cs.unm.edu
 */
#include "packet.h"

unsigned short csum(unsigned short *buf, int len)
{
  unsigned long sum;
  for(sum=0; len>0; len--)
    sum += *buf++;
  sum = (sum >> 16) + (sum &0xffff);
  sum += (sum >> 16);
  return (unsigned short)(~sum);
}

ipheader_t *make_ipheader(char *buffer) {
  ipheader_t *ip = malloc(sizeof(ipheader_t));
  
  ip->iph_chksum = csum((unsigned short *) buffer, 
			(sizeof(struct ipheader_t) + 
			 sizeof(struct tcpheader_t))
			);
  return ip;
}

int make_packet(unsigned char *packet_buffer) {
  memset(packet_buffer, 0, PACKET_LEN);
  ipheader_t *ip = make_ipheader( buf );
  
  if (make_tcp) {

  }
  else { /* Make a UDP */
    
  }
  return buf;
}


