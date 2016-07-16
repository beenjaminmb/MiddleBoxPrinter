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

iphdr *make_ipheader(char *buffer) {
  iphdr *ip = malloc(sizeof(iphdr));
  
  ip->check = csum((unsigned short *) buffer, (sizeof(struct iphdr) + 
		    sizeof(struct tcphdr))
		   );
  return ip;
}

int make_packet(unsigned char *packet_buffer) {
  memset(packet_buffer, 0, PACKET_LEN);
  iphdr *ip = make_ipheader( packet_buffer );
  int make_tcp = 0;
  if (make_tcp) {
    
  }
  else { /* Make a UDP */
    
  }
  return 0;
}
