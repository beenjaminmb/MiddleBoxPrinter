/*
  @author: Ben Mixon-Baca
  @email: bmixonb1@cs.unm.edu
 */
#include "packet.h"
#include "util.h"
unsigned short csum(unsigned short *ptr, int nbytes)
{
  register long sum;
  unsigned short oddbyte;
  register short answer;
 
  sum=0;
  while(nbytes>1) {
    sum+=*ptr++;
    nbytes-=2;
  }
  if(nbytes==1) {
    oddbyte=0;
    *((u_char*)&oddbyte)=*(u_char*)ptr;
    sum+=oddbyte;
  }
 
  sum = (sum>>16)+(sum & 0xffff);
  sum = sum + (sum>>16);
  answer=(short)~sum;
     
  return(answer);
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
