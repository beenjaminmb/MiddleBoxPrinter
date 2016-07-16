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

tcphdr *make_tcpheader(unsigned char *buffer)
{
  struct tcphdr *tcph = (struct tcphdr *)(buffer + sizeof (struct ip));
  //TCP Header
  tcph->source = htons (1234);
  tcph->dest = htons (80);
  tcph->seq = 0;
  tcph->ack_seq = 0;
  tcph->doff = 5;  //tcp header size
  tcph->fin=0;
  tcph->syn=1;
  tcph->rst=0;
  tcph->psh=0;
  tcph->ack=0;
  tcph->urg=0;
  tcph->window = htons (5840); /* maximum allowed window size */
  tcph->check = 0; //leave checksum 0 now, filled later by pseudo header
  tcph->urg_ptr = 0;
}

iphdr *make_ipheader(char *buffer, struct sockaddr_in *sin, 
		     char *source_ip, int datalen) 
{
  iphdr *iph = malloc(sizeof(iphdr));
  
  iph->ihl = 5;
  iph->version = 4;
  iph->tos = 0;
  iph->tot_len = sizeof (struct iphdr) + 
    sizeof (struct tcphdr) + datalen;
  
  iph->id = htonl(1); //Id of this packet
  iph->frag_off = 0;
  iph->ttl = START_TTL;
  iph->protocol = IPPROTO_TCP;
  iph->check = 0;      //Set to 0 before calculating checksum
  iph->saddr = inet_addr( source_ip ); //Spoof the source ip address
  iph->daddr = sin->sin_addr.s_addr;
     
  //Ip checksum
  iph->check = csum ((unsigned short *) buffer, iph->tot_len);
  return iph;
}

int make_packet(unsigned char *packet_buffer, struct sockaddr_in *sin)
{
  memset(packet_buffer, 0, PACKET_LEN);
  iphdr *ip = make_ipheader( packet_buffer, sin, 
			     "192.168.0.1", 10);
  int make_tcp = 0;
  if (make_tcp) {
    
  }
  else { /* Make a UDP */
    
  }
  return 0;
}
