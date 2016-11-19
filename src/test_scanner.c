#include "scanner.h"
#include "main.h"
#include "util.h"
#include "packet.h"
#include "worker.h"
#include "blacklist.h"
#include <assert.h>


/* void print_iphdr(iphdr *iph) */
/* { */
/*   printf("IP HEADER:\n"); */
/*   printf("iph->ihl: %x\n",  iph->ihl); */
/*   printf("iph->version: %x\n", iph->version); */
/*   printf("iph->tos: %x\n", iph->tos); */
/*   printf("iph->tot_len: %x\n", iph->tot_len); */
/*   printf("iph->id: %x\n", iph->id); */
/*   printf("iph->frag_off: %x\n", iph->frag_off); */
/*   printf("iph->ttl: %x\n", iph->ttl); */
/*   printf("iph->check: %x\n", iph->check); */
/*   printf("iph->protocol: %x\n", iph->protocol); */
/*   printf("iph->saddr: %x\n", iph->saddr); */
/*   printf("iph->daddr: %x\n", iph->daddr); */
/* } */

/* void print_probe(iphdr *iph) */
/* { */
  
/*   print_iphdr(iph); */
/*   return ; */
/* } */

int test_worker_generate(scanner_worker_t *worker)
{
  double seconds = -wall_time();
  for (int i = 0; i < ADDRS_PER_WORKER; i++) {
    make_packet(worker->probe_list[i].probe_buff, worker, i);
    iphdr *iph = (iphdr*)worker->probe_list[i].probe_buff;
    //print_probe(iph);
  }
  seconds += wall_time();
  printf("%d %s: ADDRS_PER_WORKERS %.2f WALL TIME %f\n", 
	 __LINE__, __func__, ADDRS_PER_WORKER, seconds);

  return 1;
}

int test_send_rate(scanner_worker_t *worker)
{
  double seconds = -wall_time();
  double other_time = -wall_time();
  int ttl = 2;
  printf("current ttl %d, end ttl %d\n", ttl, END_TTL);
  while ( worker->current_ttl < END_TTL ) {
    for (int i = 0; i < ADDRS_PER_WORKER; i++) {
      /* if(i == 1000) */
      /* 	{ */
      /* 	  other_time+= wall_time(); */
      /* 	  printf("1000 packets in %f sec, rate %f", other_time, */
      /* 		 i/other_time); */
      /* 	} */
      send_scan_packet((unsigned char *)
		       &worker->probe_list[i].probe_buff,
		       worker->ssocket->sockfd,
		       worker, i, ttl);
    }
    ttl++;
    worker->probe_idx = 0;
    worker->current_ttl = ttl;
  }
  seconds += wall_time();
  printf("%d %s: WALL TIME %f\n", 
	 __LINE__, __func__, seconds);
  return 1;
}

int run_tests() {
  scanner_worker_t worker;
  int points = 0;
  double seconds = -wall_time();
  points = new_worker(&worker, 0) == 0 ? 1 : 0;
  seconds += wall_time();
  printf("points: %d, wall time: %f sec \n", points, seconds);
  init_blacklist("blacklist.conf");
  points += test_worker_generate(&worker);
  //points += test_send_rate(&worker);
  printf("points: %d \n", points);
  return 0; 
}

int main(void) 
{
  run_tests();
  return 0;
}
