/*
  @author: Ben Mixon-Baca
  @email: bmixonb1@cs.unm.edu
 */
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include "util.h"
#include "sniffer.h"
#include "scanner.h"
#include "worker.h"
#include "packet.h"
#include <pcap.h>

void init_sniffer(sniffer_t *sniffer)
{
  sniffer->thread =
    smalloc_msg(sizeof(pthread_t),
		"scanner couldn't allocate sniffer thread %d\n", 0);
  
  sniffer->lock = new_mutex();
  sniffer->cond = new_cond();

  sniffer->pid = -1;
  sniffer->sniff = 1;

#ifdef USE_PCAP
  init_libpcap_capture(snifferp);
#endif

  return;  
}


void stop_sniffer(sniffer_t *sniffer)
{  

#ifdef USE_PCAP
  assert(0);
#else
  kill(sniffer->pid, SIGKILL);
  sniffer->pid = 0;
#endif
  return;
}
 
void delete_sniffer(sniffer_t *sniffer)
{
  sfree(sniffer->thread);
  sniffer->thread = NULL;


#ifdef USE_PCAP
  sfree(sniffer->cap_handle);
  sniffer->cap_handle = NULL;
#endif

  sfree(sniffer->lock);
  sniffer->lock = NULL;
  
  sfree(sniffer->cond);
  sniffer->cond = NULL;

  sfree(sniffer);
  
  return;
}

void start_sniffer(sniffer_t *sniffer, void *args)
{
  
#ifdef USE_PCAP
  assert(0);

#else
  int pid = fork();
  if ( pid  ==  0 ) {
    char *capture_file = (char*)args;
    printf("sniffing sniffer in child\n");
    const char *tcpdump[] = {"/usr/sbin/tcpdump" , "-i",
			     CAPTURE_INTERFACE, "-w", capture_file,
			     CAPTURE_FILTER, NULL};
    const char *envp[] = {NULL};
    int ret = execve(tcpdump[0], (char**)tcpdump, (char**)envp);
    if ( ret == -1 ) {
      printf("Failed to open tcpdump exiting %d %s\n", 
	     errno, strerror(errno));
      exit(-1);
    }
    return ;
  } 
  else {
    sleep(1);
    sniffer->pid = pid;
    printf("sniffer started\n");
  }
  return;
#endif /* Return should be handled by either section of code.*/

}

#ifdef USE_PCAP

void got_packet(u_char *args, const struct pcap_pkthdr *header,
		const u_char *packet)
{

}

void *sniffer_function(void * args)
{
  scanner_t *scanner = args;
  sniffer_t *sniffer = scanner->sniffer;
  int run = 1;
  struct bpf_program fp;
  char filter_exp[] = "port 23";/* The filter expression */
  bpf_u_int32 mask;/* Our netmask */
  bpf_u_int32 net;/* Our IP */

  pcap_t *handle = sniffer->cap_handle; /* Session handle */

  char errbuf[PCAP_ERRBUF_SIZE]; /* Error string */
  struct bpf_program fp;/* The compiled filter */
  char filter_exp[] = "host " SRC_IP;/* The filter expression */

  bpf_u_int32 mask; /* Our netmask */
  bpf_u_int32 net; /* Our IP */

  struct pcap_pkthdr header;/* The header that pcap gives us */
  const u_char *packet;/* The actual packet */

  /* Open the session in promiscuous mode */
  handle = pcap_open_live(CAPTURE_INTERFACE, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    printf(stderr, "Couldn't open device %s: %s\n", 
	   CAPTURE_INTERFACE, errbuf);
    exit(-1);
  }
  /* Compile and apply the filter */
  if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
    printf(stderr, "Couldn't parse filter %s: %s\n", 
	   filter_exp, pcap_geterr(handle));
    exit(-1);
  }
  if (pcap_setfilter(handle, &fp) == -1) {
    printf(stderr, "Couldn't install filter %s: %s\n",
	   filter_exp, pcap_geterr(handle));
    exit(-1);
  }


  while ( run ) {
    // Use pcap_loop or pcap_dispatch with a callback
    pcap_loop(sniffer->cap_handle, &header);

    pthread_mutex_lock(sniffer->lock);
    if ( !sniffer->sniff ) {
      run = 0;
    }
    pthread_mutex_unlock(sniffer->lock);

    
  }
  pcap_close(handle);

  return NULL;
}

void init_libpcap_capture(sniffer_t **snifferp)
{
  sniffer_t *sniffer = *snifferp;
  pcap_t *handle = sniffer->cap_handle;
  char errbuf[PCAP_ERRBUF_SIZE];

  // Find the properties for the device
  if (pcap_lookupnet(CAPTURE_INTERFACE, &net, &mask, errbuf) == -1) {
    printf(stderr, "Couldn't get netmask for "
  	   "device %s: %s\n",  CAPTURE_INTERFACE, errbuf);
    net = 0;
    mask = 0;
    exit(-1);
  }
  scanner->sniffer->cap_handle = 
    smalloc_msg(sizeof(pcap_t), "scanner couldn't allocate sniffer "
		"capture handle %d\n", 0);

}

#endif
