#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <stdlib.h>
#include <pcap.h>

#define DEFAULT_SNAPLEN 68

void print_hwadd(u_char *hwadd) {
  int i;
  for (i = 0; i < 5; i++) {
    printf("%2x:", hwadd[i]);
  }
  printf("%2x", hwadd[i]);
}

void packet_print(u_char *user, const struct pcap_pkthdr *h, const u_char *p) {
  struct ether_header *eth;
  int i;

  eth = (struct ether_header *) p;

  print_hwadd(eth->ether_shost);
  printf("->");
  print_hwadd(eth->ether_dhost);
  printf("\n");
}

int main(int argc, char **argv) {
  char ebuf[PCAP_ERRBUF_SIZE];
  pcap_t *pd;

  if (argc <= 1) {
    printf("usage : %s <network interface>\n", argv[0]);
    exit(1);
  }

  if ((pd = pcap_open_live(argv[1], DEFAULT_SNAPLEN, 1, 1000, ebuf)) == NULL) {
    (void) fprintf(stderr, "%s", ebuf);
    exit(1);
  }

  if (pcap_loop(pd, -1, packet_print, NULL) < 0) {
    (void) fprintf(stderr, "pcap_loop: %s\n", pcap_geterr(pd));
    exit(1);
  }
  
  pcap_close(pd);
  
  return 0;
}


