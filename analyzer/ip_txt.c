#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <pcap.h>

#define DEFAULT_SNAPLEN 68

void packet_print(u_char *user, const struct pcap_pkhdr *h, const u_char *p) {
  struct ip *iph;

  if (ntohs(((struct ether_header *)p)->ether_type) == ETHERTYPE_IP) {
    iph = (struct ip *) (p + sizeof(struct ether_header));
    printf("Find IP datagram\n");
  } 

}

int main(int argc, char **argv) {
  char ebuf[PCAP_ERRBUF_SIZE];
  pcap_t *pd;

  if (argc <= 1) {
    printf("Usage : %s <network interface>\n", argv[0]);
    exit(0);
  }
  
  if ((pd = pcap_open_live(argv[1], DEFAULT_SNAPLEN, 1, 1000, ebuf)) == NULL) {
    (void) fprintf(stderr, "%s", ebuf);
    exit(1);
  }

  if (pcap_loop(pd, -1, packet_print, NULL) < 0) {
    (void) fprintf(stderr, "pcap_loop: %s\n", pcap_geterr(pd));
    exit(1);
  }

}
