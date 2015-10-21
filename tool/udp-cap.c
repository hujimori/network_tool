#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <netinet/ip.h>
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

static void print_udpheader(struct ip *ip) {
  struct udphdr *udp;
  udp = (struct udphdr *) ((char *) ip + (ip->ip_hl << 2));
  printf("--------------------UDP--------------------\n");
  printf("uh_sport = %d\n", ntohs(udp->uh_sport));
  printf("uh_dport = %d\n", ntohs(udp->uh_dport));
  printf("uh_ulen = %d bytes\n", ntohs(udp->uh_ulen));
  printf("uh_sum = 0x%.4x\n", ntohs(udp->uh_sum));
  printf("\n");
}

static void print_tcpheader(struct ip *ip) {
  unsigned char *data;
  struct tcphdr *tcp;
  tcp = (struct tcphdr *) ((char *) ip + (ip->ip_hl << 2));
  printf("--------------------TCP--------------------\n");
  printf("th_sport = %d\n", ntohs(tcp->th_sport));
  printf("th_dport = %d\n", ntohs(tcp->th_dport));
  printf("th_seq = %d\n", ntohs(tcp->th_seq));
  printf("th_ack = %d\n", ntohs(tcp->th_ack));
  printf("flags = %d\n", ntohs(tcp->th_flags));
  printf("th_win = %d\n", ntohs(tcp->th_win));
  printf("th_sum = %d\n", ntohs(tcp->th_sum));
  printf("th_urp = %d\n", ntohs(tcp->th_urp));
 // strcpy(data, (char *) tcp + (tcp->th_off << 2));
  data = (char *) malloc(sizeof(char) * 65535);
  (char *) tcp + (tcp->th_off << 2);
  printf("--------------------data--------------------\n");
  printf("%s\n", (char *) tcp + (tcp->th_off << 2));
  //printf("\n");
}

static void print_icmpheader(struct ip *ip) {
  struct icmphdr *icmp;
  icmp = (struct icmphdr *) ((char *) ip + (ip->ip_hl << 2));
  printf("--------------------ICMP--------------------\n");
  switch (icmp->type) {
    case ICMP_ECHOREPLY:
      printf("Type: Echo Reply\n");
      printf("Code: Echo Reply Message");
      break;
    case ICMP_DEST_UNREACH:
      printf("Type: Destination Unreachable\n");
      switch (icmp->code) {
        case ICMP_NET_UNREACH:
          printf("Code: Network Unreachable\n");
          break;
        case ICMP_HOST_UNREACH:
          printf("Code: Host Unreachable\n");
          break;
        case ICMP_PROT_UNREACH:
          printf("Code: Protocol Unreachable\n");
          break;
        case ICMP_PORT_UNREACH:
          printf("Code: Port Unreachable\n");
          break;
        case ICMP_FRAG_NEEDED:
          printf("Code: Fragmentation Needed\n");
          break;
        case ICMP_SR_FAILED:
          printf("Code: Source Route failed\n");
          break;
        case ICMP_NET_UNKNOWN:
          printf("Code: Destination Network Unknown\n");
          break;
        case ICMP_HOST_UNKNOWN:
          printf("Code: Destination Networl Unknown\n");
          break;
        case ICMP_HOST_ISOLATED:
          printf("Code: Source Host Isolated\n");
          break;
        case ICMP_NET_ANO:
          printf("Code: Communication with Destination Network is Administratively Prohibited\n");
          break;
        case ICMP_HOST_ANO:
          printf("Code: Communication with Destination Host is Administratively Prohibited\n");
          break;
        case ICMP_NET_UNR_TOS:
          printf("Code: Destination Network Unreachable for Type of Service\n");
          break;
        case ICMP_HOST_UNR_TOS:
          printf("Code: Destination Host Unreachable for Type of Service\n");
          break; 
        case ICMP_PKT_FILTERED:
          printf("Code: Communication Administratively Prohibited\n");
          break;
        case ICMP_PREC_VIOLATION:
          printf("Code: Host Preference Violation\n");
          break;
        case ICMP_PREC_CUTOFF:
          printf("Code: Precedence Cutoff in Effect\n");
          break;
        default:
          break;
      }
      break;
    case ICMP_REDIRECT:
      printf("Type: Redirect\n");
      switch (icmp->code) {
        case ICMP_REDIR_NET:
          printf("Code: Redirect Datagrams for the Network\n");
          break;
        case ICMP_REDIRECT_HOST:
          printf("Code: Redirect Datagrams for the Host\n");
          break;
        case ICMP_REDIR_NETTOS:
          printf("Code: Redirect Datagrams for the Type of Service and Network\n");
          break;
        case ICMP_REDIR_HOSTTOS:
          printf("Code: Redirect Datagrams for the Type of Service and Host\n");
          break;
        default:
          break;
      }
      break;
    case ICMP_ECHO:
      printf("Tyep: Echo Request\n");
      printf("Code: Echo Request\n");
      break;
    case ICMP_TIME_EXCEEDED:
      printf("Type: Time Exceeded\n");
      switch (icmp->code) {
        case ICMP_EXC_TTL:
          printf("Code: Time to Live exceeded in Transit\n");
          break;
        case ICMP_EXC_FRAGTIME:
          printf("Code: Fragment Reassembly Time Exceeded\n");
          break;
        default:
          break;
      }
      break;
    default:
      printf("Type: unknown\n");
      break;
  }
  printf("Checksum: %d\n", ntohs(icmp->checksum)); 
}

static void print_ipheader(char *p) {
  struct ip *ip;
  ip = (struct ip *) p;
  printf("ip_v = 0x%x\n", ip->ip_v);
  printf("ip_hl = 0x%x\n", ip->ip_hl);
  printf("ip_tos = 0x%x\n", ip->ip_tos);
  printf("ip_len = 0x%x\n", ip->ip_len);
  printf("ip_id = 0x%x\n", ip->ip_id);
  printf("ip_off = 0x%x\n", ip->ip_off);
  printf("ip_ttl = 0x%x\n", ip->ip_ttl);
  printf("ip_p = 0x%x\n", ip->ip_p);
  printf("ip_sum = 0x%x\n", ntohs(ip->ip_sum));
  printf("ip_src = 0x%s\n",inet_ntoa(ip->ip_src));
  printf("ip_dst = 0x%s\n", inet_ntoa(ip->ip_dst));
  printf("\n");

  switch (ip->ip_p) {
    case IPPROTO_UDP:
      printf("udp\n");
      print_udpheader(ip);
      break;
    case IPPROTO_TCP:
      printf("tcp\n");
      print_tcpheader(ip);
      break;
    case IPPROTO_ICMP:
      printf("icmp\n");
      print_icmpheader(ip);
      break;
    default:
      break;
  }
}

static void usage(char *prog) {
  fprintf(stderr, "Usage: %s <device> <packet filter>\n", prog);
  exit(EXIT_FAILURE);
}

int main(int argc, char *argv[]) {
  pcap_t *handle;
  const unsigned char *packet;
  char *dev, *filter;
  char errbuf[PCAP_ERRBUF_SIZE];
  struct pcap_pkthdr header;
  struct bpf_program fp;
  bpf_u_int32 net;

  if ((dev = argv[1]) == NULL)
    usage(argv[0]);

  if ((filter = argv[2]) == NULL )
    usage(argv[0]);

  // 受信用のデバイスを開く
  if ((handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf)) == NULL) {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    exit(EXIT_FAILURE);
  }

  // イーサネットのみ
  if (pcap_datalink(handle) != DLT_EN10MB) {
    fprintf(stderr, "Device not support: %s\n", dev);
    exit(EXIT_FAILURE);
  }

  //  パケットフィルター設定
  if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
    fprintf(stderr, "Device not support: %s\n", dev);
    exit(EXIT_FAILURE);
  }  
  if (pcap_setfilter(handle, &fp) == -1) {
    fprintf(stderr, "coudln't install filter: %s\n", pcap_geterr(handle));
  }

  //  ループでパケット受信
  while (1) {
    if ((packet = pcap_next(handle, &header)) == NULL)
      continue;

    //  イーサネットヘッダーとIPヘッダーの合計サイズに満たなければ無理
 //   if (header.len < sizeof(struct ether_header) + sizeof(struct ip))
   //   continue;
    print_ipheader((char *) (packet + sizeof(struct ether_header)));
  }

  pcap_close(handle);
  return 0;

}
