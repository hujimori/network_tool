#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
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
#include <net/ethernet.h>

#define FTP_PORT 21
#define SSH_PORT 22
#define TELNET_PORT 23
#define SMTP_PORT 25
#define NAMESERVER_PORT 53
#define HTTP_PORT 80
#define NETBIOS_NS_PORT 137
#define NETBIOS_SSN_PORT 139
#define BGP_PORT 179
#define RPKI_RTR_PORT 323
#define SMB_PORT 445
#define RTSP_PORT 554
#define MSDP_PORT 639
#define LDP_PORT 646
#define PPTP_PORT 1723
#define NFS_PORT 2049
#define OPENLOW_PORT_OLD 6633
#define OPENLOW_PORT_IAMA 6653
#define HTTP_PORT_ALT 8080
#define RTSP_PORT_ALT 8554
#define BEEP_PORT 10288

static void usage(char *prog);
static void print_time();
static void print_ethernetheader(char *p);
static void print_arpheader(struct ether_header *ether);
static void print_udpheader(struct ip *ip);
static void print_tcpheader(struct ip *ip);
static void print_icmpheader(struct ip *ip);
static void print_ipheader(char *p);
static void print_application_layer(unsigned int sport, unsigned int dport);


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
  int count = 0;
  //  ループでパケット受信
  while (1) {
    if ((packet = pcap_next(handle, &header)) == NULL)
      continue;

    //  イーサネットヘッダーとIPヘッダーの合計サイズに満たなければ無理
    if (header.len < sizeof(struct ether_header) + sizeof(struct ip))
      continue;
    printf("Packet Number : %d\n", ++count);
    print_time();
    print_ethernetheader((char *) packet);
    print_ipheader((char *) (packet + sizeof(struct ether_header)));
    printf("\n");
  }

  pcap_close(handle);
  return 0;

}

static void print_application_layer(unsigned int sport, unsigned int dport) {
  printf("--------------------DATA--------------------\n");
  if (sport == FTP_PORT || dport == FTP_PORT) {
    printf("Protocol: File Transfer Protocol(FTP)\n");
  } else if (sport == SSH_PORT || dport == SSH_PORT) {
    printf("Protocol: Secure Shell(SSH)\n");
  } else if (sport == TELNET_PORT || dport == TELNET_PORT) {
    printf("Protocol: Teltype network(Telnet)\n");
  } else if (sport == SMTP_PORT || dport == SMTP_PORT) {
    printf("Protocol: Simple Mail Transfer Protocol(SMTP)\n");
  } else if (sport == HTTP_PORT || dport == HTTP_PORT || sport == HTTP_PORT_ALT || dport == HTTP_PORT_ALT) {
    printf("Protocol: Hypertext Transfer Protocol(HTTP)\n");
  } else if (sport == NETBIOS_SSN_PORT || dport == NETBIOS_SSN_PORT) {
    printf("Protocol: Network Basic Input Output System Session services(NETBIOS-SSN)\n");
  } else if (sport == BGP_PORT || dport == BGP_PORT) {
    printf("Protocol: Border Gateway Protocol(BGP)\n");
  } else if (sport == RPKI_RTR_PORT || dport == RPKI_RTR_PORT) {
    printf("Protocol: Resource Public Key Infrastructure-to-Router(RPKI-RTR)\n");
  } else if (sport == SMB_PORT || dport == SMB_PORT) {
    printf("Protocol: Server Message Block(SMB)\n");
  } else if (sport == RTSP_PORT || dport == RTSP_PORT || sport == RTSP_PORT_ALT || dport == RTSP_PORT_ALT) {
    printf("Protocol: Real Time Streaming Protocol(RTSP)\n");
  } else if (sport == MSDP_PORT || dport == MSDP_PORT) {
    printf("Protocol: Multicast Source Discovery Protocol(MSDP)\n");
  } else if (sport == LDP_PORT || dport == LDP_PORT) {
    printf("Protocol: Label Distribution Protocol(LDP)\n");
  } else if (sport == PPTP_PORT || dport == PPTP_PORT) {
    printf("Protocol: Point to Point Tunneling Protocol(PPTP)\n");
  }
}

static void print_udpheader(struct ip *ip) {
  struct udphdr *udp;
  udp = (struct udphdr *) ((char *) ip + (ip->ip_hl << 2));
  printf("--------------------UDP header--------------------\n");
  printf("Src Port: %d\n", ntohs(udp->uh_sport));
  printf("Dst Port: %d\n", ntohs(udp->uh_dport));
  printf("Length:   %dbytes\n", ntohs(udp->uh_ulen));
  printf("Checksum: 0x%.4x\n", ntohs(udp->uh_sum));
  print_application_layer(ntohs(udp->uh_sport), ntohs(udp->uh_dport));
  printf("%s\n", (char *) udp + 8);
}

static void print_tcpheader(struct ip *ip) {
  unsigned char *data;
  struct tcphdr *tcp;
  tcp = (struct tcphdr *) ((char *) ip + (ip->ip_hl << 2));
  printf("--------------------TCP header--------------------\n");
  printf("Src Port: %d\n", ntohs(tcp->th_sport));
  printf("Dst Port: %d\n", ntohs(tcp->th_dport));
  printf("Seq:      %d\n", ntohs(tcp->th_seq));
  printf("Ack:      %d\n", ntohs(tcp->th_ack));
  switch (tcp->th_flags) {
    case TH_FIN:
      printf("Flag: FIN\n");
      break;
    case TH_SYN:
      printf("Flag: SYN\n");
      break;
    case TH_RST:
      printf("Flag: RST\n");
      break;
    case TH_PUSH:
      printf("Flag: PUSH\n");
      break;
    case TH_ACK:
      printf("Flag: ACK\n");
      break;
    case TH_URG:
      printf("Flag: URG\n");
      break;
    default:
      break;
  }
  printf("Window:   %dbytes\n", ntohs(tcp->th_win));
  printf("Checksum: 0x%.4x\n", ntohs(tcp->th_sum));
  printf("Urp:      %d\n", ntohs(tcp->th_urp));
  print_application_layer(ntohs(tcp->th_sport), ntohs(tcp->th_dport)); 
  // strcpy(data, (char *) tcp + (tcp->th_off << 2));
  //printf("--------------------data--------------------\n");
  printf("%s\n", (char *) tcp + (tcp->th_off << 2));
  //printf("\n");
}

static void print_icmpheader(struct ip *ip) {
  struct icmphdr *icmp;
  icmp = (struct icmphdr *) ((char *) ip + (ip->ip_hl << 2));
  printf("--------------------ICMP header--------------------\n");
  switch (icmp->type) {
    case ICMP_ECHOREPLY:
      printf("Type: Echo Reply\n");
      printf("Code: Echo Reply Message\n");
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
  printf("--------------------IP header--------------------\n");
  printf("IP Version:     %d\n", ip->ip_v);
  printf("Header Length:  %d bytes\n", ip->ip_hl);
  printf("TOS:            %x\n", ip->ip_tos);
  printf("Length:         %d bytes\n", ip->ip_len);
  printf("ID:             %d\n", ip->ip_id);
  printf("OFFSET:         0x%x\n", ip->ip_off);
  printf("TTL:            %d\n", ip->ip_ttl);
  switch (ip->ip_p) {
    case IPPROTO_UDP:
      printf("Protocol: User Datagram Protocol(%d))\n", ip->ip_p);
      break;
    case IPPROTO_TCP:
      printf("Protocol: Transmission Contorol Protocol(%d)\n", ip->ip_p);
      break;
    case IPPROTO_ICMP:
      printf("Protocol: Internet Contorol Message Protocol(%d)\n", ip->ip_p);
      break;
    default:
      printf("Protocol: Unknown(%d)\n", ip->ip_p);
      break;
  }
  printf("Header Checksum = 0x%.4x\n", ntohs(ip->ip_sum));
  printf("Src IP: %s\n",inet_ntoa(ip->ip_src));
  printf("Dst IP: %s\n", inet_ntoa(ip->ip_dst));

  switch (ip->ip_p) {
    case IPPROTO_UDP:
      print_udpheader(ip);
      break;
    case IPPROTO_TCP:
      print_tcpheader(ip);
      break;
    case IPPROTO_ICMP:
      print_icmpheader(ip);
      break;
    default:
      break;
  }
}

static void print_arpheader(struct ether_header *ether) {
  
}

static void print_ethernetheader(char *p) {
  struct ether_header *ether;
  ether = (struct ether_header *) p;
  int i;
  u_char *ptr;

  printf("--------------------Ethernet header--------------------\n");
  printf("Dst Mac: ");
  i = ETHER_ADDR_LEN;
  ptr = ether->ether_dhost;
  do {
    printf("%s%02x", (i == ETHER_ADDR_LEN) ? "" : ":", *ptr++);
  } while (--i > 0);
  printf("\n");

  printf("Src MAC: ");
  i = ETHER_ADDR_LEN;
  ptr = ether->ether_shost;
  do {
    printf("%s%02x", (i == ETHER_ADDR_LEN) ? "" : ":", *ptr++);
  } while (--i > 0);
  printf("\n"); 
  
  switch (ntohs(ether->ether_type)) {
    case ETHERTYPE_IP:
      printf("Ether Type: IPv4(0x%04x)\n", ntohs(ether->ether_type));
      break;
    case ETHERTYPE_IPV6:
      printf("Ether Type: IPv6(0x%04x)\n", ntohs(ether->ether_type));
      break;
    case ETHERTYPE_ARP:
      printf("Ether Type: ARP(0x%04x)\n", ntohs(ether->ether_type));
      break;
    default:
      printf("Ether Type: Unknown(0x%04x)\n", ntohs(ether->ether_type));
      break;
  } 
}

static void print_time() {
  char buf[128];
  time_t now = time(NULL);
  struct tm *pnow = localtime(&now);
  
  sprintf(buf, "%d:%d:%d\n", pnow->tm_hour, pnow->tm_min, pnow->tm_sec);
  printf(buf);
}

static void usage(char *prog) {
  fprintf(stderr, "Usage: %s <device> <packet filter>\n", prog);
  exit(EXIT_FAILURE);
}
