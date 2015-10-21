#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifndef __FAVOR_BSD
#define __FAVOR_BSD
#endif
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <err.h>


// チェックサム計算用UDP擬似ヘッダー
struct pseudo_hdr {
  struct in_addr src;
  struct in_addr dst;
  unsigned char zero;
  unsigned char proto;
  unsigned short len;
};

static void usage(char *prog) {
  fprintf(stderr, "Usage: %s <src ip> <dst ip> <port> <string>\n", prog);
  exit(EXIT_FAILURE);
}

// チェックサム計算コード
static unsigned short in_cksum(unsigned short *addr, int len) {
  int nleft, sum;
  unsigned short *w;
  union {
    unsigned short us;
    unsigned char uc[2];
  } last;
  unsigned short answer;

  nleft = len;
  sum = 0;
  w = addr;

  while (nleft > 1) {
    sum += *w++;
    nleft -= 2;
  }

  if (nleft == 1) {
    last.uc[0] = *(unsigned char *) w;
    last.uc[1] = 0;
    sum += last.us;
  }

  sum = (sum >> 16) + (sum &0xffff);
  sum += (sum >> 16);
  answer = ~sum;
  return answer;
}

static void build_udp(char *p, struct in_addr *src, struct in_addr *dst, unsigned short dport, char *data) {
  char *ubuf;
  struct ip *ip;
  struct udphdr *udp;
  struct pseudo_hdr *pse;
  int needlen;

  // チェックサム計算用にUDPヘッダーとデータ、擬似ヘッダの合計サイズを計算する
  needlen = sizeof(struct pseudo_hdr) + sizeof(struct udphdr) + strlen(data);
  if ((ubuf = malloc(needlen)) == NULL) {
      errx(1, "malloc");
  }
  memset(ubuf, 0, needlen);

  pse = (struct pseudo_hdr *) ubuf;
  pse->src.s_addr = src->s_addr;
  pse->dst.s_addr = dst->s_addr;
  pse->proto = IPPROTO_UDP;
  pse->len = htons(sizeof(struct udphdr) + strlen(data));

  udp = (struct udphdr *)(ubuf + sizeof(struct pseudo_hdr));
  udp->uh_sport = htons(65001);
  udp->uh_dport = htons(dport);
  udp->uh_ulen = pse->len;
  udp->uh_sum = 0;
  
  // データ部分の書き込み
  memcpy((char *) udp + sizeof(struct udphdr), data, strlen(data));
  // チェックサム計算
  udp->uh_sum = in_cksum((unsigned short *) ubuf, needlen);

  // UDPヘッダとデータ部分をIPヘッダの後ろへ書き込む
  ip = (struct ip *) p;
  memcpy(p + (ip->ip_hl << 2), udp, needlen - sizeof(struct pseudo_hdr));

  free(ubuf);
}

static void build_ip(char *p, struct in_addr *src, struct in_addr *dst, size_t len) {
  struct ip *ip;
  ip = (struct ip *) p;
  ip->ip_v = 4;
  ip->ip_hl = 5;
  ip->ip_tos = 1;
  ip->ip_len = len;
  ip->ip_id = htons(getpid());
  ip->ip_off = 0;
  ip->ip_ttl = 0x40;
  ip->ip_p = IPPROTO_UDP;
  ip->ip_src = *src;
  ip->ip_dst = *dst;

  // チェックサム計算
  ip->ip_sum = 0;
  ip->ip_sum = in_cksum((unsigned short*) ip, ip->ip_hl << 2);
}

int main(int argc, char *argv[]) {
  int sd;
  int on = 1;
  char *data;
  char *buf;
  struct in_addr src, dst;
  struct sockaddr_in to;
  socklen_t tolen = sizeof(struct sockaddr_in);
  size_t packetsiz;
  unsigned short dport;
  
  if (argc != 5) {
    usage(argv[0]);
  }

  dport = atoi(argv[3]);
  data = argv[4];

  packetsiz= sizeof(struct ip) + sizeof(struct udphdr) + strlen(data);
  if ((buf = malloc(packetsiz)) == NULL) 
    errx(1, "malloc");
  
  // RAW socket
  if ((sd = socket(PF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) 
    errx(1, "setsockopt");

  src.s_addr = inet_addr(argv[1]);
  dst.s_addr = inet_addr(argv[2]);

  build_ip(buf, &src, &dst, packetsiz);
  build_udp(buf, &src, &dst, dport, data);

  memset(&to, 0, sizeof(struct sockaddr_in));
  to.sin_addr = dst;
  to.sin_port = htons(AF_INET);

  printf("Sending to %s from %s\n", argv[2], argv[1]);
  if(sendto(sd, buf, packetsiz, 0, (struct sockaddr *) &to, tolen) < 0) {
    perror("sendto");
  }

  close(sd);
  free(buf);

  return 0;
}

