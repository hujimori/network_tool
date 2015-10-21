#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <netdb.h> // DNS検索に必要
#include <pcap.h>
#define MAXSTRINGSIZE 256
#define MAXENTRY 1024

struct {
  unsigned long int ipaddr; // 文字列のデフォルト値
  char hostname[MAXSTRINGSIZE]; // ホスト名キャッシュの最大エントリ数
} nametable[MAXENTRY];

int tbllength = 0;

#define DEFAULT_SNAPLEN 68

// ホスト名への変換 
void intohost(long int iadd, char *hn) {
  int i;
  extern int tbllength;

  for (i = 0; i < tbllength; i++) {
    if (nametable[i].ipaddr == iadd)
      break;
  }

  if (i < tbllength) {
    strcpy(hn, nametable[i].hostname);
  } else {
    fprintf(stderr, "Internal Error onvoid intohost()\n");
    exit(1);
  }
}

// ホスト名の登録
// IPアドレスを検索し、新規ならネームサーバーを検索してキャッシュに登録
void reghost(unsigned long int iadd) {
  int i;
  struct hostent *shostname;
  extern int tbllength;

  // キャッシュ上のIPアドレスの検索
  for (i = 0; i < tbllength; i++) {
    if (nametable[i].ipaddr == iadd)  
      break; 
  }
  // キャッシュ上に存在しなかった場合IPアドレスをキャシュへ
  if (i == tbllength) {
    nametable[i].ipaddr = iadd;
    shostname = gethostbyaddr((char *)&iadd, sizeof(iadd), AF_INET);
    // ネームサーバを検索してホスト名を
    if (shostname != NULL) {
      // ネームサーバに名前があれば登録
      strcpy(nametable[i].hostname, shostname->h_name);
    } else {
      strcpy(nametable[i].hostname, "");
    }
    // データ数を登録
    tbllength++;
  }
}

void print_hostname(u_char *ipadd) {
  int i;
  unsigned long int iadd;
  struct hostnet *hostname;
  char hn[MAXENTRY];
  
  iadd = *((unsigned long int *)(ipadd));
  reghost(iadd);
  // ホスト名への変換
  intohost(iadd, hn);
  if (strlen(hn) > 0) 
    printf("%s", hn);
  else {
    for (i = 0; i < 3; i++) {
      printf("%d:", ipadd[i]);
    }
    printf("%d", ipadd[i]);
  }
}

// パケットデータの表示
void packet_print(u_char *user, const struct pcap_pkhdr *h, const u_char *p) {
  struct ip *iph;

  if (ntohs(((struct ether_header *)p)->ether_type) == ETHERTYPE_IP) {
    // パケットに対する処理 
    iph = (struct ip *) (p + sizeof(struct ether_header));
    print_hostname((u_char *)&(iph->ip_src));
    printf("->");
    print_hostname((u_char*)&(iph->ip_dst));
    printf("\n");
    fflush(stdout);
  }
}

int main(int argc, char **argv) {
  char ebuf[PCAP_ERRBUF_SIZE];
  pcap_t *pd;

  if (argc <= 1) {
    printf("usage : %s <network interface>\n", argv[0]);
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

  pcap_close(pd);
  exit(0);

}
