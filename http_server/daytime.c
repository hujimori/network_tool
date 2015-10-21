#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>

static int open_connect(char *host, char *service);

int main(int argc, char *argv[]) {
  int sock;
  FILE *f;
  char buf[1024];
  
  sock= open_connect((argc > 1 ? argv[1] : "localhost"), "daytime");
  f = fdopen(sock, "r");
  if (!f) {
    perror("fdopen(3)");
    exit(1);
  }
  fgets(buf, sizeof buf, f);
  fclose(f);
  fputs(buf, stdout);
  exit(0);
}

static int open_connect(char *host, char *service) {
  int sock;
  struct addrinfo hints, *res, *ai;
  int err;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_socktype = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  if ((err = getaddrinfo(host, service, &hints, &res)) != 0) {
    fprintf(stderr, "getaddrinfo(3): %s\n", gai_strerror(err));
    exit(1);
  }
  for (ai = res; ai; ai = ai->ai_next) {
    sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
    if (sock < 0) {
      continue;
    }
    freeaddrinfo(res);
    return sock;
  }
  fprintf(stderr, "socket(2)/connect(2) failed");
  freeaddrinfo(res);
  exit(1);
}
