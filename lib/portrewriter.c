// UwUNet port rewriter — LD_PRELOAD connect() hook.
// Rewrites loopback :443 -> 8443 (TLS edge) and :80 -> 8460 (HTTP edge).
#define _GNU_SOURCE
#include <dlfcn.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <sys/socket.h>

typedef int (*connect_t)(int, const struct sockaddr *, socklen_t);

int connect(int fd, const struct sockaddr *sa, socklen_t sn) {
  static connect_t real;
  if (!real) real = (connect_t)dlsym(RTLD_NEXT, "connect");
  struct sockaddr_in *si = (struct sockaddr_in *)sa;

  // Only rewrite loopback traffic: uwudns64.so maps *.rec.net -> 127.0.0.1, so
  // rec.net connections land here as 127.0.0.1:443/:80. Leaving non-loopback
  // :443 alone keeps google/telemetry/OCSP (real IPs) working normally.
  int loopback = sa && sa->sa_family == AF_INET &&
                 (ntohl(si->sin_addr.s_addr) >> 24) == 127;
  if (loopback && ntohs(si->sin_port) == 443) {
    struct sockaddr_in copy;
    memcpy(&copy, sa, sizeof(copy));
    copy.sin_port = htons(8443);
    return real(fd, (struct sockaddr *)&copy, sizeof(copy));
  }
  if (loopback && ntohs(si->sin_port) == 80) {
    struct sockaddr_in copy;
    memcpy(&copy, sa, sizeof(copy));
    copy.sin_port = htons(8460);
    return real(fd, (struct sockaddr *)&copy, sizeof(copy));
  }
  return real(fd, sa, sn);
}
