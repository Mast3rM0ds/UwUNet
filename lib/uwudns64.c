// uwdns64 — LD_PRELOAD resolver shim (64-bit ELF; wine builtin ws2_32/shlwapi
// uses the host Linux getaddrinfo in-process under new-wow64, so hooking libc
// getaddrinfo redirects every Windows getaddrinfo as well).
//
// Purpose: Rec Room's RefereeClientApp service probes api.rec.net:443 during
// service init (proven via WINEDEBUG=+relay 2026-10-26, threads doing
// getaddrinfo("api.rec.net","443") then connect(+probe) before failing blob
// load with -99962). We redirect *.rec.net (and *.*room*/protoplay names) to
// 127.0.0.1 so the probes land on the UwUNet edge (uwuhook.so rewrites
// 443->8443). No sudo/DNS config needed.
//
// Build (64-bit): gcc -shared -fPIC -O1 -o uwudns64.so uwudns64.c -ldl

#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>

static const char *MATCH[] = {
    ".rec.net", "rec.net", "recroom", "protoplay", "recroom.gg",
};

static int matched(const char *h) {
  if (!h) return 0;
  for (unsigned i = 0; i < sizeof(MATCH) / sizeof(MATCH[0]); i++) {
    if (strstr(h, MATCH[i])) return 1;
  }
  return 0;
}

static void ulog(const char *line, size_t n) {
  int fd = open("/tmp/opencode/uwudns.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
  if (fd < 0) return;
  write(fd, line, n);
  close(fd);
}

typedef int (*gai_t)(const char *, const char *, const struct addrinfo *, struct addrinfo **);
// NOTE: do NOT interpose freeaddrinfo — glibc's own freeaddrinfo frees
// canonname/addr/ai exactly the way our allocations need it, and interposing
// it corrupted glibc's internal cleanup in test processes (double free).

// one A record sockaddr_in, heap, owned by the returned addrinfo
int getaddrinfo(const char *node, const char *service, const struct addrinfo *hints,
                struct addrinfo **res) {
  static gai_t real;
  if (!real) real = (gai_t)dlsym(RTLD_NEXT, "getaddrinfo");
  if (hints && hints->ai_family == AF_INET6) {
    char line[256];
    int n = snprintf(line, sizeof(line), "getaddrinfo %s svc=%s -> pass (v6 hints)\n",
                     node ? node : "(null)", service ? service : "");
    ulog(line, (size_t)n);
    return real(node, service, hints, res);
  }
  if (node && matched(node) && res) {
    struct addrinfo *ai = (struct addrinfo *)calloc(1, sizeof(struct addrinfo));
    struct sockaddr_in *sa = (struct sockaddr_in *)calloc(1, sizeof(struct sockaddr_in));
    ai->ai_family = AF_INET;
    ai->ai_socktype = hints ? (hints->ai_socktype ? hints->ai_socktype : SOCK_STREAM) : SOCK_STREAM;
    ai->ai_protocol = hints && hints->ai_protocol ? hints->ai_protocol : IPPROTO_TCP;
    ai->ai_flags = hints ? hints->ai_flags : 0;
    ai->ai_addrlen = sizeof(struct sockaddr_in);
    ai->ai_canonname = strdup(node);
    sa->sin_family = AF_INET;
    sa->sin_port = htons(service ? (unsigned short)strtoul(service, NULL, 10) : 0);
    sa->sin_addr.s_addr = htonl(0x7f000001);
    ai->ai_addr = (struct sockaddr *)sa;
    ai->ai_next = NULL;
    *res = ai;
    char line[256];
    int n = snprintf(line, sizeof(line), "getaddrinfo %s svc=%s -> 127.0.0.1 (uwu)\n",
                     node, service ? service : "");
    ulog(line, (size_t)n);
    return 0;
  }
  return real(node, service, hints, res);
}



struct hostent *gethostbyname(const char *name) {
  typedef struct hostent *(*hb_t)(const char *);
  static hb_t real;
  if (!real) real = (hb_t)dlsym(RTLD_NEXT, "gethostbyname");
  if (name && matched(name)) {
    // static-ish storage: leaked under wine is fine (process-lifetime)
    static in_addr_t addrv;
    static char *aliases[1];
    static char *addrs[2];
    static struct hostent he;
    static const char *canon;
    addrv = htonl(0x7f000001);
    canon = name;
    aliases[0] = NULL;
    addrs[0] = (char *)&addrv;
    addrs[1] = NULL;
    he.h_name = (char *)canon;
    he.h_aliases = aliases;
    he.h_addrtype = AF_INET;
    he.h_length = 4;
    he.h_addr_list = addrs;
    char line[192];
    int n = snprintf(line, sizeof(line), "gethostbyname %s -> 127.0.0.1 (uwu)\n", name);
    ulog(line, (size_t)n);
    return &he;
  }
  return real(name);
}
