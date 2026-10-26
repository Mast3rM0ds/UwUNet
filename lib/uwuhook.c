// UwU hook — LD_PRELOAD shim: observe + steer Rec Room's network from Linux.
//  1) logs every outbound non-loopback connect() attempt (pid + dst:port)
//  2) rewrites dst 443 -> 8443 (UwUNet TLS edge) and 80 -> 8460 (HTTP edge)
//
// Notes learned 2026-10-26:
//  - wine forks children with the parent's unix env, so LD_PRELOAD reaches
//    services.exe AND the Referee service child automatically; do NOT try to
//    hook Win32 CreateProcessW from an ELF shim (unresolvable => crash).
//  - 32-bit wine helper stages complain "wrong ELF class" and skip the lib.

#define _GNU_SOURCE
#include <dlfcn.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>

static void ulog(const char *line, size_t n) {
  int fd = open("/tmp/opencode/uwuhook.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
  if (fd < 0) return;
  write(fd, line, n);
  close(fd);
}

typedef int (*connect_t)(int, const struct sockaddr *, socklen_t);
typedef ssize_t (*send_t)(int, const void *, size_t, int);
typedef ssize_t (*recv_t)(int, void *, size_t, int);

// hex + ascii-ish logging of first bytes of send/recv payloads on the
// redirected ports (443/80 family) — reveals client probes over the wire.
static void log_payload(const char *dir, int port, const unsigned char *buf, int len) {
  if (len <= 0) return;
  char line[220];
  int n = 0;
  int show = len > 24 ? 24 : len;
  n = snprintf(line, sizeof line, "%s%d[", dir, port);
  for (int i = 0; i < show && n < 200; i++)
    n += snprintf(line + n, (size_t)(sizeof line - n), "%02x", buf[i]);
  if (n < 200) n += snprintf(line + n, (size_t)(sizeof line - n), "]\n");
  ulog(line, (size_t)n);
}

ssize_t send(int fd, const void *buf, size_t len, int flags) {
  static send_t real;
  if (!real) real = (send_t)dlsym(RTLD_NEXT, "send");
  // port unknown here; log only loopback-ish payloads of interest
  if (buf && len && len <= 4096) log_payload("SEND ", -getpid(), buf, (int)len);
  return real(fd, buf, len, flags);
}

ssize_t recv(int fd, void *buf, size_t len, int flags) {
  static recv_t real;
  if (!real) real = (recv_t)dlsym(RTLD_NEXT, "recv");
  ssize_t r = real(fd, buf, len, flags);
  if (buf && r > 0) log_payload("RECV ", -getpid(), buf, (int)r);
  return r;
}

int connect(int fd, const struct sockaddr *sa, socklen_t sn) {
  static connect_t real;
  if (!real) real = (connect_t)dlsym(RTLD_NEXT, "connect");
  if (sa && (sa->sa_family == AF_INET || sa->sa_family == AF_INET6)) {
    const struct sockaddr_in *si = (const struct sockaddr_in *)sa;
    int port = ntohs(si->sin_port);
    int loopback = ntohl(si->sin_addr.s_addr) == 0x7f000001;
    // NOTE 2026-10-26: RefereeClientApp resolves api.rec.net via our DNS shim
    // to 127.0.0.1 and then connect()s to 127.0.0.1:443 — so loopback:443 AND
    // remote:443 both must be redirected to the edge ports (nothing can bind
    // :443 without sudo).
    if (!loopback || port == 443 || port == 80) {
      char line[192];
      int target = port;
      // UWU_TLS_PORT / UWU_HTTP_PORT let us A/B different edges (e.g. a test
      // server with a different RSA key) without rebuilding.
      const char *tlsport = getenv("UWU_TLS_PORT");
      const char *httpport = getenv("UWU_HTTP_PORT");
      if (!loopback && port == 443) target = tlsport ? atoi(tlsport) : 8443;
      else if (loopback && port == 443) target = tlsport ? atoi(tlsport) : 8443;
      else if (!loopback && port == 80) target = httpport ? atoi(httpport) : 8460;
      else if (loopback && port == 80) target = httpport ? atoi(httpport) : 8460;
      const char *dst = inet_ntoa(si->sin_addr);
      struct sockaddr_in copy;
      memcpy(&copy, sa, sizeof(copy));
      if (target != port) copy.sin_port = htons((unsigned short)target);
      int n = snprintf(line, sizeof(line), "connect pid=%d %s:%d%s:%d\n",
                       (int)getpid(), dst, port,
                       target != port ? " -> " : (loopback ? " (loop)" : " pass "),
                       target != port ? target : 0);
      ulog(line, (size_t)n);
      return real(fd, (struct sockaddr *)&copy, sizeof(copy));
    }
  }
  return real(fd, sa, sn);
}

__attribute__((constructor)) static void uwuhook_ctor(void) {
  // comm is useless under wine (always "wine"/"wine64"); cmdline shows the PE
  char line[384];
  char cmd[256] = "?";
  FILE *f = fopen("/proc/self/cmdline", "r");
  if (f) {
    size_t n = fread(cmd, 1, sizeof(cmd) - 1, f);
    fclose(f);
    for (size_t i = 0; i < n; i++) if (!cmd[i]) cmd[i] = ' ';
    cmd[n] = 0;
  }
  int n = snprintf(line, sizeof(line), "LOADED pid=%d cmdline=%s\n", (int)getpid(), cmd);
  ulog(line, (size_t)n);
}
