// uwuhook32 — freestanding 32-bit LD_PRELOAD shim for classic WOW64 wine.
// No libc: raw int 0x80 syscalls, so it loads even where multilib is absent.
//  - logs every load + every outbound connect() (pid, dst, port)
//  - rewrites dst 443 -> 8443 (UwUNet TLS edge), 80 -> 8460 (HTTP edge)
//
// i386 syscall ABI: eax=nr, ebx/ecx/edx/esi = args.
#define UWU32_LOG "/tmp/opencode/uwuhook32.log"
#define O_WRONLY 1
#define O_CREAT 64
#define O_APPEND 1024

typedef unsigned int   u32;
typedef unsigned short u16;
typedef unsigned char  u8;

static inline u32 sys0(u32 n) {
  u32 r;
  __asm__ volatile("int $0x80" : "=a"(r) : "a"(n));
  return r;
}
static inline u32 sys3(u32 n, u32 a, u32 b, u32 c) {
  u32 r;
  __asm__ volatile("int $0x80" : "=a"(r) : "a"(n), "b"(a), "c"(b), "d"(c));
  return r;
}
static inline u32 sys4(u32 n, u32 a, u32 b, u32 c, u32 d) {
  u32 r;
  __asm__ volatile("int $0x80" : "=a"(r) : "a"(n), "b"(a), "c"(b), "d"(c), "S"(d));
  return r;
}

static int logfd_cached;
static void uwu_log(const char *msg, u32 mlen) {
  if (!logfd_cached) {
    logfd_cached = (int)sys3(5 /*open*/, (u32)UWU32_LOG,
                             O_WRONLY | O_CREAT | O_APPEND, 0666);
    if (logfd_cached < 0) return;
  }
  char line[256];
  u32 pid = sys0(20 /*getpid*/);
  u32 o = 0;
  line[o++] = ' '; line[o++] = '3'; line[o++] = '2'; line[o++] = ' ';
  if (!pid) { line[o++] = '0'; }
  else { char tmp[10]; u32 i = 0; while (pid && o < sizeof(line) - mlen - 2) { tmp[i++] = (char)('0' + pid % 10); pid /= 10; } while (i) line[o++] = tmp[--i]; }
  line[o++] = ' ';
  for (u32 i = 0; i < mlen && o < sizeof(line) - 2; i++) line[o++] = msg[i];
  if (o < sizeof(line)) line[o++] = '\n';
  sys3(4 /*write*/, (u32)logfd_cached, (u32)line, o);
}

// linux i386 AF_INET sockaddr: family(2) port(2 BE) addr(4 BE) pad(8)
struct sockaddr_in32 {
  u16 sin_family;
  u16 sin_port;
  u32 sin_addr;
  u8  pad[8];
};

static u32 bswap16(u32 x) { return ((x & 0xffu) << 8) | ((x >> 8) & 0xffu); }

typedef unsigned int socklen_t32;

__attribute__((visibility("default")))
int connect(int fd, const struct sockaddr_in32 *sa, socklen_t32 addrlen) {
  if (sa && sa->sin_family == 2 /*AF_INET*/) {
    int port = bswap16(sa->sin_port);
    int target = port;
    if (port == 443) target = 8443;
    else if (port == 80) target = 8460;
    if (target != port) {
      struct sockaddr_in32 copy;
      __builtin_memcpy(&copy, sa, sizeof(copy));
      copy.sin_port = (u16)bswap16((u32)target);
      sa = &copy;
      uwu_log("connect rewrite", 15);
    } else if (sa->sin_addr != 0x0100007fu /*127.0.0.1*/) {
      uwu_log("connect outbound", 16);
    }
    u32 args[3] = { (u32)fd, (u32)sa, (u32)sizeof(struct sockaddr_in32) };
    return (int)sys4(102 /*socketcall*/, 3 /*SYS_CONNECT*/, (u32)args, 0, 0);
  }
  u32 args[3] = { (u32)fd, (u32)sa, (u32)addrlen };
  return (int)sys4(102, 3, (u32)args, 0, 0);
}

__attribute__((constructor)) static void uwu32_ctor(void) {
  // log cmdline too (raw syscall read of /proc/self/cmdline)
  char self[] = "/proc/self/cmdline";
  int sfd = (int)sys3(5, (u32)self, 0 /*O_RDONLY*/, 0);
  char cmd[200];
  u32 got = 0;
  if (sfd >= 0) {
    got = sys3(3 /*read*/, (u32)sfd, (u32)cmd, sizeof(cmd) - 1);
    sys0(6 /*close*/);
  }
  uwu_log("LOADED32", 8);
  if (got <= 200) {
    // sanitize nuls -> spaces, cap printable
    for (u32 i = 0; i + 1 < got && i < (u32)sizeof(cmd); i++)
      if (cmd[i] == 0) cmd[i] = ' ';
    uwu_log(cmd, got < (u32)sizeof(cmd) ? got : (u32)sizeof(cmd));
  }
}
