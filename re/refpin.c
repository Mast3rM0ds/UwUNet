/* refpin.c — v2: set an INT3 breakpoint on advapi32.CryptHashData inside every
 * new RefereeClientAp service process, seizing ALL threads, so traps from any
 * worker thread surface. On each legit hit: dump regs, return address, the
 * pin-code window (0x140058000..0x14005b000) while decrypted, plus the
 * pbData buffer (r8, rdx bytes), then single-step + continue.
 *
 * usage: refpin <outdir> [max_hits] [max_services]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <stdint.h>
#include <time.h>

static char ADVPE[512];

static int seized[100000];

static pid_t find_svc(void) {
    DIR *d = opendir("/proc");
    struct dirent *e;
    while (d && (e = readdir(d))) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        char path[256], comm[128];
        snprintf(path, sizeof path, "/proc/%s/comm", e->d_name);
        int fd = open(path, O_RDONLY);
        if (fd < 0) continue;
        ssize_t n = read(fd, comm, sizeof comm - 1);
        close(fd);
        if (n <= 0) continue;
        comm[n] = 0;
        if (!strncmp(comm, "RefereeClientAp", 15) && !seized[atoi(e->d_name)])
            return atoi(e->d_name);
    }
    if (d) closedir(d);
    return 0;
}

static unsigned long advapi_base(pid_t pid) {
    char mp[128]; snprintf(mp, sizeof mp, "/proc/%d/maps", pid);
    FILE *f = fopen(mp, "r"); char line[1024]; unsigned long base = 0;
    if (!f) return 0;
    while (fgets(line, sizeof line, f)) {
        if (!strstr(line, "advapi32.dll")) continue;
        base = strtoul(line, 0, 16);
        break;
    }
    fclose(f);
    return base;
}

static unsigned long advapi_crypthashdata_rva(void) {
    char cmd[1024]; char out[256];
    snprintf(cmd, sizeof cmd,
        "objdump -p '%s' | awk '/\\+base\\[/ { ord = $4; gsub(/[^0-9]/,\"\",ord); }"
        " /Export RVA/ { eat[ord] = $5 }"
        " /CryptHashData/ { want = ord }"
        " END { print eat[want] }'", ADVPE);
    int devnull = open("/dev/null", O_WRONLY);
    fflush(stdout); fflush(stderr);
    int saved = dup(2); dup2(devnull, 2); close(devnull);
    FILE *pp = popen(cmd, "r");
    dup2(saved, 2); close(saved);
    if (!pp) return 0;
    if (!fgets(out, sizeof out, pp)) { pclose(pp); return 0; }
    pclose(pp);
    return strtoul(out, 0, 16);
}

static int seize_all_threads(pid_t pid) {
    char tp[256]; snprintf(tp, sizeof tp, "/proc/%d/task", pid);
    DIR *d = opendir(tp); struct dirent *e; int n = 0;
    while (d && (e = readdir(d))) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        pid_t tid = atoi(e->d_name);
        if (ptrace(PTRACE_SEIZE, tid, 0, PTRACE_O_TRACECLONE) == 0) n++;
    }
    if (d) closedir(d);
    return n;
}

static void dump_hit(int mfd, const char *outdir, int hit, pid_t tid,
                     struct user_regs_struct *r, unsigned long bpaddr, long orig) {
    char fn[512]; int o;
    unsigned long retaddr = 0, hasharg = r->rcx, bufarg = r->rdx, lenarg = r->r8;
    /* x64 calling convention: rcx=hHash, rdx=pbData, r8=dwDataLen, r9=dwFlags */
    pread(mfd, &retaddr, 8, r->rsp);

    /* pbData bytes */
    unsigned char bbuf[4096];
    size_t blen = lenarg < sizeof bbuf ? lenarg : sizeof bbuf;
    size_t bgot = blen ? pread(mfd, bbuf, blen, bufarg) : 0;

    /* pin window + caller frame */
    unsigned char pin[0x3000];
    size_t pgot = pread(mfd, pin, sizeof pin, 0x140058000UL);

    snprintf(fn, sizeof fn, "%s/hit%03d_tid%d.txt", outdir, hit, tid);
    o = open(fn, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (o >= 0) {
        dprintf(o,
            "tid=%d rip_after_bp=%#llx\n"
            "hHash(rcx)=%#llx pbData(rdx)=%#llx len(r8)=%#llu flags(r9)=%#llx\n"
            "rax=%#llx rsp=%#llx rbp=%#llx\nretaddr=[rsp]=%#llx\n",
            tid, (unsigned long long)r->rip,
            hasharg, bufarg, (unsigned long long)lenarg, r->r9,
            (unsigned long long)r->rax, (unsigned long long)r->rsp,
            (unsigned long long)r->rbp, (unsigned long long)retaddr);
        if (bgot) {
            dprintf(o, "pbData hex:\n");
            for (size_t i = 0; i < bgot; i++) dprintf(o, "%02x%s", bbuf[i], (i%32==31)?"\n":"");
            dprintf(o, "\n");
        }
        close(o);
    }
    snprintf(fn, sizeof fn, "%s/hit%03d_pinwin.bin", outdir, hit);
    o = open(fn, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (o >= 0 && pgot > 0) { write(o, pin, pgot); close(o); }
    fprintf(stderr, "HIT tid=%d hit=%d len=%llu pb=%#llx ret=%#llx pinwin=%zu\n",
            tid, hit, (unsigned long long)lenarg, bufarg, retaddr, pgot);
}

int main(int argc, char **argv) {
    const char *outdir = argv[1];
    int max_hits = argc > 2 ? atoi(argv[2]) : 24;
    int max_svc  = argc > 3 ? atoi(argv[3]) : 12;
    int life_ms  = argc > 4 ? atoi(argv[4]) : 0;   /* optional overall deadline */
    snprintf(ADVPE, sizeof ADVPE, "%s/drive_c/windows/system32/advapi32.dll",
             getenv("WINEPREFIX") && getenv("WINEPREFIX")[0]
                ? getenv("WINEPREFIX")
                : "/home/bloink/.local/share/Steam/steamapps/compatdata/471710/pfx");
    char mk[512]; int st;
    snprintf(mk, sizeof mk, "mkdir -p %s", outdir); st = system(mk); (void)st;

    unsigned long rva = advapi_crypthashdata_rva();
    if (!rva) { fprintf(stderr, "refpin: cannot resolve CryptHashData RVA\n"); return 1; }
    fprintf(stderr, "refpin: CryptHashData RVA=%#lx from %s\n", rva, ADVPE);

    time_t t0 = time(0);
    int hits_total = 0, svc_seen = 0;
    while (hits_total < max_hits) {
        if (life_ms && (time(0) - t0) * 1000 > life_ms) break;
        pid_t pid = find_svc();
        if (!pid) { usleep(8*1000); continue; }
        seized[pid] = 1; svc_seen++;

        /* race: wait until advapi32 is mapped (or process dies) */
        unsigned long base = 0;
        for (int i = 0; i < 300; i++) {
            base = advapi_base(pid);
            if (base || kill(pid, 0) < 0) break;
            usleep(4*1000);
        }
        if (!base || kill(pid, 0) < 0) { fprintf(stderr, "svc %d: died before map\n", pid); continue; }
        unsigned long bpaddr = base + rva;
        fprintf(stderr, "svc %d: bp %#lx\n", pid, bpaddr);

        if (ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_TRACECLONE) < 0) { perror("seize"); continue; }
        int nthr = seize_all_threads(pid);
        fprintf(stderr, "svc %d: seized main + %d threads\n", pid, nthr);

        /* write the breakpoint via /proc/mem (works while threads run) */
        char memp[128]; snprintf(memp, sizeof memp, "/proc/%d/mem", pid);
        int mfd = open(memp, O_RDWR);
        if (mfd < 0) { perror("open mem"); ptrace(PTRACE_DETACH, pid, 0, 0); continue; }
        long word, orig;
        if (pread(mfd, &word, 8, bpaddr) != 8) { perror("peek"); goto nextsvc; }
        orig = word;
        long patched = (orig & ~0xffL) | 0xcc;
        if (pwrite(mfd, &patched, 8, bpaddr) != 8) { perror("poke"); goto nextsvc; }
        { long chk; pread(mfd, &chk, 8, bpaddr);
          fprintf(stderr, "svc %d: bp armed, readback=%#lx (expect ...cc)\n", pid, chk & 0xff); }

        int hits = 0;
        int alive = 1;
        while (alive && hits < max_hits) {
            if (life_ms && (time(0) - t0) * 1000 > life_ms) { alive = 0; break; }
            int sts; pid_t w = waitpid(-pid, &sts, __WALL);
            if (w <= 0) { if (errno == EINTR) continue; break; }
            if (WIFEXITED(sts) || WIFSIGNALED(sts)) { alive = 0; break; }
            if (!WIFSTOPPED(sts)) { alive = 0; break; }
            int sig = WSTOPSIG(sts);
            if (hits_total < max_hits && (sig == SIGTRAP || sig == (SIGTRAP|0x80)))
                fprintf(stderr, "  stop tid=%d sig=%d status=%#x\n", w, sig, sts);
            if (sig == (SIGTRAP | 0x80)) { ptrace(PTRACE_CONT, w, 0, 0); continue; }
            if (sig == SIGTRAP || sig == SIGSTOP) {
                struct user_regs_struct r;
                if (ptrace(PTRACE_GETREGS, w, 0, &r) < 0) { ptrace(PTRACE_CONT, w, 0, 0); continue; }
                unsigned long rip = r.rip - 1;
                if (rip == bpaddr) {
                    /* breakpoint hit! */
                    hits++; hits_total++;
                    long o2; pread(mfd, &o2, 8, bpaddr);
                    pwrite(mfd, &orig, 8, bpaddr);       /* restore */
                    r.rip = rip;
                    ptrace(PTRACE_SETREGS, w, 0, &r);
                    dump_hit(mfd, outdir, hits_total, w, &r, bpaddr, orig);
                    /* single-step over the restored instruction */
                    ptrace(PTRACE_SINGLESTEP, w, 0, 0);
                    int st4; if (waitpid(w, &st4, __WALL) != w) { alive = 0; break; }
                    if (WIFSTOPPED(st4)) {
                        long cur; pread(mfd, &cur, 8, bpaddr);
                        if ((cur & 0xff) != 0xcc)
                            pwrite(mfd, &patched, 8, bpaddr); /* re-arm */
                    } else { alive = 0; break; }
                    ptrace(PTRACE_CONT, w, 0, 0);
                    continue;
                }
                /* other event-stop (clone/fork/etc.) — just continue */
                ptrace(PTRACE_CONT, w, 0, 0);
                continue;
            }
            /* any other signal: deliver it */
            ptrace(PTRACE_CONT, w, 0, sig);
        }
        fprintf(stderr, "svc %d: loop end hits=%d alive=%d\n", pid, hits, alive);
nextsvc:
        close(mfd);
        /* detach every traced thread */
        DIR *d2 = opendir("/dev/null"); if (d2) closedir(d2);
        for (int t = 1; t < 100000 && (hits_total < max_hits); t++) {
            /* mark nothing; detach via kill-free approach below */
        }
        ptrace(PTRACE_DETACH, pid, 0, 0);
        usleep(2*1000);
    }
    fprintf(stderr, "refpin done hits=%d svc=%d\n", hits_total, svc_seen);
    return 0;
}
