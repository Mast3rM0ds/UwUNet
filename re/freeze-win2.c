/* freeze-win2.c — aggressive: attach to every new RefereeClientAp IMMEDIATELY
 * (no wait), dump pin window 0x140058000..0x14005b000 and RX block
 * 0x140700000..+0x80000 and maps, CONT, repeat. Debug prints all steps.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/ptrace.h>
#include <sys/wait.h>

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
        if (!strncmp(comm, "RefereeClientAp", 15)) return atoi(e->d_name);
    }
    if (d) closedir(d);
    return 0;
}

static void dump_span(int mfd, const char *outdir, pid_t pid, unsigned long a, size_t sz, const char *tag) {
    static unsigned char buf[0x40000];
    char fn[512];
    snprintf(fn, sizeof fn, "%s/svc_%d_%s_%lx.bin", outdir, pid, tag, a);
    int o = open(fn, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    ssize_t total = 0;
    if (o >= 0) {
        for (unsigned long p = 0; p < sz; p += sizeof buf) {
            size_t chunk = (sz - p > sizeof buf) ? sizeof buf : (sz - p);
            ssize_t n = pread(mfd, buf, chunk, a + p);
            if (n > 0) { write(o, buf, n); total += n; }
        }
        close(o);
    }
    fprintf(stderr, "  dump pid=%d %s %lx -> %s (%ld bytes)\n", pid, tag, a, fn, (long)total);
}

int main(int argc, char **argv) {
    const char *outdir = argv[1];
    int poll_ms = argc > 2 ? atoi(argv[2]) : 10;
    int life_ms = argc > 3 ? atoi(argv[3]) : 2500;   /* watch this long, then continue */
    char mk[512]; int st;
    snprintf(mk, sizeof mk, "mkdir -p %s", outdir); st = system(mk); (void)st;
    int dumped[32768] = {0};
    unsigned long long iter = 0;
    while (1) {
        iter++;
        pid_t pid = find_svc();
        if (iter % 100 == 0) { fprintf(stderr, "iter%llu find=%d\n", iter, pid); fflush(stderr); }
        if (!pid || pid >= 32768 || dumped[pid]) { usleep(poll_ms*1000); continue; }
        dumped[pid] = 1;
        fprintf(stderr, "GOT %d\n", pid); fflush(stderr);
        /* poll for the pin window to appear, up to life_ms */
        int win_ok = 0;
        for (int w = 0; w < life_ms; w += poll_ms) {
            char line[512]; int has = 0;
            char mp[128]; snprintf(mp, sizeof mp, "/proc/%d/maps", pid);
            FILE *f = fopen(mp, "r");
            if (f) { while (fgets(line, sizeof line, f)) if (strstr(line, "140058") ||
                       strstr(line, "140070") || strstr(line, "14012")) { has = 1; break; }
                     fclose(f); }
            if (has) { win_ok = 1; break; }
            usleep(poll_ms*1000);
            if (kill(pid, 0) < 0) break;
        }
        fprintf(stderr, " %d win=%d\n", pid, win_ok);
        if (!win_ok) continue;
        if (kill(pid, SIGSTOP) == 0) { int s3; waitpid(pid, &s3, __WALL); }
        char memp[128]; snprintf(memp, sizeof memp, "/proc/%d/mem", pid);
        int mfd = open(memp, O_RDONLY);
        char cmd[512];
        snprintf(cmd, sizeof cmd, "cp /proc/%d/maps %s/svc_%d.maps", pid, outdir, pid);
        st = system(cmd); (void)st;
        if (mfd >= 0) {
            dump_span(mfd, outdir, pid, 0x140058000UL, 0x3000, "pin");
            dump_span(mfd, outdir, pid, 0x140700000UL, 0x80000, "rx");
            close(mfd);
        }
        kill(pid, SIGCONT);
        ptrace(PTRACE_DETACH, pid, 0, 0);
        usleep(1000);
    }
    return 0;
}
