/* freeze-rec2.c — scan a live RecRoom.exe process for wide strings that look
 * like named-object paths the game is opening (OBJECT_ATTRIBUTES names).
 * usage: freeze-rec2 <outdir> [poll_ms] [cycles]
 * Looks for UTF-16 strings containing "BaseNamedObjects" and prints every one
 * plus ~60 chars of context. Leaves the process unharmed (CONT after sample).
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

static unsigned char needle[] = {
    'R',0,'e',0,'f',0,'e',0,'r',0,'e',0,'e',0 };

static pid_t find_game(void) {
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
        if (!strncmp(comm, "RecRoom.exe", 11))
            return atoi(e->d_name);
    }
    if (d) closedir(d);
    return 0;
}

static int has_referee(pid_t pid) {
    char maps[128];
    snprintf(maps, sizeof maps, "/proc/%d/maps", pid);
    FILE *f = fopen(maps, "r");
    if (!f) return 0;
    char line[512];
    int ok = 0;
    while (fgets(line, sizeof line, f))
        if (strstr(line, "Referee.dll")) { ok = 1; break; }
    fclose(f);
    return ok;
}

static void scan_strings(int mfd, const char *wh, unsigned long a0, size_t sz) {
    unsigned char *buf = malloc(sz + 4096);
    if (!buf) return;
    size_t got = pread(mfd, buf, sz, a0);
    if (got < sizeof needle) { free(buf); return; }
    for (size_t i = 0; i + sizeof needle <= got; i++) {
        if (!memcmp(buf + i, needle, sizeof needle)) {
            /* extract a window ending just after the hit, filtering to ASCII */
            size_t s = i > 256 ? i - 256 : 0;
            size_t e = i + sizeof needle + 256;
            if (e > got) e = got;
            char out[512]; size_t k = 0;
            for (size_t j = s; j < e && k < sizeof out - 4; j += 2)
                out[k++] = (buf[j] >= 0x20 && buf[j] < 0x7f) ? buf[j] : '?';
            out[k] = 0;
            printf("[%s] %#lx: %s\n", wh, a0 + s, out);
            fflush(stdout);
        }
    }
    free(buf);
}

int main(int argc, char **argv) {
    const char *outdir = argv[1];
    int poll_ms = argc > 2 ? atoi(argv[2]) : 400;
    int cycles  = argc > 3 ? atoi(argv[3]) : 20;
    char mk[512]; int st;
    snprintf(mk, sizeof mk, "mkdir -p %s", outdir); st = system(mk); (void)st;
    pid_t pid = 0;
    while (cycles-- > 0) {
        if (!pid || kill(pid, 0) < 0 || !has_referee(pid)) {
            pid = find_game();
            if (!pid) { usleep(poll_ms*1000); continue; }
            if (!has_referee(pid)) { usleep(poll_ms*1000); continue; }
            fprintf(stderr, "scan pid=%d\n", pid);
        }
        char maps[128], memp[128], line[512];
        snprintf(memp, sizeof memp, "/proc/%d/mem", pid);
        snprintf(maps, sizeof maps, "/proc/%d/maps", pid);
        int mfd = open(memp, O_RDONLY);
        if (mfd < 0) break;
        FILE *f = fopen(maps, "r");
        /* copy maps for records */
        char cp[512];
        snprintf(cp, sizeof cp, "cp /proc/%d/maps %s/rec2_%d.maps", pid, outdir, pid);
        st = system(cp); (void)st;
        while (fgets(line, sizeof line, f)) {
            unsigned long a0, a1; char perms[8], mp[256];
            mp[0]=0;
            if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %255[^\n]", &a0, &a1, perms, mp) < 3) continue;
            if (perms[0] != 'r') continue;
            if (perms[1] != 'w' && perms[2] != 'x') continue;
            size_t sz = a1 - a0;
            if (sz < 64) continue;
            if (strstr(mp, "Referee.dll") || strstr(mp, "GameAssembly")) continue;
            scan_strings(mfd, "mem", a0, sz > (4u<<20) ? (4u<<20) : sz);
            if (sz > (4u<<20)) {
                for (unsigned long p = a0 + (4u<<20); p + (4u<<20) <= a1; p += (4u<<20))
                    scan_strings(mfd, "mem", p, 4u<<20);
                unsigned long tail = a1 % (4u<<20);
                if (tail > 512) scan_strings(mfd, "mem", a1 - tail, tail);
            }
        }
        fclose(f);
        if (ptrace(PTRACE_ATTACH, pid, 0, 0) == 0) { int s2; waitpid(pid, &s2, __WALL); ptrace(PTRACE_CONT, pid, 0, 0); }
        close(mfd);
        usleep(poll_ms*1000);
    }
    return 0;
}
