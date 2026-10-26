/* freeze-rec.c — catch RecRoom.exe, sample its [stack] (and anon RWX spans)
 * while Referee.dll spins in its NtOpenSection/log loop.
 * usage: freeze-rec <outdir> [poll_ms] [cycles]
 * Dumps: <outdir>/rec_<pid>_stack_<t>.bin  (+ one /proc/pid/maps copy)
 * Leaves the process CONTinued (does not freeze play while sampling).
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
#include <time.h>

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
    while (fgets(line, sizeof line, f)) {
        if (strstr(line, "Referee.dll")) { ok = 1; break; }
    }
    fclose(f);
    return ok;
}

static void dump_stack(int mfd, const char *outdir, pid_t pid, int t) {
    char maps[128], out[512], line[512];
    snprintf(maps, sizeof maps, "/proc/%d/maps", pid);
    FILE *f = fopen(maps, "r");
    if (!f) return;
    unsigned long a0, a1;
    char perms[8], mp[256];
    while (fgets(line, sizeof line, f)) {
        if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %255[^\n]", &a0, &a1, perms, mp) < 3) continue;
        if (!strstr(mp, "[stack]") || perms[0] != 'r') continue;
        size_t sz = a1 - a0;
        if (sz > 8u<<20) sz = 8u<<20;
        unsigned char *buf = malloc(sz);
        if (!buf) { fclose(f); return; }
        size_t got = pread(mfd, buf, sz, a0 + (a1 > a0 + (8u<<20) ? a1 - (8u<<20) : 0));
        unsigned long base = sz == (size_t)(a1 - a0) ? a0 : a0 + (a1 - a0 - (8u<<20));
        snprintf(out, sizeof out, "%s/rec_%d_stack_%03d.bin", outdir, pid, t);
        int o = open(out, O_WRONLY|O_CREAT|O_TRUNC, 0644);
        if (o >= 0) { write(o, &base, 8); write(o, &got, 8); if (got) write(o, buf, got); close(o); }
        fprintf(stderr, "stack_t%d pid=%d base=%#lx got=%zu -> %s\n", t, pid, base, got, out);
        free(buf);
    }
    fclose(f);
    char mf[256];
    snprintf(mf, sizeof mf, "/proc/%d/maps", pid);
    char cp[512];
    snprintf(cp, sizeof cp, "cp %s %s/rec_%d.maps 2>/dev/null", mf, outdir, pid);
    int st = system(cp); (void)st;
}

int main(int argc, char **argv) {
    const char *outdir = argv[1];
    int poll_ms = argc > 2 ? atoi(argv[2]) : 250;
    int cycles  = argc > 3 ? atoi(argv[3]) : 30;
    char mk[512];
    snprintf(mk, sizeof mk, "mkdir -p %s", outdir);
    int st = system(mk); (void)st;
    pid_t pid = 0;
    int sample = 0;
    while (cycles-- > 0) {
        if (!pid || kill(pid, 0) < 0 || !has_referee(pid)) {
            pid = find_game();
            if (!pid) { usleep(poll_ms*1000); continue; }
            if (!has_referee(pid)) { usleep(poll_ms*1000); continue; }
            if (ptrace(PTRACE_ATTACH, pid, 0, 0) == 0) {
                int st; waitpid(pid, &st, __WALL);
                fprintf(stderr, "attached %d (referee mapped)\n", pid);
            } else { pid = 0; continue; }
        }
        char mem[128]; snprintf(mem, sizeof mem, "/proc/%d/mem", pid);
        int mfd = open(mem, O_RDONLY);
        if (mfd < 0) { usleep(poll_ms*1000); continue; }
        dump_stack(mfd, outdir, pid, sample++);
        close(mfd);
        if (ptrace(PTRACE_CONT, pid, 0, 0) != 0) { pid = 0; continue; }
        usleep(poll_ms*1000);
        if (kill(pid, 0) < 0) { pid = 0; }
    }
    if (pid && kill(pid, 0) >= 0) { kill(pid, SIGCONT); ptrace(PTRACE_DETACH, pid, 0, 0); }
    return 0;
}
