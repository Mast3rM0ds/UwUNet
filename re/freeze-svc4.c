// v3 — catch RefereeClientAp (wine comm, 15-char truncated), scan writable
// memory for our TLS cert (leaf DER / SPKI DER) every cycle across ALL 5
// launch attempts, and DUMP (always) at either "found" or "gave up":
//   - the app code window 0x140058000..0x14005b000  (pin-check code path)
//   - every writable anon/[heap]/[stack] span >= 32 KB
// Leaving the last process frozen; pid written to <outdir>/pid.txt.
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
#include <sys/user.h>

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
        if (!strncmp(comm, "RefereeClientAp", 15))
            return atoi(e->d_name);
    }
    if (d) closedir(d);
    return 0;
}

static int find_pattern(pid_t pid, const unsigned char *pat, size_t plen) {
    char maps[128];
    snprintf(maps, sizeof maps, "/proc/%d/maps", pid);
    FILE *f = fopen(maps, "r");
    if (!f) return 0;
    char line[512], path[256];
    unsigned long a0, a1; char perms[8];
    char memf[128]; snprintf(memf, sizeof memf, "/proc/%d/mem", pid);
    int mfd = open(memf, O_RDONLY);
    if (mfd < 0) { fclose(f); return 0; }
    int found = 0;
    while (!found && fgets(line, sizeof line, f)) {
        path[0] = 0;
        if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %255[^\n]", &a0, &a1, perms, path) < 3) continue;
        if (path[0] && !strstr(path, "[stack]") && !strstr(path, "[heap]")) continue;
        if (perms[0] != 'r' || perms[1] != 'w') continue;
        size_t sz = a1 - a0;
        unsigned char *buf = malloc(sz);
        if (!buf) continue;
        ssize_t n = pread(mfd, buf, sz, a0);
        if (n > (ssize_t)plen) {
            for (ssize_t i = 0; i + (ssize_t)plen <= n; i++) {
                if (!memcmp(buf + i, pat, plen)) {
                    fprintf(stderr, "  FOUND (span %#lx-%#lx) at %#lx\n", a0, a1, a0 + (unsigned long)i);
                    found = 1; break;
                }
            }
        }
        free(buf);
    }
    close(mfd); fclose(f);
    return found;
}

static void dump_span(int mfd, const char *outdir, unsigned long a0, unsigned long a1) {
    char fn[512];
    snprintf(fn, sizeof fn, "%s/mem_%09lx_%06lx.bin", outdir, a0, a1 - a0);
    int o = open(fn, O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (o < 0) return;
    static unsigned char zero[65536];
    unsigned char *buf = malloc(65536);
    unsigned long off = 0;
    while (off < a1 - a0) {
        unsigned long chunk = 65536 < (a1 - a0 - off) ? 65536 : (a1 - a0 - off);
        ssize_t n = pread(mfd, buf, chunk, a0 + off);
        if (n > 0) { write(o, buf, n); off += n; }
        else { write(o, zero, chunk); off += chunk; }
    }
    free(buf); close(o);
}

int main(int argc, char **argv) {
    const char *outdir = argv[1];
    int poll_ms = argc > 2 ? atoi(argv[2]) : 40;
    unsigned char spki[292], leaf[1300];
    FILE *fs = fopen("/tmp/opencode/spki.der", "rb");
    if (!fs || fread(spki, 1, sizeof spki, fs) != sizeof spki) { fprintf(stderr,"bad spki.der\n"); return 1; }
    fclose(fs);
    FILE *fl = fopen("/tmp/opencode/leaf.der", "rb");
    if (!fl || fread(leaf, 1, sizeof leaf, fl) != sizeof leaf) { fprintf(stderr,"bad leaf.der\n"); return 1; }
    fclose(fl);

    pid_t pid = 0;
    int cycles = 0;
    while (cycles < 45) {
        if (!pid || kill(pid, 0) < 0) {
            pid = find_svc();
            if (!pid) { usleep(2000); continue; }
            if (ptrace(PTRACE_ATTACH, pid, 0, 0) == 0) {
                int st; waitpid(pid, &st, __WALL);
                fprintf(stderr, "attached %d\n", pid);
            } else { pid = 0; continue; }
        }
        int s = find_pattern(pid, spki, sizeof spki);
        int l = find_pattern(pid, leaf, sizeof leaf);
        if (cycles % 10 == 0)
            fprintf(stderr, "cycle %d pid %d spki=%d leaf=%d\n", cycles, pid, s, l);
        if (s && l) break;
        if (ptrace(PTRACE_CONT, pid, 0, 0) == 0) {
            usleep(poll_ms * 1000);
            if (kill(pid, 0) < 0) { int st; waitpid(pid, &st, __WALL); pid = 0; continue; }
            if (kill(pid, SIGSTOP) == 0) { int st; waitpid(pid, &st, __WALL); }
        } else { int st; waitpid(pid, &st, __WALL); pid = 0; continue; }
        cycles++;
    }

    if (!pid || kill(pid, 0) < 0) { fprintf(stderr, "no target left\n"); return 2; }
    kill(pid, SIGSTOP); int st; waitpid(pid, &st, __WALL);
    struct user_regs_struct r;
    if (ptrace(PTRACE_GETREGS, pid, 0, &r) == 0)
        fprintf(stderr, "final RIP=%#llx\n", (unsigned long long)r.rip);
    char cmd[512], p[256];
    snprintf(p, sizeof p, "/proc/%d/maps", pid);
    snprintf(cmd, sizeof cmd, "cp %s %s/maps.txt", p, outdir); system(cmd);
    char memf[128]; snprintf(memf, sizeof memf, "/proc/%d/mem", pid);
    int mfd = open(memf, O_RDONLY);
    if (mfd < 0) { perror("open mem"); return 1; }
    dump_span(mfd, outdir, 0x140058000UL, 0x14005b000UL);
    FILE *f = fopen(p, "r");
    char line[512], path[256]; unsigned long a0, a1; char perms[8];
    while (f && fgets(line, sizeof line, f)) {
        path[0] = 0;
        if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %255[^\n]", &a0, &a1, perms, path) < 3) continue;
        if (path[0]) continue;
        if (perms[0] != 'r' || perms[1] != 'w') continue;
        if (a1 - a0 < 0x8000) continue;
        dump_span(mfd, outdir, a0, a1);
    }
    if (f) fclose(f); close(mfd);
    char pfh2[512]; snprintf(pfh2, sizeof pfh2, "%s/pid.txt", outdir);
    int of = open(pfh2, O_WRONLY|O_CREAT, 0644);
    if (of >= 0) { char b[32]; int n2 = snprintf(b, sizeof b, "%d", pid); write(of, b, n2); close(of); }
    fprintf(stderr, "dumped; pid %d frozen\n", pid);
    return 0;
}
