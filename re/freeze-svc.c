// Freezes RefereeClientApp.exe mid-service-init (the -99961 pin-check window)
// and dumps: all >=64 KB anon mappings + the app code pages of its image.
// Derived from freeze2.c (comm-based catch + delayed SIGSTOP + ptrace RIP).
// Usage: freeze-svc <outdir> [delay_ms]
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
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
        // Linux comm is truncated to 15 chars: "RefereeClientAp"
        if (!strncmp(comm, "RefereeClientAp", 15))
            return atoi(e->d_name);
    }
    if (d) closedir(d);
    return 0;
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
    fprintf(stderr, "  dumped %s\n", fn);
}

int main(int argc, char **argv) {
    const char *outdir = argv[1];
    int delay_ms = argc > 2 ? atoi(argv[2]) : 1300;
    pid_t pid = 0;
    for (int i = 0; i < 4000 && !(pid = find_svc()); i++) usleep(2000);
    if (!pid) { fprintf(stderr, "no RefereeClientApp.exe seen\n"); return 1; }
    fprintf(stderr, "found %d; sleeping %d ms\n", pid, delay_ms);
    usleep(delay_ms * 1000);
    if (kill(pid, SIGSTOP) < 0) { perror("kill STOP"); return 1; }
    usleep(100000);
    FILE *ferr = stderr;
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) == 0) {
        int st; waitpid(pid, &st, __WALL);
        struct user_regs_struct r;
        if (ptrace(PTRACE_GETREGS, pid, 0, &r) == 0)
            fprintf(ferr, "RIP=%#llx\n", (unsigned long long)r.rip);
    } else perror("ptrace");
    char p[256];
    snprintf(p, sizeof p, "/proc/%d/maps", pid);
    char cmd[512];
    snprintf(cmd, sizeof cmd, "cp %s %s/maps.txt", p, outdir); system(cmd);
    FILE *f = fopen(p, "r");
    char line[512], path[256]; unsigned long a0, a1; char perms[8];
    char memf[128]; snprintf(memf, sizeof memf, "/proc/%d/mem", pid);
    if (!f) { fprintf(stderr, "maps gone\n"); return 1; }
    int mfd = open(memf, O_RDONLY);
    if (mfd < 0) { perror("open mem"); return 1; }
    // dump the image code window (pin check lives near 0x140058000)
    dump_span(mfd, outdir, 0x140058000UL, 0x14005b000UL);
    // dump all anon private regions >= 64 KB
    while (fgets(line, sizeof line, f)) {
        path[0] = 0;
        if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %255[^\n]", &a0, &a1, perms, path) < 3) continue;
        if (path[0]) continue;
        if (perms[0] != 'r' || perms[1] != 'w') continue; // writable only
        if (a1 - a0 < 0x10000) continue;
        dump_span(mfd, outdir, a0, a1);
    }
    fclose(f); close(mfd);
    snprintf(cmd, sizeof cmd, "%d", pid);
    char pf[512]; snprintf(pf, sizeof pf, "%s/pid.txt", outdir);
    int pfh = open(pf, O_WRONLY|O_CREAT, 0644);
    if (pfh >= 0) { write(pfh, cmd, strlen(cmd)); close(pfh); }
    return 0;
}
