/* freeze-win.c — attach to each new RefereeClientAp service process as early
 * as possible; once it has the pin-window mapped, STOP it, dump the
 * pin-check code window 0x140058000-0x14005b000 (and maps), then CONTINUE so
 * the chain keeps running (multiple service attempts get dumped in pass).
 * usage: freeze-win <outdir> [poll_ms]
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

static int win_mapped(pid_t pid) {
    char mp[128]; snprintf(mp, sizeof mp, "/proc/%d/maps", pid);
    FILE *f = fopen(mp, "r"); char line[512]; int ok = 0;
    if (!f) return 0;
    while (fgets(line, sizeof line, f))
        if (strstr(line, "14005"))
        {
            ok = 1; break;
        }
    fclose(f);
    return ok;
}

int main(int argc, char **argv) {
    const char *outdir = argv[1];
    int poll_ms = argc > 2 ? atoi(argv[2]) : 20;
    char mk[512]; int st;
    snprintf(mk, sizeof mk, "mkdir -p %s", outdir); st = system(mk); (void)st;
    int dumped[16384] = {0};
    int ntries = 30000;
    while (ntries-- > 0) {
        pid_t pid = find_svc();
        if (pid <= 0 || pid >= 16384 || dumped[pid]) { usleep(poll_ms*1000); continue; }
        dumped[pid] = 1;
        if (kill(pid, 0) < 0) continue;
        usleep(600000);   /* let the pin-window decrypt a bit */
        if (win_mapped(pid)) {
            if (kill(pid, SIGSTOP) == 0) { int st2; waitpid(pid, &st2, __WALL); }
            else { fprintf(stderr, "SIGSTOP(busy仍在?) %d\n", pid); }
            /* dump pin window even if it's not yet decrypted; take map too */
            char pfh[512], cmd[512];
            snprintf(cmd, sizeof cmd, "cp /proc/%d/maps %s/svc_%d.maps", pid, outdir, pid);
            st = system(cmd); (void)st;
            char memf[128]; snprintf(memf, sizeof memf, "/proc/%d/mem", pid);
            int mfd = open(memf, O_RDONLY);
            fprintf(stderr, "%d win_mapped stop\n", pid);
            if (mfd >= 0) {
                static unsigned char buf[0x3000];
                ssize_t n = pread(mfd, buf, sizeof buf, 0x140058000UL);
                snprintf(pfh, sizeof pfh, "%s/svc_%d_pinwin.bin", outdir, pid);
                int o = open(pfh, O_WRONLY|O_CREAT|O_TRUNC, 0644);
                if (o >= 0) { write(o, buf, n); close(o); fprintf(stderr, "dump %d bytes %d -> %s\n", pid, (int)n, pfh); }
                /* also dump the broad RX window for code elsewhere */
                snprintf(pfh, sizeof pfh, "%s/svc_%d_rxbig.bin", outdir, pid);
                o = open(pfh, O_WRONLY|O_CREAT|O_TRUNC, 0644);
                if (o >= 0) {
                    static unsigned char big[0x80000];
                    n = pread(mfd, big, sizeof big, 0x140700000UL);
                    write(o, big, n);
                    close(o);
                    fprintf(stderr, "dump rxbig %d bytes %d\n", pid, (int)n);
                }
                close(mfd);
            }
            kill(pid, SIGCONT);
            ptrace(PTRACE_DETACH, pid, 0, 0);
        }
        usleep(poll_ms * 1000);
    }
    return 0;
}
