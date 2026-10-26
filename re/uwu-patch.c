/* uwu-patch.c — RecRoom.exe IAT-seam experiment ported from RecFlare's
 * patch-2025 Referee approach, wine-native:
 *   1. find RecRoom.exe with Referee.dll mapped
 *   2. PTRACE attach, stop it
 *   3. read IAT slot for Referee.dll!jjiEVn at game RVA 0xd228 (image base
 *      0x140000000 -> 0x1400d228), plus the target code bytes
 *   4. read Referee.dll image base from maps (module=0x180000000)
 *   5. optional: patch target entry with  b8 <imm32> c3  ("mov eax, imm; ret")
 *      so ANY game call through that IAT slot returns our result
 *   6. print findings to stderr
 * usage: uwu-patch <action: peek|patch> <imm32> [poll_ms]
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
#include <stdint.h>

#define IAT_RVA      0xd228
#define GAME_BASE    0x140000000ULL

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
        if (!strncmp(comm, "RecRoom.exe", 11)) return atoi(e->d_name);
    }
    if (d) closedir(d);
    return 0;
}

static int has_referee(pid_t pid) {
    char mp[128]; snprintf(mp, sizeof mp, "/proc/%d/maps", pid);
    FILE *f = fopen(mp, "r"); char line[512]; int ok = 0;
    if (!f) return 0;
    while (fgets(line, sizeof line, f))
        if (strstr(line, "Referee.dll") && strstr(line, "180000000-180001000")) { ok = 1; break; }
    fclose(f);
    return ok;
}

static int rd(int mfd, unsigned long addr, void *buf, size_t n) {
    return pread(mfd, buf, n, addr) == (ssize_t)n;
}
static int wr(int mfd, unsigned long addr, const void *buf, size_t n) {
    return pwrite(mfd, buf, n, addr) == (ssize_t)n;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: uwu-patch peek|patch [imm]\n"); return 1; }
    int do_patch = !strcmp(argv[1], "patch");
    uint32_t imm = argc > 2 ? (uint32_t)strtoul(argv[2], 0, 0) : 0;
    int poll_ms = argc > 3 ? atoi(argv[3]) : 100;

    pid_t pid = 0;
    int tries = 600;
    while (tries-- > 0) {
        pid = find_game();
        if (pid && has_referee(pid)) break;
        if (pid && !has_referee(pid)) usleep(poll_ms*1000);
        pid = 0;
        usleep(poll_ms*1000);
    }
    if (!pid) { fprintf(stderr, "no RecRoom.exe with Referee.dll found\n"); return 2; }
    fprintf(stderr, "[uwu-patch] pid=%d\n", pid);

    kill(pid, SIGSTOP);
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) == 0) { int st; waitpid(pid, &st, __WALL); }
    char memp[128]; snprintf(memp, sizeof memp, "/proc/%d/mem", pid);
    int mfd = open(memp, O_RDWR);
    if (mfd < 0) { ptrace(PTRACE_DETACH, pid, 0, 0); return 3; }

    unsigned long iat = GAME_BASE + IAT_RVA;
    unsigned long target = 0;
    if (!rd(mfd, iat, &target, 8)) { fprintf(stderr, "IAT read failed\n"); goto out; }
    fprintf(stderr, "[uwu-patch] IAT @ %#lx -> %#lx\n", iat, target);

    unsigned char code[64];
    if (rd(mfd, target, code, 64)) {
        fprintf(stderr, "[uwu-patch] target bytes: ");
        for (int i = 0; i < 24; i++) fprintf(stderr, "%02x ", code[i]);
        fprintf(stderr, "\n");
    } else fprintf(stderr, "[uwu-patch] target unreadable\n");

    if (do_patch) {
        /* find an RWX anon span in the target and tail-write the stub,
         * then repoint the IAT at it (never rewriting Themida's zones) */
        char mp[128]; snprintf(mp, sizeof mp, "/proc/%d/maps", pid);
        FILE *f = fopen(mp, "r"); char line[512]; unsigned long a0 = 0, a1 = 0, rwx = 0;
        long region[64][2]; int n = 0;
        if (f) {
            while (fgets(line, sizeof line, f)) {
                unsigned long s, e; char perms[8], p2[256]; p2[0]=0;
                if (sscanf(line, "%lx-%lx %4s %*s %*s %*s %255[^\n]", &s, &e, perms, p2) < 3) continue;
                if (p2[0]) continue;                       /* anon only */
                if (strcmp(perms, "rwxp") != 0) continue;
                if (e - s < 0x1000) continue;
                if (n < 64) { region[n][0] = s; region[n][1] = e; n++; }
            }
            fclose(f);
        }
        if (n > 0) {
            rwx = region[n-1][1] - 0x1000;                 /* end of last RWX span */
            fprintf(stderr, "[uwu-patch] rwx span #%d %#lx-%#lx, stub at %#lx\n",
                    n-1, region[n-1][0], region[n-1][1], rwx);
            unsigned char stub[6] = { 0xB8, 0,0,0,0, 0xC3 };
            stub[1] = imm & 0xff; stub[2] = (imm>>8)&0xff;
            stub[3] = (imm>>16)&0xff; stub[4] = (imm>>24)&0xff;
            if (!wr(mfd, rwx, stub, 6)) { fprintf(stderr, "stub write failed\n"); goto out; }
            if (!wr(mfd, iat, &rwx, 8)) { fprintf(stderr, "iat repoint failed\n"); goto out; }
            unsigned long chk = 0;
            rd(mfd, iat, &chk, 8);
            fprintf(stderr, "[uwu-patch] IAT now -> %#lx (stub mov eax,0x%x; ret)\n", chk, imm);
        } else fprintf(stderr, "[uwu-patch] no rwx span found\n");
    }
out:
    close(mfd);
    ptrace(PTRACE_DETACH, pid, 0, 0);
    kill(pid, SIGCONT);
    return 0;
}
