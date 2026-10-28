/* voice-patch.c — runtime dumper/patcher for the Rec Room VOICE key-exchange.
 *
 * WHY RUNTIME: GameAssembly.dll and global-metadata.dat are both encrypted at rest
 * (GameAssembly entropy ~8.0; metadata magic "RRRR", strings absent). The real IL2CPP
 * code only exists in memory after the packer + the 2025Patch injector unpack it. So
 * we cannot statically patch a file — we attach to the live game and read/write its
 * memory at the function RVAs recflare carved on this exact build (20250718.01).
 *
 * The goal: let the client ACCEPT UwUNet's plaintext "Carrot" voice approval. The
 * client's key-exchange callback CDJMICBEALM (NetworkManager_OnClientConnectedCallback,
 * RVA 0x8277880) calls RSA.Decrypt(KT) with NO null check and then SetEncryptionInfo;
 * a KT-less Carrot throws -> FailedToConnectToVoice, and even a valid KT would flip the
 * transport to a cipher we can't speak. We must make the client skip the crypto and
 * stay plaintext. The exact patch needs the DECRYPTED bytes of these functions, which
 * is what `dump` prints.
 *
 * Targets (RVAs into GameAssembly.dll, image base 0x180000000):
 *   CDJMICBEALM        0x8277880  key-exchange callback (where the throw lives)
 *   RecRoom_SetEncryptionInfo 0x735CA20  applies the derived key to the transport
 *   SetKey (encrypt layer)    0x735DF90  stores the 32-byte key (plaintext if neutered)
 *
 * Build (on the box that runs the game, native):
 *   cc -O2 -o voice-patch re/voice-patch.c
 * Use (game must be RUNNING and past the anti-cheat, i.e. in/near a room):
 *   ./voice-patch dump                 # print decrypted bytes of the 3 targets
 *   ./voice-patch peek 0x8277880 256   # dump an arbitrary RVA
 *   ./voice-patch poke 0x735df90 c3    # write bytes (hex) at an RVA (e.g. ret)
 *
 * poke is the delicate one — only run the bytes UwUNet hands you after reading a dump.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <stdint.h>

#define IMAGE_BASE 0x180000000ULL   /* GameAssembly.dll preferred base; RVAs are relative to it */

/* Find a running Rec Room process. Under Proton/Wine the comm is truncated to 15
 * chars, so match a few spellings of the depot exe and the classic name. */
static pid_t find_game(void) {
    DIR *d = opendir("/proc");
    struct dirent *e;
    pid_t found = 0;
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
        if (strstr(comm, "Recroom") || strstr(comm, "RecRoom") || strstr(comm, "recroom")) {
            found = atoi(e->d_name);
            /* prefer a process that actually has GameAssembly mapped (checked by caller) */
        }
    }
    if (d) closedir(d);
    return found;
}

/* Lowest mapped address of GameAssembly.dll in this process = its runtime base. */
static unsigned long gameassembly_base(pid_t pid) {
    char mp[128]; snprintf(mp, sizeof mp, "/proc/%d/maps", pid);
    FILE *f = fopen(mp, "r"); if (!f) return 0;
    char line[512]; unsigned long base = 0;
    while (fgets(line, sizeof line, f)) {
        if (!strstr(line, "GameAssembly.dll")) continue;
        unsigned long s;
        if (sscanf(line, "%lx-", &s) == 1) { if (!base || s < base) base = s; }
    }
    fclose(f);
    return base;
}

static int mfd_rd(int mfd, unsigned long addr, void *buf, size_t n) {
    return pread(mfd, buf, n, addr) == (ssize_t)n;
}
static int mfd_wr(int mfd, unsigned long addr, const void *buf, size_t n) {
    return pwrite(mfd, buf, n, addr) == (ssize_t)n;
}

static void hexdump(const char *name, unsigned long rva, int mfd, unsigned long base, int n) {
    unsigned long addr = base + rva;
    unsigned char buf[512]; if (n > (int)sizeof buf) n = sizeof buf;
    printf("== %s  rva 0x%lx  runtime 0x%lx ==\n", name, rva, addr);
    if (!mfd_rd(mfd, addr, buf, n)) { printf("  <unreadable>\n"); return; }
    for (int i = 0; i < n; i += 16) {
        printf("  +%03x: ", i);
        for (int j = 0; j < 16 && i + j < n; j++) printf("%02x ", buf[i + j]);
        printf(" |");
        for (int j = 0; j < 16 && i + j < n; j++) { unsigned char c = buf[i + j]; putchar(isprint(c) ? c : '.'); }
        printf("|\n");
    }
}

int main(int argc, char **argv) {
    const char *action = argc > 1 ? argv[1] : "dump";
    pid_t pid = find_game();
    if (!pid) { fprintf(stderr, "no Rec Room process found — is the game running?\n"); return 2; }
    unsigned long base = gameassembly_base(pid);
    fprintf(stderr, "[voice-patch] pid=%d GameAssembly base=%#lx%s\n", pid, base,
            base == IMAGE_BASE ? " (preferred)" : base ? " (relocated)" : " (NOT MAPPED — unpack not done?)");
    if (!base) return 3;

    kill(pid, SIGSTOP);
    if (ptrace(PTRACE_ATTACH, pid, 0, 0) == 0) { int st; waitpid(pid, &st, __WALL); }
    char memp[128]; snprintf(memp, sizeof memp, "/proc/%d/mem", pid);
    int mfd = open(memp, O_RDWR);
    if (mfd < 0) { perror("open mem"); ptrace(PTRACE_DETACH, pid, 0, 0); kill(pid, SIGCONT); return 3; }

    int rc = 0;
    if (!strcmp(action, "dump")) {
        hexdump("CDJMICBEALM (key-exchange callback)", 0x8277880, mfd, base, 256);
        hexdump("RecRoom_SetEncryptionInfo",           0x735CA20, mfd, base, 128);
        hexdump("SetKey (encrypt layer)",               0x735DF90, mfd, base, 128);
    } else if (!strcmp(action, "peek") && argc >= 3) {
        unsigned long rva = strtoul(argv[2], 0, 0);
        int n = argc > 3 ? atoi(argv[3]) : 128;
        hexdump("peek", rva, mfd, base, n);
    } else if (!strcmp(action, "poke") && argc >= 4) {
        unsigned long rva = strtoul(argv[2], 0, 0);
        const char *hx = argv[3];
        unsigned char bytes[64]; int nb = 0;
        for (const char *p = hx; p[0] && p[1] && nb < (int)sizeof bytes; p += 2)
            bytes[nb++] = (unsigned char)strtoul((char[]){p[0], p[1], 0}, 0, 16);
        unsigned long addr = base + rva;
        unsigned char before[64];
        mfd_rd(mfd, addr, before, nb);
        if (mfd_wr(mfd, addr, bytes, nb)) {
            printf("[voice-patch] wrote %d byte(s) at rva 0x%lx (runtime 0x%lx)\n", nb, rva, addr);
            printf("  before:"); for (int i = 0; i < nb; i++) printf(" %02x", before[i]); printf("\n");
            printf("  after :"); for (int i = 0; i < nb; i++) printf(" %02x", bytes[i]); printf("\n");
        } else { fprintf(stderr, "write failed\n"); rc = 4; }
    } else {
        fprintf(stderr, "usage: voice-patch dump | peek <rva> [n] | poke <rva> <hexbytes>\n");
        rc = 1;
    }

    close(mfd);
    ptrace(PTRACE_DETACH, pid, 0, 0);
    kill(pid, SIGCONT);
    return rc;
}
