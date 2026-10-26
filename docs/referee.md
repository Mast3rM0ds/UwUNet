# Referee deep-dive (Option 2 groundwork)

## Component map (Oct 25–26 2026 findings)

| Binary | Size | Protection | Role |
|---|---|---|---|
| `Recroom_Release.exe` | 1.0 MB | none (native x64 C++ that hosts a CLR; loads mscoree/mono, "Superpower" etc.) | service driver: installs/starts `RefereeClientApp` service, waits RUNNING, launches game target |
| `RefereeClientApp.exe` | 4.3 MB | **Themida** (`.themida`+`.boot` sections), import obfuscation (kernel32 → only `GetModuleHandleA`) | Windows service; loads "blobs" then launches/arms game |
| `Referee.dll` | 63 MB | **Themida**, same pattern | anti-cheat core; loaded in-process by the game (writes `Referee.Game.log`, "session init") |
| `RefereeClientInstaller.exe` | 330 KB | native | install/uninstall service (works under Wine: `Installing service 'RefereeClientApp'... success`) |
| `RecRoom.exe` | 672 KB | none | **Unity IL2CPP bootstrap** (672 KB + UnityPlayer.dll + GameAssembly.dll is a canonical IL2CPP layout). Has `.fptable` section. Strings contain `WindowsPlayer.exe` and it does ShellExecute; direct run ends in `ShellExecuteEx failed: File not found.` |

## The `-99xxx` failure ladder

```
Game   : Unable to initialize session with status -99903     (Referee.Game.log)
App    : One or more blobs of type 0 were not found or loaded with status -99962
App    : Unable to load configuration with status -99986. Stopping service.
Launcher: Service transitioned to 'STOPPED' ... retry x5
```

The service never touches disk/registry for config (verified via
`WINEDEBUG=+file,+reg` trace: only its own exe path + `C:\ProgramData`
attribute check). So "blobs of type 0" are:

1. most likely **embedded in the Themida-protected image**
   (`RefereeClientApp.exe` / `Referee.dll`), decrypted at runtime, or
2. provisioned over the network (services now dead; our port-redirect
   would have caught it — we captured **no** SNI during the failing runs),
3. delivered via the launcher process (e.g. shared memory / env passed
   by `Recroom_Release.exe` — TBD, trace in progress).

`WindowsPlayer.exe` does not exist in the depot. `RecRoom.exe`'
ShellExecute of it means the exe is materialized at runtime by the
Referee layer from those very blobs. **If we recover or reconstruct the
blob format (or get a WindowsPlayer.exe cached blob dump from any
community member who still has the shutdown-era cache), the client boots.**

## Boot flow (as observed)

```
Steam launch (+forcemode:vr)
 └ Recroom_Release.exe (CLR host)
    ├ RefereeClientInstaller.exe -install   (Installs Referee service)   ✓ under Wine
    ├ service RecereeClientApp start/stop loop ×5            ✗ blobs of type 0 / config
    └ (service normally) launches target binary → RecRoom.exe
        RecRoom.exe loads Referee.dll in-process → session init (with service)
      Verbose traces also show mscoree/mono load inside the launcher.
```

## Oct 26 00:00–00:30 — the blob hunt, flattened

**Method.** LD_PRELOAD hooks that work in wine process trees
(`lib/uwuhook.so` 64-bit + `lib/uwuhook32.so` freestanding 32-bit,
raw-syscall, loads where glibc multilib is missing). Hook logs every
outbound `connect()` with pid; then freeze-dump tooling
(`scripts/dump-service.sh`): polls `/proc/*/cmdline` for the service
process (`wine64-preloader` target — the 64-bit exe runs under Proton
new-wow64, path is `i386-unix/wine64-preloader`), and either freezes at
`FREEZE_DELAY` s or **at the millisecond a pattern appears in
Referee.App.log** (`STOP_ON_LOGMATCH=...`), then dd's
`/proc/$pid/mem` with `@@REGION` framing; `re/dump-slice.py` slices
private `r-x` regions out for offline analysis.

**What the failure ladder actually is** (from the frozen-at-error dump,
strings at `0x11c6230–0x11c6a10` in the 329 MB `-99962` snapshot):

```
Failed to load blob '%ws' with status %lld and NT status 0x%lx, source %u
One or more blobs of type %u were not retrievable with status %lld
One or more blobs of type %u were not found or loaded with status %lld
Failed to parse configuration with parse error %d
Unable to load configuration with status %lld. Stopping service.
Unable to load client library with status %lld. Stopping service.
Failed to execute blob ID %llu.%u.%u.%u ...
Unable to find target process 'RecRoom.exe' or launcher process 'RecRoom_Release.exe'
```

- Blob IDs are **version quadruples** (`%llu.%u.%u.%u`) — Referee blobs
  are version-addressed payloads.
- Blob loading dispatches on an **`EBlobSource` enum** with mangled
  functions `GetBlobsLocal`, `GetClientLibrary`, `GetClientConfiguration`
  and a struct `FBlobHeader` (RTTI-visible). The App embeds
  **libcurl 8.14.1** (schannel TLS) — remote blob sources exist but were
  never reached.
- Local blob path pattern is **`%s\Referee\%s`** →
  `C:\ProgramData\Referee\<file>` (same dir as the logs).
- PDB paths leak scope: `C:\a1\_work\2\s\Referee\Src\Bin\Release\RefereeClientApp.pdb`.

**Exhausted sources for the blobs (all verified empirically):**
1. ❌ network — no `connect()` at all during the 2 s life (hook-verified
   in the actual service process, both 32- and 64-bit preloads).
2. ❌ Steamworks/Steam-client presence — same -99962 when launched via
   Steam (`-applaunch`); `gamedrive`/`forcelgadd` are generic Proton
   defaults, not Rec Room-specific.
3. ❌ disk — `+file/+reg` trace: only its own exe + `ProgramData`
   attribute check; `C:\ProgramData\Referee` contains only logs.
4. ❌ registry — no custom key reads (trace verified).
5. ❌ installer/launcher resources — `7z l` shows no payload: the install
   script just registers the service.
6. ⏳ **unverifiable: decrypted-at-execution pages.** Themida's per-page
   decryption means static dumps of `text.bin` stay encrypted; the blob
   list (and possibly the blobs themselves) likely lives inside the
   Themida VM's decrypted working pages, or the config blob payload
   inside `Referee.dll`'s encrypted regions.

**Working conclusion.** Blob type 0 ("configuration") must come from
`C:\ProgramData\Referee\<name>` blob files that **nothing in the depot
or installer ever provisions** — they were deployed by Rec Room's own
services pre-shutdown (per-machine provisioned) or fetched over the
network by an earlier launcher generation. **The single highest-value
action is obtaining a shutdown-era copy of a live machine's
`C:\ProgramData\Referee\*` directory** (any Windows player who kept the
folder), plus the community's shut-down-window dumps. Even one sample
gives `FBlobHeader` layout + names, and may directly contain the
`WindowsPlayer.exe` material.

## Themida / wow64 facts (tooling)

- All Rec Room PEs are **x86-64**, not just the launcher: also
  `RefereeClientApp.exe`, `Referee.dll` (63 MB), installer.
- Themida sections: `.themida` + `.boot` (3.7 MB stub) on App+Referee.dll.
- Proton Experimental uses new-wow64 hybrid: 64-bit PEs at
  `i386-unix/wine64-preloader`; the transient 32-bit stage exists only
  briefly, so freeze-tooling must filter on `wine64-preloader`.
- Hidden strings: format strings encrypted until used; the only place
  they linger is the log-writing instant — which is why
  `STOP_ON_LOGMATCH` beats `FREEZE_DELAY`.
- Direct `wine RefereeClientApp.exe` sometimes fails earlier with
  error 1063 ("not run as a service") after the services state gets
  messy — launching via `Recroom_Release.exe` is always the reliable repro.


## Leads to follow (priority order)

1. **Obtain a shutdown-era `C:\ProgramData\Referee\*`** from any Windows
   player (one .zip answers FBlobHeader layout + blob names, possibly
   contains the WindowsPlayer.exe payload). Ask in RestoRoom/REC26 +
   community channels; this is the rescue divisor.
2. **Freeze at the parse step**: place a synthetic file in
   `C:\ProgramData\Referee\` and `STOP_ON_LOGMATCH="parse"` to capture
   format validation feedback (`Failed to parse configuration with
   parse error %d`) — iterate to reverse the FBlobHeader layout if the
   community route stalls.
3. **Keep dump tooling** (`scripts/dump-service.sh` + `re/dump-slice.py`)
   ready: `-99962` capture + full slice flow is proven and reproducible
   (`LAUNCH` via Recroom_Release.exe is required — direct service runs
   can wedge into error 1063).
4. Rec Room's own ship notes hint blobs relate to "real-time update
   configuration", consistent with blob types (type 0 = config; likely
   type 1 = payload / `WindowsPlayer.exe`).

## Tooling notes

- `objdump -h` is enough for section classification (themida[, .boot]).
- `strings -el` against rec[].exe is very effective — UTF-16 strings.
- `pefile` may be shadowed/broken in this env; use objdump.
- Harness kills long foreground shells; run captures in background
  (`timeout N ... > log 2>&1`).

## Oct 26 00:40–01:20 — stub bypass experiment: CONCLUSIVE NEGATIVE (+ new kill-switch discovery)

### What the hand-built stub proved
- `re/build-stub.py` final form: 2048-byte PE32+ DLL, single `.uwu` section (RWX),
  exports ordinal-1 `jjiEVn` by name, DllMain returns TRUE, **no syscalls**.
  - Raw `syscall` from 64-bit PE code under wine is TRAPPED: new-wow64 installs
    a seccomp filter whose SIGSYS handler treats rax as an **NT** syscall number
    (`trace:seh:sigsys_handler` events in run logs). rax=3 (Linux `close`) is
    NT #3 = `NtMapUserPhysicalPagesScatter` → wine aborts. DllMain/jji writes
    must go through NT/kernel32 APIs or nothing.
  - Useful so: export directory Size field must cover tables+strings
    (40 = ED struct only fails resolution: "jjiEVn not found"); the data-dir
    RVA must point at the actual ED; kernel32 hint-name arrays can't overlap
    adjacent strings (caused the bogus `kernel32.dll.37008` ordinal).
- Stub loads into RecRoom.exe through **the static import descriptor**
  (not LoadLibraryW — earlier +loaddll reading was wrong).

### Kill switch discovered in RecRoom.exe itself
- RecRoom.exe's `.text` section characteristics = `C0000020`
  (WRITE|READ|CODE, **no MEM_EXECUTE**). Base mapping is the same in real and
  stub runs (`map_image_into_view` lines identical), yet only real-deferee runs
  boot.
- `.text` on disk has entropy **7.99/8 across all 48 KB** → fully encrypted.
  `.rdata` 4.47 (partly encrypted), `.fptable` all zeros (runtime-filled).
  The whole-game decryption is NOT on disk anywhere.
- With only the stub present: entry fault at `0x140001264` —
  first *execute* fault (non-exec .text), then after we patched a gamedir
  copy of the exe to `E0000020` (+EXECUTE), the entry executes the still
  encrypted bytes → garbage / NULL-read fault (`c0000005`).
  Patching section chars is NECESSARY but not sufficient.
- Freeze-dumps of a live RecRoom.exe with the REAL Referee.dll
  (`freeze2` → `/tmp/opencode/recfreeze`): at both t≈1.2 s and t=-99903,
  the mapped `.text` at `0x140001000` is byte-identical to the disk
  (still encrypted), in-memory PE header untouched (entry stays 0x1264).
  Execution happens inside Themida VM allocations instead:
  RIP `0x186f967cb` inside `0x186caf000..0x18737b000` (6.8 MB, entropy 5.2–7.3,
  mixed VM-interpreter/scratch), plus `0x180001000` 39 MB and `0x18293a000`
  67 MB companion regions. **No pristine decrypted `.text` image ever
  materializes in a dump — code is virtualized/interpreted.**
- Conclusion: a `Referee.dll` stub can never bypass this. RecRoom.exe is
  Themida-virtualized wholesale, with the VM shipped inside Themida'd
  `Referee.dll`. The "game is playable if you stub Referee" theory is dead.

### Path forward (unchanged user decision)
- Keep the real Referee.dll + RefereeClientApp chain (they RUN under wine);
  attack the **blob store**: synthetic `C:\ProgramData\Referee\*` blobs +
  `STOP_ON_LOGMATCH="parse"` freezes to reverse `FBlobHeader`, and
  community outreach (RestoRoom/REC26) for a shutdown-era copy of
  `ProgramData/Referee/*`.

### Tooling
- `re/build-stub.py` — final stub generator (kept; documents the wine syscall
  trap + export-dir requirements inline).
- `/tmp/opencode/freeze2.c(::freeze2)` — process catcher: finds comm
  `RecRoom.exe`, pets looked at 1.2 s delay, SIGSTOPs, PTRACE GETREGS RIP,
  dumps every anon region ≥32 KB into a directory.linux Needs PTRACE_ATTACH
  after SIGSTOP for regs. Related scripts/dump-service.sh (service-side).
- gamedir/RecRoom.exe is now a PATCHED copy (+EXECUTE `.text`); depot copy
  untouched. If reusing gamedir for real-referee runs, both work.

## Oct 26 01:25–02:10 — RefereeClientApp init traced live (relay) + api.rec.net probe discovery

Setup: `gamedir2/` = symlinks to ALL depot files (depot still untouched); run
`Recroom_Release.exe` (the real launch path — launching `RecRoom.exe` directly
skips the launcher and never even attempts the service start). Full boot chain
under `WINEDEBUG=+relay`, `LD_PRELOAD` shim, ~28 MB relay log per run.

### The service boot ladder (proven)
- `RefereeClientApp.exe` is registered as a Windows service (ImagePath =
  `Z:\...\RecRoom\RefereeClientApp.exe`, Start=3/manual) by
  `RefereeClientInstaller.exe` (its log: recreates the service, grants
  `0x94` to Authenticated Users).
- `Recroom_Release.exe` runs as **Client Launcher**: StartService ×5 with
  growing backoff; each attempt spawns a NEW RefereeClientApp.exe process.
- Service init sequence (from App.log): `Started service initialization.` →
  fails within ~2 s → `Stopping service.` → SCM STOP → `Exited service loop.`

### The -99962/-99961 error ladder (meaningful — codes encode HOW FAR it got)
- **DNS/TCP unreachable → status -99962** ("One or more blobs of type 0 were
  not found or loaded"). Verified: with no `api.rec.net` resolution, getaddrinfo
  fails and the ladder is -99962.
- **TLS handshake to a live server (any cert) → status -99961** (same message
  text). Verified across: our real edge cert, an A/B cert with a totally
  different RSA keypair, ALPN-negotiating server, 2-cert chain server — all
  -99961. The handshake itself ALWAYS completes (see next point).

### What the service does on the wire (proven)
- Service init calls `getaddrinfo("api.rec.net","443")` (×4 threads + a 5th
  retry), then `socket/connect/sck send recv` loop.
- ClientHello (captured raw via a custom TLS-listener): **TLS 1.2 only**
  (client version `0303`, no supported_versions ext), SNI `api.rec.net`,
  **ALPN offers exactly `http/1.1`**, ~25 ciphersuites, no TLS 1.3.
- schannel handshake against UwUNet's self-signed `rec.crt` **completes
  cleanly** (GNUTLS trace `Handshake completed`) — the client does NOT verify
  our CA.
- Then the client does crypt32 work (CertOpenStore memory-store +
  `CertAddEncodedCertificateToStore` of our 0x514-byte leaf, OID parsing),
  computes ONE app-level `CryptCreateHash(0x800c=SHA256)`+
  `CryptHashData(len=0x126=294 bytes)` + `CryptGetHashParam(HP_HASHVAL)` and
  then **closes the socket without ever sending one byte of app data** (no
  HTTP request ever reaches our server; harvest shows only `tls-sni` events).
- **294-byte hash input is NOT derived from the received cert**: 294 ≠ SPKI
  (292 for our RSA-2048), ≠ SPKI BIT-STRING content (270), and the same
  0x126 occurs for a different keypair too. Plus crypt32's standard
  `SHA1(leaf DER)` per handshake (843/1300 bytes — just cert fingerprinting).
  So the 294-byte value is service-internal (baked/config/provisioned) — but
  see the open question below.

### A/B disproofs (both cert variants gave identical -99961)
1. Different RSA keypair (SPKI) → same error ⇒ it is *not* an SPKI pin.
2. Server negotiating ALPN (`http/1.1`) → same error ⇒ ALPN not required.
3. Server appending an extra chain cert (RSA-3072, 1079-byte DER) → still one
   0x126 hash ⇒ **not** a chain-scan of received certs either.

### File system (proven negative)
- The service's init opens ONLY its own logs + `CreateDirectoryW(
  "C:\\ProgramData\\Referee")`. NO blob-file opens, no `%llu.%u.%u.%u` id
  strings, no NtQueryDirectoryFile on the blob dir during this failure path.
  So "blobs of type 0" are NOT read as local files at this stage — they're
  expected to arrive/FETCH through the api.rec.net channel (which we can't
  fake yet) **or** the fetch happens inside Themida-virtualized code paths we
  haven't reached.

### Tooling (new, reusable)
- `lib/uwudns64.c` / `.so` — LD_PRELOAD `getaddrinfo` shim: maps
  `*.rec.net`|`*recroom*`|`*protoplay*` → 127.0.0.1 (and `gethostbyname`);
  do NOT interpose `freeaddrinfo` (glibc handles it; interposing corrupts).
  Verifies under plain Linux AND inside the wine processes.
- `lib/uwuhook.c` updated: now rewrites **loopback:443→8443 and loopback:80→
  8460** too (the service probes 127.0.0.1:443 after our DNS shim), and
  honors `UWU_TLS_PORT` / `UWU_HTTP_PORT` env overrides for A/B tests (e.g.
  pointing api.rec.net at the AB server on :9443 without rebuilding).
  Also has send()/recv() payload logging — heavy noise from wine's internal
  dbus/uinput sockets, use sparingly.
- `/tmp/opencode/ab-tls.js` — standalone TLS server (:9443) with `ALPN:
  http/1.1`, `ab.crt/ab.key` (fresh RSA-2048), optional extra chain cert
  `extra2.crt` (RSA-3072) for chain-scan tests. `/tmp/opencode/hello-dump.js`,
  `hello-dump2.js` — raw ClientHello decoder listeners (:9445/:9446).
- `re/freeze-svc{,2,3,4}.c` — comm-based catchers for `RefereeClientAp`
  (comm truncates at 15 chars — first hang was the matcher). Stall-free
  STOP/md-scan cycles work, but the pin-check code window is Themida-
  re-encrypted after execution, so post-hoc code reads see ciphertext.
- A/B helpers: leaf/SPKI DERs cached at `/tmp/opencode/{leaf,spki}.der`;
  computed sha256(SPKI)=`093ee105…` for our cert (kept for pattern-scans).
- Wine service registry side: `reg query 'HKLM\System\CurrentControlSet\
  Services\RefereeClientApp'` shows DisplayName/ImagePath/Start; nothing
  Rec Room-specific under HKLM\Software (no Referee/RecRoom config tree).

### Footgun note (repeat offenders)
- `pkill -f /pattern/` self-murders your own shell if the pattern appears in
  the command line — killed us twice more today. Stick to
  `ps -eo pid,comm` + `kill` (or `pkill -x` with exact comm names).

### Interpretation / open question
The service treats `api.rec.net:443` as a **mandatory provisioning endpoint**
before any blob/type-0 work. With a generic HTTPS server it closes
immediately — so it needs SERVER-SIDE knowledge we don't have yet: either a
custom post-TLS protocol, a TLS-level check we haven't identified, or an
authentication of the server's identity baked into the 294-byte-hash check.
This is exactly the class of detail that community intel (RestoRoom/REC26,
people who ran the client with the LIVE servers) would answer quickly — the
next big push should be to ask around for: the provisioning traffic shape and
whether anyone has a shutdown-era `C:\ProgramData\Referee\*` blob store.

## Oct 26 (afternoon) — CORRECTION: -99961 is SPKI public-key pinning (proven)

**The earlier "294-byte hash is NOT derived from the cert" claim (section
01:25–02:10) was WRONG.** It rested on a miscalculated SPKI length
("292 for RSA-2048"). The live `ref-hash-watch.py` capture at 03:03 settles it:

- The 294-byte (`0x126`) buffer passed to `CryptHashData` is **byte-identical**
  to our leaf cert's `SubjectPublicKeyInfo` DER:
  `openssl x509 -in certs/rec.crt -pubkey -noout | openssl pkey -pubin -outform DER`
  → 294 bytes, sha256 `89a1c02d…519a2` — exactly the frozen buffer
  `re/logs/refhash/buf_6987_1888091_294_89a1c02d.bin` (verified with `cmp`).
- So the service computes **SHA-256(server SPKI)** and compares it to a
  baked-in expected hash. This is textbook HPKP-style **public-key pinning**.

**Why the A/B disproofs were a false negative.** "Different RSA keypair → same
-99961" does NOT disprove a pin — a *different* key also fails the pin, because
neither key is Rec Room's. The test couldn't distinguish "no pin" from "a pin we
can't satisfy." Both cert variants failed for the same reason: the pin expects
Rec Room's real public key, which we don't have.

**Consequence — the wall is now fully characterised:**
1. `RefereeClientApp.exe` connects `api.rec.net:443`, completes the TLS
   handshake against ANY cert (it does not verify our CA), then **pins the
   server's public key**: SHA-256(SPKI) must equal a value baked into the
   (Themida-protected) image.
2. We can **never** satisfy this server-side — it would require Rec Room Inc.'s
   private key. Presenting any cert we can generate fails by construction.
3. Therefore the only routes to a booting client are, exactly as RecFlare
   concluded (docs/recflare.md):
   a. **Bypass the pin client-side** — patch the comparison (the native
      equivalent of RecFlare's `NotifyServerCertificate` no-op) inside
      `RefereeClientApp.exe`/`Referee.dll` at runtime (ptrace + /proc/pid/mem
      under wine — no Windows injector needed), OR
   b. **Target an older build** (RecFlare's playable 20250718.01) whose boot
      path tolerates a dead `api.rec.net` with no provisioning pin at all.

The 294-byte-hash *provisioning* hunt is therefore a dead end for "satisfy it":
there is nothing to satisfy. The remaining RE value is finding the **compare
site** (the return address of that `CryptHashData` call lands in Referee code
that does the memcmp against the baked pin) so the pin can be neutralised.
`re/refpin.c` aims at exactly this but has not landed a clean INT3 trap yet
(threads stop with sig=5 but rip != bpaddr; needs fixing).
