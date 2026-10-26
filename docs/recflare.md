# How RecFlare Does It — Research Notes (2026-10-26)

Sources recflare/server, recflare/patch-2025 (+ its CLAUDE.md), recflare/patch
(= djdevin/recnet-plugin, BepInEx plugin, + its CLAUDE.md and README).

## TL;DR — the community never solved our problem, because they avoided it

RecFlare **never impersonates the RefereeClientApp.exe boot chain** (no api.rec.net
provisioning, no blobs-of-type-0, no 294-byte hash). They sidestep it two ways:

1. **Target older builds** shipped via Steam DepotDownloader manifests:
   - 20230414 — manifest `6426603215211043630` (BepInEx/C# plugin, primary target)
   - 20250718.01 — manifest `1151455856673601091` (native patch, "playable")
   - 2026 builds (final-era): only "mostly work alpha" — our depot's exact era and
     problem (`20260323` alpha, and our June-2026 finals).
2. **Bypass the anti-cheat client-side**, inside the game process — never fight the
   boot service. The 2025 patch hooks **4 functions in Referee.dll itself and
   replaces them with pure no-ops (original never called)** —
   `Referee.dll + {0x76E850, 0x2E6F680, 0x2E6F670, 0x2E6F6E0}` for build 20250718.

Devil's-advocate framing of our dead end: months of chasing the 294-byte hash is the
road the community never traveled. Two readings, both good for us:
- either the strict boot-service gating arrived with the 2026 finals (RecFlare's
  playable 2025 setup has **no provisioning server at all** — so the 2025 chain
  tolerates a dead api.rec.net), or
- the in-process Referee.dll checks are the actual game-side gate, and no-oping
  them is sufficient regardless of the service outcome.

Either way, our `-99903` game-side failure after `-99961` may therefore NOT be
"service fails blobs/config" — it may be in-process Referee.dll checks. That means
a candidate new local lead: **patch Referee.dll in-process instead of feeding the
provisioning channel**. The 294-byte-hash hunt (docs/referee.md) remains good RE
documentation for upstream, but it may not be our critical path to playable.

## How the two RecFlare clients work

### Native patch (2025 build): `2025Patch.dll` + `Injector.exe`
- C++ DLL, MinHook, RVAs hardcoded into `GameAssembly.dll` and `Referee.dll`
  (per-build locked — obfuscated names re-roll every build, so nothing is
  pattern-scanned except a return-spoof gadget).
- `Injector.exe` waits for an unpatched `Recroom_Release.exe` AND both
  `GameAssembly.dll` + `Referee.dll` in the module list → `CreateRemoteThread` +
  `LoadLibraryW`. Two clients side-by-side supported (mutex-serialized).
- Injection is timed: it waits for Referee.dll to load, then settles 2 s.
- Uses `spoof_call` (return-address spoofing) for all il2cpp callbacks so Referee's
  stack walks don't see the DLL's return address; every hook is `__try/__except`
  and falls through to the original on failure — *except* the replace-only ones.

### BepInEx plugin (2023 build): `RecNetPlugin` (Harmony/IL2CPP)
- Patches: `SendRequestPatch` (rewrite `ns.rec.net` → configured host in BestHTTP
  URIs), `PhotonPatches` (app-id/ns/port overrides), `EACPatches` (force EAC is-ready
  and stub challenge-response), `DisableTLSPinning` (skip `NotifyServerCertificate`),
  `ImageSigningPatch` (force mscorlib RSA verify true), `Plugin.cs` (deactivate
  in-game CheatManager), `DUIDMismatchPatch` (force mismatch → false; **default on**).
- The 2023 build runs Photon **payload encryption** — matches Luxon (their custom
  Photon server). The 2025 build negotiates **datagram encryption** silently, which
  self-hosted servers choke on; native patch forces `EnetPeer.IsTransportEncrypted →
  false` to stay on the payload path. Our 2026 build likely also needs this.
- RecFlare's custom Photon server: **Luxon** (open-source-ish parts: `hst/luxon`,
  `hst/netproxy`).

## Full hook inventory (patch-2025) — the community's final client bypass set

| Hook | Effect |
| --- | --- |
| `Referee` Check1-4 (`Referee.dll` + RVAs above) | **Replaced with no-ops, original never called** — full in-process anti-cheat kill |
| `NotifyServerCertificate` (GA+0x77E5E30) | no-op — TLS pinning bypass (same target we already identified!) |
| `HTTPRequest.SendRequest` (GA+0x77E0950) | rewrites `ns.rec.net` → `ApiHost` from ini, builds a fresh `System.Uri` object |
| `CheatManager` module-scan closure (GA+0x2148FB0) | replace-only suppressor: scan still runs and flags, but the `FatalApplicationQuit(0x1FC85836)` reaction is swallowed. `533223478` is a fixed reason code; find it post-build via `B9 36 58 C8 1F` scanning |
| `CheatManager.CheckForDUIDMismatch` (GA+0x2133600) | forced false — skips the player-reporting migration path / Create-Account hang |
| `VerifyImageSig`/`BLDFMLMAFLH` (GA+0x7CF32F0) | forced true — image content-signature check |
| `GetNameServerAddress` (GA+0x757B960) | writes `NameServerPortInAppSettings` (=+0x180) just before running |
| `EnetPeer.IsTransportEncrypted` (GA+0x7521380) | forced false → Photon payload encryption |
| `getaddrinfo` / `GetAddrInfoW` (ws2_32, winsock-layer) | redirects `*.photonengine`/`exitgames`/`photonindustries`; blocks dead telemetry hosts (`rudderstack.com`, `backtrace.io`, `cloud.unity3d.com`) |

Plus voice re-key: Tachyon voice handshake RSA pubkey swap (`VoiceKeyXml` ini knob,
overrides the `<RSAKeyValue>` static right after the `.cctor` runs, game imports it
itself), AT stays encrypted to the client-baked key otherwise.

## Server-side contract wisdom recflarmed from `recflare/server`

- Client API base is **`ns.rec.net`**, not api.rec.net (BestHTTP rewrites `ns.rec.net`
  in URIs). api.rec.net is only the boot/provisioning host.
- `api/config/v2` needs a `StorefrontConfig` key present or Utf8Json deserialization
  crashes the client. Simplest way to get exact shape: find `IHCMHKGLBEA<Dto>` in
  Cpp2IL dumps; the ctor's trailing `mov` block = `____stringByteKeys` — literal keys
  in declaration order.
- **Dead-endpoint discipline**: on the client there is ONE serial request queue, and
  a failing request retries with backoff, starving the entire queue (room-save blob
  → 30 s timeout, Photon disconnect from backlog). Response must be **instant** — a
  real 2xx or a real fast 404. NXDOMAIN or a black hole is poison. Never block a
  recflare/`*.rec.net` host at DNS — stub it server-side first, then (optionally)
  DNS-block.
- `datacollection` must return `200 {"success":true}` immediately.
- `cards`, `moderation`, `platformnotifications` → fast 404 is fine.
- `PlayerReporting/v1/deviceId` → **still unsolved by RecFlare** when a genuine DUID
  mismatch occurs (they suppress on the client instead); the accepting response shape
  is unknown; where the "old" id comes from is unknown.
- Image/content signatures need `key-id=KEY:RSA:p1.rec.net`, signed with Rec Room's
  PRIVATE key → no mirror can satisfy (`sig=p1` URLs) → must bypass client-side.
- Voice handshake (Tachyon `{AI, AT, VB, CKA, CIA, CPK}`): `VB` self-tests decrypts to
  `19 32 C5 68 80 28 9E 22 CA A8 71 09 14 88 5C 1B` if the key swap took.
- Client's Photon app IDs are fetched **from the server** — swapping Photon servers is
  just server config; don't need to fake anything client-side when it's set up right.

## Implications for UwUNet

1. **Our local lead was likely over-weighted.** The 294-byte-hash provisioning hunt
   is one road; the community-favored road is to **no-op Referee.dll in-process**,
   treating `-99961` only as a probe signal, never needing to answer it.
2. Either way, `-99961` was bypassed to a playable 2025 client by RecFlare without any
   provisioning server.
3. **Wine-specific advantage**: under Proton/wine, every Windows memory operation
   inside the game process (create thread/LoadLibrary, patch bytes) is available to us
   via ptrace + `/proc/pid/mem` — no Windows DLL needed. We can do exactly what
   `Injector.exe` + MinHook do, but with a Linux-native tool.
4. **Our `uwudns64` + `uwuhook` already handle** the winsock-layer equivalents of
   RecFlare's winsock hooks. We just need to add the in-process hooks.

## Candidate next steps (upstream-friendly)

- **Fastest to playable on our depot**: download the 20250718.01 build
  (`depotdownloader -app 471710 -depot 471711 -manifest 1151455856673601091`), run it
  under wine with `Injector.exe` + `2025Patch.dll` + `2025patch.ini`, set
  `ApiHost=` our edge, and see if RecFlare's proven client boots against UwUNet.
  If yes, we get a working client today with zero new RE work.
- **Longer-term / upstream contribution**: a wine-native "referee-silencer" that
  no-ops our 2026 build's Referee.dll checks (RVAs differ; find equivalents like
  RecFlare did — signature/scan).
- Keep the 294-byte-hash research as RE documentation for upstream (worth sharing,
  but not our critical path to playable).
