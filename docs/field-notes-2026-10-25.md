# UwUNet Field Notes — M0 Harvest, Oct 25 2026

Findings from poking at the final "School's Out" Steam build (appid 471710,
installed fresh Oct 25 2026 under Proton Experimental 11.0 on Nobara 44).

## Boot architecture (this is what stands between us and the game)

The Steam build does NOT boot straight into the game. Chain:

    Steam → Recroom_Release.exe  (.NET app, MSVC-signed)
          → installs & runs Windows service "RefereeClientApp"
            (RefereeClientApp.exe, native, packed: "Referee Protector Output Library")
          → service loads "blobs of type 0" config
          → launcher hands off to RecRoom.exe (Unity IL2CPP, GameAssembly.dll)

Observed error codes (Referee logs, %ProgramData%/Referee/*.log):
- Launcher: service start loop fails; "Service transitioned to 'STOPPED'"
- App:      `[ERROR] One or more blobs of type 0 were not found or loaded with status -99962`
- App:      `Unable to load configuration with status -99986. Stopping service.`
- Game:     `Unable to initialize session with status -99903`
- Installer: service install/uninstall works normally under Wine.

Implication: the Referee layer needs config blobs that used to be provisioned
by Rec Room's own services (or shipped locally and are now missing). This is
the same anti-tamper wall other revival projects hit. Options:
a) Reimplement/stub the Referee service's expected config surface;
b) Patch/stub the launcher to boot RecRoom.exe directly;
c) Capture the config blob format from an old working install backup / other
   revival communities, who have almost certainly already solved this.

`RefereeClientApp.exe` and `Referee.dll` are packed; `Recroom_Release.exe`
(A .NET launcher, MSIL) is string-readable: log fragments show it is the
windows-service driver that starts "the game" once the service is RUNNING:
`[Client Launcher] Launched game successfully. Exiting application.`

## Networking mover

- `global-metadata.dat` in RecRoom_Data/il2cpp_data/Metadata/ is a decoy:
  52 MB of 0x52 ('R'); real metadata lives obfuscated inside GameAssembly.dll.
- 29 rec.net hostnames known (RestoRoom capture). TLS SNI capture works even
  without decrypting, via our edge's SNI logger.
- Wine does not use the Wineprefix hosts file for ws2_32 resolution
  (resolution goes through the host resolver). Redirect strategy used:
  connect()-hook portrewriter.so via LD_PRELOAD (rewrites dst 443→8443,
  80→8460), because unprivileged processes can't bind 443. Verified working
  when we curl'd the edge with --resolve; game-side confirmation pending.
- Binding :443 rootlessly is possible via `unshare -Urn` + iptables REDIRECT
  (scripts/boot-game.sh) — but launching via Steam daemon inside that netns
  is fragile; LD_PRELOAD path (scripts/game-direct.sh) avoids it.

## What actually works right now

- UwUNet web signup/login (scrypt/PBKDF2 accounts, HMAC tokens):
  `node server/src/uwunet-edge.ts` → https://localhost:8462 (HTTP) or SNI TLS
  on 8443. See data/uwunet.db.json.
- Harvest logging of every request + SNI to data/harvest/requests.jsonl.
- Next client-side experiment: launch RecRoom.exe directly (skipping
  Referee) with portrewriter preload — in progress; check
  data/harvest/requests.jsonl for tls-sni hits.

## Oct 26 (afternoon) — pivot to the reference 2025-build route (chosen)

Given the finals-build wall is unsatisfiable public-key pinning (see
docs/referee.md correction), switched to the community's proven route rather
than more RE: the reference's **patch-2025** against build **20250718.01** (manifest
`1151455856673601091`), which bypasses Referee unconditionally and rewrites
`ns.rec.net`→`ApiHost`.

Staged (no Steam creds needed yet): `tools/depotdownloader/` (DepotDownloader
3.4.0 linux-x64), `tools/patch2025-dl/extracted/` (2025Patch v0.0.8), and
`client2025/{stage-patch.sh,run.sh,README-run.md}`. Blocking step = the depot
download, which needs the owner's Steam login + Steam Guard (run DepotDownloader
with `!`). After that: `stage-patch.sh [ApiHost]` → `run.sh screen`. First goal:
boot past `-99961`; then point ApiHost at our edge so the long-blocked harvest
of real app-layer requests finally happens. the reference orgs: github.com/the reference
(server, patch-2025, patch-2026, client).

## Oct 26 (evening) — 2025 client boots to (apparent) login against UwUNet edge

Milestone: the reference-patched 20250718.01 client boots past anti-cheat AND
completes its full startup HTTP sequence against the UwUNet edge, all 200s, no
unimplemented endpoints left; then goes idle (login/title screen).

Pipeline that works (client2025/run.sh):
- the reference 2025 patch (Referee bypass) with ApiHost EMPTY.
- `uwudns64.so` LD_PRELOAD maps *.rec.net -> 127.0.0.1 (covers BOTH BestHTTP and
  .NET HttpClient; the patch's URL-rewrite only covered BestHTTP — that was the
  first stall). `portrewriter.so` (now loopback-only) maps :443->8443, :80->8460.
- Edge (server/src/uwunet-edge.ts) fixes that unblocked it, in order discovered:
  1. default TLS secure context (no-SNI/bare-IP handshakes were failing).
  2. cert rec.crt regenerated to cover all 43 service subdomains + 127.0.0.1.
  3. UwUNet CA imported into Proton prefix 471710 ROOT store (wine `reg import`;
     certutil is a stub) so .NET HttpClient trusts us. (reg blob in scratchpad.)
  4. `GET /` now serves the RecNet nameserver ENDPOINTS DOC (JSON service map,
     mirrors the reference apps/ns) — content-negotiated vs the human HTML page. THIS
     was the key unblock: the client discovers api/econ/etc. hosts from it.
  5. config/v2 + gameconfigs served from the reference statics (server/static/).
  6. Live FIXTURES system: server/fixtures/<path>[.json] served per-request
     (raw bytes or JSON) so new GET endpoints are just file drops. Seeded:
     avatar/v1/defaultunlocked, defaultbaseavataritems (econ statics),
     config/1b057e6e-... (opaque 18KB cdn blob, byte-for-byte from the reference).
  7. HEAD / -> 200.

Startup request order observed: ns GET / -> api gameconfigs -> cdn config blob
-> api versioncheck/v4 + islandedversions -> econ avatar/defaultunlocked -> idle.

Serial request queue: client tries ~3-4x then STOPS (not infinite retry), so a
missing endpoint needs a relaunch once its fixture is added (live pickup only
works if the client is still actively retrying).

Next: LOGIN/auth flow (auth.rec.net). Edge has /Auth/connect/token + signup;
need to harvest the 2025 client's exact login calls. Then accounts/me, rooms,
match, and Photon (multiplayer) — PhotonConfig currently from the reference static.
