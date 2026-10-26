# UwUNet Architecture

Recovering the map of what Rec Room Inc. ran, from RestoRoom's captured
subdomain list (2026-04-03 SNI capture) and endpoint docs (see
`docs/endpoints/`), plus protocol notes from REC26.

## Service topology

All TLS 1.2. Cloudflare (`104.18.8.90` / `104.18.9.90`) fronts most REST
services; assets sat on Azure. We reimplement on our own domain(s).

### Must-implement for basic gameplay (priority order)

1. **auth** — login, refresh tokens, session. *Nothing boots past the
   login screen without this.*
2. **accounts** — profile data, username, avatar references.
3. **api (catch-all)** — general REST surface (`/api/*`).
4. **rooms / Room_server** — room listings, "Room_server/..." endpoints,
   `photon_access_token`, publish state.
5. **match** — matchmaking / join flow.
6. **chat** — in-game chat.
7. **lists** — friends, block lists.
8. **img / cdn / strings-cdn / studiocdn** — assets. Since these are gone
   upstream, either community archives (RecRoomArchive, meow.net uploads)
   or a runtime asset cache we build ourselves.
9. **econ / commerce** — inventory & purchases. Likely stub "everything is
   unlocked" semantics; must still respond with valid shapes.
10. **clubs / discovery / leaderboard / cards / playersettings / notify** —
    later phases.
11. **Photon relay** — real-time room networking. Client code exists as
    `RecRoom.Networking.PhotonImpl.Runtime`; needs a Photon-compatible
    UDP relay + `photon_access_token` issuer. Biggest single lift.

### Never reimplemented (by design)

`datacollection` (telemetry), `ai` (Roomie), `-test`/staging subdomains,
`ns`/`ns-fd` internal routing, `webservice-go`.

## Client redirect

- Final-build client is IL2CPP Unity; real metadata is not on disk
  (decoy file of `R` bytes), so runtime-unpack (Il2CppDumper against the
  in-memory image) is required for deep work.
- Historical use of EasyAntiCheat must be checked on the final Steam build
  (no `EasyAntiCheat` folder present in a fresh Oct 2026 install — likely
  removed at end of life, which helps us).
- TLS pinning: community SSLPatcher.dll exists (RestoRoom PR #140);
  verify it still loads in the Proton prefix.
- First redirect step: `/etc/hosts` (or Wine prefix hosts) → points
  `api.rec.net`, `auth.rec.net`, ... at our UwUNet box, then validate with
  the harvest proxy.

## Data storage

SQLite first (single binary, zero setup, good enough for thousands of
accounts), with WAL. Schema mirrors endpoint response shapes.

## Deployment

Hosted on our own box initially; single region; nobody else's data
collection.
