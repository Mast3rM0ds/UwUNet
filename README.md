# UwUNet

> *"Our costs always ended up overwhelming the revenue we brought in."* — Rec Room Inc., March 2026
>
> *"You will no longer be able to login to and play Rec Room."* — June 1, 2026

**NOTE: UwUNet was made with the help of AI. Testing was done by humans and humans only.**

**UwUNet is a community-run, self-hosted revival network for Rec Room,** which
was shut down on June 1, 2026 after 10 years and 150 million players. It replaces
the dead `rec.net` backend with servers we host ourselves, so the Steam client you
already own can be brought back from the dead — as if Rec Room never stopped.

Everything here is ours: our own backend, our own accounts, our own Photon realtime
apps. We do not depend on anyone else's servers to stay up.

## Status

**Playable.** A patched client boots all the way into the game against UwUNet:

- ✅ Boot past the anti-cheat / certificate wall (older playable build `20250718.01`)
- ✅ Auth, tokens, Steam cached-login, and real usernames/passwords
- ✅ Spawn into your **dorm** and move around
- ✅ All 27 first-party rooms (RROs) **and the Rec Center** — resolve, browse,
  search, and matchmake into shared Photon rooms
- ✅ Multiplayer: two players matchmake into the same Photon room and see each other
- ✅ **Account portal** — claim your Steam account with a username + password
- ✅ **God accounts** — maker pen and full build permissions in every room

What's still rough: in-game economy, some social surfaces, and the Play-menu feeds
are partial; the three rooms with server-side save blobs (Rec Center, Make It To
Midnight, Showdown) need user-supplied saves for full interactive fidelity.

## How it works

| Piece | What it does |
|---|---|
| `server/src/uwunet-edge.ts` | The edge: one TLS SNI-routed Node server impersonating `*.rec.net` (auth, accounts, rooms, matchmaking, econ stubs, boot surface) |
| Photon Cloud | Real-time multiplayer + voice, under our own Photon App IDs |
| `server/static/`, `server/fixtures/` | Response shapes and boot config for build `20250718.01` |
| `client2025/` | Scripts to stage the 2025 client patch and point the client at UwUNet |
| `client-windows/` | CA import + hosts redirect for Windows players |

The edge serves **metadata only** for first-party rooms (room id, name, Unity scene
GUID, capacity). No copyrighted room build or save data is included — 24 of the 27
RROs play entirely from scenes already baked into the client you own.

## Accounts

Players log in through Steam and get an auto-created `Player<id>` account. Visit the
account portal (served at the edge root, e.g. `https://rec.net/` once your client
trusts the UwUNet CA) to claim it with a real **username and password**.

## Running the server

```bash
cd server
UWU_SPAWN=dorm node src/uwunet-edge.ts     # TLS on :8443, plain HTTP on :8460
```

The edge reads its Photon region + App IDs from `data/photon.json` (gitignored —
your keys stay private). See [docs/](docs/) for the full architecture, the client
patch/launch steps, and field notes.

## Legal

Non-commercial, fan-run. We do not redistribute game assets or proprietary code; we
reimplement a dead service's interface for interoperability and preservation, like
the community projects that came before. Accounts and servers are entirely our own
and separate from anything Rec Room Inc. ever ran.
