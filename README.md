# UwUNet

> *"Our costs always ended up overwhelming the revenue we brought in."* — Rec Room Inc., March 2026
>
> *"You will no longer be able to login to and play Rec Room."* — June 1, 2026

**NOTE: UwUNet was made with the help of AI, Testing was done by humans and humans only**

**UwUNet is a community-run, self-hosted revival network for Rec Room,**
which was shut down on June 1, 2026 after 10 years and 150 million players.

It replaces the dead `rec.net` backend with servers we host ourselves, so the
client you already have on Steam can be brought back from the dead.

## Status

**Research & foundation phase.** Nothing playable yet. The hard truth:

- The official servers are gone, so we can't capture live traffic anymore.
- The final client ("School's Out" build) ships a decoy `global-metadata.dat`
  (52 MB of the byte `0x52 ... RRRR`) — real metadata is hidden inside
  `GameAssembly.dll` and must be recovered at runtime.
- We're building on the open research of
  [RestoRoom](https://github.com/RestoRoom/RestoRoom) and REC26, and every
  finding we make gets contributed upstream. Revivals shouldn't be a fork race.

## What needs to be rebuilt (from community research)

See [docs/architecture.md](docs/architecture.md) for the full map.

| Service | Purpose | Status |
|---|---|---|
| `auth.rec.net` | Login, tokens | 🏗️ skeleton in `server/` |
| `accounts.rec.net` | Profiles | ❌ |
| `rooms.rec.net` | Room listings | ❌ |
| `match.rec.net` | Matchmaking | ❌ |
| Photon relay | Real-time multiplayer | ❌ biggest lift |
| CDN | Assets | ❌ |

## Legal

Non-commercial, fan-run. We do not redistribute game assets or proprietary
code; we reimplement a dead service's interface for interoperability and
preservation, like the community projects that came before
(RRecRoomArchive, RestoRoom, REC26). Accounts are separate from anything
Rec Room Inc. ever ran.

## Quick start (dev)

```bash
cd server && npm run dev   # http://localhost:7666 (placeholder API surface)
```
