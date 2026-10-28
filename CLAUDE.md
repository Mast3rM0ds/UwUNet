# CLAUDE.md — UwUNet

Context for AI sessions working in this repo. See `README.md` for the project pitch.

## What this is

UwUNet is a community-run, self-hosted revival of **Rec Room** (shut down 2026-06-01).
We replace the dead `rec.net` backend with servers **we host ourselves** so the Steam
client (`appid 471710`, playable build `20250718.01`) boots and plays against us — "as
if Rec Room never stopped." **Full ownership:** our own edge, accounts, and Photon
realtime apps. We depend on no one else's servers.

`github.com/recflare/server` is an **interoperability REFERENCE ONLY** (not a dependency).
Read it with `gh api repos/recflare/server/contents/<path> --jq .content | base64 -d`
to match response shapes. Never vendor or call it.

## Architecture

| Path | Role |
|---|---|
| `server/src/uwunet-edge.ts` | **The edge.** One Node process: TLS SNI server impersonating `*.rec.net` on **:8443 (TLS)** + **:8460 (HTTP)**. Auth, accounts, rooms, matchmaking, econ stubs, images, the SignalR notify-hub WebSocket. ~2800 lines, hand-rolled router. |
| `server/src/voice/voice-server.ts` | Voice server (UDP :8470, plaintext, Dissonance/LiteNetLib). Parked — see `docs/voice-server.md` + memory. |
| `server/static/` | Build config: `gameconfigs-v1-all-2025.json`, `rro-rooms.json` (first-party rooms). |
| `server/fixtures/` | Per-path responses. `GET /a/b` → `fixtures/a/b` (raw) or `fixtures/a/b.json` (JSON), served live (no restart). Also the room thumbnails (`*.jpg`). |
| `data/` *(gitignored)* | `uwunet.db.json` (accounts/outfits, atomic save), `harvest/requests.jsonl` (traffic log), `photon.json` (our Photon IDs). |
| `certs/` *(gitignored)* | Edge TLS: `rec.crt`/`rec.key` + `uwunet-ca.*`. |
| `client2025/run.sh` | Launch the patched client: `./run.sh [screen|vr]`. |
| `lib/*.c` → `*.so` | `LD_PRELOAD` shims (`.so` gitignored, rebuilt per OS): `uwudns64` (`*.rec.net`→127.0.0.1), `portrewriter` (loopback :443→8443, :80→8460). |
| `re/voice-patch.c` | Runtime ptrace dumper/patcher for the game (RE work). |
| `scripts/` | Helpers: `regen-cert.sh`, `pf-voice.conf`, etc. |

**Runtime:** plain Node ≥ 22.18 type-strips the TS directly (no build, no `package.json`,
no deps). Parse-check edits with:
`node --experimental-strip-types --check server/src/uwunet-edge.ts`
Because Node only *strips* types, the edge uses **erasable syntax only** — no `enum`,
`namespace`, or constructor parameter-properties.

## Running it

- **Edge:** `sh start-server.sh` → `edge.pid`, logs to `edge.log` (`TLS_PORT`/`HTTP_PORT` env, default 8443/8460). Restart = `kill $(cat edge.pid); sh start-server.sh`.
- **Voice:** `sh start-voice.sh` → `voice.pid`/`voice.log`. Only advertised when `UWU_VOICE_ADDR` is set on the edge (else off — a dead voice addr *fails room entry*).
- **Client:** `client2025/run.sh screen` (or `vr`). It preloads the shims + socat-forwards local 8443/8460 to the VPS. `EDGE_EXTERNAL=1` uses a locally-run edge instead.

### VPS (production)
`vps-caa6c6fd.vps.ovh.net` / `51.38.36.86`, OVH **FreeBSD**, repo at `~/UwUNet` as user
`freebsd`. **The user runs all VPS commands themselves.** Deploy:
```
git pull
kill $(cat edge.pid 2>/dev/null) 2>/dev/null; sh start-server.sh
```
`pf` redirects 443→8443 / 80→8460 (`/etc/pf.conf`, needs `doas`; `set skip on lo0`; voice
UDP 8470 passed). The edge is **not** auto-started on reboot. `data/` (incl. `photon.json`)
is placed manually and never committed.

## Conventions (how to not break the client)

- **Dead-endpoint discipline.** Unknown path → **fast 404** (never 503 — the client re-queues
  a 5xx and starves its serial request pump). But an endpoint the client **awaits** before
  building a feature (maker-pen catalog, avatar, a `Promise.all` batch) must return an **empty
  200 in the correct shape** — a 404 there throws and breaks the whole feature. **Wrong shape
  is a fatal malform.** Match recflare's shape exactly; verify with the harvest after deploy.
- **Harvest-driven.** Every request logs to `data/harvest/requests.jsonl` (`event`:
  `request`/`response`/`unimplemented`/`fixture`/`ws-msg`/`placeholder-image`/`tls-sni`).
  Find gaps: `grep '"event":"unimplemented"' … | grep -oE '"path":"[^"]*"' | sort | uniq -c | sort -rn`.
  Ignore bot-scanner noise (`/.env`, `/.git/*`, `/wp/`, `/login`).
- **Fixtures first.** New static endpoint? Drop a file in `server/fixtures/` — no code, no restart.
- **Images:** served from `server/fixtures/`; the query string is stripped so `?w=512` matches;
  any image miss falls back to `_placeholder.jpg`.

## Hard constraints — DO NOT violate

- **Never SIGKILL / `kill -9` the game or wineserver.** It truncates the Proton prefix `.reg`
  files to 0 bytes → "32-bit installation, cannot support 64-bit" boot failure. **Always
  SIGTERM and wait.** (Recovery: restore `system.reg` from `system.reg.old`, `user.reg`/
  `userdef.reg` from Proton's `default_pfx/` — see memory `uwunet-client-launch`.)
- **Never press "Change Accounts" in-game** — it crashes the client.
- **Never send the Steam ticket/credentials or the user's email to third parties.**
- **Secrets are gitignored** (`certs/`, `*.key`, `*.pem`, `data/`). Never commit them, and
  never put secrets (Photon IDs, SteamID, tokens) in committed files — **including this one.**
- **Commit/push only when the user asks.** Commit messages end with
  `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`; PR descriptions end with
  `🤖 Generated with [Claude Code](https://claude.com/claude-code)`.

## Switching OS / new machine — setup checklist

The dev + gaming box is moving OSes (the FreeBSD VPS is **not** changing). On the new box:

1. **Carry over the gitignored dirs** from the old machine (they are NOT in git and can't be
   regenerated identically):
   - `certs/` — the CA private key can't be re-created; `regen-cert.sh` *reuses* `rec.key` so
     the SPKI stays stable. Copy the whole dir.
   - `data/` — `uwunet.db.json` (accounts/outfits), `photon.json` (Photon App IDs). Only needed
     if you run the edge locally; production data lives on the VPS.
2. **Fix hardcoded paths.** `client2025/run.sh` has `UWU=/home/bloink/UwUNet` and
   `STEAM=~/.local/share/Steam`; several `scripts/*.sh` and `re/*.sh` hardcode `/home/bloink`.
   Update to the new user/home.
3. **Rebuild the native shims** (`.so` are gitignored; build line is in each `.c` header):
   `gcc -shared -fPIC -O1 -o lib/uwudns64.so lib/uwudns64.c -ldl` (and `portrewriter.so`
   likewise). Rebuild `voice-patch`: `cc -O2 -o voice-patch re/voice-patch.c`.
4. **Re-stage the client depot** — `client2025/depot/` is gitignored (large). Re-download build
   `20250718.01` (DepotDownloader) then `client2025/stage-patch.sh` to apply the 2025 patch +
   injector.
5. **Steam + Proton Experimental** installed; `appid 471710`. The `compatdata/471710` prefix
   path changes with the Steam root.
6. **Node ≥ 22.18** (for unflagged TS type-stripping).

## Current status (2026-10-28)

Playable end-to-end: boots past anti-cheat/cert wall, auth + Steam cached-login, dorm + all
first-party rooms + Rec Center, 2-player Photon multiplayer, god accounts (maker pen).
Recently fixed: maker-pen palette, avatar save (DB-persisted), room thumbnails.
**In progress:** parties (rides the notify-hub WS; harvesting the protocol — see memory
`uwunet-boot-progress`). **Parked:** voice (plan in `docs/voice-server.md`).
