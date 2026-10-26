# UwUNet Roadmap

## M0 — Harvest (now)

Goal: recover what the dead client asks for, since the live reference is gone.

- [x] Map subdomains + endpoints from RestoRoom research
- [x] Confirm metadata decoy in final build
- [ ] Boot client under Proton with hosts redirected to a local UwUNet
      "harvest proxy" and log every attempted hostname/path/method
- [ ] Load SSLPatcher.dll in the Proton prefix; if pinned, decrypt bodies
- [ ] Runtime-unpack IL2CPP (`Il2CppDumper` against dumped memory) to recover
      API strings & Photon config appIds
- [ ] Publish findings as docs + upstream PRs to RestoRoom/REC26

## M1 — Boot past the login screen

- [ ] `auth` + `accounts` returning plausible shapes for whatever the client
      sends (drives schema decisions from harvest data)
- [ ] Stub every other service with truthful 200/empty shapes
- [ ] Client reaches the build UI without crashing

## M2 — Rooms & social

- [ ] Room listing/search/join
- [ ] Friends, chat, avatars
- [ ] Local asset cache for CDN content

## M3 — Multiplayer

- [ ] Photon-compatible relay
- [ ] Local sync in a room (dorm → Rec Center)

## M4 — Public beta

- [ ] Accounts for strangers, moderation tooling, uptime
