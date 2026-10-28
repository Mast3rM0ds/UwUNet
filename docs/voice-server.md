# UwUNet voice server (Tachyon / Dissonance)

Rec Room `20250718.01` does **in-room proximity voice** with **Dissonance** running over a
**Rec-Room-forked Netcode-for-GameObjects (NGO)** session on a **stock LiteNetLib** UDP transport —
a *dedicated voice server you host yourself*. It is **not** Photon Voice (`PhotonVoiceAppId` is
vestigial on this build) and **not** peer-to-peer (the client only ever `StartClient()`s; it never
hosts). No voice server → the client logs `Voice: No VoiceConnectionInfo, not using Dissonance` and
silently runs with no voice.

This is why realtime + text worked but you couldn't hear your friend in paintball: realtime is
Photon (our App IDs), voice is this server, and we weren't running it.

> Protocol reverse-engineered by recflare (`recflare/skills`, skill `rr-voice-server`, 12 refs,
> build `20250718.01` = our build). recflare runs no voice server of their own. This doc is UwUNet's
> own distillation + build plan so the work lives in our repo.

## How the client is pointed at us

Two separate voice paths, both minted server-side — we control the address in **both**:

| path | source field | endpoint | our edge |
|---|---|---|---|
| **in-room proximity** (hear people in the room — the one that matters for paintball) | `VoiceConnectionInfo` = `"<ip>:<port>"` string | `GET player/connection-info?roomInstanceId=` (Matchmaking, svc 4) | already returns this field (currently `""`) |
| **party voice** (party call overlay) | `VoiceConnectionInfo` DTO `.Address` | `POST voiceconnection/{chatThreadId}` (Chat, svc 9) | not wired yet |

The client does: `Split(":")` → `IPAddress.Parse` → `UInt16.Parse` → configure `LiteNetLibTransport`
→ `NetworkManager.StartClient()`. **Room load has a dedicated voice stage** (`FailedToConnectToVoice
= 5`); a `VoiceConnectionInfo` that points at a server that does not answer **fails room entry** —
worse than empty. So the edge only advertises the address once the server actually completes the
handshake. Gate: env `UWU_VOICE_ADDR` (unset = `""` = voice off, safe).

## The four layers (outermost first — a failure at layer 1 looks identical to layer 4 in the UI)

```
UDP datagram
└─ RecRoomClientEncryptLayer   TRAILING marker byte: 0x11 plaintext / 0x2A encrypted
   └─ LiteNetLib (STOCK)       connection handshake, channels, reliability
      └─ NGO (Rec-Room fork)   24-byte batch header, bitpacked messages
         └─ NamedMessage       u16 type (1 = DissToServer, 2 = DissToClient) | i32 len
            └─ Dissonance (STOCK)   magic 0x8bc7 session/voice packets
```

### Layer 1 — RecRoomClientEncryptLayer  (the key insight: we run PLAINTEXT)

A **trailing** marker byte on every datagram. Outbound branches only on whether a key is set:
- **no key:** append one byte `0x11`. No RNG, no transform.
- key set: 8 random bytes + crypto + trailing `0x2A` (`+9`).

Inbound reads the **last** byte: `0x11` → strip it (`length--`), **no key check, no validation**;
`0x2A` → decrypt; anything else → drop.

**A server that appends `0x11` to every datagram and strips a trailing `0x11` from every inbound one
is accepted through the entire handshake. No key, no crypto.** `ExtraPacketSizeForLayer = 9` is a
worst-case reservation, not the bytes added — plaintext grows by exactly 1.

The catch: the NGO approval (layer 3) makes the **client** flip to encrypted (`0x2A`), and its key is
derived from material we can't read without Rec Room's RSA private key. So we keep the client in
plaintext with a **one-function client patch** (see "Client patch" below). Everything else is
plaintext and needs no crypto.

### Layer 2 — LiteNetLib  (STOCK — the open-source RevenantX library)

Stock `ConnectRequest` / `ConnectAccept`. `ConnectAccept` = 15-byte packet, property `6`:
`[0]=6, [1..8]=ConnectionTime i64 LE, [9]=connectionNumber (<4), [10]=isReused (<=1, not written by
Make), [11..14]=peerId i32 LE`. We implement the stock peer state machine: receive ConnectRequest →
reply ConnectAccept → Connected. **`NetConstants.ProtocolId` was not readable from the image** — log
the inbound ConnectRequest and read it live (milestone 1).

### Layer 3 — NGO fork

**Batch header: 24 bytes.** `Magic u16 @0 = 0x1160`, `BatchSize u32 @4` (= datagram length),
`BatchHash u64 @8 = XXHash.Hash64(buf+24, size-24, seed 0)`, **`BatchCount u16 @16`** (moved from
stock @2 — the whole "fork"), bytes `[2:4]`/`[18:24]` padding. **The hash IS enforced.**

**Bit-packed ints** (`BytePacker`): `encoded = (value << 3) | numBytes`, LE in `numBytes` bytes;
`numBytes = b0 & 7`. `numBytes == 5` → raw LE u32 in bytes 1..4 (no shift). Signed callers ZigZag
first. Rejects `> 0x1FFFFFFF`.

**`ConnectionApprovedMessage`** (server→client), wire order:
bitpacked-zigzag `MessageVersions.Length`; per entry `u32 Hash` raw LE + bitpacked-zigzag `Version`;
bitpacked `OwnerClientId` (ulong, **no zigzag**); bitpacked-zigzag `NetworkTick`; then if `Payload
!= null`: bitpacked `Payload.Length` (unsigned) + **one bitpacked ushort per UTF-16 char**. No
ConnectedClientIds, no sceneObjectCount (dropped in the fork). **`Payload` carries the Tachyon JSON**
`{"DR":"Carrot","KT":<bytes>}` into `NetworkManager.RecRoom_ConnectionInfo`. The `"Carrot"` compare
is **logged only, nothing branches on it**; `KT` is passed to `RSA.Decrypt` with no null check (must
be present) — but with the client patched to not apply the derived key, `KT` can be any bytes.
Message hash = `XXHash.Hash32(UTF8(typeName))`.

**`NamedMessage`** (the Dissonance carrier): `Hash` is a **ushort** (NOT stock's ulong!):
`u16 NamedMessageType | i32 length | <stock Dissonance packet>`. Types: `1 = DissonanceToServer`
(client→server), `2 = DissonanceToClient` (server→client). **A server replies on 2.**

### Layer 4 — Dissonance  (STOCK — Placeholder Software, magic `0x8bc7`)

Stock Dissonance server session. Reference: the open-source Placeholder Software Dissonance source.
- **Identity:** `LocalPlayerName == accountId.ToString()` (decimal). Client announces its own name in
  the Dissonance handshake; server never assigns it.
- **Roster** is Dissonance session membership, **server-owned**, broadcast via `OnPlayerJoinedSession`
  / `OnPlayerLeftSession`.
- **On leave:** broadcast stock Dissonance `RemoveClient` (MessageType `0`) in a type-`2` frame, or
  the departed player's playback leaks forever (`Failed to find player for voice playback: {id}`).
- **No positions:** `TrackPlayerPosition` has zero callers — Unity 3D audio spatialises off the
  avatar; the server relays `VoiceData` by account id only.
- Still must implement Dissonance room/channel routing (room names live in client prefab assets, not
  derivable — infer from the handshake / relay to all in-instance).

## Instance routing (who hears whom)

The connect payload carries **no room/instance id** — only `AI` = account id (plaintext decimal
string; the other 5 fields are encrypted and we ignore them). Route by **recording account → room
instance at `player/connection-info` issuance** and looking it up by `AI` on connect (option 1, no
crypto, no client change). `AI` is client-asserted/unauthenticated; bind with a server nonce later if
it matters. Alternative: a **per-instance port** (routing implicit, most robust) — a later option.

## Client patch (stay plaintext)

The approval flips the client to encrypted voice with a key we can't produce. Neuter it so the client
stays plaintext:

- **`LiteNetLibTransport.RecRoom_SetEncryptionInfo(ulong, byte[])`** `0x735CA20` — make it a no-op
  (early `ret`), **or** `RecRoomClientEncryptLayer.SetKey` `0x735DF90`. Far smaller than swapping the
  1024-bit RSA modulus. Both the host and the friend re-run the patch (they patched once already).

(Full-encryption alternative: patch the RSA modulus in `DMIBBCKIGCG..cctor` `0x827A820` to our
keypair, then decrypt `CKA`/`CIA` and mint a real `KT` to the client's `CPK`. Bigger patch; not
needed for first audio.)

## Build milestones

1. **Client reaches us.** Edge advertises `UWU_VOICE_ADDR`; server receives the LiteNetLib
   ConnectRequest. Read `ProtocolId` live. *(UDP + encrypt-layer strip + connect parse.)*
2. **Transport connects.** Correct `ConnectAccept` → room load passes the voice stage (no
   `FailedToConnectToVoice`). Voice "connects" even before audio.
3. **NGO session.** Batch header + `ConnectionApprovedMessage("Carrot")` → `TachyonClient` considers
   itself connected. *(Client patch applied so it stays plaintext.)*
4. **Roster.** Dissonance handshake + join/leave broadcast → players appear in each other's voice
   session; leave sends `RemoveClient`.
5. **Audio.** Relay `VoiceData` to other accounts in the same instance. You hear your friend.

## Files

- `server/src/voice/wire.ts` — byte reader/writer, NGO bitpacking, XXHash32/64, encrypt-layer
  wrap/unwrap. Pure, unit-testable.
- `server/src/voice/voice-server.ts` — UDP socket, LiteNetLib peer state, NGO + Dissonance framing,
  instance roster, relay. Run standalone: `node server/src/voice/voice-server.ts` (`VOICE_PORT`,
  default 8470).
- `start-voice.sh` — launch wrapper (pid/log), mirrors `start-server.sh`.
- edge: `UWU_VOICE_ADDR` → `VoiceConnectionInfo` in `player/connection-info`; records account →
  instance for routing.
</content>
</invoke>
