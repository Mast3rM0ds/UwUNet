// voice-server.ts — UwUNet's Rec Room voice server (Tachyon / Dissonance).
//
// Standalone UDP server. The client, handed our "ip:port" in VoiceConnectionInfo,
// dials in and runs Dissonance-over-forked-NGO-over-LiteNetLib. We relay voice.
//
//   node server/src/voice/voice-server.ts         # VOICE_PORT (default 8470)
//
// The full protocol and the four layers are in docs/voice-server.md. This file is
// organised the same way, outermost layer first. We run PLAINTEXT end to end (the
// client is kept plaintext by a one-function patch), so there is no crypto here.
//
// Milestones (docs/voice-server.md): 1 client reaches us · 2 transport connects ·
// 3 NGO "Carrot" session · 4 roster · 5 audio. The one value we could NOT read
// statically is LiteNetLib's ProtocolId — this server logs the raw ConnectRequest
// so a single live run locks it (set UWU_VOICE_PROTOCOL_ID once known).

import * as dgram from "node:dgram";
import { readFileSync, existsSync } from "node:fs";
import * as path from "node:path";
import {
  Reader, Writer, layerWrap, layerUnwrap, packUint, packInt, unpackUint,
  xxhash64, messageHash32,
} from "./wire.ts";

const VOICE_PORT = Number(process.env.VOICE_PORT ?? 8470);
// LiteNetLib NetConstants.ProtocolId. Not readable from the image; stock recent
// LiteNetLib is 13 (older: 11/12). Logged-and-confirmed on first live connect.
const PROTOCOL_ID = Number(process.env.UWU_VOICE_PROTOCOL_ID ?? 13);
const DATA_DIR = process.env.UWU_DATA_DIR ?? path.resolve(import.meta.dirname, "../../../data");
const ROUTING_FILE = path.join(DATA_DIR, "voice-routing.json"); // account -> instance, written by the edge
const VERBOSE = process.env.UWU_VOICE_VERBOSE === "1";

const now = () => new Date().toISOString().slice(11, 23);
const log = (...a: unknown[]) => console.log(now(), ...a);
const hex = (b: Buffer, n = 48) => b.subarray(0, n).toString("hex").replace(/(..)/g, "$1 ").trim() + (b.length > n ? " …" : "");

// ============================================================================
// Layer 2: LiteNetLib (stock). PacketProperty is the low 5 bits of byte 0.
// ============================================================================

const P = {
  Unreliable: 0, Channeled: 1, Ack: 2, Ping: 3, Pong: 4,
  ConnectRequest: 5, ConnectAccept: 6, Disconnect: 7, UnconnectedMessage: 8,
  MtuCheck: 9, MtuOk: 10, Broadcast: 11, Merged: 12, ShutdownOk: 13,
  PeerNotFound: 14, InvalidProtocol: 15, NatMessage: 16, Empty: 17,
} as const;
const P_NAME: Record<number, string> = Object.fromEntries(Object.entries(P).map(([k, v]) => [v, k]));
const propName = (p: number) => P_NAME[p] ?? `#${p}`;

/** ConnectAccept — 15 bytes, per litenetlib-fork-encrypt-layer (stock .Make). */
function makeConnectAccept(connectionTime: bigint, connectNum: number, peerId: number): Buffer {
  const w = new Writer();
  w.u8(P.ConnectAccept);        // [0]
  w.u64(connectionTime);        // [1..8]  must equal the client's ConnectTime
  w.u8(connectNum & 0xff);      // [9]
  w.u8(0);                      // [10] isReused — client needs <=1; Make leaves 0
  w.u32(peerId >>> 0);          // [11..14]
  return w.build();
}

// ============================================================================
// Layer 3: forked NGO. 24-byte batch header, magic 0x1160, XXHash64 @8, count @16.
// ============================================================================

const NGO_MAGIC = 0x1160;

/** Validate + unpack a batch into its concatenated message bytes. null = reject. */
function ngoReadBatch(body: Buffer): { count: number; messages: Buffer } | null {
  if (body.length < 24) return null;
  const magic = body.readUInt16LE(0);
  if (magic !== NGO_MAGIC) return null;
  const batchSize = body.readUInt32LE(4);
  if (batchSize !== body.length) { if (VERBOSE) log("ngo batchSize", batchSize, "!= len", body.length); return null; }
  const batchHash = body.readBigUInt64LE(8);
  const count = body.readUInt16LE(16);
  const payload = body.subarray(24);
  const got = xxhash64(payload, 0);
  if (got !== batchHash) { if (VERBOSE) log("ngo hash", got.toString(16), "!=", batchHash.toString(16)); return null; }
  return { count, messages: payload };
}

/** Wrap concatenated message bytes in a batch header. */
function ngoWriteBatch(count: number, messages: Buffer): Buffer {
  const head = Buffer.alloc(24);
  head.writeUInt16LE(NGO_MAGIC, 0);
  head.writeUInt32LE(24 + messages.length, 4);
  head.writeBigUInt64LE(xxhash64(messages, 0), 8);
  head.writeUInt16LE(count, 16);
  return Buffer.concat([head, messages]);
}

// ConnectionApprovedMessage (server->client). Carries the Tachyon "Carrot" JSON in
// Payload. Order per ngo-fork-batch-and-approval. MessageVersions: the registered
// message types with their XXHash32(typeName) + version; we advertise the minimum.
const APPROVED_HASH = messageHash32("Unity.Netcode.ConnectionApprovedMessage");

function buildConnectionApproved(ownerClientId: number, payloadJson: string): Buffer {
  const w = new Writer();
  // MessageVersions — advertise just ConnectionApprovedMessage@0 for now (live
  // capture of the client's ConnectionRequest gives the full set it expects).
  packInt(w, 1);                 // MessageVersions.Length (zigzag)
  w.u32(APPROVED_HASH >>> 0);    // entry: u32 Hash raw LE
  packInt(w, 0);                 // entry: Version (zigzag)
  packUint(w, ownerClientId);    // OwnerClientId (ulong overload, NO zigzag)
  packInt(w, 0);                 // NetworkTick (zigzag)
  // Payload (the fork's extra string): length then one bitpacked ushort per UTF-16 char
  packUint(w, payloadJson.length);
  for (let i = 0; i < payloadJson.length; i++) packUint(w, payloadJson.charCodeAt(i));
  return w.build();
}

// NamedMessage carries Dissonance. Hash is a USHORT (not stock ulong):
//   u16 NamedMessageType | i32 length | <stock Dissonance packet>
const NM = { DissonanceToServer: 1, DissonanceToClient: 2 } as const;

function buildNamedMessage(type: number, dissonancePacket: Buffer): Buffer {
  const w = new Writer();
  w.u16(type);
  w.u32(dissonancePacket.length); // FastBufferWriter.WriteValueSafe(byte[]) prefixes i32
  w.bytes(dissonancePacket);
  return w.build();
}

// ============================================================================
// Layer 4: Dissonance (stock, magic 0x8bc7). Reference: Placeholder Software.
// MessageTypes: RemoveClient 0, ClientState 1, VoiceData 2, TextData 3,
// HandshakeRequest 4, HandshakeResponse 5, ErrorWrongSession 6, ...
// Identity = account id as a decimal string (the client sets LocalPlayerName).
// ============================================================================

const DISS_MAGIC = 0x8bc7;
const D = { RemoveClient: 0, ClientState: 1, VoiceData: 2, TextData: 3, HandshakeRequest: 4, HandshakeResponse: 5 } as const;

function dissMagicOk(p: Buffer) { return p.length >= 2 && p.readUInt16BE(0) === DISS_MAGIC; }

// ============================================================================
// Instance routing — account -> room instance, recorded by the edge at
// player/connection-info issuance (voice-instance-routing option 1). The connect
// payload's only readable identity is AI (account id, plaintext decimal string).
// ============================================================================

let routing: Record<string, string> = {};
function loadRouting() {
  try {
    if (existsSync(ROUTING_FILE)) routing = JSON.parse(readFileSync(ROUTING_FILE, "utf8"));
  } catch (e) { log("routing load failed:", (e as Error).message); }
}
const instanceOf = (accountId: string) => routing[accountId] ?? "global"; // TODO: default-global until routing is populated

// ============================================================================
// Peer state + server
// ============================================================================

interface Peer {
  key: string;            // "ip:port"
  rinfo: dgram.RemoteInfo;
  peerId: number;
  connectionTime: bigint;
  connectNum: number;
  accountId?: string;     // from the NGO ConnectionRequest payload (AI), once parsed
  instance: string;
  approved: boolean;
  lastSeen: number;
}

const peers = new Map<string, Peer>();
let nextPeerId = 0;
const sock = dgram.createSocket("udp4");

function send(peer: Peer, liteNetLibPacket: Buffer) {
  const datagram = layerWrap(liteNetLibPacket); // append the 0x11 plaintext marker
  sock.send(datagram, peer.rinfo.port, peer.rinfo.address);
}

/** Members of an instance that are approved and not this account. */
function instancePeers(instance: string, exceptAccount?: string): Peer[] {
  return [...peers.values()].filter((p) => p.approved && p.instance === instance && p.accountId !== exceptAccount);
}

sock.on("message", (raw, rinfo) => {
  const key = `${rinfo.address}:${rinfo.port}`;
  const inner = layerUnwrap(raw);
  if (!inner) {
    // trailing 0x2A: the client went encrypted — the stay-plaintext client patch
    // (docs/voice-server.md "Client patch") is missing. Surface it loudly.
    if (raw[raw.length - 1] === 0x2a) log("⚠ encrypted (0x2A) packet from", key, "— client not patched to stay plaintext");
    return;
  }
  if (inner.length < 1) return;
  const prop = inner[0] & 0x1f;
  const peer = peers.get(key);
  if (peer) peer.lastSeen = Date.now();

  switch (prop) {
    case P.ConnectRequest:
      handleConnectRequest(inner, rinfo, key);
      break;
    case P.Ping:
      // reply Pong so LiteNetLib keeps the peer alive. Echo the ping body.
      if (peer) { const w = new Writer().u8(P.Pong).bytes(inner.subarray(1)); send(peer, w.build()); }
      break;
    case P.Channeled:
      if (peer) handleChanneled(peer, inner);
      break;
    case P.Unreliable:
      if (peer) handleNgoDatagram(peer, inner.subarray(1)); // voice rides here (unreliable)
      break;
    case P.Disconnect:
      if (peer) removePeer(peer, "client disconnect");
      break;
    default:
      if (VERBOSE) log("rx", propName(prop), "from", key, hex(inner));
  }
});

function handleConnectRequest(inner: Buffer, rinfo: dgram.RemoteInfo, key: string) {
  // CAPTURE HARNESS: the exact stock layout + ProtocolId offset is version-specific
  // and was not readable statically. Log it so one live connect locks the format.
  log("ConnectRequest from", key, "len", inner.length);
  log("  raw:", hex(inner, 64));
  // Best-effort stock parse (recent LiteNetLib): [0]=prop, [1..4]=protocolId,
  // [5..12]=connectionTime(i64), [13]=addrSize, [14..]=addr, then connectData.
  const r = new Reader(inner, 1);
  const protocolId = r.remaining >= 4 ? r.u32() : -1;
  const connectionTime = r.remaining >= 8 ? r.u64() : 0n;
  log(`  parsed protocolId=${protocolId} connectionTime=${connectionTime} (expecting ProtocolId=${PROTOCOL_ID})`);
  if (protocolId !== PROTOCOL_ID) {
    log(`  ⚠ protocolId mismatch — set UWU_VOICE_PROTOCOL_ID=${protocolId} and restart to accept this client`);
    // Still proceed to accept using the client's own time, so we can observe the next layer.
  }
  let peer = peers.get(key);
  if (!peer) {
    peer = {
      key, rinfo, peerId: nextPeerId++, connectionTime, connectNum: 0,
      instance: "global", approved: false, lastSeen: Date.now(),
    };
    peers.set(key, peer);
  } else {
    peer.connectionTime = connectionTime;
  }
  send(peer, makeConnectAccept(connectionTime, peer.connectNum, peer.peerId));
  log("  -> ConnectAccept peerId", peer.peerId, "(transport should now report Connected)");
}

function handleChanneled(peer: Peer, inner: Buffer) {
  // Stock LiteNetLib channeled header: [0]=prop,[1..2]=sequence,[3]=channelId,
  // then payload. We must Ack it for reliable delivery, then hand the payload up.
  // Reliability (ack bitfields, ordering, fragmentation) is scaffolded here; a live
  // capture confirms the header size for this build before we trust ordering.
  const seq = inner.readUInt16LE(1);
  const channel = inner[3];
  sendAck(peer, channel, seq);
  handleNgoDatagram(peer, inner.subarray(4));
}

function sendAck(peer: Peer, channel: number, seq: number) {
  // Minimal Ack: prop, channelId, then an ack window. TODO: real windowed bitfield
  // once the channel header is confirmed from capture.
  const w = new Writer().u8(P.Ack).u8(channel).u16(seq);
  send(peer, w.build());
}

function handleNgoDatagram(peer: Peer, body: Buffer) {
  const batch = ngoReadBatch(body);
  if (!batch) { if (VERBOSE) log("non-batch NGO datagram from", peer.key, hex(body)); return; }
  // Messages are concatenated; each is [bitpacked type index][len?][body]. The
  // pre-approval message-type order is the client's local order (ConnectionRequest
  // at index 1 per the spec). We detect the two we care about by shape.
  let r = new Reader(batch.messages);
  for (let i = 0; i < batch.count && r.remaining > 0; i++) {
    if (!dispatchNgoMessage(peer, r)) break; // stop if we can't frame the rest yet
  }
}

function dispatchNgoMessage(peer: Peer, r: Reader): boolean {
  // The message header framing (type index + length) needs the client's registered
  // order from a live capture. Until then: recognise a ConnectionRequest by its
  // embedded "AI" JSON (it carries the Tachyon payload) and approve.
  const rest = r.buf.subarray(r.off);
  const asText = rest.toString("latin1");
  const aiMatch = asText.match(/"AI"\s*:\s*"(\d+)"/);
  if (aiMatch && !peer.approved) {
    approve(peer, aiMatch[1]);
    r.off = r.buf.length; // consumed (single-message connect batch, the common case)
    return false;
  }
  // NamedMessage (Dissonance). Try to frame it: u16 type | i32 len | packet.
  if (r.remaining >= 6) {
    const save = r.off;
    const type = r.u16();
    const len = r.u32();
    if ((type === NM.DissonanceToServer) && len > 0 && len <= r.remaining) {
      const packet = r.bytes(len);
      onDissonanceToServer(peer, packet);
      return true;
    }
    r.off = save;
  }
  return false; // unknown framing — wait for capture to complete the parser
}

function approve(peer: Peer, accountId: string) {
  peer.accountId = accountId;
  peer.instance = instanceOf(accountId);
  peer.approved = true;
  const payload = JSON.stringify({ DR: "Carrot" }); // KT omitted: client must be patched to not require a real key
  const msg = buildConnectionApproved(peer.peerId, payload);
  // Deliver reliably (channeled). TODO: proper channel/seq from capture.
  const framed = ngoWriteBatch(1, msg);
  const w = new Writer().u8(P.Channeled).u16(0).u8(0).bytes(framed);
  send(peer, w.build());
  log("approved account", accountId, "instance", peer.instance, "-> Carrot (peerId", peer.peerId + ")");
  broadcastRoster(peer, true);
}

// --- Dissonance relay (layer 4) ---

function onDissonanceToServer(peer: Peer, packet: Buffer) {
  if (!dissMagicOk(packet)) { if (VERBOSE) log("bad Dissonance magic from", peer.key); return; }
  const type = packet[2]; // stock: magic(2) then message type byte
  if (type === D.VoiceData) {
    // Relay to everyone else in the instance, re-wrapped as DissonanceToClient.
    const frame = buildNamedMessage(NM.DissonanceToClient, packet);
    const batch = ngoWriteBatch(1, frame);
    const out = new Writer().u8(P.Unreliable).bytes(batch).build();
    for (const other of instancePeers(peer.instance, peer.accountId)) send(other, out);
  } else if (type === D.HandshakeRequest) {
    // TODO: stock Dissonance HandshakeResponse (joins the session, assigns the
    // session id). Needs the Placeholder Software body format — milestone 4.
    if (VERBOSE) log("Dissonance HandshakeRequest from", peer.accountId, "(response TODO)");
  }
}

function broadcastRoster(peer: Peer, _joined: boolean) {
  // TODO (milestone 4): emit Dissonance session join so remote clients spawn a
  // RecRoomVoicePlayback for this account id.
}

function removePeer(peer: Peer, why: string) {
  peers.delete(peer.key);
  if (!peer.approved || !peer.accountId) return;
  log("peer gone:", peer.accountId, "—", why);
  // Tell everyone else in the instance to drop this player, or their playback leaks
  // forever ("Failed to find player for voice playback"). RemoveClient (type 0).
  // TODO: build the stock Dissonance RemoveClient body for peer.accountId.
}

// Idle reaper — a backstop so a client that vanished without a Disconnect is still
// removed from the roster (voice-stale-playback-on-leave sub-case 2).
setInterval(() => {
  const cutoff = Date.now() - 15000;
  for (const p of peers.values()) if (p.lastSeen < cutoff) removePeer(p, "idle timeout");
}, 5000).unref();

// Pick up account->instance updates the edge writes while we run.
setInterval(loadRouting, 2000).unref();

loadRouting();
sock.on("listening", () => {
  const a = sock.address();
  log(`UwUNet voice server on ${a.address}:${a.port} (ProtocolId ${PROTOCOL_ID}, plaintext)`);
  log(`routing file: ${ROUTING_FILE} (${Object.keys(routing).length} entries)`);
  log("waiting for a client — point VoiceConnectionInfo at this host:port (UWU_VOICE_ADDR on the edge)");
});
sock.on("error", (e) => { log("socket error:", e.message); });
process.on("SIGTERM", () => { log("SIGTERM — shutting down"); sock.close(() => process.exit(0)); });
sock.bind(VOICE_PORT);
