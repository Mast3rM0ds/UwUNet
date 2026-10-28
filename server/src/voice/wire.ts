// wire.ts — byte-level primitives for the Rec Room voice stack.
//
// Pure and unit-testable: no sockets, no state. Everything the voice server needs
// to read and write the LiteNetLib / forked-NGO / Dissonance wire formats lives here.
// See docs/voice-server.md for where each piece sits in the four layers.

// ----------------------------------------------------------------------------
// Layer 1: RecRoomClientEncryptLayer — a TRAILING marker byte on every datagram.
// Outbound with no key = append one 0x11. Inbound = look at the LAST byte:
//   0x11 -> plaintext, strip it (no key check, no validation)
//   0x2A -> encrypted (we never send these; we keep the client plaintext via a
//           one-function client patch — see docs/voice-server.md "Client patch")
//   else -> client drops it; for us, an inbound we can't read.
// ----------------------------------------------------------------------------

export const MARKER_PLAINTEXT = 0x11;
export const MARKER_ENCRYPTED = 0x2a;

/** Append the plaintext marker. Returns a new buffer (data unchanged by ref). */
export function layerWrap(data: Buffer): Buffer {
  return Buffer.concat([data, Buffer.from([MARKER_PLAINTEXT])]);
}

/** Strip the trailing marker. Returns null if the datagram is encrypted/unknown. */
export function layerUnwrap(data: Buffer): Buffer | null {
  if (data.length < 1) return null;
  const marker = data[data.length - 1];
  if (marker === MARKER_PLAINTEXT) return data.subarray(0, data.length - 1);
  return null; // 0x2A encrypted or unknown marker — can't read it plaintext
}

// ----------------------------------------------------------------------------
// Little-endian cursor reader/writer. LiteNetLib and NGO are LE on the wire.
// ----------------------------------------------------------------------------

export class Reader {
  buf: Buffer;
  off: number;
  constructor(buf: Buffer, off = 0) {
    this.buf = buf;
    this.off = off;
  }
  get remaining() {
    return this.buf.length - this.off;
  }
  u8() {
    return this.buf[this.off++];
  }
  u16() {
    const v = this.buf.readUInt16LE(this.off);
    this.off += 2;
    return v;
  }
  u32() {
    const v = this.buf.readUInt32LE(this.off);
    this.off += 4;
    return v;
  }
  i32() {
    const v = this.buf.readInt32LE(this.off);
    this.off += 4;
    return v;
  }
  u64() {
    const v = this.buf.readBigUInt64LE(this.off);
    this.off += 8;
    return v;
  }
  bytes(n: number) {
    const v = this.buf.subarray(this.off, this.off + n);
    this.off += n;
    return v;
  }
}

export class Writer {
  private chunks: number[] = [];
  u8(v: number) {
    this.chunks.push(v & 0xff);
    return this;
  }
  u16(v: number) {
    this.chunks.push(v & 0xff, (v >>> 8) & 0xff);
    return this;
  }
  u32(v: number) {
    this.chunks.push(v & 0xff, (v >>> 8) & 0xff, (v >>> 16) & 0xff, (v >>> 24) & 0xff);
    return this;
  }
  u64(v: bigint) {
    for (let i = 0n; i < 8n; i++) this.chunks.push(Number((v >> (i * 8n)) & 0xffn));
    return this;
  }
  bytes(b: Buffer | number[]) {
    for (const x of b) this.chunks.push(x & 0xff);
    return this;
  }
  build() {
    return Buffer.from(this.chunks);
  }
}

// ----------------------------------------------------------------------------
// Layer 3: NGO BytePacker bit-packed ints.
//   encoded = (value << 3) | numBytes, written LE in numBytes bytes.
//   numBytes = b0 & 7. numBytes == 5 -> raw LE u32 in bytes 1..4 (no shift).
//   Values 0..0x1FFFFFFF use the 1–4 byte form; 0x20000000..0xFFFFFFFF the 5-byte.
//   Signed callers ZigZag first: (n << 1) ^ (n >> 63).
// ----------------------------------------------------------------------------

/** Write an unsigned value (0..0xFFFFFFFF) bit-packed. */
export function packUint(w: Writer, value: number) {
  if (value < 0 || value > 0xffffffff) throw new RangeError(`packUint out of range: ${value}`);
  if (value <= 0x1fffffff) {
    // smallest nb in 1..4 whose (value<<3) fits
    let nb = 1;
    while (value >= 1 << (8 * nb - 3)) nb++;
    const encoded = (value << 3) | nb; // may exceed 32-bit int; build LE by hand
    let v = BigInt(value) * 8n + BigInt(nb);
    for (let i = 0; i < nb; i++) {
      w.u8(Number(v & 0xffn));
      v >>= 8n;
    }
  } else {
    w.u8(5); // tag only; high bits unused
    w.u32(value);
  }
}

/** Read a bit-packed unsigned value. */
export function unpackUint(r: Reader): number {
  const b0 = r.u8();
  const nb = b0 & 7;
  if (nb === 5) return r.u32();
  let v = BigInt(b0);
  for (let i = 1; i < nb; i++) v |= BigInt(r.u8()) << BigInt(8 * i);
  return Number(v >> 3n);
}

/** ZigZag-encode a signed integer, then bit-pack (NetworkTick, Version, lengths). */
export function packInt(w: Writer, value: number) {
  const n = BigInt(value);
  const zz = (n << 1n) ^ (n >> 63n); // 64-bit arithmetic shift semantics
  const zzu = zz & 0xffffffffffffffffn;
  if (zzu > 0xffffffffn) throw new RangeError(`packInt zigzag too large: ${value}`);
  packUint(w, Number(zzu));
}

export function unpackInt(r: Reader): number {
  const zz = BigInt(unpackUint(r));
  return Number((zz >> 1n) ^ -(zz & 1n));
}

// ----------------------------------------------------------------------------
// XXHash — NGO batch hash (Hash64, seed 0) and message-type hash (Hash32, seed 0).
// Canonical xxHash. The batch hash IS enforced by the client, so if a real capture
// rejects our batches, re-verify seed/variant here against a known NGO vector.
// ----------------------------------------------------------------------------

const P32_1 = 2654435761n, P32_2 = 2246822519n, P32_3 = 3266489917n, P32_4 = 668265263n, P32_5 = 374761393n;
const M32 = 0xffffffffn;
const rotl32 = (x: bigint, r: bigint) => ((x << r) | (x >> (32n - r))) & M32;

export function xxhash32(input: Buffer, seed = 0): number {
  const s = BigInt(seed) & M32;
  let h: bigint;
  let i = 0;
  const len = input.length;
  if (len >= 16) {
    let v1 = (s + P32_1 + P32_2) & M32;
    let v2 = (s + P32_2) & M32;
    let v3 = s;
    let v4 = (s - P32_1) & M32;
    const round = (v: bigint, lane: bigint) => rotl32((v + lane * P32_2) & M32, 13n) * P32_1 & M32;
    for (; i <= len - 16; i += 16) {
      v1 = round(v1, BigInt(input.readUInt32LE(i)));
      v2 = round(v2, BigInt(input.readUInt32LE(i + 4)));
      v3 = round(v3, BigInt(input.readUInt32LE(i + 8)));
      v4 = round(v4, BigInt(input.readUInt32LE(i + 12)));
    }
    h = (rotl32(v1, 1n) + rotl32(v2, 7n) + rotl32(v3, 12n) + rotl32(v4, 18n)) & M32;
  } else {
    h = (s + P32_5) & M32;
  }
  h = (h + BigInt(len)) & M32;
  for (; i + 4 <= len; i += 4) {
    h = (h + BigInt(input.readUInt32LE(i)) * P32_3) & M32;
    h = rotl32(h, 17n) * P32_4 & M32;
  }
  for (; i < len; i++) {
    h = (h + BigInt(input[i]) * P32_5) & M32;
    h = rotl32(h, 11n) * P32_1 & M32;
  }
  h ^= h >> 15n;
  h = (h * P32_2) & M32;
  h ^= h >> 13n;
  h = (h * P32_3) & M32;
  h ^= h >> 16n;
  return Number(h & M32);
}

const P64_1 = 11400714785074694791n, P64_2 = 14029467366897019727n, P64_3 = 1609587929392839161n,
  P64_4 = 9650029242287828579n, P64_5 = 2870177450012600261n;
const M64 = 0xffffffffffffffffn;
const rotl64 = (x: bigint, r: bigint) => ((x << r) | (x >> (64n - r))) & M64;
const round64 = (acc: bigint, lane: bigint) => (rotl64((acc + lane * P64_2) & M64, 31n) * P64_1) & M64;
const mergeRound64 = (acc: bigint, val: bigint) => {
  acc ^= round64(0n, val);
  return ((acc * P64_1) & M64) + P64_4 & M64;
};

export function xxhash64(input: Buffer, seed = 0): bigint {
  const s = BigInt(seed) & M64;
  const len = input.length;
  let h: bigint;
  let i = 0;
  if (len >= 32) {
    let v1 = (s + P64_1 + P64_2) & M64;
    let v2 = (s + P64_2) & M64;
    let v3 = s;
    let v4 = (s - P64_1) & M64;
    for (; i <= len - 32; i += 32) {
      v1 = round64(v1, input.readBigUInt64LE(i));
      v2 = round64(v2, input.readBigUInt64LE(i + 8));
      v3 = round64(v3, input.readBigUInt64LE(i + 16));
      v4 = round64(v4, input.readBigUInt64LE(i + 24));
    }
    h = (rotl64(v1, 1n) + rotl64(v2, 7n) + rotl64(v3, 12n) + rotl64(v4, 18n)) & M64;
    h = mergeRound64(h, v1);
    h = mergeRound64(h, v2);
    h = mergeRound64(h, v3);
    h = mergeRound64(h, v4);
  } else {
    h = (s + P64_5) & M64;
  }
  h = (h + BigInt(len)) & M64;
  for (; i + 8 <= len; i += 8) {
    h ^= round64(0n, input.readBigUInt64LE(i));
    h = (rotl64(h, 27n) * P64_1 + P64_4) & M64;
  }
  if (i + 4 <= len) {
    h ^= (BigInt(input.readUInt32LE(i)) * P64_1) & M64;
    h = (rotl64(h, 23n) * P64_2 + P64_3) & M64;
    i += 4;
  }
  for (; i < len; i++) {
    h ^= (BigInt(input[i]) * P64_5) & M64;
    h = (rotl64(h, 11n) * P64_1) & M64;
  }
  h ^= h >> 33n;
  h = (h * P64_2) & M64;
  h ^= h >> 29n;
  h = (h * P64_3) & M64;
  h ^= h >> 32n;
  return h & M64;
}

/** NGO message-type hash = XXHash.Hash32(UTF8(typeName)). */
export function messageHash32(typeName: string): number {
  return xxhash32(Buffer.from(typeName, "utf8"), 0);
}
