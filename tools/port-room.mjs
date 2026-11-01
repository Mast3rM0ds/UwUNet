#!/usr/bin/env node
// tools/port-room.mjs — the room porter (manual-friendly CLI).
//
//   node tools/port-room.mjs <RoomName>            port a room by its rec.net name
//   node tools/port-room.mjs --index               (re)build the shard blob index
//   node tools/port-room.mjs --list-shards         index progress / coverage report
//   node tools/port-room.mjs --index-bundles       build the Rec Room Studio bundle index
//   node tools/port-room.mjs --studio [RoomName]   attach Studio bundles to registered rooms
//   node tools/port-room.mjs --holotars [RoomName] recover Holotar recordings of registered rooms
//
// Pipeline for `<RoomName>`:
//   1. Wayback CDX: find a 200 snapshot of https://rec.net/room/<RoomName>
//   2. Parse the page's Next.js flight payload -> the full RoomDto (16+ subrooms incl.
//      every CurrentSave: SubRoomDataSaveId / DataBlob / DataBlobHash — verbatim live-shape)
//   3. Blob index: map each subroom's DataBlob key to its recroom-cdn-room-files-* shard
//   4. Download every .room blob from archive.org (zip-member extraction) into
//      server/fixtures/room/, VERIFYING sha256 == the recorded DataBlobHash
//   4b. Rec Room Studio subrooms (CurrentSave.UnityAssetId): find the Windows build of the scene
//      bundle + its dependencies in the recroom-cdn-assetbundle-* index (--index-bundles, once),
//      download them into server/fixtures/room/ and record them on CurrentSave.UnitySubAssets
//   4c. Holotar recordings: every "<key>.htr" a downloaded scene blob names, from the
//      recroom-cdn-htr-* shards into server/fixtures/data/ (the client's cdn.rec.net/data/)
//   5. Room image (img.rec.net/<ImageName>) from Wayback into server/fixtures/
//   6. Register the room in server/static/rro-rooms.json (ids left as raw digit literals —
//      quoteBigLiterals in the edge keeps them lossless) + byName
//   7. Append to the room rows: `archive`, `staffpicks`, `foryou` in room-rows.json —
//      rows are read per request, so they land with no edge restart
//   8. Remember: server/static/rro-rooms.json is read at startup — RESTART the edge
//      (local: /tmp/opencode/edgeup.sh; VPS: pull + restart) to see door links/bulk resolve.
//
// Game-id note: room/subroom ids exceed 2^53. This tool NEVER Number()s them; JSON writes
// raw digits and the edge serves them losslessly (its 64-bit sentinel pipeline).
// The Wayback-served RoomDto strings ("RoomId":"…") are converted back to JSON numbers
// here, matching what the live rec.net game API actually serialized.

import { readFileSync, writeFileSync, existsSync, mkdirSync, readdirSync } from "node:fs";
import { execFileSync, spawnSync } from "node:child_process";
import crypto from "node:crypto";
import path from "node:path";

const ROOT = path.dirname(path.dirname(new URL(import.meta.url).pathname));
const staticDir = path.join(ROOT, "server", "static");
const fixturesDir = path.join(ROOT, "server", "fixtures");
const roomFixtures = path.join(fixturesDir, "room");
const indexFile = path.join(ROOT, "data", "porter", "blob-index.json");
const debugDir = path.join(ROOT, "data", "porter");

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const UA = "Mozilla/5.0 (X11; Linux x86_64) UwUNet-porter/1.0";
const sha256b64 = (buf) => crypto.createHash("sha256").update(buf).digest("base64");

const bundleIndexDir = path.join(ROOT, "data", "porter", "bundles");
const htrIndexFile = path.join(ROOT, "data", "porter", "htr-index.json");
const dataFixtures = path.join(fixturesDir, "data"); // cdn.rec.net/data/<key> (Holotar recordings)

async function get(url, { raw = false, retries = 3 } = {}) {
	for (let i = 0; i < retries; i++) {
		try {
			const res = await fetch(url, { headers: { "User-Agent": UA, redirect: "follow" }, redirect: "follow" });
			if (!res.ok) throw new Error(`HTTP ${res.status} ${url}`);
			return raw ? Buffer.from(await res.arrayBuffer()) : await res.text();
		} catch (e) {
			if (i === retries - 1) throw e;
			await sleep(2000 * (i + 1));
		}
	}
}

// ---------- step 1+2: wayback room page -> RoomDto ----------
async function flightSnapshots(roomName) {
	const cdx = JSON.parse(
		await get(`http://web.archive.org/cdx/search/cdx?url=rec.net/room/${encodeURIComponent(roomName)}&output=json&limit=50&filter=statuscode:200`),
	);
	if (cdx.length < 2) throw new Error(`no wayback snapshot of rec.net/room/${roomName}`);
	return cdx.slice(1).map((r) => r[1]).reverse(); // oldest..newest, all 200 timestamps
}

// raw_decode equivalent: find the object END by brace-matching (strings aware)
function sliceJsonObject(text, start) {
	let depth = 0;
	let inStr = false;
	let esc = false;
	for (let k = start; k < text.length; k++) {
		const c = text[k];
		if (inStr) {
			if (esc) esc = false;
			else if (c === "\\") esc = true;
			else if (c === '"') inStr = false;
		} else if (c === '"') inStr = true;
		else if (c === "{") depth++;
		else if (c === "}") {
			depth--;
			if (depth === 0) return text.slice(start, k + 1);
		}
	}
	return null;
}

function extractDto(flightText) {
	const i = flightText.indexOf('"RoomId"');
	if (i < 0) throw new Error("flight payload has no RoomId — the snapshot depth may be too young");
	let start = flightText.lastIndexOf("{", i);
	for (let tries = 0; tries < 500 && start > 0; tries++) {
		const chunk = sliceJsonObject(flightText, start);
		if (chunk) {
			try {
				const o = JSON.parse(chunk);
				if (o && o.SubRooms && o.SubRooms.length) return o;
			} catch { /* keep scanning */ }
		}
		start = flightText.lastIndexOf("{", start - 1);
	}
	throw new Error("could not locate the full RoomDto object in the flight payload");
}

async function roomDto(roomName) {
	const snapshots = await flightSnapshots(roomName);
	let lastErr = null;
	for (const ts of [...snapshots].reverse()) { // newest first
		try {
			const page = await get(`http://web.archive.org/web/${ts}/https://rec.net/room/${roomName}`);
			const pushes = [...page.matchAll(/self\.__next_f\.push\(\[1,("(?:[^"\\]|\\.)*")\]\)/g)].map((m) => JSON.parse(m[1]));
			const flight = pushes.join("");
			if (!flight) throw new Error("no Next.js flight payload in the snapshot");
			const dto = extractDto(flight);
			const withSaves = (dto.SubRooms ?? []).filter((s) => s.CurrentSave?.DataBlob).length;
			console.log(`→ ${ts}: RoomDto "${dto.Name}", ${dto.SubRooms.length} subrooms, ${withSaves} with CurrentSave blobs`);
			if (withSaves === 0) throw new Error("snapshot has no subroom save blobs (post-shutdown page) — trying an earlier one");
			return dto;
		} catch (e) {
			lastErr = e;
		}
	}
	throw lastErr ?? new Error("no usable snapshot");
}

// ---------- step 3: shard blob index ----------
async function loadIndex() {
	try {
		return JSON.parse(readFileSync(indexFile, "utf8"));
	} catch {
		return { shards: {} }; // shardId -> { keys: [Key: url] }
	}
}

async function listShardZips(shard) {
	const md = JSON.parse(await get(`https://archive.org/metadata/${shard}`));
	return (md.files ?? []).filter((f) => f.name.endsWith(".zip")).map((f) => f.name);
}

async function cdKeys(shard, zipName) {
	// central directory of the zip, via ranged request (single GET: EOCD + CD)
	const url = `https://archive.org/download/${shard}/${zipName}`;
	const head = await fetch(url, { method: "HEAD", headers: { "User-Agent": UA } });
	const size = Number(head.headers.get("content-length") ?? 0);
	if (!size) throw new Error(`no size for ${url}`);
	const tail = Buffer.from(
		await (await fetch(url, { headers: { "User-Agent": UA, Range: `bytes=${size - 4096}-${size - 1}` } })).arrayBuffer(),
	);
	const k = tail.lastIndexOf(Buffer.from([0x50, 0x4b, 0x06, 0x06])); // PK\x06\x06 zip64 EOCD
	let eocd;
	if (k >= 0) {
		eocd = { cdSize: Number(tail.readBigUInt64LE(k + 40)), cdOfs: Number(tail.readBigUInt64LE(k + 48)) };
	} else {
		const k2 = tail.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
		if (k2 < 0) throw new Error(`no EOCD in ${url}`);
		eocd = { cdSize: tail.readUInt32LE(k2 + 12), cdOfs: tail.readUInt32LE(k2 + 16) };
	}
	const cd = Buffer.from(
		await (await fetch(url, { headers: { "User-Agent": UA, Range: `bytes=${eocd.cdOfs}-${eocd.cdSize + eocd.cdOfs - 1}` } })).arrayBuffer(),
	);
	// parse the central directory manually (sig PK\x01\x02, fixed 46-byte header + name)
	const names = [];
	let off = 0;
	while (off + 46 <= cd.length && cd.readUInt32LE(off) === 0x02014b50) {
		const nlen = cd.readUInt16LE(off + 28);
		const elen = cd.readUInt16LE(off + 30);
		const clen = cd.readUInt16LE(off + 32);
		names.push(cd.subarray(off + 46, off + 46 + nlen).toString("utf8"));
		off += 46 + nlen + elen + clen;
	}
	const keys = names.filter((n) => /\.(room|meta|inv|behaviour)$/.test(n) || n.includes("."));
	return { names, keys };
}

async function buildIndex() {
	// advancedsearch: encode [] (bare [] in the URL pares out server-side) and page through
	const ids = [];
	let page = 1;
	for (; ;) {
		const u = new URL("https://archive.org/advancedsearch.php");
		u.search = new URLSearchParams({ q: "recroom-cdn-room-files", rows: "200", page: String(page), output: "json", "fl[]": "identifier" }).toString();
		const res = await fetch(u, { headers: { "User-Agent": UA } });
		const docs = (await res.json()).response.docs;
		if (!docs.length) break;
		for (const doc of docs) {
			const id = doc.identifier;
			if (id?.startsWith("recroom-cdn-room-files-") && !ids.includes(id)) ids.push(id);
		}
		page++;
		if (page > 20) break;
	}
	const idx = await loadIndex();
	let done = 0;
	for (const shard of ids) {
		// skip only shards a FULL scan previously completed (a handful of seeded keys
		// from shard_map seeding must not blocks-list the shard forever)
		if (idx.shards[shard]?.keys?.length > 1000) {
			done++;
			continue;
		}
		try {
			const zip = (await listShardZips(shard)).sort().pop();
			const { keys } = await cdKeys(shard, zip);
			idx.shards[shard] = { zip, keys };
			done++;
			console.log(`scanned ${done}/${ids.length}: ${shard} (${keys.length} files)`);
			if (done % 10 === 0) {
				mkdirSync(path.dirname(indexFile), { recursive: true });
				writeFileSync(indexFile, JSON.stringify(idx));
			}
		} catch (e) {
			console.log(`shard ${shard} ERR ${e.message}`);
		}
	}
	mkdirSync(path.dirname(indexFile), { recursive: true });
	writeFileSync(indexFile, JSON.stringify(idx));
	console.log(`index built: ${done}/${ids.length} shards`);
	return idx;
}

async function findBlob(key, idx) {
	const hit = Object.entries(idx.shards).find(([, s]) => (s.keys ?? []).includes(key));
	if (hit) return { shard: hit[0], zip: hit[1].zip };
	throw new Error(`blob ${key} not found in any indexed shard — run --index first`);
}

async function downloadBlob(shard, zipName, key) {
	const url = `https://archive.org/download/${shard}/${zipName}/${key}`;
	return await get(url, { raw: true, retries: 5 });
}

// ---------- Rec Room Studio bundles: the recroom-cdn-assetbundle-* index ----------
// A Studio subroom (CurrentSave.UnityAssetId set) loads its scene from asset bundles the CDN
// named "<guid hex>.SubRoom.<Main|SubAsset>.<Target>.<Version>.assetbundle" (Target 0 Windows,
// 2 Android). The archive keeps ~900k bundles under random keys in ~20 GB zips, so the index
// reads only what identifies one: the UnityFS header (Unity revision, CAB nodes) and, for builds
// our client can load, the head of the serialized file holding the AssetBundle object (target
// platform, its own name, and its externals — the CABs of the bundles it depends on). Members
// are stored uncompressed, so every read is a byte range into the zip, batched into multi-range
// requests. The client runs Unity 2021.3.41f1: the Unity 6 rebuilds (6000.x) the CDN also held
// at shutdown will not load in it, and neither will the Android / console builds.
const UNITY_LOADABLE = /^20(19|20|21)\./;
const WINDOWS_PLATFORMS = new Set([5, 19]); // BuildTarget StandaloneWindows / StandaloneWindows64
// "<guid hex>.SubRoom.Main.0.3.assetbundle" -> guid, kind, target, version
const STUDIO_NAME = /^([0-9a-f]{32})\.SubRoom\.(\w+)\.(\d+)\.(\d+)\.assetbundle$/i;

// LZ4 block decode. A truncated `src` (a head-of-block probe) decodes to the prefix it covers.
function lz4Block(src, usize) {
	const dst = Buffer.alloc(usize);
	let i = 0;
	let o = 0;
	while (i < src.length) {
		const tok = src[i++];
		let lit = tok >> 4;
		if (lit === 15) for (let b = 255; b === 255 && i < src.length; lit += b) b = src[i++];
		const n = Math.min(lit, src.length - i, usize - o);
		src.copy(dst, o, i, i + n);
		o += n;
		i += lit;
		if (i + 2 > src.length) break;
		const off = src[i] | (src[i + 1] << 8);
		i += 2;
		let len = tok & 15;
		if (len === 15) for (let b = 255; b === 255 && i < src.length; len += b) b = src[i++];
		len = Math.min(len + 4, usize - o);
		for (let s = o - off; len-- > 0;) dst[o++] = dst[s++];
	}
	return dst.subarray(0, o);
}

function unityDecompress(src, flags, usize) {
	const kind = flags & 0x3f;
	if (kind === 0) return src;
	if (kind === 2 || kind === 3) return lz4Block(src, usize);
	if (kind === 1) return lzmaBlock(src, usize);
	throw new Error(`unsupported UnityFS compression ${kind}`);
}

// Unity LZMA block: 5 property bytes, then a raw LZMA1 stream (no size header). Node has no
// LZMA, so xz(1) decodes it; a truncated stream exits 1 but still writes the prefix it covers.
function lzmaBlock(src, usize) {
	const props = src[0];
	const lzma1 = `lc=${props % 9},lp=${Math.floor(props / 9) % 5},pb=${Math.floor(props / 45)},dict=${src.readUInt32LE(1)}`;
	const r = spawnSync("xz", ["-dc", "--format=raw", `--lzma1=${lzma1}`], { input: src.subarray(5), maxBuffer: usize + (1 << 20) });
	if (r.error) throw new Error(`xz: ${r.error.message}`);
	if (r.status !== 0 && !r.stdout?.length) throw new Error(`xz: ${String(r.stderr).trim()}`);
	return r.stdout.subarray(0, usize);
}

const cstrAt = (buf, o) => {
	const e = buf.indexOf(0, o);
	if (e < 0) throw new RangeError("unterminated string");
	return [buf.toString("latin1", o, e), e + 1];
};

// UnityFS header -> where the block info sits. Offsets are relative to the member's first byte.
function unityFsHeader(d, memberSize) {
	let [sig, o] = cstrAt(d, 0);
	if (sig !== "UnityFS") return null;
	const ver = d.readUInt32BE(o);
	o += 4;
	let rev;
	[, o] = cstrAt(d, o);
	[rev, o] = cstrAt(d, o);
	const csz = d.readUInt32BE(o + 8);
	const usz = d.readUInt32BE(o + 12);
	const flags = d.readUInt32BE(o + 16);
	o += 20;
	if (ver >= 7) o = (o + 15) & ~15;
	const atEnd = (flags & 0x80) !== 0;
	const biOfs = atEnd ? memberSize - csz : o;
	let dataStart = atEnd ? o : o + csz;
	if (flags & 0x200) dataStart = (dataStart + 15) & ~15;
	return { rev, flags, csz, usz, biOfs, dataStart };
}

function unityFsBlockInfo(bi) {
	let p = 16;
	const blocks = [];
	let u = 0;
	let c = 0;
	for (let n = bi.readUInt32BE(p), k = (p += 4, 0); k < n; k++, p += 10) {
		const b = { usize: bi.readUInt32BE(p), csize: bi.readUInt32BE(p + 4), flags: bi.readUInt16BE(p + 8), u, c };
		u += b.usize;
		c += b.csize;
		blocks.push(b);
	}
	const nodes = [];
	for (let n = bi.readUInt32BE(p), k = (p += 4, 0); k < n; k++) {
		const off = Number(bi.readBigUInt64BE(p));
		const size = Number(bi.readBigUInt64BE(p + 8));
		const flags = bi.readUInt32BE(p + 16);
		let name;
		[name, p] = cstrAt(bi, p + 20);
		nodes.push({ name, off, size, flags });
	}
	return { blocks, nodes };
}

// The blocks overlapping uncompressed [from, to) of the bundle's data stream.
const blocksFor = (blocks, from, to) => blocks.filter((b) => b.u < to && b.u + b.usize > from);

// Decompress a contiguous run of blocks fetched as one compressed range; the last block may be
// a truncated prefix (it then decodes to the part it covers).
function decodeRun(run, buf) {
	const parts = [];
	for (const b of run) {
		const at = b.c - run[0].c;
		if (at >= buf.length) break;
		parts.push(unityDecompress(buf.subarray(at, at + b.csize), b.flags, b.usize));
	}
	return Buffer.concat(parts);
}

// Decoded bytes [from, to) of many members' data streams. Only the blocks overlapping a span are
// fetched, and of the last one only a compressed prefix sized to decode past `to` (LZ4 and LZMA
// both decode a prefix from a prefix — a single-block LZMA bundle needn't come down whole).
// A guess that falls short is refetched in full. -> Map(span -> Buffer starting at `from`).
async function readSpans(url, spans) {
	const plan = spans.map((sp) => {
		const run = blocksFor(sp.e.blocks, sp.from, sp.to);
		if (!run.length) throw new Error("span outside the data stream");
		const last = run.at(-1);
		const need = Math.min(sp.to, last.u + last.usize) - last.u;
		const kind = last.flags & 0x3f;
		const guess = kind === 0 ? need : kind === 1 ? need + Math.ceil(need / 50) + 4096 : need + Math.ceil(need / 255) + 64;
		const base = sp.e.data + sp.e.h.dataStart;
		const full = base + last.c + last.csize - 1;
		return { sp, run, a: base + run[0].c, end: Math.min(full, base + last.c + guess - 1), full };
	});
	const decode = (p, buf) => decodeRun(p.run, buf).subarray(p.sp.from - p.run[0].u);
	const bufs = await fetchRanges(url, plan.map((p) => [p.a, p.end]));
	const out = new Map();
	const retry = [];
	for (const p of plan) {
		let d = null;
		try {
			d = decode(p, bufs.get(p.a));
		} catch { /* a cut LZ4 sequence can fail — refetch */ }
		if (d && (d.length >= p.sp.to - p.sp.from || p.end === p.full)) out.set(p.sp, d);
		else if (p.end < p.full) retry.push(p);
	}
	if (retry.length) {
		const again = await fetchRanges(url, retry.map((p) => [p.a, p.full]));
		for (const p of retry) out.set(p.sp, decode(p, again.get(p.a)));
	}
	return out;
}

// SerializedFile (format 19+) metadata -> its objects: [{ start, size, classID }], offsets from the
// file's first byte. Walks the type table (type trees skipped by their sizes) to the object table.
function serializedObjects(s) {
	const { version, dataOffset } = serializedHead(s);
	if (version < 19) throw new Error(`serialized format ${version}`);
	const le = s[16] === 0;
	let o;
	[, o] = cstrAt(s, version >= 22 ? 48 : 20);
	const i32 = () => ((o += 4), le ? s.readInt32LE(o - 4) : s.readInt32BE(o - 4));
	o += 4; // platform
	const typeTree = s[o++] !== 0;
	const types = [];
	for (let n = i32(), k = 0; k < n; k++) {
		const classID = i32();
		o += 3; // isStrippedType, scriptTypeIndex
		if (classID === 114) o += 16; // MonoBehaviour script id
		o += 16; // old type hash
		if (typeTree) {
			const nodes = i32();
			const strings = i32();
			o += nodes * 32 + strings;
			if (version >= 21) {
				const deps = i32(); // type dependencies (an i32 each)
				o += 4 * deps;
			}
		}
		types.push(classID);
	}
	const objects = [];
	for (let n = i32(), k = 0; k < n; k++) {
		o = (o + 3) & ~3;
		o += 8; // path id
		const start = dataOffset + (version >= 22 ? Number(le ? s.readBigInt64LE(o) : s.readBigInt64BE(o)) : (le ? s.readUInt32LE(o) : s.readUInt32BE(o)));
		o += version >= 22 ? 8 : 4;
		const size = i32() >>> 0;
		objects.push({ start, size, classID: types[i32()] });
	}
	return objects;
}

// SerializedFile head -> target platform, metadata size, data offset.
function serializedHead(s) {
	const version = s.readUInt32BE(8);
	const v22 = version >= 22;
	const metaSize = v22 ? s.readUInt32BE(20) : s.readUInt32BE(0);
	const dataOffset = v22 ? Number(s.readBigUInt64BE(32)) : s.readUInt32BE(12);
	const bigEndian = s[16] !== 0;
	const [, o] = cstrAt(s, v22 ? 48 : 20);
	const platform = bigEndian ? s.readUInt32BE(o) : s.readUInt32LE(o);
	return { version, metaSize, dataOffset, platform };
}

async function multiRange(url, ranges) {
	const res = await fetch(url, {
		headers: { "User-Agent": UA, Range: "bytes=" + ranges.map(([a, b]) => `${a}-${b}`).join(",") },
		signal: AbortSignal.timeout(120_000), // a stalled archive.org connection otherwise hangs the shard forever
	});
	if (res.status !== 206) throw new Error(`HTTP ${res.status} (multi-range ${url})`);
	const buf = Buffer.from(await res.arrayBuffer());
	const type = res.headers.get("content-type") ?? "";
	const parts = new Map();
	if (!type.startsWith("multipart/byteranges")) {
		const m = /bytes (\d+)-/.exec(res.headers.get("content-range") ?? "");
		parts.set(Number(m?.[1] ?? ranges[0][0]), buf);
		return parts;
	}
	const boundary = Buffer.from("--" + type.split("boundary=")[1].replace(/"/g, ""));
	for (let p = buf.indexOf(boundary); p >= 0;) {
		const h = buf.indexOf("\r\n\r\n", p);
		if (h < 0) break;
		const m = /content-range: bytes (\d+)-(\d+)/i.exec(buf.toString("latin1", p, h));
		if (!m) break;
		const a = Number(m[1]);
		const end = h + 4 + (Number(m[2]) - a + 1);
		parts.set(a, buf.subarray(h + 4, end));
		p = buf.indexOf(boundary, end);
	}
	return parts;
}

// Fetch byte ranges in multi-range batches (bounded by count and bytes), `conc` batches in
// flight, each retried. -> Map(range start -> bytes).
async function fetchRanges(url, ranges, { maxRanges = 150, maxBytes = 4 << 20, conc = 6 } = {}) {
	const batches = [];
	for (let i = 0; i < ranges.length;) {
		const batch = [];
		let bytes = 0;
		while (i < ranges.length && batch.length < maxRanges && (batch.length === 0 || bytes + ranges[i][1] - ranges[i][0] < maxBytes)) {
			bytes += ranges[i][1] - ranges[i][0] + 1;
			batch.push(ranges[i++]);
		}
		batches.push(batch);
	}
	const out = new Map();
	const worker = async () => {
		for (let batch; (batch = batches.shift());) {
			for (let tries = 0; ; tries++) {
				try {
					for (const [a, b] of await multiRange(url, batch)) out.set(a, b);
					break;
				} catch (e) {
					if (tries === 4) throw e;
					await sleep(3000 * (tries + 1));
				}
			}
		}
	};
	await Promise.all(Array.from({ length: conc }, worker));
	return out;
}

// A zip's central directory with zip64 sizes/offsets: [{ name, size, lho }].
async function zipEntries(url) {
	let r0;
	for (let tries = 0; ; tries++) {
		try {
			r0 = await fetch(url, { headers: { "User-Agent": UA, Range: "bytes=0-0" }, signal: AbortSignal.timeout(60_000) });
			break;
		} catch (e) {
			if (tries === 4) throw e;
			await sleep(3000 * (tries + 1));
		}
	}
	const finalUrl = r0.url;
	const size = Number((r0.headers.get("content-range") ?? "").split("/")[1]);
	if (!size) throw new Error(`no size for ${url}`);
	const [tail] = (await fetchRanges(finalUrl, [[size - 65536, size - 1]])).values();
	let cdOfs;
	let cdSize;
	const k = tail.lastIndexOf(Buffer.from([0x50, 0x4b, 0x06, 0x06]));
	if (k >= 0) {
		cdSize = Number(tail.readBigUInt64LE(k + 40));
		cdOfs = Number(tail.readBigUInt64LE(k + 48));
	} else {
		const k2 = tail.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
		if (k2 < 0) throw new Error(`no EOCD in ${url}`);
		cdSize = tail.readUInt32LE(k2 + 12);
		cdOfs = tail.readUInt32LE(k2 + 16);
	}
	const [cd] = (await fetchRanges(finalUrl, [[cdOfs, cdOfs + cdSize - 1]])).values();
	const entries = [];
	for (let off = 0; off + 46 <= cd.length && cd.readUInt32LE(off) === 0x02014b50;) {
		const nlen = cd.readUInt16LE(off + 28);
		const elen = cd.readUInt16LE(off + 30);
		const clen = cd.readUInt16LE(off + 32);
		let csize = cd.readUInt32LE(off + 20);
		const usize32 = cd.readUInt32LE(off + 24);
		let lho = cd.readUInt32LE(off + 42);
		for (let e = off + 46 + nlen; e + 4 <= off + 46 + nlen + elen;) {
			const id = cd.readUInt16LE(e);
			const len = cd.readUInt16LE(e + 2);
			if (id === 1) {
				let p = e + 4;
				if (usize32 === 0xffffffff) p += 8;
				if (csize === 0xffffffff) (csize = Number(cd.readBigUInt64LE(p))), (p += 8);
				if (lho === 0xffffffff) lho = Number(cd.readBigUInt64LE(p));
			}
			e += 4 + len;
		}
		entries.push({ name: cd.toString("utf8", off + 46, off + 46 + nlen), method: cd.readUInt16LE(off + 10), size: csize, lho });
		off += 46 + nlen + elen + clen;
	}
	return { url: finalUrl, entries };
}

// Index one assetbundle shard -> data/porter/bundles/<shard>.json. Only loadable Windows
// builds are recorded (name, own CAB, dependency CABs); the rest is tallied in `stats`.
async function indexBundleShard(shard) {
	const md = JSON.parse(await get(`https://archive.org/metadata/${shard}`));
	const zip = (md.files ?? []).filter((f) => f.name.endsWith(".zip")).map((f) => f.name).sort().pop();
	if (!zip) throw new Error(`${shard}: no zip`);
	const { url, entries } = await zipEntries(`https://archive.org/download/${shard}/${zip}`);
	const stats = { members: entries.length, unityFs: 0, loadable: 0, windows: 0, named: 0, skipped: 0, revs: {}, why: {} };
	const skip = (stage, err, e) => {
		if (e && (stats.examples ??= {})[stage]?.length !== 6) (stats.examples[stage] ??= []).push(`${e.name} ${e.h.rev} ${String(err?.message ?? err).slice(0, 60)}`);
		stats.skipped++;
		const k = `${stage}: ${String(err?.message ?? err).replace(/\d+/g, "N")}`;
		stats.why[k] = (stats.why[k] ?? 0) + 1;
	};
	const bundles = [];

	// 1. local header + UnityFS header + (usually) the block info, one range per member
	const HEAD = 2048;
	const members = entries.filter((e) => e.method === 0 && e.name.endsWith(".assetbundle"));
	const heads = await fetchRanges(url, members.map((e) => [e.lho, e.lho + 30 + e.name.length + 64 + HEAD - 1]));
	const say = (msg) => process.argv.includes("--verbose") && console.log(`  ${shard}: ${msg}`);
	say(`${members.length} members, headers read`);
	const live = [];
	const needBlockInfo = [];
	for (const e of members) {
		const raw = heads.get(e.lho);
		if (!raw || raw.readUInt32LE(0) !== 0x04034b50) continue;
		e.data = e.lho + 30 + raw.readUInt16LE(26) + raw.readUInt16LE(28);
		const d = raw.subarray(e.data - e.lho);
		let h;
		try {
			h = unityFsHeader(d, e.size);
		} catch {
			h = null;
		}
		if (!h) continue;
		stats.unityFs++;
		const major = h.rev.split(".").slice(0, 2).join(".");
		stats.revs[major] = (stats.revs[major] ?? 0) + 1;
		if (!UNITY_LOADABLE.test(h.rev)) continue;
		stats.loadable++;
		e.h = h;
		if (h.biOfs + h.csz <= d.length) e.bi = d.subarray(h.biOfs, h.biOfs + h.csz);
		else needBlockInfo.push(e);
		live.push(e);
	}
	if (needBlockInfo.length) {
		const got = await fetchRanges(url, needBlockInfo.map((e) => [e.data + e.h.biOfs, e.data + e.h.biOfs + e.h.csz - 1]));
		for (const e of needBlockInfo) e.bi = got.get(e.data + e.h.biOfs);
	}
	for (const e of live) {
		try {
			Object.assign(e, unityFsBlockInfo(unityDecompress(e.bi, e.h.flags, e.h.usz)));
			const serial = e.nodes.filter((n) => n.flags & 4).sort((a, b) => a.off - b.off);
			e.node = serial[0];
			if (!e.node || !e.blocks.length) throw new Error("no serialized node");
		} catch (err) {
			e.node = null;
			skip("blockinfo", err);
		}
	}
	// 2. platform: the head of the first serialized file (the AssetBundle-bearing one — a scene
	// bundle's .sharedAssets, else the bundle's CAB file); its data offset comes along
	const probes = live.filter((e) => e.node).map((e) => ({ e, from: e.node.off, to: e.node.off + 1024 }));
	say(`${probes.length} loadable builds, probing platforms`);
	const probed = await readSpans(url, probes);
	const windows = [];
	for (const sp of probes) {
		try {
			sp.e.serial = serializedHead(probed.get(sp));
			if (WINDOWS_PLATFORMS.has(sp.e.serial.platform)) windows.push(sp.e);
		} catch (err) {
			skip("platform", err, sp.e);
		}
	}
	stats.windows = windows.length;

	// 3. Windows builds: the metadata (object table + externals, the CABs depended on), then the
	// AssetBundle object (class 142): m_Name — the bundle's own name — and m_Dependencies
	say(`${windows.length} Windows builds, reading metadata`);
	const metas = windows.map((e) => ({ e, from: e.node.off, to: e.node.off + e.serial.dataOffset }));
	const metaBufs = await readSpans(url, metas);
	const abs = [];
	for (const sp of metas) {
		const { e } = sp;
		try {
			const meta = metaBufs.get(sp);
			const ab = serializedObjects(meta).find((x) => x.classID === 142);
			if (!ab) throw new Error("no AssetBundle object");
			e.deps = [...meta.toString("latin1").matchAll(/archive:\/CAB-([0-9a-f]{32})\//gi)].map((m) => m[1].toLowerCase());
			abs.push({ e, from: e.node.off + ab.start, to: e.node.off + ab.start + Math.min(ab.size, 1 << 20) });
		} catch (err) {
			skip("metadata", err, e);
		}
	}
	say(`${abs.length} AssetBundle objects, reading names`);
	const abBufs = await readSpans(url, abs);
	for (const sp of abs) {
		const { e } = sp;
		try {
			const ab = abBufs.get(sp);
			const len = ab.readUInt32LE(0);
			const name = ab.toString("latin1", 4, 4 + len);
			// GUID-named Studio bundles, and others ("content.0.3.assetbundle") a room may depend on by CAB
			if (!name.endsWith(".assetbundle")) throw new Error(`unexpected bundle name "${name.slice(0, 40)}"`);
			const cab = e.node.name.slice(4, 36).toLowerCase();
			const deps = [...e.deps, ...[...ab.toString("latin1").matchAll(/cab-([0-9a-f]{32})/g)].map((m) => m[1])];
			stats.named++;
			bundles.push({ m: e.name, n: name, cab, deps: [...new Set(deps)].filter((d) => d !== cab), rev: e.h.rev, plat: e.serial.platform, size: e.size });
		} catch (err) {
			skip("name", err, e);
		}
	}
	mkdirSync(bundleIndexDir, { recursive: true });
	writeFileSync(path.join(bundleIndexDir, `${shard}.json`), JSON.stringify({ shard, zip, stats, bundles }));
	return stats;
}

async function listItems(query, prefix) {
	const ids = [];
	for (let page = 1; page <= 20; page++) {
		const u = new URL("https://archive.org/advancedsearch.php");
		u.search = new URLSearchParams({ q: query, rows: "200", page: String(page), output: "json", "fl[]": "identifier" }).toString();
		const docs = (await (await fetch(u, { headers: { "User-Agent": UA } })).json()).response.docs;
		if (!docs.length) break;
		for (const { identifier: id } of docs) if (id?.startsWith(prefix) && !ids.includes(id)) ids.push(id);
	}
	return ids.sort();
}

// node tools/port-room.mjs --index-bundles [shard ...] [--jobs N] — resumable: a shard with an
// index file is skipped (delete the file to rescan it).
async function buildBundleIndex(only) {
	const jobs = Number(process.argv[process.argv.indexOf("--jobs") + 1]) || 3;
	const ids = only.length ? only : await listItems("recroom-cdn-assetbundle", "recroom-cdn-assetbundle-");
	const todo = ids.filter((s) => !existsSync(path.join(bundleIndexDir, `${s}.json`)));
	console.log(`${ids.length} assetbundle shards, ${ids.length - todo.length} already indexed, ${todo.length} to go (${jobs} at a time)`);
	let done = 0;
	const worker = async () => {
		for (let shard; (shard = todo.shift());) {
			const t0 = Date.now();
			try {
				const s = await indexBundleShard(shard);
				console.log(`[${++done}] ${shard}: ${s.members} members, ${s.loadable} loadable, ${s.windows} windows, ${s.named} named, ${s.skipped} skipped ${JSON.stringify(s.revs)} (${((Date.now() - t0) / 1000).toFixed(0)}s)`);
			} catch (e) {
				console.log(`[${++done}] ${shard}: ERR ${e.message} — rerun to retry`);
			}
		}
	};
	await Promise.all(Array.from({ length: jobs }, worker));
}

function loadBundleIndex() {
	const byGuid = new Map(); // guid hex -> [record]
	const byCab = new Map();
	let shards = 0;
	if (existsSync(bundleIndexDir)) {
		for (const f of readdirSync(bundleIndexDir).filter((f) => f.endsWith(".json"))) {
			const { shard, zip, bundles } = JSON.parse(readFileSync(path.join(bundleIndexDir, f), "utf8"));
			shards++;
			for (const b of bundles) {
				const rec = { ...b, shard, zip };
				const guid = STUDIO_NAME.exec(b.n)?.[1].toLowerCase();
				if (guid) byGuid.set(guid, [...(byGuid.get(guid) ?? []), rec]);
				byCab.set(b.cab, rec);
			}
		}
	}
	return { shards, byGuid, byCab };
}

// ---------- step 4b: Studio bundles ----------
// A save naming a UnityAssetId gets its Windows build from the bundle index: the newest
// "<guid>.SubRoom.Main.0.<v>" build, plus every bundle it depends on (by CAB, transitively).
// Each is downloaded to server/fixtures/room/<its CDN name> and recorded on
// CurrentSave.UnitySubAssets the way the reference stores builds — { UnityAssetId, Target,
// Version, Filename, Hash } — which the edge serves to the save detail and
// /unity_assets/baked/bulk. Bundles already in server/fixtures/room/ under the CDN naming (any
// target, e.g. hand-recovered Android builds) are recorded too. With no Windows build the
// edge advertises no asset, and the subroom loads its baked scene + DataBlob only.
const guidOf = (hex) => `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;

async function attachStudioBundles(dto) {
	const saves = (dto.SubRooms ?? []).filter((sr) => sr.CurrentSave?.UnityAssetId);
	if (!saves.length) return;
	const bi = loadBundleIndex();
	if (!bi.shards) console.log("! Studio room, but no bundle index yet — run: node tools/port-room.mjs --index-bundles");
	const local = existsSync(roomFixtures) ? readdirSync(roomFixtures) : [];
	for (const sr of saves) {
		const cs = sr.CurrentSave;
		delete cs.UnityAsset; // pre-index porter field; the edge reads UnitySubAssets only
		const hex = String(cs.UnityAssetId).toLowerCase().replaceAll("-", "");
		const rows = [];
		const missing = [];
		const mains = (bi.byGuid.get(hex) ?? [])
			.map((b) => ({ b, m: STUDIO_NAME.exec(b.n) }))
			.filter(({ m }) => m[2] === "Main" && m[3] === "0")
			.sort((x, y) => Number(y.m[4]) - Number(x.m[4]));
		if (mains.length) {
			const closure = [];
			const seen = new Set();
			for (const queue = [mains[0].b]; queue.length;) {
				const b = queue.shift();
				if (seen.has(b.cab)) continue;
				seen.add(b.cab);
				closure.push(b);
				for (const d of b.deps) {
					const dep = bi.byCab.get(d);
					if (dep) queue.push(dep);
					else if (!missing.includes(d)) missing.push(d);
				}
			}
			for (const b of closure) {
				const m = STUDIO_NAME.exec(b.n);
				// non-Studio names ("content.0.3.assetbundle") repeat across bundles: key them by CAB
				const filename = m ? b.n : `${b.cab}.${b.n}`;
				const file = path.join(roomFixtures, filename);
				let buf = existsSync(file) ? readFileSync(file) : null;
				if (buf?.length !== b.size) {
					process.stdout.write(`  ${sr.Name}: ${filename} from ${b.shard} ... `);
					buf = await downloadBlob(b.shard, b.zip, b.m);
					if (buf.length !== b.size) throw new Error(`${b.m}: got ${buf.length} bytes, the zip says ${b.size}`);
					mkdirSync(roomFixtures, { recursive: true });
					writeFileSync(file, buf);
					console.log(`✓ ${(buf.length / 1024).toFixed(0)} KB`);
				}
				rows.push({ UnityAssetId: guidOf(m ? m[1].toLowerCase() : b.cab), Target: 0, Version: Number(m?.[4] ?? 0), Filename: filename, Hash: sha256b64(buf) });
			}
		}
		for (const f of local) {
			const m = STUDIO_NAME.exec(f);
			if (!m || m[1].toLowerCase() !== hex || m[2] !== "Main" || rows.some((r) => r.Filename === f)) continue;
			if (m[3] === "0" && rows.length) continue; // the index's build (with its dependencies) wins
			rows.push({ UnityAssetId: guidOf(hex), Target: Number(m[3]), Version: Number(m[4]), Filename: f, Hash: sha256b64(readFileSync(path.join(roomFixtures, f))) });
		}
		cs.UnitySubAssets = rows;
		const win = rows.filter((r) => r.Target === 0);
		const others = rows.filter((r) => r.Target !== 0).map((r) => `${r.Target}.${r.Version}`);
		if (win.length) console.log(`  ${sr.Name}: Studio scene ${win[0].Filename} + ${win.length - 1} dependencies${others.length ? `, other targets ${others}` : ""}`);
		else console.log(`  ${sr.Name}: no Windows 2021.3 build of ${cs.UnityAssetId} archived${others.length ? ` (have targets ${others})` : ""} — subroom loads without its Studio scene`);
		if (missing.length) console.log(`  ${sr.Name}: ! ${missing.length} dependency bundle(s) not in the index: ${missing.join(", ")}`);
	}
}

// ---------- step 4c: Holotar recordings ----------
// A room's scene blob names each Holotar projector's recording by key ("<key>.htr"); the client
// downloads it from cdn.rec.net/data/<key>.htr (the reference cdn worker's /data/ prefix), so a
// missing file is a silent holotar AND its voice track. recroom-cdn-htr-* holds the archived
// recordings under their real keys — the 32-hex keys only: the older 25-char base36 keys were
// never captured. Recovered files go to server/fixtures/data/, which the edge serves as-is.
const HTR_REF = /(?<![0-9A-Za-z])([0-9a-z]{25}|[0-9a-f]{32})\.htr/g;

async function loadHtrIndex() {
	if (existsSync(htrIndexFile)) return JSON.parse(readFileSync(htrIndexFile, "utf8"));
	const idx = { shards: {} };
	for (const shard of await listItems("recroom-cdn-htr", "recroom-cdn-htr-")) {
		const zip = (await listShardZips(shard)).sort().pop();
		const { keys } = await cdKeys(shard, zip);
		idx.shards[shard] = { zip, keys: keys.filter((k) => k.endsWith(".htr")) };
		console.log(`  holotar index: ${shard} (${idx.shards[shard].keys.length} recordings)`);
	}
	mkdirSync(path.dirname(htrIndexFile), { recursive: true });
	writeFileSync(htrIndexFile, JSON.stringify(idx));
	return idx;
}

async function attachHolotars(dto) {
	const refs = new Set();
	for (const sr of dto.SubRooms ?? []) {
		const blob = sr.CurrentSave?.DataBlob;
		const file = blob ? path.join(roomFixtures, blob) : null;
		if (file && existsSync(file)) for (const m of readFileSync(file).toString("latin1").matchAll(HTR_REF)) refs.add(m[0]);
	}
	if (!refs.size) return;
	const idx = await loadHtrIndex();
	const where = new Map();
	for (const [shard, { zip, keys }] of Object.entries(idx.shards)) for (const k of keys) where.set(k, { shard, zip });
	let have = 0;
	const lost = [];
	for (const key of refs) {
		const file = path.join(dataFixtures, key);
		if (existsSync(file)) {
			have++;
			continue;
		}
		const loc = where.get(key);
		if (!loc) {
			lost.push(key);
			continue;
		}
		const buf = await downloadBlob(loc.shard, loc.zip, key);
		mkdirSync(dataFixtures, { recursive: true });
		writeFileSync(file, buf);
		have++;
	}
	console.log(`  holotars: ${have}/${refs.size} recordings in server/fixtures/data/${lost.length ? ` — ${lost.length} never archived (e.g. ${lost[0]}): those projectors stay silent` : ""}`);
}

// ---------- step 5: room image from wayback ----------
async function fetchImage(imageName) {
	try {
		const cd = JSON.parse(await get(`http://web.archive.org/cdx/search/cdx?url=img.rec.net/${encodeURIComponent(imageName)}&output=json&limit=-3&filter=statuscode:200`));
		if (cd.length < 2) return null;
		const buf = await get(`http://web.archive.org/web/${cd[cd.length - 1][1]}/https://img.rec.net/${imageName}`, { raw: true });
		return buf;
	} catch {
		return null;
	}
}

// ---------- step 6+7: register ----------
function readJson(p, fallback) {
	// Plain JSON.parse would float-round raw 64-bit digit literal values
	// (649924194922273060 -> ...000). Wrap them in sentinels first, like the edge does.
	try {
		const txt = readFileSync(p, "utf8").replace(/("(?:RoomId|SubRoomId|SubRoomDataSaveId)":\s*)(\d{16,})/g, '$1"__BIG__$2__"');
		return JSON.parse(txt);
	} catch {
		return fallback;
	}
}

// The live game API serialized RoomId/SubRoomId/SubRoomDataSaveId as BARE 64-bit digit
// literals. JS cannot hold those (Number >2^53 rounds: 649924194922273060 -> ...000), so in
// memory they stay strings and dumpLossless() unquotes them on write. The edge's
// quoteBigLiterals re-wraps them at load; nothing on this path ever loses a digit.
const LOSSLESS_ID_KEYS = /^"(RoomId|SubRoomId|SubRoomDataSaveId)":("(\d+)"|"__BIG__(\d+)__")/;
function dumpLossless(obj, file) {
	let out = JSON.stringify(obj, null, 1);
	// "RoomId": "649924194922273060"  ->  "RoomId": 649924194922273060  (digit literal)
	// sentinel strings written directly into the file become plain digit literals too.
	out = out.replace(/"(RoomId|SubRoomId|SubRoomDataSaveId)":\s*"(\d+)"/g, '"$1": $2');
	out = out.replace(/"__BIG__(\d+)__"/g, "$1");
	writeFileSync(file, out);
}
function numericizeIds(dto) {
	dto.RankedEntityId = dto.RankedEntityId != null ? String(dto.RankedEntityId) : null;
	for (const sr of dto.SubRooms ?? []) {
		const cs = sr.CurrentSave;
		if (cs) {
			cs.UnityAssetId = cs.UnityAssetId ?? null;
			cs.ReferencedUnityAssetIds = cs.ReferencedUnityAssetIds ?? [];
			cs.OMVersion = cs.OMVersion ?? 0;
		}
		sr.StagedSubRoomDataSaveId = sr.StagedSubRoomDataSaveId ?? null;
		sr.ShouldAutoStageSaves = sr.ShouldAutoStageSaves ?? true;
	}
	return dto;
}
const toRawNumberSafe = (v) => {
	const s = String(v);
	const n = Number(s);
	return Number.isSafeInteger(n) ? n : s;
};

async function port(name) {
	const strict = process.argv.includes("--strict");
	const dto = await roomDto(name);
	const image = await fetchImage(dto.ImageName);
	if (image) {
		writeFileSync(path.join(fixturesDir, dto.ImageName), image);
		console.log(`✓ image ${dto.ImageName} (${(image.length / 1024).toFixed(0)} KB) -> server/fixtures/`);
	} else console.log(`! image ${dto.ImageName} not archived — tile will fall back to the generic placeholder`);

	numericizeIds(dto);
	await attachStudioBundles(dto);
	console.log("room id:", dto.RoomId, " ranked:", String(dto.RankedEntityId).slice(0, 24));

	// reusable porter note: subroom SaveIds/Hashes — verify + download
	const idx = existsSync(indexFile) ? await loadIndex() : await buildIndex();
	let ok = 0;
	mkdirSync(roomFixtures, { recursive: true });
	const roomsList = [];
	for (const sr of dto.SubRooms) {
		const cs = sr.CurrentSave;
		if (!cs?.DataBlob || !cs?.DataBlobHash) {
			console.log(`  ${sr.Name}: NO CurrentSave blob — client will load its baked scene only`);
			continue;
		}
		const key = cs.DataBlob;
		const blobPath = path.join(roomFixtures, key);
		if (existsSync(blobPath) && sha256b64(readFileSync(blobPath)) === cs.DataBlobHash) {
			console.log(`  ${key}: cached (hash ok)`);
			ok++;
			continue;
		}
		let loc = null;
		try {
			loc = await findBlob(key, idx);
		} catch {
			// blob was never archived (andy_liner's capture is a subset of the live CDN)
			if (strict) {
				throw new Error(`--strict: blob ${key} (${sr.Name}) not found in any shard — aborting`);
			}

			console.log(`  ${sr.Name}: blob ${key} NOT ARCHIVED — preserving CurrentSave metadata`);
			continue;
		}
		process.stdout.write(`  ${key}: from ${loc.shard} ... `);
		const buf = await downloadBlob(loc.shard, loc.zip, key);
		const h = sha256b64(buf);
		if (h !== cs.DataBlobHash) {
			console.log(`✗ sha256 mismatch (have ${h})`);
			roomsList.push(`${key}:HASH-MISMATCH`);
			continue;
		}
		writeFileSync(blobPath, buf);
		console.log(`✓ ${(buf.length / 1024).toFixed(0)} KB`);
		ok++;
	}
	if (roomsList.length) console.log(`! ${roomsList.join(", ")} — sha256 mismatches, registration aborted`);
	else console.log(`✓ ${ok}/${(dto.SubRooms ?? []).length} blobs hash-verified`);
	if (roomsList.length) process.exit(1);
	await attachHolotars(dto);

	// register in rro-rooms.json
	const rroPath = path.join(staticDir, "rro-rooms.json");
	const rro = readJson(rroPath, { rooms: {}, byName: {} });
	const defaults = {
		Roles: [],
		LoadScreens: [],
		Badges: [],
		Tags: [{ Tag: "rro", Type: 2 }],
		BoostCount: 0,
		CurrentSnapshotId: null,
		CCU: null,
		PromoImages: dto.PromoImages ?? [],
		PromoExternalContent: [],
		RestrictedCircuitsAllowListNames: [],
		IsDeveloperOwned: false,
		IsJuniorCreated: false,
	};
	for (const [k, v] of Object.entries(defaults)) if (dto[k] === undefined) dto[k] = v;
	// older snapshots lack fields the client's DTO parser expects; fill them like the modern ones
	if (dto.IsPlacePlay === undefined) dto.IsPlacePlay = false;
	for (const sr of dto.SubRooms ?? []) if (sr.DataSavedAt === undefined) sr.DataSavedAt = null;
	// The client signature-checks load-screen images ("?sig=p1" -> "Signature missing" ->
	// error 8715 kicked to dorm), and our fixture CDN can't forge rec.net signatures — drop
	// the load screens entirely; rooms join without them.
	dto.LoadScreens = [];
	dto.PromoImages = [];
	rro.rooms[String(dto.RoomId)] = dto;
	rro.byName[dto.Name.toLowerCase()] = toRawNumberSafe(dto.RoomId);
	dumpLossless(rro, rroPath);
	console.log(`✓ registered "${dto.Name}" (${dto.RoomId}) in server/static/rro-rooms.json — ${Object.keys(rro.rooms).length} rooms total`);

	// room rows: archive + staffpicks + foryou (read per request, no restart needed)
	const rowsPath = path.join(staticDir, "room-rows.json");
	const rows = readJson(rowsPath, { rows: {}, playlists: {} });
	const id = String(dto.RoomId);
	const push = (slug) => {
		const cur = (rows.rows[slug] ?? []).map((x) => String(x));
		if (!cur.includes(id)) rows.rows[slug] = [...cur, id].slice(-30);
	};
	push("archive");
	push("staffpicks");
	push("foryou");
	writeFileSync(rowsPath, JSON.stringify(rows, null, 1));
	console.log("✓ appended to room rows: archive, staffpicks, foryou");

	console.log(`
RESTART THE EDGE to load the new rro-rooms entry (bulk/door):
  local:  sh /tmp/opencode/edgeup.sh
  VPS:    ssh freebsd@51.38.36.86 'cd ~/UwUNet && git pull origin master -q; pkill -f "[u]wunet-edge.ts"; nohup env UWU_SPAWN=dorm node server/src/uwunet-edge.ts >> edge.log 2>&1 &'`);
}



// node tools/port-room.mjs --studio [RoomName ...] — (re)attach Studio bundles to rooms already
// registered in rro-rooms.json (every room with a UnityAssetId save when none is named).
async function studio(names) {
	const rroPath = path.join(staticDir, "rro-rooms.json");
	const rro = readJson(rroPath, { rooms: {}, byName: {} });
	const want = names.map((n) => n.toLowerCase());
	const rooms = Object.values(rro.rooms).filter((r) =>
		want.length ? want.includes(String(r.Name).toLowerCase()) : (r.SubRooms ?? []).some((sr) => sr.CurrentSave?.UnityAssetId),
	);
	for (const n of want) if (!rooms.some((r) => String(r.Name).toLowerCase() === n)) console.log(`! "${n}" is not registered — port it first`);
	for (const room of rooms) {
		console.log(`→ ${room.Name}`);
		await attachStudioBundles(room);
	}
	dumpLossless(rro, rroPath);
	console.log(`✓ rro-rooms.json updated (${rooms.length} rooms) — RESTART the edge to serve the bundles`);
}

// node tools/port-room.mjs --holotars [RoomName ...] — recover the Holotar recordings of rooms
// already registered (every room when none is named). Files land in server/fixtures/data/,
// served live — no edge restart.
async function holotars(names) {
	const rro = readJson(path.join(staticDir, "rro-rooms.json"), { rooms: {}, byName: {} });
	const want = names.map((n) => n.toLowerCase());
	for (const room of Object.values(rro.rooms)) {
		if (want.length && !want.includes(String(room.Name).toLowerCase())) continue;
		console.log(`→ ${room.Name}`);
		await attachHolotars(room);
	}
}

const args = process.argv.slice(2);
if (args[0] === "--index") await buildIndex();
else if (args[0] === "--index-bundles") await buildBundleIndex(args.slice(1).filter((a, i, all) => a.startsWith("recroom-") && all[i - 1] !== "--jobs"));
else if (args[0] === "--studio") await studio(args.slice(1));
else if (args[0] === "--holotars") await holotars(args.slice(1));
else if (args[0] === "--list-shards") console.log(JSON.stringify(await loadIndex(), null, 1));
else if (args[0]) await port(args[0].replace(/^.*\/room\//, ""));
else {
	console.log("usage: node tools/port-room.mjs <RoomName|rec.net/room/URL>");
	console.log("       node tools/port-room.mjs --index      (re)build the shard index");
	console.log("       node tools/port-room.mjs --list-shards");
	console.log("       node tools/port-room.mjs --index-bundles [shard ...] [--jobs N]   (Studio bundle index)");
	console.log("       node tools/port-room.mjs --studio [RoomName ...]   (attach Studio bundles to registered rooms)");
	console.log("       node tools/port-room.mjs --holotars [RoomName ...] (recover Holotar recordings of registered rooms)");
	process.exit(1);
}
