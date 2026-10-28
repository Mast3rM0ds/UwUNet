#!/usr/bin/env node
// tools/port-room.mjs — the room porter (manual-friendly CLI).
//
//   node tools/port-room.mjs <RoomName>            port a room by its rec.net name
//   node tools/port-room.mjs --index               (re)build the shard blob index
//   node tools/port-room.mjs --list-shards         index progress / coverage report
//
// Pipeline for `<RoomName>`:
//   1. Wayback CDX: find a 200 snapshot of https://rec.net/room/<RoomName>
//   2. Parse the page's Next.js flight payload -> the full RoomDto (16+ subrooms incl.
//      every CurrentSave: SubRoomDataSaveId / DataBlob / DataBlobHash — verbatim live-shape)
//   3. Blob index: map each subroom's DataBlob key to its recroom-cdn-room-files-* shard
//   4. Download every .room blob from archive.org (zip-member extraction) into
//      server/fixtures/room/, VERIFYING sha256 == the recorded DataBlobHash
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

import { readFileSync, writeFileSync, existsSync, mkdirSync, statSync } from "node:fs";
import { execFileSync } from "node:child_process";
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

async function cdTxt(shard, zipName) {
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
  const q = encodeURIComponent("recroom-cdn-room-files");
  const res = await fetch(`https://archive.org/advancedsearch.php?q=${q}&fl[]=identifier&rows=300&output=json`, { headers: { "User-Agent": UA } });
  const ids = (await res.json()).response.docs.map((d) => d.identifier).filter((i) => i.startsWith("recroom-cdn-room-files-"));
  const idx = await loadIndex();
  let done = 0;
  for (const shard of ids) {
    if (idx.shards[shard]) {
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
  try {
    return JSON.parse(readFileSync(p, "utf8"));
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
  const dto = await roomDto(name);
  const image = await fetchImage(dto.ImageName);
  if (image) {
    writeFileSync(path.join(fixturesDir, dto.ImageName), image);
    console.log(`✓ image ${dto.ImageName} (${(image.length / 1024).toFixed(0)} KB) -> server/fixtures/`);
  } else console.log(`! image ${dto.ImageName} not archived — tile will fall back to the generic placeholder`);

  numericizeIds(dto);
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
    const loc = await findBlob(key, idx);
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
  if (ok < (dto.SubRooms ?? []).length) throw new Error(`${ok}/${dto.SubRooms?.length} blobs verified — aborting registration`);
  console.log(`✓ all ${ok} blobs hash-verified`);

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



const args = process.argv.slice(2);
if (args[0] === "--index") await buildIndex();
else if (args[0] === "--list-shards") console.log(JSON.stringify(await loadIndex(), null, 1));
else if (args[0]) await port(args[0].replace(/^.*\/room\//, ""));
else {
  console.log("usage: node tools/port-room.mjs <RoomName|rec.net/room/URL>");
  console.log("       node tools/port-room.mjs --index      (re)build the shard index");
  console.log("       node tools/port-room.mjs --list-shards");
  process.exit(1);
}
