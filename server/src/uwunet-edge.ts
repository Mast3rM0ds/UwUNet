// UwUNet TLS edge — M0/M1. Single TLS server (SNI-routed) impersonating all
// rec.net hostnames plus a plain-HTTP backend. Runs on unpriv ports
// (8443/8460); a netns iptables REDIRECT puts 443/80 traffic here.
//
// Implemented for real: signup/login/token + accounts + version/config.
// Everything else: 503 + logged, so harvest teaches us the real surface.

import tls from "node:tls";
import http from "node:http";
import crypto from "node:crypto";
import { mkdirSync, readFileSync, existsSync, writeFileSync, renameSync, copyFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const DATA = path.join(HERE, "..", "data");
mkdirSync(path.join(DATA, "harvest"), { recursive: true });

// Resolve certs relative to the repo (HERE is <repo>/server) so this works on any
// checkout — dev box or VPS — without a machine-specific hardcoded home path.
const CERT_PATH = process.env.UWU_CERT_DIR ?? path.join(HERE, "..", "certs");
const TLS_PORT = Number(process.env.TLS_PORT ?? 8443);
const HTTP_PORT = Number(process.env.HTTP_PORT ?? 8460);

// ---------------------------------------------------------------- logging
function log(evt: Record<string, unknown>) {
  try {
    appendLog(JSON.stringify({ t: Date.now(), ...evt }) + "\n");
  } catch {}
}
let logBuf = "";
import { appendFileSync } from "node:fs";
function appendLog(line: string) {
  logBuf += line;
  if (logBuf.length > 4096) flushLog();
}
function flushLog() {
  if (logBuf) {
    try {
      appendFileSync(path.join(DATA, "harvest", "requests.jsonl"), logBuf);
    } catch {}
    logBuf = "";
  }
}

// ---------------------------------------------------------------- storage
type User = {
  Id: string; // canonical positive base-10 integer (RecNet account id), stored as string
  Username: string;
  DisplayName: string;
  Email?: string;
  PwHashB64: string;
  SaltB64: string;
  Created: string;
  AgeFlagged?: boolean;
  PlatformType?: string; // "0" = Steam
  PlatformId?: string;   // SteamID64 etc.
};
// A friend-graph edge from one player's point of view: type 0=none, 1=request sent, 2=request
// received, 3=friends; fav/ign/mut are that player's own 0/1 flags toward the other.
type Rel = { type: number; fav: number; ign: number; mut: number };
type Db = {
  users: Record<string, User>;
  refresh: Record<string, string>;
  nextId?: number;
  // relationships[a][b] = a's edge toward b. Stored on both sides so each player's /get is a
  // direct lookup and each keeps their own flags.
  relationships?: Record<string, Record<string, Rel>>;
  // Per-account worn outfit (slot 0), the body the client PUTs to /outfits/me. Persisted so an
  // avatar survives an edge restart (it used to live in an in-memory map → reverted to default
  // on every deploy/reboot).
  outfits?: Record<string, Record<string, unknown>>;
};
const DB_FILE = path.join(DATA, "uwunet.db.json");
function loadDb(): Db {
  // Try the live file, then the last-good backup. A valid DB must be an object with `users`,
  // so a truncated/partial file (which parses to something else, or not at all) is rejected.
  for (const f of [DB_FILE, `${DB_FILE}.bak`]) {
    if (!existsSync(f)) continue;
    try {
      const parsed = JSON.parse(readFileSync(f, "utf8"));
      if (parsed && typeof parsed === "object" && parsed.users) return parsed as Db;
    } catch {}
  }
  // A DB file exists but neither it nor its backup is usable: set it aside instead of letting
  // the next save overwrite it with an empty DB. This is how a claimed account was lost once —
  // never silently discard accounts.
  if (existsSync(DB_FILE)) {
    try { renameSync(DB_FILE, `${DB_FILE}.corrupt-${Date.now()}`); } catch {}
  }
  return { users: {}, refresh: {}, nextId: 1000000, relationships: {}, outfits: {} };
}
// RecNet account ids are integers; allocate sequentially (stored as a string).
function allocAccountId(): string {
  const id = db.nextId ?? 1000000;
  db.nextId = id + 1;
  return String(id);
}
const db = loadDb();
if (!db.outfits) db.outfits = {}; // field added later; back-fill for DBs saved before it existed
function saveDb() {
  // Atomic save: write a temp file, snapshot the current good DB to .bak, then rename the temp
  // over the live file. A crash at any point leaves either the old DB or the full new one — never
  // a half-written file that loadDb would reject (and then clobber with an empty DB).
  try {
    const tmp = `${DB_FILE}.tmp`;
    writeFileSync(tmp, JSON.stringify(db, null, 1));
    try { if (existsSync(DB_FILE)) copyFileSync(DB_FILE, `${DB_FILE}.bak`); } catch {}
    renameSync(tmp, DB_FILE);
  } catch {}
}

// ---------------------------------------------------------------- crypto
import { pbkdf2Sync } from "node:crypto";
function hashPw(pw: string, salt: Buffer): string {
  return pbkdf2Sync(pw, salt, 120_000, 32, "sha256").toString("base64");
}
function newToken(kind: "at" | "rt", userId: string): string {
  // Compact self-contained token: kind.expiry64.userIdB64.sig
  const payload = `${kind}.${Date.now() + (kind === "at" ? 3_600_000 : 2_592_000_000)}.${userId}`;
  const body = Buffer.from(payload).toString("base64url");
  const sig = crypto
    .createHmac("sha256", process.env.UWU_SECRET ?? "uwunet-dev-secret")
    .update(body)
    .digest("base64url");
  return `${body}.${sig}`;
}
// --- RecNet access token: real HS256 JWT (the client decodes sub/role/scope
// and rejects a token that is only `sub` or non-integer). Mirrors the reference's
// generateToken claim set. ---
const UWU_SECRET = process.env.UWU_SECRET ?? "uwunet-dev-secret";
const TOKEN_TTL = 86400;
const TOKEN_SCOPES = [
  "profile", "rn", "rn.accounts", "rn.accounts.gc", "rn.api", "rn.chat",
  "rn.clubs", "rn.commerce", "rn.match.read", "rn.match.write", "rn.notify",
  "rn.rooms", "rn.storage", "offline_access",
];
const TOKEN_SCOPE_STR =
  "offline_access profile rn rn.accounts rn.accounts.gc rn.api rn.chat rn.clubs rn.commerce rn.match.read rn.match.write rn.notify rn.rooms rn.storage";
const BASE_ROLES = ["gameClient"];
// "God" accounts: full staff powers — developer + moderator + screenshare roles (in the token
// and answered by the /role/* lookups the client gates its dev UI on), maker pen and every
// build permission in every room, and Rec Room Plus. Configured via UWU_GOD_IDS (comma-
// separated account ids); defaults to 1000000, the owner's account. These are the operator's
// own accounts, so the grant is deliberate.
const godIds = new Set<number>(
  (process.env.UWU_GOD_IDS ?? "1000000")
    .split(",")
    .map((s) => Number.parseInt(s.trim(), 10))
    .filter((n) => Number.isInteger(n)),
);
const GOD_ROLES = ["developer", "moderator", "screenshare"];
const isGod = (id: number | string) => godIds.has(Number(id));
// Staff roles (developer/moderator/screenshare) are SEPARATE from the maker-pen grant and OFF
// by default. They ride in the access token and the /role lookups the client gates its dev/mod
// UI on — but a client that believes it is staff calls dev/mod endpoints during CONNECTION that
// this edge does not fully serve yet, which fails login ("failed to connect to RecNet"). So
// staff is opt-in via UWU_STAFF_IDS, to be enabled only once verified not to break the boot.
// Maker-pen-everywhere (isGod) is safe on its own (it is read at room load) and stays on.
const staffIds = new Set<number>(
  (process.env.UWU_STAFF_IDS ?? "")
    .split(",")
    .map((s) => Number.parseInt(s.trim(), 10))
    .filter((n) => Number.isInteger(n)),
);
const isStaff = (id: number | string) => staffIds.has(Number(id));
const b64urlJson = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
function signJwt(claims: Record<string, unknown>): string {
  const data = `${b64urlJson({ alg: "HS256", typ: "JWT" })}.${b64urlJson(claims)}`;
  const sig = crypto.createHmac("sha256", UWU_SECRET).update(data).digest("base64url");
  return `${data}.${sig}`;
}
function mintAccessToken(u: User, ver: string): string {
  const now = Math.floor(Date.now() / 1000);
  const plat = Number(u.PlatformType ?? 0);
  const claims: Record<string, unknown> = {
    iss: "https://auth.rec.net",
    aud: "https://auth.rec.net",
    nbf: now,
    iat: now,
    exp: now + TOKEN_TTL,
    auth_time: now,
    amr: "cached_login",
    client_id: "recroom",
    sub: u.Id,
    idp: "local",
    platform: plat,
    platform_id: u.PlatformId ?? "",
    "rn.ver": ver,
    "rn.plat": plat,
    role: isStaff(u.Id) ? [...BASE_ROLES, ...GOD_ROLES] : [...BASE_ROLES],
    scope: TOKEN_SCOPES,
    jti: crypto.randomUUID(),
  };
  // rn.plus is only added for staff accounts: a non-staff token stays byte-for-byte the known-
  // good shape (no rn.plus key at all), which is what the client booted fine with before.
  if (isStaff(u.Id)) claims["rn.plus"] = true;
  return signJwt(claims);
}

type Token = { kind: string; exp: number; userId: string };
function verifyToken(t?: string): Token | null {
  if (!t) return null;
  const parts = t.split(".");
  if (parts.length === 3) {
    // HS256 JWT (our access token)
    const data = `${parts[0]}.${parts[1]}`;
    const sig = crypto.createHmac("sha256", UWU_SECRET).update(data).digest("base64url");
    if (sig !== parts[2]) return null;
    try {
      const claims = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
      const exp = Number(claims.exp) * 1000;
      if (Number.isFinite(exp) && exp < Date.now()) return null;
      return { kind: "at", exp, userId: String(claims.sub) };
    } catch {
      return null;
    }
  }
  if (parts.length !== 2) return null;
  const body = parts[0];
  const sig = crypto
    .createHmac("sha256", process.env.UWU_SECRET ?? "uwunet-dev-secret")
    .update(body)
    .digest("base64url");
  if (sig !== parts[1]) return null;
  let payload: string;
  try {
    payload = Buffer.from(body, "base64url").toString("utf8");
  } catch {
    return null;
  }
  const [kind, exp, userId] = payload.split(".");
  if (Number(exp) < Date.now()) return null;
  return { kind, exp: Number(exp), userId };
}

// ---------------------------------------------------------------- accounts
function accountJson(u: User) {
  return {
    Id: u.Id,
    Username: u.Username,
    DisplayName: u.DisplayName,
    Email: u.Email ?? null,
    Created: u.Created,
    IsTwoFactorEnabled: false,
    TierIndex: 0,
    AccountFlags: [],
    IsConfirmed: true,
    IsAdultAccount: true,
    AgeFlagged: false,
  };
}

// RecNet public account DTO (camelCase) — the shape the game client parses for
// bulk/account lookups. Mirrors the reference's toAccountDto. Numeric fields are
// NUMBERS (accountId/platforms/pronouns/identityFlags) — the client's strict
// reader throws on a quoted number.
function accountDto(u: User) {
  return {
    accountId: Number(u.Id),
    username: u.Username,
    displayName: u.DisplayName,
    profileImage: "DefaultProfileImage.jpg",
    bannerImage: "",
    displayEmoji: "",
    isJunior: false,
    platforms: 0,
    personalPronouns: 0,
    identityFlags: 0,
    createdAt: u.Created,
  };
}
// Synthesized account for an id we don't have — so every requested id is present.
function defaultAccountDto(id: number) {
  return {
    accountId: id,
    username: `Player${id}`,
    displayName: `Player${id}`,
    profileImage: "DefaultProfileImage.jpg",
    bannerImage: "",
    displayEmoji: "",
    isJunior: false,
    platforms: 0,
    personalPronouns: 0,
    identityFlags: 0,
    createdAt: new Date().toISOString(),
  };
}
// Private self DTO (/account/me): public DTO + owner-only fields. juniorState/
// parentAccountId omitted (null makes the client's enum parser throw).
function selfAccountDto(u: User) {
  return {
    ...accountDto(u),
    email: u.Email ?? "",
    birthday: "1904-01-01T00:00:00.000Z",
    availableUsernameChanges: 1,
  };
}
const userById = (id: number) =>
  Object.values(db.users).find((u) => Number(u.Id) === id) ?? null;

// ---------------------------------------------------------------- routing
type Ctx = {
  req: http.IncomingMessage;
  res: http.ServerResponse;
  path: string;
  query: URLSearchParams;
  body: string;
  authUser: User | null;
  send: (status: number, obj: unknown) => void;
  // Zero-length 200 body (the reference's `c.body(null, 200)`). The client treats an empty body as
  // a void/success ack; a `{}` here is parsed as a typed object and fails ("Malformed '{}'").
  empty: () => void;
};

type Handler = (ctx: Ctx) => Promise<void> | void;

const routes: Array<{ method: string; re: RegExp; h: Handler }> = [];

function route(method: string, pattern: string, h: Handler) {
  const re = new RegExp(
    "^" +
      pattern
        // NOTE: must NOT escape { } here — doing so turned "{roomId}" into "\{roomId\}",
        // which the next replace (/\{(\w+)\}/) could no longer match, so every {param}
        // route compiled to a literal path and 404'd (static and ** routes were unaffected).
        .replace(/[.+?^$()|[\]\\]/g, "\\$&")
        .replace(/\{(\w+)\}/g, "([^/]+)")
        .replace(/\*\*/g, ".*") +
      "$",
  );
  routes.push({ method, re, h });
  console.error(`[uwunet] route: ${method} ${pattern}`);
}

// --- system / boot-gating endpoints ---
route("GET", "/health", (c) =>
  c.send(200, { ok: true, net: "UwUNet", ts: Date.now() }),
);

const PAGE = `<!doctype html><html><head><meta charset=utf-8><title>UwUNet</title>
<style>
body{font-family:system-ui;background:#17122b;color:#e8e2ff;display:flex;justify-content:center;padding-top:8vh;margin:0}
main{max-width:420px;width:100%;padding:24px;border-radius:16px;background:#221a3f;box-shadow:0 8px 40px rgba(0,0,0,.4)}
h1{margin:0 0 4px;font-size:28px}h1 span{color:#7b5cff}
p.sub{margin:0 0 20px;color:#a99fd0;font-size:13px}
label{display:block;margin:12px 0 4px;font-size:12px;color:#a99fd0;text-transform:uppercase;letter-spacing:.08em}
input{width:100%;box-sizing:border-box;padding:10px;border-radius:8px;border:1px solid #463a7a;background:#17122b;color:#fff;font-size:15px}
button{width:100%;margin-top:16px;padding:12px;border:0;border-radius:8px;background:linear-gradient(90deg,#7b5cff,#b45cff);color:#fff;font-size:15px;font-weight:600;cursor:pointer}
button.ghost{background:transparent;border:1px solid #463a7a;margin-top:8px}
#out{margin-top:14px;font-size:13px;color:#ff9a9a;min-height:18px;white-space:pre-wrap}
#ok{color:#8fffb0}
#tok{word-break:break-all;color:#a99fd0;font-size:11px}
</style></head><body><main>
<h1>UwU<span>Net</span></h1>
<p class=sub>claim your account &mdash; give yourself a real username &amp; password. keep it kind.</p>
<form onsubmit="return doClaim(event)">
<label>your current in-game name (or SteamID)</label><input id=who required placeholder="Player1000000">
<label>choose a username</label><input id=u required pattern="[A-Za-z0-9_\-]{3,20}" placeholder="3-20: letters, numbers, _ -">
<label>password (8+ chars)</label><input id=p type=password required minlength=8>
<label>current password (only if you claimed before)</label><input id=cp type=password>
<button>claim account</button>
</form><div id=out></div>
<p class=sub style="margin-top:16px">open Rec Room once first so your account exists &mdash; it shows your current name (Player&hellip;). enter that here, pick a username, then relaunch.</p></main>
<script>
const out=document.getElementById('out');
async function doClaim(e){e.preventDefault();out.textContent='working...';out.id='';
  const r=await fetch('/uwunet/claim',{method:'POST',headers:{'content-type':'application/json'},
    body:JSON.stringify({account:who.value.trim(),username:u.value.trim(),password:p.value,currentPassword:cp.value})});
  const j=await r.json().catch(()=>({}));
  if(!r.ok){out.textContent=j.Error||('error '+r.status);out.id='';return false}
  out.id='ok';out.textContent='done! you are now '+j.username+'. relaunch Rec Room to see your new name.';return false}
</script></body></html>`;

// RecNet nameserver service-discovery map. GET ns.rec.net/ returns this so the
// client learns every service host. We advertise the real *.rec.net subdomains;
// uwudns64 funnels them all to this one edge. Mirrors the reference server apps/ns.
const NS_SUBDOMAINS: Record<string, string> = {
  Accounts: "accounts", AI: "ai", API: "api", Auth: "auth",
  BugReporting: "bugreporting", Cards: "cards", CDN: "cdn", Chat: "chat",
  Clubs: "clubs", CMS: "cms", Commerce: "commerce", Data: "data",
  DataCollection: "datacollection", Discovery: "discovery", Econ: "econ",
  GameLogs: "gamelogs", Geo: "geo", Images: "img", Leaderboard: "leaderboard",
  Link: "link", Lists: "lists", Matchmaking: "match", Moderation: "moderation",
  Notifications: "notify", PlatformNotifications: "platformnotifications",
  PlayerSettings: "playersettings", RoomComments: "roomcomments",
  RoomieIntegrations: "roomieintegrations", Rooms: "rooms", Storage: "storage",
  Strings: "strings", StringsCDN: "strings-cdn", Studio: "studio",
  Thorn: "thorn", Videos: "videos", WWW: "www",
};
const NS_DOMAIN = process.env.UWU_NS_DOMAIN ?? "rec.net";
const nsEndpoints = Object.fromEntries(
  Object.entries(NS_SUBDOMAINS).map(([label, sub]) => [
    label,
    `https://${sub}.${NS_DOMAIN}`,
  ]),
);

route("GET", "/", (c) => {
  // The game client fetches the endpoints doc here (JSON); a browser gets the
  // human signup page. Negotiate on Accept so both work on the same host.
  const accept = String(c.req.headers.accept ?? "");
  if (accept.includes("text/html")) {
    c.res.setHeader("content-type", "text/html; charset=utf-8");
    c.res.writeHead(200);
    c.res.end(PAGE);
    return;
  }
  c.send(200, nsEndpoints);
});

// Static config bodies for build 20250718.01 (see server/static/README.md).
// 64-bit ids defeat JS numbers: JSON.parse (and Number) round ports ids like 649924194922273060
// to ...280, so a room parsed, held and re-serialized by this edge is NEVER byte-exact and the
// client's id-typed fields (RoomId/SubRoomId, strict longs) reject or mismatch it ("room doesn't
// exist"). Policy: EVERY 16+ digit integer literal in a static file loads wrapped as a
// "__BIG__<digits>__" sentinel string (quoteBigLiterals), travels through the edge untouched,
// and send() unquotes it back to a raw digit literal on the wire. Any id comparison/on the edge
// canonicalizes both sides through unwrapId. Anything < 16 digits parses as a plain number.
const STATIC = path.join(HERE, "static");
const unwrapId = (s: string): string => s.replace(/__BIG__(\d+)__/g, "$1");
const quoteBigLiterals = (txt: string): string => {
  let out = "";
  let inStr = false;
  let esc = false;
  let i = 0;
  while (i < txt.length) {
    const ch = txt[i];
    if (inStr) {
      out += ch;
      if (esc) esc = false;
      else if (ch === "\\") esc = true;
      else if (ch === '"') inStr = false;
      i++;
    } else if (ch === '"') {
      inStr = true;
      out += ch;
      i++;
    } else if (ch >= "0" && ch <= "9") {
      let j = i;
      while (j < txt.length && txt[j] >= "0" && txt[j] <= "9") j++;
      const digits = txt.slice(i, j);
      out += digits.length >= 16 ? `"__BIG__${digits}__"` : digits;
      i = j;
    } else {
      out += ch;
      i++;
    }
  }
  return out;
};
const readStatic = (name: string, fallback: unknown): unknown => {
  try {
    return JSON.parse(quoteBigLiterals(readFileSync(path.join(STATIC, name), "utf8")));
  } catch {
    return fallback;
  }
};
const configV2 = readStatic("api-config-v2.json", {});
const gameConfigs2025 = readStatic("gameconfigs-v1-all-2025.json", []);

// Default avatar-item catalog, projected into the client's camelCase v4 DTO
// (toAvatarItemV4). GET /api/avatar/v4/items returns owned items + this catalog;
// the client NEEDS it to resolve the default avatar (empty [] -> "Failed to
// parse avatar data! / Expected LegacyData but was null" -> login code: doll).
const str = (v: unknown) => (typeof v === "string" ? v : "");
const num = (v: unknown) => (typeof v === "number" ? v : 0);
const toAvatarItemV4 = (item: Record<string, unknown>) => ({
  avatarItemId: num(item.AvatarItemId),
  avatarItemDesc: str(item.AvatarItemDesc),
  friendlyName: str(item.FriendlyName),
  tooltip: str(item.Tooltip),
  tagList: str(item.TagList),
  avatarItemType: num(item.AvatarItemType),
  rarity: num(item.Rarity),
  isBaseAvatarItem: item.IsBaseAvatarItem === true,
});
const avatarV4Catalog = (readStatic("default-avatar-items.json", []) as Record<string, unknown>[])
  .map(toAvatarItemV4);
// The real default-avatar custom items (the client's hardcoded default hair set),
// pulled from a live RecNet-compatible server. customAvatarItems/v1/bulk resolves
// the client's fixed GUID set to these; returning [] instead makes the client's
// avatar parser throw "Expected LegacyData but was null" and fail login.
const defaultCustomItems = readStatic("default-custom-avatar-items.json", []) as Array<
  Record<string, unknown>
>;
const customItemsById = new Map(
  defaultCustomItems.map((it) => [String(it.CustomAvatarItemId), it]),
);
// The default worn avatar (valid OutfitSelections + FaceFeatures). A fresh account
// gets this from outfits/me so the client can build an avatar; the empty envelope
// (OutfitSelections:"") fails the parse ("Expected LegacyData but was null").
const defaultAvatar = readStatic("default-avatar.json", {
  OutfitSelections: "",
  FaceFeatures: "",
  SkinColor: "",
  HairColor: "",
});

const DORM_SCENE = "76d98498-60a1-430c-ab76-b54a29b7a163"; // base sandbox/dorm scene
// The CANONICAL dorm template: the reference's room 1 (DORM_TEMPLATE_ROOM_ID), fetched live from
// the reference API/rooms/1 — the exact empty-dorm RoomDto real clients accept. getOrCreate-
// DormRoom clones this per account. We spread it and override ONLY the identity fields, so the
// whole shape (ImageName "DormRoom.jpg", CurrentSave: null, no subroom blobs, every flag) is
// verbatim what the client's strict parser expects. Hand-built variants all failed "Malformed
// Response"; this one matches a known-good room byte-for-byte except identity.
const roomTemplate = readStatic("room-template.json", {}) as Record<string, unknown>;
const templateSubRoom = (Array.isArray(roomTemplate.SubRooms) && roomTemplate.SubRooms[0]) || {};
// Orientation (room 13) is a PUBLIC system room, identical for every account, so we serve
// the reference's live /rooms/13?include=767277 body verbatim rather than mangling the dorm template.
// This eliminated the room-DTO as a suspect for the `Enumerable.First` abort during room-load:
// the dorm template had IsSandbox:true on its subroom (orientation's is false), which makes the
// client load the maker-pen/circuit/save path and `.First()` an empty save/circuit collection.
const orientationRoomStatic = readStatic("orientation-room.json", {}) as Record<string, unknown>;

// Rec Room first-party rooms (RROs) + the Rec Center: metadata only (room id, name, the baked
// Unity scene GUID, capacity) from the reference's public room data — no copyrighted room build.
// The interactive save layer is nulled: the client loads the baked scene it already ships, so
// 24 of the 27 RROs (which have no save on the reference either) play exactly as Rec Room did.
// Serving these lets the client resolve, list and matchmake into every RRO and the Rec Center.
const rroData = readStatic("rro-rooms.json", { rooms: {}, byName: {} }) as {
  rooms: Record<string, Record<string, unknown>>;
  byName: Record<string, number>;
};
const rroRoomById = (id: number | string): Record<string, unknown> | undefined => rroData.rooms[unwrapId(String(id))];
const rroRoomIdByName = (name: string): number | string | undefined => rroData.byName[name.toLowerCase()];

// RRO ownership: make one account the Creator/owner of every first-party room, so they show
// as that player's rooms and that account can manage/build them. Resolved from the DB by
// username or display name (default "sonakrie"), or forced with UWU_RRO_OWNER_ID. Applied to
// the loaded RRO data in place at startup — restart the edge once the account exists.
const RRO_OWNER_NAME = (process.env.UWU_RRO_OWNER ?? "UwUArchivist").toLowerCase();
const rroOwnerId: number | null = (() => {
  const envId = Number(process.env.UWU_RRO_OWNER_ID);
  if (Number.isInteger(envId) && envId > 0) return envId;
  const u = Object.values(db.users).find(
    (x) => x.Username?.toLowerCase() === RRO_OWNER_NAME || x.DisplayName?.toLowerCase() === RRO_OWNER_NAME,
  );
  return u ? Number(u.Id) : null;
})();
if (rroOwnerId !== null) {
  for (const room of Object.values(rroData.rooms)) {
    room.CreatorAccountId = rroOwnerId;
    room.Roles = [{ AccountId: rroOwnerId, Role: 255, LastChangedByAccountId: null, InvitedRole: 0 }];
    for (const sr of Array.isArray(room.SubRooms) ? (room.SubRooms as Record<string, unknown>[]) : []) {
      sr.CreatorAccountId = rroOwnerId;
    }
  }
  console.log(`[uwunet] RRO owner -> account ${rroOwnerId} ("${RRO_OWNER_NAME}") on all ${Object.keys(rroData.rooms).length} first-party rooms`);
} else {
  console.log(`[uwunet] RRO owner "${RRO_OWNER_NAME}" not found in DB — RROs keep original ownership (set UWU_RRO_OWNER or UWU_RRO_OWNER_ID)`);
}
// An RRO's first subroom, as matchmaking needs it (scene = the baked UnitySceneId).
// Ids stay STRINGS end to end: ported room/subroom ids exceed 2^53 and Number round-trips
// corrupt them.
const rroSubRoom = (
  id: number | string,
): { subRoomId: string; scene: string; name: string; maxCapacity: number } | undefined => {
  const dto = rroRoomById(id);
  if (!dto) return undefined;
  const sr = ((Array.isArray(dto.SubRooms) ? (dto.SubRooms as Record<string, unknown>[])[0] : undefined) ??
    {}) as Record<string, unknown>;
  return {
    subRoomId: sr.SubRoomId !== undefined ? unwrapId(String(sr.SubRoomId)) : "1",
    scene: typeof sr.UnitySceneId === "string" ? (sr.UnitySceneId as string) : "",
    name: typeof dto.Name === "string" ? (dto.Name as string) : `Room${id}`,
    maxCapacity: typeof sr.MaxPlayers === "number" ? (sr.MaxPlayers as number) : 16,
  };
};
// A first-party subroom's published save (CurrentSave), by room + subroom id. Only the RROs
// with a baked interactive save carry one (MakeItToMidnight et al.); the other 24 are null.
const rroSubRoomSave = (
  roomId: number | string,
  subRoomId: number | string,
): Record<string, unknown> | undefined => {
  const dto = rroRoomById(roomId);
  if (!dto || !Array.isArray(dto.SubRooms)) return undefined;
  const sr = (dto.SubRooms as Record<string, unknown>[]).find((s) => unwrapId(String(s.SubRoomId)) === unwrapId(String(subRoomId)));
  const save = sr?.CurrentSave;
  return save && typeof save === "object" ? (save as Record<string, unknown>) : undefined;
};
// The save-detail projection (SubRoomDataSaveDetailDto) the client awaits before downloading the
// scene blob. Field names, casing and ORDER mirror the reference's toSaveDetail exactly — a
// missing/extra/mis-cased field is a fatal "Malformed Response" and the room won't load. The main
// bundle is lifted to top-level UnityAsset; UnitySubAssets are the dependency bundles only
// (filtered to the caller's target), which our maker-pen RROs don't carry, so [] in practice. The
// load-bearing fields are DataBlob (the /room/{blob} scene key) + DataBlobHash.
const subRoomSaveDetail = (
  save: Record<string, unknown>,
  target: number,
): Record<string, unknown> => {
  const subAssets = (Array.isArray(save.UnitySubAssets) ? (save.UnitySubAssets as Record<string, unknown>[]) : [])
    .filter((a) => Number(a.Target ?? 0) === target)
    .map((a) => ({
      UnityAssetId: (a.UnityAssetId as string) ?? null,
      UnityAsset: (a.Filename as string) ?? (a.UnityAsset as string) ?? null,
      UnityAssetHash: (a.Hash as string) ?? (a.UnityAssetHash as string) ?? null,
    }));
  const mainAsset = (save.UnityAsset as string) ?? null;
  // A save that names a Unity asset (UnityAssetId) the client must load as an asset bundle, yet
  // for which we serve NO bundle (no main UnityAsset, no UnitySubAssets), is an impossible state
  // the live service never sent: the client tries to resolve that asset, finds none, and aborts
  // the room load (error 8715) BEFORE it ever downloads the scene DataBlob. Our first-party saves
  // are maker-pen content carried entirely by DataBlob on the baked UnitySceneId, so when we can't
  // back the asset we don't advertise it — null the id (key stays, matching the reference's
  // maker-pen shape) so the client loads the baked scene + DataBlob only.
  const assetBacked = subAssets.length > 0 || mainAsset !== null;
  return {
    UnitySubAssets: subAssets,
    ReferencedUnityAssets: [],
    UnityAsset: mainAsset,
    UnityAssetHash: (save.UnityAssetHash as string) ?? null,
    SubRoomDataSaveId: Number(save.SubRoomDataSaveId) || 0,
    SubRoomId: Number(save.SubRoomId) || 0,
    UnityAssetId: assetBacked ? ((save.UnityAssetId as string) ?? null) : null,
    ReferencedUnityAssetIds: assetBacked && Array.isArray(save.ReferencedUnityAssetIds) ? save.ReferencedUnityAssetIds : [],
    DataBlob: (save.DataBlob as string) ?? null,
    DataBlobHash: (save.DataBlobHash as string) ?? null,
    PersistenceVersion: Number(save.PersistenceVersion) || 0,
    OMVersion: Number(save.OMVersion) || 0,
    SavedByAccountId: save.SavedByAccountId ?? null,
    SavedOnPlatform: Number(save.SavedOnPlatform) || 0,
    SavedOnDeviceClass: Number(save.SavedOnDeviceClass) || 0,
    Description: typeof save.Description === "string" ? save.Description : "",
    ModerationState: Number(save.ModerationState) || 0,
    CreatedAt: typeof save.CreatedAt === "string" ? save.CreatedAt : "",
    UgcSubVersion: Number(save.UgcSubVersion) || 0,
  };
};
// The RRO DTOs as a browse list — every first-party room except the Orientation tutorial
// (room 13 is new-user-only, not a place you browse to). Used by the hot feed and search.
const rroDtoList = (): Record<string, unknown>[] =>
  Object.entries(rroData.rooms)
    .filter(([id]) => Number(id) !== 13)
    .map(([, dto]) => dto);
// A discovery row's RRO ids, from static/room-rows.json `rows` (editorial: nothing ranks
// here; read per request, so editing it needs no restart). Keyed by the row slug folded to
// lowercase (the reference lists.app.ts ROW_FEEDS). "*" = every browsable RRO. Unknown key →
// undefined. Ids that are not RROs are DROPPED — roomDtoFor() would otherwise synthesize a
// dorm for them when the client resolves the row through /rooms/bulk.
// Ids may be NUMBER or STRING — ported room ids exceed 2^53 (the client's 64-bit RoomIds)
// and MUST survive untouched; they resolve through rroRoomById(String(id)). Anything else
// is DROPPED — roomDtoFor() would otherwise synthesize a dorm when the row lands on the
// client through /rooms/bulk.
const roomRowIds = (key: string): string[] | undefined => {
  const f = readStatic("room-rows.json", {}) as { rows?: Record<string, unknown> };
  const v = f.rows?.[key.toLowerCase()];
  if (v === "*") return rroDtoList().map((d) => String(d.RoomId));
  if (!Array.isArray(v)) return undefined;
  return v
    .map((x) => (typeof x === "number" || typeof x === "string" ? String(x) : ""))
    .filter((id) => id !== "" && rroRoomById(id) !== undefined);
};
const dormRoomDto = (id: number, username: string) => ({
  ...roomTemplate,
  RoomId: id,
  Name: `@${username}'s Dorm`,
  CreatorAccountId: id,
  RankedEntityId: String(id),
  Stats: { CheerCount: 0, FavoriteCount: 0, VisitorCount: 0, VisitCount: 0 },
  Roles: [{ AccountId: id, Role: 255, LastChangedByAccountId: null, InvitedRole: 0 }],
  // CurrentSave stays null (template default) = built-in empty dorm, no content download.
  SubRooms: [{ ...templateSubRoom, RoomId: id, CreatorAccountId: id }],
});

// versioncheck/v4: the boot's "connect to RecNet" step needs a real 200 here
// (404 -> "Failed to connect to RecNet"). This shape was accepted (no
// "Malformed Response"); keep it.
route("GET", "/api/versioncheck/v4", (c) => {
  // the reference's live shape (recorded from a real patched-client boot): a bare
  // status object. The old ClientForceUpgrade shape was never accepted by the
  // 2025 client's parser.
  c.send(200, {
    VersionStatus: 0,
    UpdateNotificationStage: 0,
    IsVersionIslanded: false,
    IsCrossPlayDisabled: false,
  });
});

// islandedversions: the {IslandedVersions:[]} wrapper threw "Malformed
// Response" in the client. It expects the bare list.
route("GET", "/api/versioncheck/islandedversions", (c) => {
  c.send(200, []);
});

// Cached logins for a platform id (Steam/Meta). The client auto-login-probes
// its platform id here at boot; a 404 is fatal ("Failed to load Rec Room
// accounts"). Return the accounts linked to this platform id — [] when none,
// which sends the client to a fresh login / create-account instead of erroring.
// GET (older builds) and POST (2025 build posts deviceId/platformAuth/time,
// which we accept and ignore). Shape per the reference: CachedLogin[].
const cachedLoginHandler = (c: Ctx) => {
  const parts = c.path.split("/");
  const platform = parts[3] ?? "0";
  const platformId = parts[4] ?? "";
  const linked = Object.values(db.users).filter(
    (u) => u.PlatformType === platform && u.PlatformId === platformId,
  );
  c.send(
    200,
    linked.map((u) => ({
      platform: Number(platform),
      platformId,
      accountId: Number(u.Id), // client's parser wants a Number token here
      lastLoginTime: u.Created,
      requirePassword: false,
    })),
  );
};
route("GET", "/cachedlogin/forplatformid/**", cachedLoginHandler);
route("POST", "/cachedlogin/forplatformid/**", cachedLoginHandler);

// EAC challenge stub — anti-cheat isn't implemented; the client's handshake
// just needs a JSON-quoted string back as text/plain.
route("GET", "/eac/challenge", (c) => {
  c.res.setHeader("content-type", "text/plain; charset=utf-8");
  c.res.writeHead(200);
  c.res.end(`"AA=="`);
});

route("GET", "/api/config/v2", (c) => {
  // Empty {} crashes the client's Utf8Json reader — serve the real shape.
  c.send(200, configV2);
});

route("GET", "/api/gameconfigs/v1/all", (c) => {
  c.send(200, gameConfigs2025);
});

// --- auth: real signup/login ---
const readAuthHeader = (c: Ctx) => {
  const h = c.req.headers.authorization;
  if (!h?.startsWith("Bearer ")) return null;
  return verifyToken(h.slice(7));
};

async function parseBodyJson(c: Ctx): Promise<Record<string, unknown>> {
  try {
    return JSON.parse(c.body || "{}");
  } catch {
    // x-www-form-urlencoded fallback (OAuth style)
    try {
      return Object.fromEntries(new URLSearchParams(c.body));
    } catch {
      return {};
    }
  }
}

// RecNet game-client token endpoint: POST /connect/token (auth.rec.net), form-
// encoded. The 20250718 client auto-logs-in here at boot. With no cached account
// it posts grant_type=create_account (platform=0 Steam, platform_id=SteamID64,
// platform_auth={Ticket,AppId}); we mint an account bound to that platform id and
// return a RecNet token body (access_token = HS256 JWT). The Steam ticket is
// accepted and not verified (single-operator revival — ownership isn't gated here).
route("POST", "/connect/token", async (c) => {
  const b = await parseBodyJson(c);
  const grant = String(b.grant_type ?? b.grantType ?? "");
  const ver = String(b.ver ?? "20250718.01");
  log({ event: "token", grant, platform: b.platform, platform_id: b.platform_id });

  const issue = (u: User, created: boolean) => {
    // Seed the Orientation (-2) presence at the EARLIEST auth point: the client calls GET
    // /player/connection-info right after /connect/token (before /player/login), and that
    // response's photonRoomId/region come from the stored presence. Without the seed here it
    // returned photonRoomId:"" and the client had no room to connect Photon to. the reference seeds
    // this at account creation; we seed on any token issue if there's no live presence yet.
    const uid = Number(u.Id);
    // Record the client-reported deviceClass (screen/PC = 2) so the heartbeat echoes it and
    // presence stays in sync. Default 0 only when the client sends nothing.
    const dc = Number(b.device_class ?? b.deviceClass ?? 0);
    deviceClassById.set(uid, Number.isFinite(dc) ? dc : 0);
    if (!presenceById.has(uid)) presenceById.set(uid, defaultSpawnInstance(uid));
    const at = mintAccessToken(u, ver);
    const rt = newToken("rt", u.Id);
    db.refresh[rt] = u.Username.toLowerCase();
    saveDb();
    c.send(200, {
      access_token: at,
      expires_in: TOKEN_TTL,
      token_type: "Bearer",
      refresh_token: rt,
      scope: TOKEN_SCOPE_STR,
      key: "8oQ+e+WQaOBPbEcakhqs3dwZZdOmmyDUmJSD9u4AHMY=",
      ...(created ? { created: true } : {}),
    });
  };

  if (grant === "create_account" || grant === "cached_login") {
    const platform = String(b.platform ?? "0");
    const platformId = String(b.platform_id ?? b.platformId ?? "");
    const wantId = b.account_id != null ? String(b.account_id) : null;
    // Prefer the posted account id (cached_login), else the platform identity.
    let u =
      (wantId && Object.values(db.users).find((x) => x.Id === wantId)) ||
      Object.values(db.users).find(
        (x) => x.PlatformType === platform && x.PlatformId === platformId,
      ) ||
      null;
    let created = false;
    if (!u) {
      const id = allocAccountId();
      const uname = `Player${id}`;
      u = {
        Id: id,
        Username: uname,
        DisplayName: uname,
        PwHashB64: "",
        SaltB64: "",
        Created: new Date().toISOString(),
        PlatformType: platform,
        PlatformId: platformId,
      };
      db.users[uname.toLowerCase()] = u;
      created = true;
      saveDb();
      log({ event: "account-created", id, platform, platformId });
    }
    return issue(u, created);
  }

  if (grant === "refresh_token") {
    const rt = String(b.refresh_token ?? "");
    const userName = db.refresh[rt];
    const u = userName ? db.users[userName] : null;
    if (!u) return c.send(400, { error: "invalid_grant", error_description: "Bad refresh token." });
    return issue(u, false);
  }

  if (grant === "password") {
    const username = String(b.username ?? "");
    const password = String(b.password ?? "");
    const u = db.users[username.toLowerCase()];
    if (!u || !u.PwHashB64) {
      return c.send(400, { error: "invalid_grant", error_description: "Unknown account." });
    }
    if (hashPw(password, Buffer.from(u.SaltB64, "base64")) !== u.PwHashB64) {
      return c.send(400, { error: "invalid_grant", error_description: "Bad password." });
    }
    return issue(u, false);
  }

  log({ event: "auth-unknown-grant", grant });
  return c.send(400, { error: "unsupported_grant_type" });
});

// --- accounts service (accounts.rec.net) ---
// Bulk public-account lookup: GET /account/bulk?id=1,2,3 (or repeated id=, or
// POST form body). Synthesizes a default for any id not in the DB so every
// requested id is present in the array response.
const bulkAccountsHandler = async (c: Ctx) => {
  const raw: string[] = [...c.query.getAll("id")];
  if (c.req.method === "POST") {
    const b = await parseBodyJson(c);
    if (b.id != null) raw.push(String(b.id));
  }
  const ids = [
    ...new Set(
      raw
        .flatMap((v) => v.split(","))
        .map((v) => Number.parseInt(v.trim(), 10))
        .filter((n) => !Number.isNaN(n)),
    ),
  ];
  const byId = new Map(Object.values(db.users).map((u) => [Number(u.Id), u]));
  c.send(200, ids.map((id) => (byId.has(id) ? accountDto(byId.get(id)!) : defaultAccountDto(id))));
};
route("GET", "/account/bulk", bulkAccountsHandler);
route("POST", "/account/bulk", bulkAccountsHandler);

// The caller's own account (auth-gated).
route("GET", "/account/me", (c) => {
  if (!c.authUser) return c.send(401, {});
  c.send(200, selfAccountDto(c.authUser));
});

// A single public account by id: GET /account/{id}. Default for unknown ids.
route("GET", "/account/**", (c) => {
  const id = Number.parseInt(c.path.split("/").pop() ?? "", 10);
  if (Number.isNaN(id)) return c.send(404, { Code: 404, Error: "bad account id" });
  const u = userById(id);
  c.send(200, u ? accountDto(u) : defaultAccountDto(id));
});

// ---- post-login wave (shapes mirrored from the reference) --------------------
// Parse bulk ids from repeated ?id=, comma lists, and a form body.
const parseIds = (c: Ctx): number[] => {
  const raw: string[] = [...c.query.getAll("id")];
  if (c.body) {
    try {
      for (const [k, v] of new URLSearchParams(c.body)) if (k === "id") raw.push(v);
    } catch {}
  }
  return [
    ...new Set(
      raw
        .flatMap((v) => v.split(","))
        .map((v) => Number.parseInt(v.trim(), 10))
        .filter((n) => !Number.isNaN(n)),
    ),
  ];
};

// --- match.rec.net (presence + realtime handshake) ---
// Shapes from the reference server apps/match/src/{openapi,match.app}.ts.
const GAME_VERSION = "20250718.01";

// Server-side presence: which room instance each player is currently in. Set when they
// matchmake (see /matchmake/dorm), read back in the heartbeat. The client compares the
// heartbeat's roomInstance to its own; if the server says "no room" after the client just
// joined one, matchmaking logs "local presence is out-of-sync" and kicks to the title with
// "An error occurred". Cleared on logout. (In-memory — one process, resets on relaunch.)
const presenceById = new Map<number, unknown>();
// Per-account deviceClass reported by the client in the /connect/token body (`device_class`).
// A screen/PC client sends device_class=2; the heartbeat playerDto MUST echo that exact value.
// Hardcoding 0 made the client's local presence (deviceClass 2) disagree with the heartbeat,
// which it reports as "RecNet presence heartbeat response indicates local presence is
// out-of-sync!" every ~30s. the reference stores deviceClass from the token request and replays it.
const deviceClassById = new Map<number, number>();

// PlayerDto: the player's presence as the client reads it (GET /player, POST
// /player/login, /player/heartbeat). The matchmaking loop deserializes this; an empty
// `{}` makes it "Received malformed RecNet response" -> matchmake retries forever. The
// photon*/voice*/experiments keys must be PRESENT (null) even in presence. roomInstance
// null = not in a room yet.
const playerDto = (playerId: number, roomInstance: unknown = null) => ({
  appVersion: GAME_VERSION,
  deviceClass: deviceClassById.get(playerId) ?? 0,
  errorCode: 0,
  isOnline: true,
  playerId,
  roomInstance,
  statusVisibility: 0,
  vrMovementMode: 1,
  platform: 0,
  photonAuthToken: null,
  photonRealtimeAppId: null,
  photonVoiceAppId: null,
  photonChatAppId: null,
  photonRegion: null,
  photonRoomId: null,
  voiceConnectionInfo: null,
  voiceServerId: null,
  experiments: null,
});
const selfPlayerId = (c: Ctx) => (c.authUser ? Number(c.authUser.Id) : 1000000);

// Session LoginLock, recorded at /player/login and verified on each heartbeat. the reference's
// login acks EMPTY (not a PlayerDto); the heartbeat returns the presence unless the posted
// lock no longer matches (superseded session). Our old login returned a PlayerDto, which the
// client read as a presence that disagreed with its local session.
const loginLockById = new Map<number, string>();
const parseLoginLock = (c: Ctx): string | undefined => {
  try { return new URLSearchParams(c.body || "").get("LoginLock") ?? undefined; } catch { return undefined; }
};

// New players are placed in ORIENTATION (RoomId 13) by the client's new-user flow, which
// loads the scene LOCALLY (no matchmake) and tags its instance with the sentinel id -2. The
// presence heartbeat MUST echo roomInstanceId -2 or the client declares "RecNet presence
// heartbeat ... local presence is out-of-sync!" and sticks forever at "preparing". the reference's
// auth worker seeds this presence at account creation (placeNewPlayerInOrientation); we seed
// it at login when the player has no live presence yet. Shape mirrors match's roomInstance.
const ORIENTATION_INSTANCE_ID = -2;
const ORIENTATION_ROOM_ID = 13;
const ORIENTATION_SCENE = "c79709d8-a31b-48aa-9eb8-cc31ba9505e8"; // room 13 SubRoom 23 UnitySceneId
// The Orientation RoomDto the client resolves via ?name=SocialOrientation/Orientation. Same
// proven shape as dormRoomDto (the client parses that one fine), but roomId 13, the Orientation
// scene, and IsDorm:false — so it is CONSISTENT with the seeded -2 presence (roomId 13). A `{}`
// here is "Malformed Response: '{}'" (fatal ~28s); the caller's dorm RoomDto gave a RoomId that
// disagreed with the -2 presence and stalled the scene load.
const orientationRoomDto = () => orientationRoomStatic;
// Room-by-id lookup: Orientation (13) -> the tuned Orientation DTO; any other RRO / the Rec
// Center -> its real DTO; everything else is a player dorm. `id` may be a STRING: ported room
// ids exceed 2^53 and a Number round-trip would corrupt them (649924194922273060 → ...280).
const roomDtoFor = (id: number | string): Record<string, unknown> => {
  const s = unwrapId(String(id));
  const n = Number(s);
  if (Number.isSafeInteger(n) && n === ORIENTATION_ROOM_ID) return orientationRoomDto();
  return rroRoomById(s) ?? (Number.isSafeInteger(n)
    ? dormRoomDto(n, userById(n)?.Username ?? `Player${n}`)
    : ({ ...roomTemplate, RoomId: s, Name: `Room ${s}` } as Record<string, unknown>));
};
const orientationRoomInstance = () => {
  let region = "usw";
  try {
    const pf = path.join(DATA, "photon.json");
    if (existsSync(pf)) region = (JSON.parse(readFileSync(pf, "utf8")).region as string) || "usw";
  } catch { /* default */ }
  return {
    roomInstanceId: ORIENTATION_INSTANCE_ID,
    roomId: ORIENTATION_ROOM_ID,
    subRoomId: 23,
    roomInstanceType: 0, // Public
    location: ORIENTATION_SCENE,
    dataBlob: "",
    eventId: 0,
    clubId: 0,
    roomCode: "",
    photonRegion: region,
    photonRegionId: region,
    photonRoomId: `rec.${ORIENTATION_ROOM_ID}`,
    name: "^Orientation",
    maxCapacity: 1, // Orientation is solo (the reference room 13 MaxPlayers 1) — matches orientationRoomDto
    isFull: false,
    isPrivate: false,
    isInProgress: false,
    EncryptVoiceChat: false,
  };
};
// When UWU_SPAWN=dorm, a fresh launch is seeded into the player's OWN DORM instead of
// Orientation. The Orientation tutorial scene (Theater Department) never spawns the local
// player rig in screen mode — no avatar skeleton, no camera, no controls, just a black
// screen with audible menu, reproduced identically on Linux/Proton and native Windows.
// The dorm is an ordinary room whose spawn path is the proven dormMatchmake one, and it is
// the room the user actually wants. Default (unset) stays on Orientation.
const SPAWN_IN_DORM = process.env.UWU_SPAWN === "dorm";
const photonRegion = () => {
  try {
    const pf = path.join(DATA, "photon.json");
    if (existsSync(pf)) return (JSON.parse(readFileSync(pf, "utf8")).region as string) || "usw";
  } catch { /* default */ }
  return "usw";
};
// The same dorm roomInstance dormMatchmake returns, as a reusable builder.
const dormRoomInstance = (id: number, username: string) => {
  const region = photonRegion();
  return {
    roomInstanceId: id,
    roomId: id,
    subRoomId: 1,
    roomInstanceType: 1, // Dormroom
    location: DORM_SCENE,
    dataBlob: "",
    eventId: 0,
    clubId: 0,
    roomCode: "",
    photonRegion: region,
    photonRegionId: region,
    photonRoomId: `uwu-dorm-${id}`,
    name: `@${username}'s Dorm`,
    maxCapacity: 4,
    isFull: false,
    isPrivate: true,
    isInProgress: false,
    EncryptVoiceChat: false,
  };
};
// The room a fresh launch is seeded into: Orientation by default, the dorm under UWU_SPAWN=dorm.
const defaultSpawnInstance = (id: number) =>
  SPAWN_IN_DORM ? dormRoomInstance(id, userById(id)?.Username ?? `Player${id}`) : orientationRoomInstance();
const isOrientationPresence = (p: unknown) =>
  !!p && typeof p === "object" && (p as Record<string, unknown>).roomInstanceId === ORIENTATION_INSTANCE_ID;

route("POST", "/player/login", (c) => {
  const id = selfPlayerId(c);
  const lock = parseLoginLock(c);
  if (lock) loginLockById.set(id, lock);
  // Seed the Orientation presence so the first heartbeat echoes roomInstanceId -2 and the
  // client (locally loading Orientation) stays in sync. Don't clobber a live room presence
  // set by a later matchmake.
  if (!presenceById.has(id)) presenceById.set(id, defaultSpawnInstance(id));
  c.empty(); // the reference acks an EMPTY body here, NOT a PlayerDto
});
route("POST", "/player/logout", (c) => {           // empty ack
  const id = selfPlayerId(c);
  // The client fires a spurious logout right after the launch seed; clearing presence then
  // would wipe it and bounce the player out. Preserve the Orientation seed — and, under the
  // dorm experiment, the seeded dorm presence too.
  const keep = isOrientationPresence(presenceById.get(id)) || (SPAWN_IN_DORM && presenceById.has(id));
  if (!keep) {
    presenceById.delete(id);
    loginLockById.delete(id);
  }
  c.empty();
});
route("POST", "/player/exclusivelogin", (c) => c.send(200, { errorCode: 0 }));
route("POST", "/player/verifylock", (c) => c.empty());
route("POST", "/player/heartbeat", (c) => {
  const id = selfPlayerId(c);
  // Verify the beat still owns the session. A posted lock that disagrees with the one
  // recorded at login belongs to a superseded session -> return EMPTY so that stale client
  // stops (the reference's behavior). The current session's lock always matches, so it gets the
  // presence payload back and stays in sync.
  const posted = parseLoginLock(c);
  const stored = loginLockById.get(id);
  if (posted && stored && posted !== stored) { c.empty(); return; }
  c.send(200, playerDto(id, presenceById.get(id) ?? null));
});
// Status visibility toggle — the reference acks with an EMPTY body (not a PlayerDto, not {}).
route("PUT", "/player/statusvisibility", (c) => c.empty());
// GET /player — presence for the caller (or a default online player when no ids given).
route("GET", "/player", (c) => {
  const id = selfPlayerId(c);
  c.send(200, [{ ...playerDto(id, presenceById.get(id) ?? null), isOnline: true }]);
});
// QoS probe targets — Rec Room's own region endpoints, served verbatim. An empty list
// makes NetworkPingHandler.GetNetworkRegionPings throw NullReferenceException.
route("GET", "/player/qos", (c) =>
  c.send(200, [
    { id: "us-west1", address: "34.169.254.144:50000" },
    { id: "europe-west1", address: "35.205.141.119:50000" },
    { id: "asia-northeast1", address: "35.200.67.228:50000" },
    { id: "us-east1", address: "34.73.244.122:50000" },
    { id: "us-central1", address: "34.69.179.51:50000" },
    { id: "northamerica-northeast1", address: "34.152.4.100:50000" },
  ]));
route("PUT", "/player/photonregionpings", (c) => c.empty());
route("PUT", "/player/gameserverregionpings", (c) => c.empty());
// Voice: when a UwUNet voice server is running (server/src/voice/voice-server.ts), set
// UWU_VOICE_ADDR="<ip>:<port>" so connection-info advertises it as VoiceConnectionInfo and
// the client dials in for in-room (Dissonance) voice. UNSET = "" = voice off, which is the
// SAFE default: a VoiceConnectionInfo that points at a server that doesn't answer fails the
// client's room-load voice stage (FailedToConnectToVoice) — worse than no voice. See
// docs/voice-server.md.
const VOICE_ADDR = process.env.UWU_VOICE_ADDR ?? "";
const VOICE_SERVER_ID = process.env.UWU_VOICE_SERVER_ID ?? "uwu-voice-1";
// Record account -> room instance so the voice server can route by AI (the only identity in
// the Tachyon connect payload). The voice server reads this file; see voice-instance-routing.
const recordVoiceRoute = (accountId: number, instance: string) => {
  try {
    const rf = path.join(DATA, "voice-routing.json");
    let map: Record<string, string> = {};
    if (existsSync(rf)) { try { map = JSON.parse(readFileSync(rf, "utf8")); } catch { map = {}; } }
    if (map[String(accountId)] === instance) return; // no change
    map[String(accountId)] = instance;
    writeFileSync(rf, JSON.stringify(map));
  } catch { /* routing is best-effort */ }
};

// connection-info: the realtime creds in the {success,value,error} envelope. Photon realtime
// comes from data/photon.json; voice is our own LiteNetLib/Dissonance server, advertised only
// when UWU_VOICE_ADDR is set and the player is in a real instance.
// experiments must be a full ConnectionExperiments object (verbatim from the reference).
route("GET", "/player/connection-info", (c) => {
  if (!c.authUser) return c.send(401, {});
  // Photon realtime credentials, read fresh from data/photon.json (gitignored) so app
  // ids aren't baked into source: {realtimeAppId, voiceAppId?, chatAppId?, region?}.
  let ph: Record<string, string> = {};
  try {
    const pf = path.join(DATA, "photon.json");
    if (existsSync(pf)) ph = JSON.parse(readFileSync(pf, "utf8"));
  } catch { /* no photon config yet */ }
  // The Photon room name the client joins comes from HERE, not the matchmake response: it
  // reads the roomInstance the player's stored presence names (set by /matchmake/dorm). An
  // empty photonRoomId makes PUN fail "JoinOrCreateRoom failed. A roomname is required."
  const presence = presenceById.get(selfPlayerId(c)) as Record<string, unknown> | undefined;
  const photonRoomId = (presence?.photonRoomId as string) ?? "";
  const photonRegion = (presence?.photonRegion as string) ?? ph.region ?? "usw";
  // Advertise voice only for a real instance (a numeric id that isn't offline Orientation -2),
  // and only when a voice server address is configured. Otherwise "" = voice off (safe).
  const instanceId = typeof presence?.roomInstanceId === "number" ? (presence.roomInstanceId as number) : null;
  const voiceOn = VOICE_ADDR !== "" && instanceId !== null && instanceId !== ORIENTATION_INSTANCE_ID;
  if (voiceOn) recordVoiceRoute(selfPlayerId(c), String(instanceId));
  c.send(200, {
    success: true,
    value: {
      photonAuthToken: "",
      photonRealtimeAppId: ph.realtimeAppId ?? "",
      photonVoiceAppId: ph.voiceAppId ?? "",
      photonChatAppId: ph.chatAppId ?? "",
      photonRegion,
      photonRoomId,
      voiceConnectionInfo: voiceOn ? VOICE_ADDR : "",
      voiceServerId: voiceOn ? VOICE_SERVER_ID : "",
      experiments: {
        networkTransformSyncInterval: 10.0,
        shouldUseUnreliableOnChange: false,
        shouldAvoidDiscontinuityRPCs: true,
        shouldAvoidRedundantDiscontinuity: false,
        r2RuntimeStaticBaking: true,
        r2AutoEmbodiment: true,
        r2RuntimeStaticBakingMinShapeThreshold: 1,
        r2UseCheapReplicas: true,
        shouldUseGameServerNetworking: false,
      },
    },
    error: null,
  });
});

// --- match.rec.net matchmaking ---
// PLAY sends the caller into their own dorm. `/matchmake/dorm` (and `/matchmake/none`,
// which falls back to the dorm) return a MatchmakeResponse; the client reads roomInstance
// for the Photon coordinates + Unity scene, then connects to Photon. Two hard rules from
// the reference's spec: (1) `correlationId` MUST echo the request's CorrelationId or the client
// refuses with "Unable to connect to RecNet game session"; (2) `location` is the dorm's
// Unity scene id — empty makes the client reject the instance. photonRoomId is the Photon
// room co-joiners share; deterministic per dorm so re-joins land in the same room.
const EMPTY_GUID = "00000000-0000-0000-0000-000000000000";
const dormMatchmake = (c: Ctx) => {
  if (!c.authUser) return c.send(401, {});
  const id = selfPlayerId(c);
  let correlationId = EMPTY_GUID;
  try {
    const q = new URLSearchParams(c.body || "");
    correlationId = q.get("CorrelationId") || q.get("correlationId") || correlationId;
  } catch { /* non-form body */ }
  const region = (() => {
    try {
      const pf = path.join(DATA, "photon.json");
      if (existsSync(pf)) return (JSON.parse(readFileSync(pf, "utf8")).region as string) || "usw";
    } catch { /* default */ }
    return "usw";
  })();
  const roomInstance = {
    roomInstanceId: id,
    roomId: id,
    subRoomId: 1,
    roomInstanceType: 1, // Dormroom
    location: DORM_SCENE,
    dataBlob: "",
    eventId: 0,
    clubId: 0,
    roomCode: "",
    photonRegion: region,
    photonRegionId: region,
    photonRoomId: `uwu-dorm-${id}`,
    name: `@${c.authUser.Username}'s Dorm`,
    maxCapacity: 4,
    isFull: false,
    isPrivate: true,
    isInProgress: false,
    EncryptVoiceChat: false,
  };
  presenceById.set(id, roomInstance); // so the heartbeat agrees the player is in this room
  c.send(200, { result: 0, errorCode: 0, roomInstance, correlationId });
};
route("POST", "/matchmake/dorm", dormMatchmake);
// /matchmake/none — the client posts this at startup and WHILE SITTING IN ORIENTATION when it
// needs an instance but isn't going anywhere in particular. Per the reference it must answer the
// instance the player is ALREADY in (re-committing presence), never force a destination —
// forcing the dorm here warps the player out of Orientation and overwrites the -2 seed, which
// desyncs presence and aborts the room load. Only a caller with NO live presence falls back to
// their dorm.
const noneMatchmake = (c: Ctx) => {
  if (!c.authUser) return c.send(401, {});
  const id = selfPlayerId(c);
  let correlationId = EMPTY_GUID;
  try {
    const q = new URLSearchParams(c.body || "");
    correlationId = q.get("CorrelationId") || q.get("correlationId") || correlationId;
  } catch { /* non-form body */ }
  const current = presenceById.get(id);
  if (current) {
    c.send(200, { result: 0, errorCode: 0, roomInstance: current, correlationId });
    return;
  }
  dormMatchmake(c); // no live presence -> fall back to the dorm
};
route("POST", "/matchmake/none", noneMatchmake);
// The client reports how its Photon join went; accepted and ignored (empty 200). A 404 here
// makes matchmaking treat the join as failed and re-matchmake in a loop.
route("POST", "/roominstance/**/reportjoinresult", (c) => c.empty());

// --- public room matchmaking (RROs + the Rec Center) --------------------------------------
// Send the caller into a SHARED instance of a first-party room. Everyone who matchmakes into
// the same room+subroom gets the same deterministic photonRoomId, so they land in the same
// Photon room and see each other — that's how the Rec Center fills up. roomInstanceId is
// stable per room and differs from the caller's dorm instance (their account id), which is
// what the client keys a room transition off.
const PUBLIC_INSTANCE_BASE = 500000;
const publicRoomInstance = (roomId: number | string, subRoomId?: number | string) => {
  const sr = rroSubRoom(roomId);
  const sub = subRoomId ?? sr?.subRoomId ?? 1;
  const region = photonRegion();
  // Stable numeric instance id from the (possibly 64-bit) room id: a big id rounds as a
  // float, so take it modulo a safe range as BigInt, then add the base as a plain Number.
  const instBase =
    Number(BigInt(String(roomId)) % 9000000000n) + PUBLIC_INSTANCE_BASE;
  // Wire typing: the matchmake instance's id fields are strict longs on the client. Small
  // ids convert to numbers; big (>2^53) ids ride the BIG sentinel and are unquoted into raw
  // digit literals by send().
  const wireId = (v: unknown): unknown => {
    const s = unwrapId(String(v));
    return /^\d{16,}$/.test(s) ? `__BIG__${s}__` : Number(s);
  };
  return {
    roomInstanceId: instBase,
    roomId: wireId(roomId),
    subRoomId: wireId(sub ?? sr?.subRoomId ?? 1),
    roomInstanceType: 0, // Public
    location: sr?.scene ?? "",
    dataBlob: "",
    eventId: 0,
    clubId: 0,
    roomCode: "",
    photonRegion: region,
    photonRegionId: region,
    photonRoomId: `uwu-room-${roomId}-${sub}`,
    name: sr?.name ?? `Room${roomId}`,
    maxCapacity: sr?.maxCapacity ?? 16,
    isFull: false,
    isPrivate: false,
    isInProgress: false,
    EncryptVoiceChat: false,
  };
};
// The newer client reads the PascalCase envelope on /matchmake/v2/ and /matchmake/invite/; the
// legacy routes (and our working /matchmake/dorm) read the lowercase one. Same instance, two
// spellings — pick by the request path, like the reference's matchmakeResult.
const isPascalMatchmake = (p: string) => p.startsWith("/matchmake/v2/") || p.startsWith("/matchmake/invite/");
const toV2RoomInstance = (ri: Record<string, unknown>) => ({
  RoomInstanceId: ri.roomInstanceId, RoomId: ri.roomId, SubRoomId: ri.subRoomId, Location: ri.location,
  EventId: ri.eventId, ClubId: ri.clubId, RoomCode: ri.roomCode, Name: ri.name, MaxCapacity: ri.maxCapacity,
  IsFull: ri.isFull, IsPrivate: ri.isPrivate, IsInProgress: ri.isInProgress, EncryptVoiceChat: ri.EncryptVoiceChat,
  RoomInstanceType: ri.roomInstanceType, MatchmakingPolicy: 0,
  // the reference's v2 instance omits the Photon fields; the client tolerates extras and needs these
  // to connect, so include them.
  PhotonRegion: ri.photonRegion, PhotonRegionId: ri.photonRegionId, PhotonRoomId: ri.photonRoomId, DataBlob: ri.dataBlob,
});
const matchmakeCorrelationId = (c: Ctx) => {
  let cid = EMPTY_GUID;
  try { cid = new URLSearchParams(c.body || "").get("CorrelationId") || new URLSearchParams(c.body || "").get("correlationId") || cid; } catch {}
  if (cid === EMPTY_GUID && c.body) { try { const j = JSON.parse(c.body); cid = j.CorrelationId || j.correlationId || cid; } catch {} }
  return cid;
};
const sendMatchmake = (c: Ctx, errorCode: number, roomInstance: Record<string, unknown> | null) => {
  const correlationId = matchmakeCorrelationId(c);
  if (isPascalMatchmake(c.path)) {
    c.send(200, { ErrorCode: errorCode, CorrelationId: correlationId, RoomInstance: roomInstance ? toV2RoomInstance(roomInstance) : null });
  } else {
    c.send(200, { errorCode, result: errorCode, roomInstance, correlationId });
  }
};
// POST /matchmake/room/{roomId}[/{subRoomId}] (+ the v2 spelling): enter an RRO / the Rec Center.
// Room ids are kept as STRINGS through the lookup: ported ids exceed 2^53 and Number-parsing
// them rounds them (649924194922273060 → ...280) — rroRoomById(String) would 404 the room.
const roomMatchmake = (c: Ctx) => {
  if (!c.authUser) return c.send(401, {});
  const m = /\/room\/(\d+)(?:\/(\d+))?$/.exec(c.path);
  if (!m) return sendMatchmake(c, 2, null); // 2 = couldn't resolve
  const roomId = m[1];
  const subRoomId = m[2];
  if (!rroRoomById(roomId)) return sendMatchmake(c, 2, null); // not a room we serve
  const inst = publicRoomInstance(roomId, subRoomId);
  presenceById.set(selfPlayerId(c), inst); // the heartbeat now agrees the player is here
  sendMatchmake(c, 0, inst);
};
route("POST", "/matchmake/room/{roomId}", roomMatchmake);
route("POST", "/matchmake/room/{roomId}/{subRoomId}", roomMatchmake);
route("POST", "/matchmake/v2/room/{roomId}", roomMatchmake);
route("POST", "/matchmake/v2/room/{roomId}/{subRoomId}", roomMatchmake);

// POST /matchmake/(v2/)player/{playerId}: follow a friend — return the instance their presence
// names, so you land in their Photon room. This is how you join your friend wherever they are.
const playerMatchmake = (c: Ctx) => {
  if (!c.authUser) return c.send(401, {});
  const m = /\/player\/(\d+)$/.exec(c.path);
  if (!m) return sendMatchmake(c, 2, null);
  const inst = presenceById.get(Number.parseInt(m[1], 10)) as Record<string, unknown> | undefined;
  if (!inst || inst.roomInstanceId === -2) return sendMatchmake(c, 20, null); // 20 = target not joinable (offline Orientation)
  presenceById.set(selfPlayerId(c), inst);
  sendMatchmake(c, 0, inst);
};
route("POST", "/matchmake/player/{playerId}", playerMatchmake);
route("POST", "/matchmake/v2/player/{playerId}", playerMatchmake);

// GET /photon_access_token — the permission table + Photon credentials the client needs to
// SPAWN into a room (the reference apps/rooms/src/rooms.app.ts). 404ing this was the dorm's
// `FailedToSpawnPlayer (Code 8700)`: the client awaits it inside JoinRoomLoadWithPhoton, and a
// faulted fetch aborts the whole room load. PhotonAccessToken is always "" — Photon Cloud
// (ours, like the reference's) accepts an empty token; the real service signed it with a secret we
// don't have. The permission table decides who may build; it does not gate the spawn, but the
// client reads the whole table from this one response so we serve it faithfully.
const ROLE_NONE = 0, ROLE_COOWNER = 30, ROLE_CREATOR = 255;
const PERMISSION_ROLES = [ROLE_NONE, 10, 20, ROLE_COOWNER, ROLE_CREATOR]; // None,Host,Moderator,CoOwner,Creator
const BUILD_PERMISSIONS = [
  "CAN_USE_MAKER_PEN", "CAN_USE_ROOM_RESET_BUTTON", "CAN_USE_DELETE_ALL_BUTTON",
  "CAN_SAVE_INVENTIONS", "CAN_SPAWN_INVENTIONS", "CAN_USE_PLAY_GIZMOS_TOGGLE",
];
const buildsByDefault = (role: number) => role >= ROLE_COOWNER; // managers (co-owner and up) may build
const photonAccessTokenDto = (roomInstanceId: number | null, role: number) => {
  const row = (Permission: string, Role: number, Value: string, Override: boolean) =>
    ({ Override, Permission, Role, Type: 0, Value });
  const permissions: Array<ReturnType<typeof row>> = [];
  if (buildsByDefault(role)) {
    // A manager (the dorm's own creator): the whole table, a row per (permission, role tier).
    for (const at of PERMISSION_ROLES)
      for (const name of BUILD_PERMISSIONS)
        permissions.push(row(name, at, buildsByDefault(at) ? "True" : "False", false));
  } else {
    // Everyone else: their own values only, at Role 0 and (if non-zero) their role. A visitor,
    // host or moderator builds nothing by default, so every value is "False".
    for (const at of role === ROLE_NONE ? [ROLE_NONE] : [ROLE_NONE, role])
      for (const name of BUILD_PERMISSIONS)
        permissions.push(row(name, at, "False", true));
  }
  return { Permissions: permissions, PhotonAccessToken: "", RoomInstanceId: roomInstanceId };
};
// A god account: every build permission True at every role tier, so whatever role the client
// thinks it holds in whatever room, it reads True — maker pen, reset, delete-all, invention
// save/spawn and play-gizmos, everywhere.
const godPhotonAccessTokenDto = (roomInstanceId: number | null) => {
  const permissions = [];
  for (const at of PERMISSION_ROLES)
    for (const name of BUILD_PERMISSIONS)
      permissions.push({ Override: true, Permission: name, Role: at, Type: 0, Value: "True" });
  return { Permissions: permissions, PhotonAccessToken: "", RoomInstanceId: roomInstanceId };
};
route("GET", "/photon_access_token", (c) => {
  if (!c.authUser) return c.send(401, {});
  const id = selfPlayerId(c);
  const presence = presenceById.get(id) as Record<string, unknown> | undefined;
  const roomInstanceIdRaw = presence?.roomInstanceId;
  const roomIdRaw = presence?.roomId;
  const roomInstanceId = roomInstanceIdRaw !== undefined ? Number(unwrapId(String(roomInstanceIdRaw))) : null;
  const roomId = roomIdRaw !== undefined ? unwrapId(String(roomIdRaw)) : null;
  if (isGod(id)) return c.send(200, godPhotonAccessTokenDto(roomInstanceId)); // build anything, anywhere
  // The caller owns their own dorm (roomId === their account id) → Creator; otherwise a visitor.
  const role = roomId !== null && Number(roomId) === id ? ROLE_CREATOR : ROLE_NONE;
  c.send(200, photonAccessTokenDto(roomInstanceId, role));
});

// --- rooms.rec.net: the room object the client loads after matchmake ---
// GET /dormroom/me — returns the caller's dorm ROOM ID as a BARE NUMBER (the reference's
// `DormRoomId` = Number(dorm.RoomId)), NOT a RoomDto. The client then fetches the full room
// from GET /rooms/{id}. Returning a RoomDto here makes the client fail to parse a number
// ("Malformed Response") -> "No such room". Our dorm's roomId == the account id.
route("GET", "/dormroom/me", (c) => c.send(200, selfPlayerId(c)));
// GET /rooms?id=&name= — single-room lookup. Returns the RoomDto when found, or `{}` (empty
// object, NOT a 404) when there's no match — the client reads {} as "no such room, keep going".
// A 404 here instead aborts the BootSequence with the fatal "No such room". id may be a
// comma-separated list (first valid integer wins). Every room we know is a dorm.
route("GET", "/rooms", (c) => {
  const idParam = c.query.get("id");
  if (idParam) {
    // Ids stay strings: /rooms?id= can carry a 64-bit room id which a Number would round.
    const id = (idParam.split(",")[0] ?? "").trim();
    if (/^\d+$/.test(id)) {
      c.send(200, roomDtoFor(id));
      return;
    }
  }
  // Name lookup (e.g. ?name=SocialOrientation&include=... — the new-user onboarding probe).
  // the reference's LIVE server returns `{}` (empty object) for a name with no matching room, and
  // the client reads that as "no such named room" and moves on using its local Orientation +
  // the seeded -2 presence. Returning a real dorm RoomDto here instead gave the client a room
  // whose RoomId (account id) disagreed with its Orientation presence (roomId 13), so it never
  // loaded the Orientation scene. Known special room "Orientation" -> room 13 DTO; else `{}`.
  const nameParam = c.query.get("name");
  if (nameParam) {
    const n = nameParam.toLowerCase();
    if (n === "orientation" || n === "socialorientation") {
      // New-user onboarding room. MUST be a valid RoomDto (a `{}` here malforms fatally at ~28s).
      // Serve the Orientation room (13) so it matches the seeded -2 presence.
      c.send(200, orientationRoomDto());
      return;
    }
    const rroId = rroRoomIdByName(n);
    if (rroId !== undefined) {
      // An RRO / the Rec Center resolved by name (e.g. ?name=RecCenter) -> its real DTO.
      c.send(200, roomDtoFor(rroId));
      return;
    }
    c.send(200, {}); // the reference's no-match response for any other unknown named room
    return;
  }
  c.send(200, null); // neither id nor name resolvable
});
// GET /rooms/bulk — rooms by id (?id= repeated and/or comma-separated) or by name
// (?name= — the door-link resolver path). Returns a RoomDto array (missing ids omitted).
// MUST be registered before /rooms/** or that catch-all 404s it with "no such room" — which
// the BootSequence surfaces as the fatal "No such room". Every room we know is a dorm, so
// return a dorm DTO per requested id.
route("GET", "/rooms/bulk", (c) => {
  const rawIds = [...c.query.getAll("id")]
    .flatMap((v) => v.split(","))
    .map((s) => s.trim())
    .filter((s) => /^\d+$/.test(s));
  // The door/room-link resolver asks bulk by NAME (the reference lists ?name= as a legal
  // bulk param). An empty array here is the client's "room doesn't exist".
  const nameParam = c.query.get("name");
  if (!rawIds.length && nameParam) {
    const id = rroRoomIdByName(nameParam.toLowerCase());
    c.send(200, id === undefined ? [] : [roomDtoFor(id)]);
    return;
  }
  c.send(200, rawIds.map((rid) => roomDtoFor(rid)));
});
// Per-room, per-player saved data (the blob @'YourRoom' machines store). GET must NEVER 404:
// the reference's own docs — "A player who has never saved any — or an unknown room — gets an EMPTY
// `Data`... a 404 here would stall the room load." We used to fall through to the /rooms/**
// catch-all's 404 for this path, which stalled the dorm's spawn chain after login.
const roomPlayerData = new Map<string, string>(); // `${roomId}:${accountId}` -> base64 blob
const playerDataKey = (roomId: number, accountId: number) => `${roomId}:${accountId}`;
route("GET", "/rooms/{roomId}/playerdata/me", (c) => {
  if (!c.authUser) return c.send(401, {});
  const m = /^\/rooms\/(\d+)\/playerdata\/me$/.exec(c.path);
  if (!m) return c.send(404, {});
  const roomId = Number.parseInt(m[1], 10);
  c.send(200, { Data: roomPlayerData.get(playerDataKey(roomId, selfPlayerId(c))) ?? "" });
});
// Save the caller's per-room player data (form field `data`, base64 the client builds; the
// server never decodes it). Answer the same bare `{ Data }` with what was stored.
route("PUT", "/rooms/{roomId}/playerdata/me", (c) => {
  if (!c.authUser) return c.send(401, {});
  const m = /^\/rooms\/(\d+)\/playerdata\/me$/.exec(c.path);
  if (!m) return c.send(404, {});
  const roomId = Number.parseInt(m[1], 10);
  let data = "";
  try {
    data = new URLSearchParams(c.body).get("data") ?? "";
  } catch { /* unparseable — store empty */ }
  roomPlayerData.set(playerDataKey(roomId, selfPlayerId(c)), data);
  c.send(200, { Data: data });
});
// The caller's XP in a room: zero XP for a fresh player, room progression echoed off.
route("GET", "/rooms/{roomId}/experience/player", (c) => {
  if (!c.authUser) return c.send(401, {});
  c.send(200, { RoomExperienceEnabled: false, Experience: 0, ConcurrencyCode: crypto.randomUUID() });
});

// Keepsakes (room mementos) — stubbed like the reference: feature on, zero storage, and the
// room listing answers an EMPTY body (204) rather than an array, which the client reads as
// "no keepsakes" (it treats a BODY here as data). The categories endpoint must be an object
// ({Results, TotalResults}) — an array fails its parser and takes the keepsake load down.
route("GET", "/api/keepsakes/globalconfig", (c) =>
  c.send(200, { KeepsakeFeatureEnabled: true, KeepsakeRoomLimit: 10, SocialXpBoostEnabled: false }));
route("GET", "/api/keepsakes/categories", (c) => c.send(200, { Results: [], TotalResults: 0 }));
route("GET", "/api/keepsakes/rooms/{roomId}", (c) => {
  // the reference answers 204 with NO body (not "null"): the client treats a body here as data.
  c.res.statusCode = 204;
  c.res.setHeader("content-length", "0");
  c.res.end();
});

// ---- post-login wave 2 (shapes mirrored from the reference's workers+tests) ----
// MUST sit before the /rooms/** catch-all below — dispatch picks the FIRST matching
// route, and that catch-all would swallow every rooms path registered after it.

// --- rooms.rec.net: my-rooms / queues ---
// `*by/me` lists answer a BARE array of RoomDto. A fresh account owns only its auto-
// provisioned dorm, which `ownedby/me` deliberately drops (the reference apps/rooms:
// rooms.app.ts "/rooms/ownedby/me" — dorm excluded), and has never visited another
// room (no interaction rows), so visitedby/me is [] too. We only ever synthesize
// dorms, so both stay [] here.
route("GET", "/rooms/ownedby/me", (c) => {
  if (!c.authUser) return c.send(401, {});
  c.send(200, []);
});
route("GET", "/rooms/visitedby/me", (c) => {
  if (!c.authUser) return c.send(401, {});
  c.send(200, []);
});
// Play > Library's "Favorites" row (MyFavorites → the reference rooms.app.ts
// "/rooms/favoritedby/me"): a bare RoomDto[]. Nothing can favorite a room yet, so [] —
// before this it fell into /rooms/** and 404'd "no such room" (a failed-load row).
route("GET", "/rooms/favoritedby/me", (c) => {
  if (!c.authUser) return c.send(401, {});
  c.send(200, []);
});
// Play > Library's "My Rooms" row (MyCreatedRooms). The reference rooms.app.ts serves both
// "/rooms/createdby/me" and the legacy "/roomserver/rooms/createdby/me" with its ownedRooms
// handler — the dorm INCLUDED (every room the account created; ours is only the dorm). Only
// ownedby/me drops it.
const createdByMe = (c: Ctx) => {
  if (!c.authUser) return c.send(401, {});
  c.send(200, [roomDtoFor(selfPlayerId(c))]);
};
route("GET", "/rooms/createdby/me", createdByMe);
route("GET", "/roomserver/rooms/createdby/me", createdByMe);
// No instance queue yet → always empty (the reference apps/match match.app.ts: /rooms/requiring/*).
route("GET", "/rooms/requiring/developer", (c) => c.send(200, []));
route("GET", "/rooms/requiring/rrplus", (c) => c.send(200, []));

// Room browse filter chips (the reference apps/api routes/rooms.ts "/api/rooms/v1/filters").
// The client deserializes an OBJECT, not an array; TrendingFilters is a real list.
route("GET", "/api/rooms/v1/filters", (c) =>
  c.send(200, {
    PinnedFilters: [
      "recroomoriginal", "community", "featured", "quest", "pvp", "hangout",
      "game", "art", "store", "tutorial", "fandom", "performance", "action", "horror",
    ],
    PopularFilters: ["pvp", "quest", "game", "hangout", "art"],
    TrendingFilters: ["roleplay", "nomp", "rp", "casual", "fun", "action", "military", "sports"],
  }));

// --- discovery.rec.net page sources ---
// `{type}` IS the filename: static/<type>.json served verbatim (the reference apps/discovery
// discovery.app.ts "/sections/pagesource/:type"). With Discovery.UseNewDiscoveryServerAPI
// the client asks this instead of the embedded-config gameconfigs. File missing → 404,
// like the reference's unpublished names. The body is the bare ARRAY with camelCase
// fields — NOT the { pageSource, sections } wrapper the old game configs wrapped it in.
route("GET", "/sections/pagesource/{type}", (c) => {
  const type = c.path.split("/").pop() ?? "";
  if (!/^[A-Za-z0-9_-]+$/.test(type)) return c.send(404, {});
  const body = readStatic(`${type}.json`, null);
  if (body === null) return c.send(404, {});
  c.send(200, body);
});
// Sections by id (the reference apps/discovery discovery.app.ts "/sections/bulk"): the Play
// tabs' curated lists (static/curated-lists.json) name SECTION ids in ItemIds, and the client
// resolves them here. Answer = the catalogue static/sections.json (the reference's, verbatim)
// FILTERED by the repeated ?id= — catalogue order (not query order), unknown ids dropped, a
// repeated id once, rows verbatim (same camelCase shape as pagesource). No id at all → []
// (NOT the whole catalogue); only a missing catalogue is a 404. Comma-separated ids are
// tolerated too (a deviation; section ids never contain a comma).
route("GET", "/sections/bulk", (c) => {
  const ids = c.query.getAll("id").flatMap((v) => v.split(",")).map((s) => s.trim()).filter(Boolean);
  if (ids.length === 0) return c.send(200, []);
  const rows = readStatic("sections.json", null);
  if (!Array.isArray(rows)) return c.send(404, {});
  const wanted = new Set(ids);
  c.send(200, (rows as Array<Record<string, unknown>>).filter((s) => typeof s.id === "string" && wanted.has(s.id)));
});

// --- econ.rec.net: store + RR+ ---
// Gift-drop storefront: serves sf{id}.json via assets (the reference econ.app.ts
// "/api/storefronts/v3/giftdropstore/:id"). Our build (20250718.01) is a 2025 client,
// so storefront 3 reads the 2025 store dump sf3-2025.json; other ids try sf{id}-2025
// then plain sf{id}. No capture → 404.
route("GET", "/api/storefronts/v3/giftdropstore/{id}", (c) => {
  const id = c.path.split("/").pop() ?? "";
  if (!/^[A-Za-z0-9_-]+$/.test(id)) return c.send(404, {});
  const body =
    readStatic(`storefronts/sf${id}-2025.json`, null) ??
    readStatic(`storefronts/sf${id}.json`, null);
  if (body === null) return c.send(404, {});
  c.send(200, body);
});
// RR+ sign-up bonus: fixed numbers (the reference econ.app.ts "/api/CampusCard/v1/SignUpBonus").
route("GET", "/api/CampusCard/v1/SignUpBonus", (c) =>
  c.send(200, { RRPlusSignUpBonusId: 3, MinFreeItemsPrice: 6000, MaxFreeItemsPrice: 10000 }));
// The caller's RR+ subscription. No labels carry it here → `{}` = "not subscribed"
// (the reference econ.app.ts POST "/api/CampusCard/v1/UpdateAndGetSubscription"; auth is
// OPTIONAL there — a 401 would stall the client's load, so none is sent).
route("POST", "/api/CampusCard/v1/UpdateAndGetSubscription", (c) => c.send(200, {}));
// 2025 builds: the season read is a bare [] (the reference "/api/subscriptionseasons/v1/
// seasons/current" serves [] to any build below 20260323 — ours is 20250718.01).
route("GET", "/api/subscriptionseasons/v1/seasons/current", (c) => c.send(200, []));

// --- images / chat privacy ---
// The photo-tagging preference is ONE key in the player-settings bag, served as a BARE
// integer (the reference apps/api routes/images.ts "/api/players/v1/playerPhotoTaggingSetting"
// — an enum ordinal the client defines; 0 until the player sets one).
route("GET", "/api/players/v1/playerPhotoTaggingSetting", (c) => {
  if (!c.authUser) return c.send(401, {});
  c.send(200, 0);
});
route("PUT", "/api/players/v1/playerPhotoTaggingSetting", (c) => {
  if (!c.authUser) return c.send(401, {});
  c.send(200, 0); // nothing persisted — answer the (unset) stored value
});
// Named-image catalog (the reference apps/api routes/images.ts "/api/images/v2/named").
route("GET", "/api/images/v2/named", (c) => c.send(200, []));

// Objective progress reports (the reference econ.app.ts "/api/objectives/v1/updateobjective").
// No objectives store — echo the Group back as camelCase `group`, never completed, so the
// client gets a well-formed body. The client POSTs this constantly; a 404 is a retry storm
// (seen 1181x in one session's harvest).
route("POST", "/api/objectives/v1/updateobjective", (c) => {
  let group = 0;
  try { const b = c.body ? JSON.parse(c.body) : null; group = Number((b as Record<string, unknown>)?.Group) || 0; } catch { /* */ }
  c.send(200, { group, isCompleted: false, clearedAt: new Date().toISOString() });
});
// Text purity / sanitization gates (the reference gameplay.ts "/api/sanitize/*"): the client
// checks a display name / room name / invention title before accepting it. We don't filter —
// `isPure` says clean, and the sanitizer returns the text untouched (a bare JSON string).
route("POST", "/api/sanitize/v1/isPure", (c) => {
  if (!c.authUser) return c.send(401, {});
  c.send(200, { IsPure: true });
});
route("POST", "/api/sanitize/v1", (c) => {
  let value = "";
  try { const b = c.body ? JSON.parse(c.body) : null; value = String((b as Record<string, unknown>)?.Value ?? ""); } catch { /* */ }
  c.send(200, value);
});
// Caller's role check before the Maker Pen opens (the reference rooms.ts "/api/rooms/v1/
// verifyRole"): a bare boolean. Our god/creator model grants build everywhere, so an authed
// caller always holds the role.
const verifyRole = (c: Ctx) => c.send(200, Boolean(c.authUser));
route("POST", "/api/rooms/v1/verifyRole", verifyRole);
route("GET", "/api/rooms/v1/verifyRole", verifyRole);
// Push-notification category toggles (the reference platformnotifications.app.ts
// "/config/categories"): a { Results, TotalResults } PAGE of PascalCase categories. One
// muteable "Friends" category — we send no notifications yet, so it's a stub.
route("GET", "/config/categories", (c) =>
  c.send(200, {
    Results: [{ CategoryId: 2, Importance: 0, Name: "Friends", Description: "Friend requests and friend activity", IsMuteable: true }],
    TotalResults: 1,
  }));
// Who may DM the caller / add them to a group chat: enum by NUMBER (0 Friends·1
// Favorites·2 NoOne), keyed by the TOKEN's player id, defaulting to Friends for both —
// exactly what a player who never set them reads (the reference apps/chat chat.app.ts).
route("GET", "/thread/chatPrivacySetting", (c) => {
  if (!c.authUser) return c.send(401, {});
  c.send(200, {
    playerId: selfPlayerId(c),
    directMessagePrivacySetting: 0,
    groupChatPrivacySetting: 0,
  });
});

// --- api.rec.net monolith surface ---
// Online-friend count (the reference apps/api routes/social.ts "/api/messages/v1/
// friendOnlineStatus": { success, value: { FriendsOnlineCount } }). Count friends who currently
// have presence (roughly: logged in this session) — relationshipsForPlayer is defined below but
// this closure only reads it at request time, after module load.
route("POST", "/api/messages/v1/friendOnlineStatus", (c) => {
  if (!c.authUser) return c.send(401, {});
  const online = relationshipsForPlayer(selfPlayerId(c))
    .filter((r) => r.RelationshipType === REL_FRIEND && presenceById.has(r.PlayerID)).length;
  c.send(200, { success: true, value: { FriendsOnlineCount: online } });
});
// External platform invite referrers (NOT in the reference — GUESSED [] for a fresh account;
// the client 404-tolerated this before, so it has an empty-list path).
route("POST", "/api/externalfriendinvite/v1/getplatformreferrers", (c) => c.send(200, []));
// Influencer partner program (the reference econ.app.ts "/api/influencerpartnerprogram/
// influencers"): { InfluencerIds, ContinuationToken } — an object, not a bare array.
route("GET", "/api/influencerpartnerprogram/influencers", (c) => {
  if (!c.authUser) return c.send(401, {});
  c.send(200, { InfluencerIds: [], ContinuationToken: null });
});

// --- lists.rec.net ---
// One discovery ROW's contents (the reference lists.app.ts "/algorithmiclists/:list"): the
// envelope is { Type: echoed?type=, Entities: [{Id:"str", Context:null}] }, and a row with
// nothing behind it is a 200 with NO entities (a 404 renders as a failed carousel; an
// empty one is hidden — lists.test.ts:890). Nothing ranks here, so a ROOM row (type 1, the
// reference's default) is filled editorially from static/room-rows.json via roomRowIds(); the
// client then resolves the ids through /rooms/bulk. `{list}` is the row slug (a section's
// sourceMetadata, e.g. battle_algoendpoint) — or, per the reference's own docs, the SECTION
// id itself, which we map to its slug through static/sections.json. The store rows (types
// 4/5) and any unknown row stay EMPTY; every other type gets the room row, like the reference.
route("GET", "/algorithmiclists/{list}", (c) => {
  const t = Number.parseInt(c.query.get("type") ?? "", 10);
  const type = t >= 0 && t <= 255 ? t : 1; // echoed only when it fits the client's byte
  let key = "";
  try {
    key = decodeURIComponent(c.path.split("/").pop() ?? "").toLowerCase();
  } catch { /* malformed escape — unknown row */ }
  let ids = roomRowIds(key);
  if (ids === undefined) {
    const sec = (readStatic("sections.json", []) as Array<Record<string, unknown>>).find(
      (s) => String(s.id).toLowerCase() === key,
    );
    if (sec && typeof sec.sourceMetadata === "string") ids = roomRowIds(sec.sourceMetadata);
  }
  const entities =
    type !== 4 && type !== 5 ? (ids ?? []).map((id) => ({ Id: String(id), Context: null })) : [];
  c.send(200, { Type: type, Entities: entities });
});
// Send a list body whose 64-bit ListIds must be NUMBERS on the wire: JSON.stringify can't
// print them exactly, so they travel as digit strings and are unquoted here. Otherwise exactly
// c.send — fixed Content-Length (BestHTTP malforms larger chunked bodies) + the harvest log.
const sendWithListIds = (c: Ctx, obj: unknown) => {
  const out = JSON.stringify(obj).replace(/"ListId":"(\d+)"/g, '"ListId":$1');
  const buf = Buffer.from(out, "utf8");
  log({ event: "response", host: c.req.headers.host, method: c.req.method, url: c.req.url, path: c.path, status: 200, body: out });
  c.res.setHeader("content-type", "application/json; charset=utf-8");
  c.res.setHeader("content-length", String(buf.length));
  c.res.setHeader("x-uwunet", "uwunet");
  c.res.writeHead(200);
  c.res.end(buf);
};
// Curated lists by id (the reference lists.app.ts "/curatedlists/bulk": ?id= repeated). The
// reference answers ONE canned list for anything — never [], and an unknown id is still a
// 200, since a 404 shows as a failed row. We answer one list per requested id instead: a
// static/room-rows.json `playlists` entry (the gameconfig PlayMenuCuratedCarouselsMap ids +
// the Fun with Friends PlaylistById), else a captured list from static/curated-lists.json by
// ListId (the Play tabs' page lists — so by-id agrees with by-name), else the canned shape with
// no items; no usable id at all → the canned list alone. Shape per the reference: ItemIds =
// room ids as STRINGS (real RROs only), ImageName a string (the client parses it into a string
// field), Description null, NO Accessibility.
route("GET", "/curatedlists/bulk", (c) => {
  const ids = [
    ...new Set(c.query.getAll("id").flatMap((v) => v.split(",")).map((s) => s.trim()).filter(Boolean)),
  ];
  const pl =
    (readStatic("room-rows.json", {}) as {
      playlists?: Record<string, { Name?: string; ItemIds?: unknown[] }>;
    }).playlists ?? {};
  const canned = (id: string) => ({
    ListId: /^\d+$/.test(id) ? id : "17859340", // the reference's canned id
    CreatorAccountId: 1,
    Name: pl[id]?.Name ?? "My List",
    Description: null,
    ImageName: "",
    Type: 1,
    ItemIds: (pl[id]?.ItemIds ?? [])
      .map(Number)
      .filter((n) => Number.isInteger(n) && rroRoomById(n) !== undefined)
      .map(String),
    CreatedAt: "2025-07-18T00:00:00Z",
  });
  const lists = (ids.length > 0 ? ids : [""]).map(
    (id) => (!pl[id] && curatedLists.find((l) => String(l.ListId) === id)) || canned(id),
  );
  sendWithListIds(c, lists);
});
// One curated list (the reference lists: curated-lists.ts + lists.app.ts "/curatedlists").
// Params: creatorAccountId&type&name. Order: a capture matching the name, a RESERVED
// `__`-prefixed list served empty, the page default for the type when NO name was given,
// else an empty placeholder (anything other than "a list" breaks the client). ListId is
// a NUMBER on the wire even though 64-bit.
const curatedLists = readStatic("curated-lists.json", []) as Array<Record<string, unknown>>;
const CURATED_DEFAULT_IMAGE = "DefaultRoomImage.jpg";
const CURATED_PLACEHOLDER_IMAGE = "DefaultListImage.jpg";
const CURATED_PLACEHOLDER_CREATED_AT = "2026-08-24T18:44:52.438Z";
const curatedListPlaceholder = (creator: number, type: number, name: string) => ({
  ListId: 1,
  CreatorAccountId: creator,
  Name: name,
  Description: null,
  ImageName: CURATED_PLACEHOLDER_IMAGE,
  Type: type,
  ItemIds: [] as Array<unknown>,
  Accessibility: 0,
  CreatedAt: CURATED_PLACEHOLDER_CREATED_AT,
});
route("GET", "/curatedlists", (c) => {
  const typeRaw = Number.parseInt(c.query.get("type") ?? "", 10);
  const type = Number.isInteger(typeRaw) ? typeRaw : 0;
  const creatorId = Number.parseInt(c.query.get("creatorAccountId") ?? "", 10) || 0;
  const name = c.query.get("name") ?? "";
  const key = name.toLowerCase();
  const hit =
    key !== "" ? curatedLists.find((l) => String(l.Name).toLowerCase() === key) : undefined;
  let list: Record<string, unknown>;
  if (hit) {
    list = hit;
  } else if (name.startsWith("__")) {
    // Reserved playlist nobody owns yet: served EMPTY, room image, Accessibility 1.
    list = {
      ListId: 0,
      CreatorAccountId: creatorId,
      Name: name,
      Description: null,
      ImageName: CURATED_DEFAULT_IMAGE,
      Type: type,
      ItemIds: [],
      Accessibility: 1,
      CreatedAt: new Date(0).toISOString(),
    };
  } else if (name === "") {
    // No list named: the page default for the type — the first capture there is.
    if (curatedLists.length > 0) {
      list = curatedLists[0];
    } else {
      list = curatedListPlaceholder(creatorId, type, name);
    }
  } else {
    // No such list: a well-formed but EMPTY placeholder — a {} or 404 breaks the client.
    list = curatedListPlaceholder(creatorId, type, name);
  }
  sendWithListIds(c, list);
});

// --- community board (the reference apps/api routes/gameplay.ts "/api/communityboard/v2/
// current" — the bundled static blob, verbatim, same for everybody, no auth) ---
route("GET", "/api/communityboard/v2/current", (c) => {
  const board = readStatic("community-board.json", null);
  if (board === null) return c.send(200, {});
  c.send(200, board);
});

// --- cards / accounts ---
// No external channels linked → [] (the reference apps/api routes/account.ts
// "/iam/me/channels/:type"); the {type} is accepted and not inspected.
route("GET", "/iam/me/channels/{type}", (c) => c.send(200, []));

// --- econ: inventory stubs (all [] for an account that has bought nothing) ---
route("GET", "/api/consumables/v2/getUnlocked", (c) => {
  if (!c.authUser) return c.send(401, {});
  c.send(200, []);
});
route("GET", "/api/equipment/v2/getUnlocked", (c) => {
  if (!c.authUser) return c.send(401, {});
  c.send(200, []);
});
// Pending game rewards (the reference econ.app.ts "/api/gamerewards/v1/pending").
route("GET", "/api/gamerewards/v1/pending", (c) => c.send(200, []));
// Every key the caller holds across all rooms (the reference econ.app.ts
// "/api/roomkeys/v1/mine") — none bought/awarded → [].
route("GET", "/api/roomkeys/v1/mine", (c) => {
  if (!c.authUser) return c.send(401, {});
  c.send(200, []);
});
// Room-currency balances by room: empty stub (the reference econ.app.ts
// "/api/roomcurrencies/v1/getAllBalances").
route("GET", "/api/roomcurrencies/v1/getAllBalances", (c) => c.send(200, []));
// The caller's own holdings of a room's consumables (the reference econ.app.ts
// ".../roomConsumable/room/:roomId/me": a bare array — a bare array; none → []).
route("GET", "/api/roomconsumables/v1/roomConsumable/room/{roomId}/me", (c) => {
  if (!c.authUser) return c.send(401, {});
  c.send(200, []);
});
// Objectives progress: the bundled default verbatim, no auth (the reference econ.app.ts
// "/api/objectives/v1/myprogress", apps/econ/static/my-progress.json).
route("GET", "/api/objectives/v1/myprogress", (c) => {
  const p = readStatic("my-progress.json", null);
  if (p === null) return c.send(200, { Objectives: [], ObjectiveGroups: [] });
  c.send(200, p);
});
// Player events: created + RSVPs (the reference apps/api openapi.ts PlayerEventsAll = the
// envelope {Created, Responses}) — none of either for a fresh account.
route("GET", "/api/playerevents/v1/all", (c) => {
  if (!c.authUser) return c.send(401, {});
  c.send(200, { Created: [], Responses: [] });
});
// Speech-to-text config; Enabled:false here, Key/Region still present (the reference apps/api
// routes/config.ts "/api/config/v1/azurespeech").
route("GET", "/api/config/v1/azurespeech", (c) =>
  c.send(200, { Key: "dce8de5b297747d9b5bddcc7f19e8c5b", Region: "eastus", Enabled: false }));
// Voice-moderation vendor credentials (the reference apps/moderation moderation.app.ts
// "/voice/config") — empty means "voice moderation off", but both keys must be present
// STRINGS; a null trips the client's parser. AccountId is a STRING even though it reads
// numeric.
route("GET", "/voice/config", (c) => c.send(200, { AccountId: "", ApiKey: "" }));

// --- events / campaigns / circuits ---
// Purchase campaigns (the reference apps/commerce "/purchasecampaign/allcurrent/v2"): none.
route("GET", "/purchasecampaign/allcurrent/v2", (c) => c.send(200, []));
// Maker Pen circuit palettes (the reference apps/api routes/gameplay.ts
// "/api/CircuitChipLists/:list"): nothing records favourites → always []; an unknown
// palette name is [] too, NOT a 404 (a 404 shows as a failed palette).
route("GET", "/api/CircuitChipLists/{list}", (c) => c.send(200, []));
// The active progression event: a BARE event id (the reference apps/api routes/progression.ts
// "/api/progressionEvents/active" stub = 18). A 404 would stall the load.
route("GET", "/api/progressionEvents/active", (c) => c.send(200, 18));

// One progression event's definition (the reference apps/api routes/progression.ts
// "/api/progressionEvents/event/:id{[0-9]+}"). The archived official event, verbatim from
// static/progression-events/ (copied from the reference's apps/api/static archive — ids
// 2-9 and 12-18; 1, 4, 10, 11 are gaps in the reference archive too).
// Served AS RAW TEXT, not parsed + re-stringified: a keepsake room's RoomId is a 64-bit
// number (8364812036745705361) that a JS round-trip rounds to a different room. 404 for an
// id the archive does not hold (EMPTY body — c.body(null, 404), not a JSON error). No auth:
// it is the same record for everybody.
const rawStaticText = (name: string): string | null => {
  try {
    return readFileSync(path.join(STATIC, name), "utf8");
  } catch {
    return null;
  }
};
const PROGRESSION_EVENTS: Array<[number, string]> = [
  [2, "Coming_in_Hot_Progression_Event_Alpha_EventId_2.json"],
  [3, "Rec_Room_EventId_3.json"],
  [5, "Progression_Event_Alpha_Repeat_EventId_5.json"],
  [6, "Invasion_EventId_6.json"],
  [7, "Science_Party_EventId_7.json"],
  [8, "Base_Event_EventId_8.json"],
  [9, "Invasion_2_EventId_9.json"],
  [12, "Science_Experiment_Restoration_EventId_12.json"],
  [13, "Anime_Season_EventId_13.json"],
  [14, "Summer_Party_EventId_14.json"],
  [15, "Medieval_Season_EventId_15.json"],
  [16, "Treat_Collection_Challenge_EventId_16.json"],
  [17, "Tricks_Challenge_EventId_17.json"],
  [18, "Yetis_Challenge_EventId_18.json"],
];
const progressionEventById = new Map(PROGRESSION_EVENTS);
route("GET", "/api/progressionEvents/event/{id}", (c) => {
  const id = Number.parseInt(c.path.split("/").pop() ?? "", 10);
  const file = progressionEventById.get(id);
  const text = file ? rawStaticText(`progression-events/${file}`) : null;
  if (text === null) {
    // 404 with NO body (the reference's `c.body(null, 404)`), not a JSON error object.
    c.res.setHeader("content-length", "0");
    c.res.writeHead(404);
    c.res.end();
    return;
  }
  c.res.setHeader("content-type", "application/json; charset=utf-8");
  c.res.setHeader("x-uwunet", "uwunet");
  c.res.setHeader("content-length", String(Buffer.byteLength(text, "utf8")));
  c.res.writeHead(200);
  c.res.end(text);
});
// The caller's progress through one progression event (same route, "/record/:id{[0-9]+}").
// STUB like the reference: every counter 0 for any id, echoing the id requested — nothing
// tracks progress through an event here either (the /active stub above is bare 18). Auth-
// gated because the record is the CALLER's and the path names no player.
route("GET", "/api/progressionEvents/record/{id}", (c) => {
  if (!c.authUser) return c.send(401, {}); // reference: 401 with empty body
  c.send(200, {
    AccountId: selfPlayerId(c),
    ProgressionEventId: Number.parseInt(c.path.split("/").pop() ?? "", 10) || 0,
    Xp: 0,
    GameMinutesToday: 0,
    RewardsCollected: 0,
    BonusRewardsCollected: 0,
    XpBoostLastPurchasedAt: null,
    PremiumRewardsCollected: 0,
    LimitedRewardCollectionState: 0,
  });
});

// --- clubs.rec.net ---
// No home club: the client EXPECTS a 404 here and errors on an empty object (the reference
// apps/clubs "/club/home/me" GET — the bare club when set, c.notFound() otherwise).
route("GET", "/club/home/me", (c) => {
  if (!c.authUser) return c.send(401, {});
  // the reference 404s a home club with {"success":false,"error":{"message":"not found"}}.
  c.send(404, { success: false, error: { message: "not found" } });
});

// --- moderation: vote-to-kick reasons (the reference apps/api routes/moderation.ts
// VOTE_TO_KICK_REASONS — the order IS the render order; hate, sexual, griefing, conduct) ---
route("GET", "/api/PlayerReporting/v1/voteToKickReasons", (c) => {
  if (!c.authUser) return c.send(401, {});
  c.send(200, [
    { Reason: "Discriminatory language", ReportCategory: 102 },
    { Reason: "Discriminatory behavior", ReportCategory: 102 },
    { Reason: "Threats or encouraging suicide", ReportCategory: 102 },
    { Reason: "Toxic behavior", ReportCategory: 102 },
    { Reason: "Sexual behavior in public", ReportCategory: 101 },
    { Reason: "Sexual language in public", ReportCategory: 101 },
    { Reason: "Non-consensual sexual behavior", ReportCategory: 101 },
    { Reason: "Player in walls or floor", ReportCategory: 103 },
    { Reason: "Friendly fire", ReportCategory: 103 },
    { Reason: "Microphone spam", ReportCategory: 103 },
    { Reason: "Abusing bugs or exploits", ReportCategory: 103 },
    { Reason: "Spawn camping", ReportCategory: 103 },
    { Reason: "Inactive in games (AFK)", ReportCategory: 6 },
    { Reason: "Prefab swapping", ReportCategory: 6 },
    { Reason: "Not following game rules", ReportCategory: 6 },
  ]);
});

// --- rooms.rec.net discovery (the reference apps/rooms rooms.app.ts) ---
// "Hot" rooms feed ("/rooms/hot", params tag/skip/take — take defaults 100). The shape is
// the PAGED one, { Results, TotalResults } (RoomDto[] page — see the reference's
// integration test "GET /rooms/hot returns a paginated { Results, TotalResults }"), NOT a
// bare array (rooms/ownedby/me-style [] here would malform the browse screen's paged reader).
route("GET", "/rooms/hot", (c) => {
  const tag = c.query.get("tag") ?? "";
  const skip = Number.parseInt(c.query.get("skip") ?? "0", 10) || 0;
  const take = Number.parseInt(c.query.get("take") ?? "100", 10) || 100;
  log({ event: "rooms-hot", tag, skip, take });
  // The RROs + Rec Center are our "hot" rooms, paged. This is how they show up in the room
  // browser so the player can tap in (matchmake into them via /matchmake/room/{id}). A tag
  // with its own row in static/room-rows.json is served from it — Play > Explore's first row
  // is Hot/`new`, and it is a DEDUPE source (gameconfig PlayMenuDedupeSources), so serving
  // every RRO there would empty the category rows under it. Deliberate deviation: the
  // reference's tag=new excludes RROs entirely. Every other tag (rro, empty, …) is unchanged.
  // An EMPTY row (e.g. staffpicks) falls back too: before rows existed every tag got every RRO.
  const rowIds = tag ? roomRowIds(tag) : undefined;
  const all = rowIds?.length ? rowIds.map((id) => roomDtoFor(id)) : rroDtoList();
  c.send(200, { Results: all.slice(skip, skip + take), TotalResults: all.length });
});
// A CarouselEndpoint row asked of the rooms worker by slug (the reference rooms.app.ts
// "/rooms/carousel/rising" — "the one the client asks for by name"; paged like /rooms/hot,
// take defaults 100). Defensive: which host a CarouselEndpoint row hits is unconfirmed, so
// the same editorial rows as /algorithmiclists answer here. Unknown slug → an EMPTY page
// (not the reference's 404, which renders as a failed carousel). MUST sit before /rooms/**.
route("GET", "/rooms/carousel/{slug}", (c) => {
  let slug = "";
  try {
    slug = decodeURIComponent(c.path.split("/").pop() ?? "");
  } catch { /* malformed escape — unknown slug */ }
  const skip = Number.parseInt(c.query.get("skip") ?? "0", 10) || 0;
  const take = Number.parseInt(c.query.get("take") ?? "100", 10) || 100;
  log({ event: "rooms-carousel", slug, skip, take });
  const all = (roomRowIds(slug) ?? []).map((id) => roomDtoFor(id));
  c.send(200, { Results: all.slice(skip, skip + take), TotalResults: all.length });
});

// GET /rooms/search/name + /rooms/search — name search over the RROs (+ the Rec Center), so a
// player can find a first-party room by name and tap in. Paged shape like /rooms/hot.
const rroSearch = (c: Ctx) => {
  const q = (c.query.get("query") ?? c.query.get("name") ?? "").toLowerCase();
  const take = Number.parseInt(c.query.get("take") ?? "50", 10) || 50;
  const all = rroDtoList().filter(
    (d) => !q || String((d as Record<string, unknown>).Name ?? "").toLowerCase().includes(q),
  );
  c.send(200, { Results: all.slice(0, take), TotalResults: all.length });
};
route("GET", "/rooms/search/name", rroSearch);
route("GET", "/rooms/search", rroSearch);

// GET /rooms/featuredrooms/current — a single always-active featured group. Auth-gated
// (the build is read off the token, so no token is a 401: {error:"Unauthorized"} per the
// rooms worker's `unauthorized`), and gated on the token's BUILD — serve only to the
// FEATURED_ROOMS_VERSIONS allow-list (the reference's, verbatim); other builds get the
// plain 404 the path gave while it was parked, because this payload breaks the 2023
// client's other room listings. The bare `YYYYMMDD` mirrors authedGameVersion (every
// point release of it is the same build). Nothing else is per-player: with nothing
// published here the group is VALID but empty.
const FEATURED_ROOMS_VERSIONS: ReadonlySet<string> = new Set(["20250718"]);
route("GET", "/rooms/featuredrooms/current", (c) => {
  if (!c.authUser) return c.send(401, { error: "Unauthorized" });
  const tok = c.req.headers.authorization!.slice(7);
  let claims: Record<string, unknown> = {};
  try {
    claims = JSON.parse(Buffer.from(tok.split(".")[1], "base64url").toString("utf8"));
  } catch {}
  const raw = String(claims["rn.ver"] ?? "");
  const version = raw.split(/[.-]/)[0] ?? "";
  if (!FEATURED_ROOMS_VERSIONS.has(version)) {
    // 404 with NO body (c.notFound() in the reference).
    c.res.setHeader("content-length", "0");
    c.res.writeHead(404);
    c.res.end();
    return;
  }
  c.send(200, {
    FeaturedRoomGroupId: 1,
    name: "Featured Rooms",
    StartAt: "2025-12-01T11:01:00Z", // getFeaturedRooms' fixed stub window
    EndAt: "9999-12-08T11:00:00Z",
    Rooms: [], // nothing published here yet
  });
});

// Sub-room saves — the client fetches the published save's metadata here to get the scene-data
// blob (DataBlob) before downloading it from /room/{blob}. MUST sit before the /rooms/** catch-
// all (first-match-wins) or it 404s "no such room" and the join aborts (match reportjoinresult
// error_code 8700). Only RROs with a baked save (e.g. MakeItToMidnight, room 20930) resolve a
// save; the rest have none. Order here matters: the literal `no_unity_assets` list must precede
// the numeric `{saveId}` detail — the detail's regex pins to digits so the list path can't fall
// into it, but registration order settles it first anyway.
const SUBROOM_SAVES_PAGE = { Results: [], TotalResults: 0, TotalCount: 0 };
route("GET", "/rooms/{roomId}/subrooms/{subRoomId}/saves/no_unity_assets", (c) => {
  if (!c.authUser) return c.send(401, {});
  // A published RRO carries its CurrentSave in the room DTO, so the history list isn't needed to
  // play — answer the reference's empty page (unknown room/subroom is a page, never a 404).
  c.send(200, SUBROOM_SAVES_PAGE);
});
route("GET", "/rooms/{roomId}/subrooms/{subRoomId}/saves/{saveId}", (c) => {
  if (!c.authUser) return c.send(401, {});
  const m = /^\/rooms\/(\d+)\/subrooms\/(\d+)\/saves\/(\d+)$/.exec(c.path);
  if (!m) return c.send(404, { Code: 404, Error: "no such save" });
  const save = rroSubRoomSave(m[1], m[2]);
  if (!save || Number(save.SubRoomDataSaveId) !== Number.parseInt(m[3], 10)) {
    return c.send(404, { Code: 404, Error: "no such save" });
  }
  const t = Number.parseInt(c.query.get("unityAssetTarget") ?? "", 10);
  c.send(200, subRoomSaveDetail(save, Number.isInteger(t) ? t : 0));
});
route("GET", "/rooms/{roomId}/subrooms/{subRoomId}/saves", (c) => {
  if (!c.authUser) return c.send(401, {});
  c.send(200, SUBROOM_SAVES_PAGE);
});

// GET /rooms/{id} — during "preparing", the client fetches the full Room to build the scene
// (subrooms, save). We serve the caller's dorm (roomId == their account id, set in matchmake).
route("GET", "/rooms/**", (c) => {
  // Only the bare `/rooms/<number>` form is a room fetch; sub-paths (boosts, interactions)
  // and non-numeric ids (bulk, named/*) stay tolerated 404s.
  const m = /^\/rooms\/(\d+)$/.exec(c.path);
  if (!m) return c.send(404, { Code: 404, Error: "no such room" });
  const id = m[1]; // string-exact: 64-bit room ids round as Numbers
  const u = userById(id);
  c.send(200, roomDtoFor(id));
});

// --- notify.rec.net (SignalR hub negotiate; the WS itself is not up yet) ---
route("POST", "/hub/v1/negotiate", (c) => {
  const negotiateVersion = Number(c.query.get("negotiateVersion")) || 0;
  const id = crypto.randomUUID();
  c.send(200, {
    negotiateVersion,
    connectionId: id,
    connectionToken: id,
    availableTransports: [{ transport: "WebSockets", transferFormats: ["Text"] }],
  });
});

// --- clubs.rec.net ---
route("GET", "/subscription/mine/member", (c) => c.send(200, [])); // [] when none / unauth
// Subscription details for an account: their subscription club + subscriber count.
// A fresh account has no subscription club yet -> clubId 0, no subscribers.
route("GET", "/subscription/details/**", (c) => {
  const id = Number.parseInt(c.path.split("/").pop() ?? "", 10);
  c.send(200, {
    AccountId: Number.isNaN(id) ? 0 : id,
    ClubId: 0,
    SubscriberCount: 0,
  });
});
// Deep-link pageview consume: nothing pending for us.
route("POST", "/pageview/consume", (c) => c.send(200, {}));

// --- playersettings.rec.net ---
route("GET", "/playersettings", (c) => {
  if (!c.authUser) return c.send(401, {});
  // the reference's live payload for a brand-new account (recorded verbatim): the OOBE
  // and orientation-complete keys. With [] the client treats itself as mid-tutorial,
  // which strands the room-load spawn chain (fading camera never resolves).
  const id = Number(c.authUser.Id ?? c.authUser.accountId ?? selfPlayerId(c) ?? 0);
  const setting = (Key: string, Value: string) => ({ PlayerId: id, Key, Value });
  c.send(200, [
    setting("Recroom.OOBE", "77"),
    setting("TUTORIAL_COMPLETE_MASK", "43"),
    setting("FIRST_TIME_IN_FLAGS", "0"),
    setting("Recroom.AccountCreation.HasStarted", "True"),
    setting("Recroom.AccountCreation.HasFinished", "True"),
    setting("Recroom.AccountCreation.HasChosenUsername", "True"),
    setting("Recroom.AccountCreation.HasCreatedPassword", "True"),
    setting("Recroom.AccountCreation.AcceptedCodeOfConduct", "True"),
    setting("LastSelectedLocale", "en"),
    setting("PlayerSessionCount", "2"),
    setting("accepted_user_agreements", "True"),
    setting("Growth.LastEmailPromptTime", new Date().toISOString()),
    setting("HAS_RECEIVED_WATCH", "True"),
    setting("HAS_COMPLETED_ORIENTATION", "True"),
    setting("OrientationCompletionTime", new Date().toISOString()),
    setting("PurchaseCampaignShowTriggerDebugText", "False"),
    setting("THIRD_PERSON_PREFERENCE", "False"),
    setting("MakerPen_GridSnap_V2", "0.5"),
    setting("MakerPen_AngleSnap_V2", "45"),
    setting("BACKPACK_FAVORITE_TOOL", "-1"),
    setting("HasCheckedForPlatformReferrers", "True"),
    setting("HAS_OPENED_WATCH_MENU_BEFORE", "True"),
    setting("SCREENS_HEAD_BOB", "1"),
    setting("AutosaveInterval", "300"),
  ]);
});
// PUT upserts settings; the reference returns the settings ARRAY ([{PlayerId,Key,Value}]), not {}.
// We don't persist, so echo an empty array (correct type — the client parses a list).
route("PUT", "/playersettings", (c) => c.send(200, []));

// --- platformnotifications.rec.net ---
route("GET", "/crm/me/config/v3", (c) => {
  if (!c.authUser) return c.send(401, {});
  c.send(200, {
    Value: {
      UserConfig: {
        AssignedCrmType: 0,
        AssignedPushNotificationService: null,
        AllowPush: false,
      },
      BrazeConfig: null,
    },
    Success: true,
    Error: null,
    error_id: null,
  });
});
route("GET", "/preferences", (c) => c.send(200, { MutedCategories: [] }));

// --- rooms.rec.net ---
route("GET", "/publishState/configs", (c) =>
  c.send(200, {
    value: {
      UpdateMaxCount: 3,
      UpdateRollingWindowInDays: 365,
      UpdateExpirationInDays: 30,
      UpdateCooldownInDays: 45,
    },
    success: true,
    error_id: null,
    error: null,
  }),
);

// --- econ.rec.net ---
route("GET", "/api/avatar/v4/items", (c) => {
  if (!c.authUser) return c.send(401, {});
  c.send(200, avatarV4Catalog); // owned (none yet) + default catalog, projected to v4
});
// Owned custom avatar items: paginated envelope, empty for a fresh account.
route("GET", "/econ/customAvatarItems/v1/owned", (c) => {
  if (!c.authUser) return c.send(401, {});
  c.send(200, { Results: [], TotalResults: 0 });
});
route("GET", "/api/storefronts/v4/balance/**", (c) => {
  if (!c.authUser) return c.send(401, {});
  const currencyType = Number.parseInt(c.path.split("/").pop() ?? "", 10);
  if (Number.isNaN(currencyType)) return c.send(400, {});
  c.send(200, [{ Balance: 0, CurrencyType: currencyType, Platform: -2 }]);
});

// --- api.rec.net (legacy monolith surface) ---
route("GET", "/api/customAvatarItems/v1/isCreationAllowedForAccount", (c) =>
  c.send(200, { success: true, value: null }),
);
route("GET", "/api/customAvatarItems/v1/isCreationEnabled", (c) => c.send(200, true));
route("GET", "/api/customAvatarItems/v1/isRenderingEnabled", (c) => c.send(200, true));
// Resolve custom-avatar-item ids to items: a BARE ARRAY of the ones that matched,
// in request order (the reference apps/api/src/routes/avatar.ts). Unknown ids are simply
// absent — a miss is NOT an error and the client reads the items it got back.
const bulkCustomItems = (c: Ctx) => {
  const ids: string[] = [...c.query.getAll("customAvatarItemIds")];
  if (c.body) {
    try {
      for (const [k, v] of new URLSearchParams(c.body)) {
        if (k.toLowerCase() === "customavataritemids") ids.push(v);
      }
    } catch {}
  }
  const wanted = ids.flatMap((v) => v.split(",")).map((v) => v.trim()).filter(Boolean);
  const seen = new Set<string>();
  const out: unknown[] = [];
  for (const id of wanted) {
    if (seen.has(id)) continue;
    seen.add(id);
    const it = customItemsById.get(id);
    if (it) out.push(it);
    // A miss is NOT an error: the reference's bulk omits unknown ids and the client reads
    // the items it got back. We USED to synthesize a fake item for a missing default
    // id (e.g. 5726c274 — which the reference itself returns "not found" for) by cloning a
    // real one under the requested id. The clone reused the source item's
    // CustomAvatarItemSaveId / UnityAssetId / assetbundle verbatim, so the client
    // received two items sharing one save+asset identity — a collision that corrupted
    // the in-room avatar assembly: the skeleton silently never built (black screen,
    // audible-but-invisible world). Omit misses, exactly like the reference.
  }
  c.send(200, out);
};
route("POST", "/api/customAvatarItems/v1/bulk", bulkCustomItems);
route("GET", "/api/customAvatarItems/v1/bulk", bulkCustomItems);
// Custom-item saves that replace legacy avatar items, keyed by AvatarItemDesc.
// Empty map = "render the legacy items as-is".
route("POST", "/api/customAvatarItems/GetCustomAvatarItemCurrentSavesForLegacyAvatarItems", (c) =>
  c.send(200, {}),
);
route("GET", "/api/customAvatarItems/GetCustomAvatarItemCurrentSavesForLegacyAvatarItems", (c) =>
  c.send(200, {}),
);
// Locked avatar items in bulk (empty for a fresh account).
route("POST", "/api/avatar/v1/lockeditems/bulk", (c) => c.send(200, []));
route("GET", "/api/avatar/v1/lockeditems/bulk", (c) => c.send(200, []));

// Inventions (reference apps/api routes/avatar.ts, tags:['Inventions']). The MAKER PEN
// builds its WHOLE palette (shapes + circuits + inventions) in one Promise.all / WhenAll;
// a 404 on ANY of these throws and rejects the WhenAll, so every tab comes up empty and
// the client stalls in WaitForShapes. Serve the reference's empty shapes so the palette
// builds: both are plain InventionDto arrays, empty when nobody has published anything.
route("GET", "/api/inventions/v2/search", (c) => c.send(200, [])); // browse/search → InventionDto[]
route("GET", "/api/inventions/v1/fromcreators", (c) => c.send(200, [])); // by-creator portfolio → []
route("GET", "/api/inventions/v2/mine", (c) => c.send(200, [])); // caller's own drafts → []
// A creator's custom avatar items (reference CustomAvatarItemsPage) — the client fetches
// this for other players/creators (e.g. 1000001). Page shape: TotalResults = Results.length.
route("GET", "/api/customAvatarItems/v2/fromCreator/{accountId}", (c) =>
  c.send(200, { Results: [], TotalResults: 0 }),
);
// Item wishlist for an account (empty for everyone here).
route("GET", "/api/itemWishlists/v1/wishlist/{accountId}", (c) => c.send(200, []));

// progression bulk: GET returns a default progression per id; POST returns [].
route("GET", "/api/players/v2/progression/bulk", (c) =>
  c.send(200, parseIds(c).map((id) => ({ PlayerId: id, Level: 1, XP: 0 }))),
);
route("POST", "/api/players/v2/progression/bulk", (c) => c.send(200, []));
route("GET", "/api/players/v1/progression/bulk", (c) =>
  c.send(200, parseIds(c).map((id) => ({ PlayerId: id, Level: 1, XP: 0 }))),
);
route("POST", "/api/players/v1/progression/bulk", (c) => c.send(200, []));

// reputation bulk: one all-zero record per requested id (client renders a card each).
const defaultReputation = (id: number) => ({
  AccountId: id,
  IsCheerful: true,
  Noteriety: 0,
  SelectedCheer: 0,
  CheerCredit: 20,
  CheerGeneral: 0,
  CheerHelpful: 0,
  CheerCreative: 0,
  CheerGreatHost: 0,
  CheerSportsman: 0,
  SubscriberCount: 0,
  SubscribedCount: 0,
});
const reputationBulk = (c: Ctx) =>
  c.send(200, parseIds(c).map(defaultReputation));
route("GET", "/api/playerReputation/v2/bulk", reputationBulk);
route("POST", "/api/playerReputation/v2/bulk", reputationBulk);

// outfits/me: the stored worn outfit in the NEWER envelope (StoredOutfit), with a
// populated `LegacyData` object. The client's OutfitManager.GetAndApplyUnknownAvatarItems
// reads outfit.LegacyData and throws "Expected LegacyData but was null" if it's absent —
// which is why the old flat EmptyOutfit shape ({OutfitSelections,FaceFeatures,...}) failed.
// Shape per the reference server apps/api/src/openapi.ts (StoredOutfit). LegacyData.SelectionsV1
// is the semicolon-delimited legacy descriptor string (our flat OutfitSelections).
const storedOutfit = () => ({
  // the reference's brand-new-account envelope is the FLAT four-empty-strings shape — the
  // client bootstraps its own default doll from built-ins when everything is empty. A
  // crafted default (with real selections) instead applies something the rig may not
  // resolve, leaving the fade camera without its target (black screen).
  FaceFeatures: "",
  HairColor: "",
  OutfitSelections: "",
  SkinColor: "",
});
// Per-player worn outfit (slot 0). The client builds/normalizes its avatar on spawn and
// PUTs the result here; a 404 on that write left the avatar unestablished (no skeleton, so
// the head-pivot camera renders black). We store it and read it back, like the reference's
// `outfit` table. PERSISTED to the DB (db.outfits[id]) so the avatar survives an edge restart
// — it used to live in an in-memory map and reverted to default on every deploy/reboot.
// Nothing saved yet → the default outfit.
const getOutfit = (id: number): Record<string, unknown> | undefined => db.outfits?.[String(id)];
route("GET", "/outfits/me", (c) => {
  if (!c.authUser) return c.send(401, {});
  c.send(200, getOutfit(selfPlayerId(c)) ?? storedOutfit());
});
// Save the caller's outfit. the reference stores the body verbatim in the slot it names (slot 0 =
// worn, what GET reads) and answers the base envelope WITHOUT a Value — the outfit is not
// echoed. Lenient on an unparseable body: still ack, so the avatar apply never stalls here.
route("PUT", "/outfits/me", (c) => {
  if (!c.authUser) return c.send(401, {});
  try {
    const body = c.body ? (JSON.parse(c.body) as Record<string, unknown>) : null;
    if (body && (typeof body.Slot !== "number" || body.Slot === 0)) {
      (db.outfits ??= {})[String(selfPlayerId(c))] = body;
      saveDb(); // persist so the avatar survives an edge restart
    }
  } catch { /* unparseable — still ack */ }
  // the reference answers the bare { Success, Error, error_id } envelope — NOT { Success, Slot }.
  c.send(200, { Success: true, Error: null, error_id: null });
});
// The wardrobe list behind the newer outfit screen (2025 client): every saved slot, ordered,
// slot 0 included, `[]` when none — same table PUT /outfits/me writes.
route("GET", "/outfits/me/saved", (c) => {
  if (!c.authUser) return c.send(401, []);
  const o = getOutfit(selfPlayerId(c));
  c.send(200, o ? [o] : []);
});
// Pending avatar gift boxes — none (no purchases/gifting). A JSON array; the client opens
// each via /api/avatar/v2/gifts/consume.
route("GET", "/api/avatar/v2/gifts", (c) => c.send(200, []));

// moderation: "not blocked" / "not a referee".
const NOT_BLOCKED = {
  ReportCategory: -1,
  Duration: 0,
  GameSessionId: 0,
  IsHostKick: false,
  Message: null,
  PlayerIdReporter: null,
  IsBan: false,
  IsVoiceModAutoban: false,
  IsDeviceBan: false,
  IsWarning: false,
  VoteKickReason: null,
  TimeoutStartedAt: null,
  AssociatedAccountUsername: null,
  ShowCreatorCodeOfConduct: false,
  TopMessageOverride: null,
  BottomMessageOverride: null,
};
route("GET", "/api/PlayerReporting/v1/moderationBlockDetails", (c) => c.send(200, NOT_BLOCKED));
route("POST", "/api/PlayerReporting/v1/moderationBlockDetails", (c) => c.send(200, NOT_BLOCKED));
route("GET", "/api/PlayerReporting/v1/referee", (c) => c.send(200, false));
route("POST", "/api/PlayerReporting/v1/referee", (c) => c.send(200, false));
// PlayerReporting /hile — the reference's live server returns a bare `false`. Must be 200: a 404
// here throws during room-load and quits the app (see AI block below).
route("POST", "/api/PlayerReporting/v1/hile", (c) => c.send(200, false));

// --- 2025 AI features (ai.rec.net / lists.rec.net) ---
// The client checks AI access/budget during boot AND during room load
// (GET /gameai/user/access?roomId=13 fires while loading Orientation). the reference serves all of
// these as 200s; a 404 throws an unobserved HTTP exception that, inside the room-load critical
// section (OperationContext.PauseNetworking "InitialLoad"), escalates to AppExitState
// Running=>PreparingToExit — the client quit mid-Orientation-load. Shapes are verbatim from
// the reference server apps/ai/src/ai.app.ts + apps/lists/src/lists.app.ts. No AI backend exists;
// Game AI is refused with a 200 (success:false), Roomie/Maker report budget so the client does
// not take a hard-failure path.
const GAME_AI_UNSUPPORTED = {
  success: false,
  error_id: "AI.RoomDoesNotSupportGameAI",
  error: "This room does not support Rec Room Game AI",
};
const INT32_MAX = 2147483647;
route("GET", "/gameai/user/access", (c) => c.send(200, GAME_AI_UNSUPPORTED));
route("GET", "/gameai/room/{roomId}/spendsummary", (c) => c.send(200, { ...GAME_AI_UNSUPPORTED, value: null }));
// Roomie AI access — our build (20250718.01, not 20260323) takes the "granted, max energy"
// branch so the client's no-credit path is never entered.
route("GET", "/roomieai/user/access", (c) =>
  c.send(200, {
    success: true,
    error_id: null,
    error: null,
    value: {
      MaxEnergyFromSubscriptions: INT32_MAX,
      EnergyLeft: INT32_MAX,
      NextSubscriptionEnergyRechargeAt: null,
      OutputAudioEnabled: true,
    },
  }));
route("GET", "/roomieai/user/facts", (c) => c.send(200, { UserContext: "", UserFacts: [] }));
route("POST", "/roomieai/realtime-session/create", (c) =>
  c.send(200, { success: false, error_id: "", error: "AI conversation is unavailable.", value: null }));
route("GET", "/makerai/user/access", (c) => c.send(200, { Success: true, Error: null, error_id: null }));
route("GET", "/makerai/user/balances", (c) =>
  c.send(200, {
    UsageDollars: 0,
    UsersMaxUsageDollars: 0,
    RRPlusUsageDollars: 0,
    UsersMaxRRPlusUsageDollars: 0,
    TimeBalanceStatus: "Empty",
    TimeExpiresAt: "0001-01-01T00:00:00",
    UsageBalanceStatus: "Good",
    UsagePercent: 0,
    RRPlusUsageBalanceStatus: "Good",
    RRPlusUsagePercent: 0,
  }));
// contextualfeatures (lists.rec.net) — bare ack; client POSTs its context, reads back only
// whether the post was accepted.
route("POST", "/contextualfeatures", (c) => c.send(200, { success: true, error_id: null, error: null }));

// --- 2025 room economy (econ.rec.net) ---
// The player SPAWN reads room economy data. the reference serves these as 200s; a 404 makes
// RecRoom.Systems.Economy.RoomKeys.RoomKeysManager THROW, which RoomLoad reports as
// FailedToSpawnPlayer (Code 8700) — the player never enters and the client loops
// Orientation<->Dorm. Shapes from the reference server apps/econ/src/econ.app.ts: an empty room is
// empty collections. (Serving these is what let us get past the room-load exit wall.)
route("GET", "/api/roomkeys/v1/room", (c) => c.send(200, []));
route("GET", "/api/roomcurrencies/v1/currencies", (c) => c.send(200, []));
route("GET", "/api/roomconsumables/v1/roomConsumable/room/{roomId}", (c) => c.send(200, []));
route("GET", "/api/ugcPurchasables/v1/items/room/{roomId}", (c) => c.send(200, []));
route("GET", "/econ/roomInventory/room/{roomId}", (c) => c.send(200, []));
route("GET", "/econ/roomInventory/room/{roomId}/player", (c) => c.send(200, []));
route("GET", "/econ/roomInventoryItemTags/room/{roomId}", (c) => c.send(200, []));
route("GET", "/econ/roomOffer/room/{roomId}", (c) => c.send(200, []));
route("GET", "/econ/roomOffer/room/{roomId}/purchaseCounts", (c) =>
  c.send(200, { Value: [], Success: true, Error: null, error_id: null }));
route("GET", "/econ/roomGiftDropShops/room/{roomId}", (c) => c.send(200, []));
route("GET", "/econ/roomEconConfig/{roomId}", (c) => {
  const m = /\/roomEconConfig\/(\d+)/.exec(c.path);
  c.send(200, { RoomId: m ? Number(m[1]) : 0, EnableSortingTabs: false });
});
// CampusCard (RR+ subscription) — a non-subscriber gets an empty object.
route("GET", "/api/CampusCard/v1/UpdateAndGetSubscription", (c) => c.send(200, {}));

// --- boot/PLAY peripherals (shapes from the reference server apps/api openapi.ts) ---
// QuickPlay: a pending quick-play action; all-null = none pending. Checked on PLAY.
route("GET", "/api/quickPlay/v1/getandclear", (c) =>
  c.send(200, { RoomName: null, ActionCode: null, TargetPlayerId: null }));
// Crash-reporter config (Backtrace). Sensible defaults; keeps boot from 404ing here.
route("GET", "/api/config/v1/backtrace", (c) =>
  c.send(200, {
    ReportBudget: 0,
    FilterType: 0,
    SampleRate: 0,
    LogLineCount: 0,
    CaptureNativeCrashes: 0,
    ANRThresholdMs: 0,
    MessageCount: 0,
    MessageRegex: "",
    VersionRegex: "",
  }));
// Messages inbox — empty for a fresh account.
route("GET", "/api/messages/v2/get", (c) => c.send(200, []));
// --- relationships (the friend graph behind the Friends tab) --------------------------------
// RelationshipType on the wire: 0=none, 1=request sent, 2=request received, 3=friends. The DTO
// is the relationship from the CALLER's point of view (PlayerID is the OTHER player).
const REL_NONE = 0, REL_SENT = 1, REL_RECV = 2, REL_FRIEND = 3;
type RelDto = { PlayerID: number; RelationshipType: number; Favorited: number; Ignored: number; Muted: number };
const relFor = (a: number, b: number): Rel | undefined => db.relationships?.[String(a)]?.[String(b)];
function relSet(a: number, b: number, patch: Partial<Rel>) {
  (db.relationships ??= {});
  const ka = String(a);
  (db.relationships[ka] ??= {});
  const cur = db.relationships[ka][String(b)] ?? { type: REL_NONE, fav: 0, ign: 0, mut: 0 };
  db.relationships[ka][String(b)] = { ...cur, ...patch };
}
const relDto = (a: number, b: number): RelDto => {
  const r = relFor(a, b) ?? { type: REL_NONE, fav: 0, ign: 0, mut: 0 };
  return { PlayerID: b, RelationshipType: r.type, Favorited: r.fav, Ignored: r.ign, Muted: r.mut };
};
// Every edge the caller has an opinion about (a live type, or a surviving flag).
const relationshipsForPlayer = (id: number): RelDto[] =>
  Object.entries(db.relationships?.[String(id)] ?? {})
    .filter(([, r]) => r.type !== REL_NONE || r.fav || r.ign || r.mut)
    .map(([b]) => relDto(id, Number(b)));
// Friend-graph transitions. Edges are written on BOTH sides so each player's /get is a lookup.
function sendFriendRequest(id: number, target: number) {
  const t = relFor(id, target)?.type ?? REL_NONE;
  if (t === REL_FRIEND || t === REL_SENT) return; // no-op
  if (t === REL_RECV) { relSet(id, target, { type: REL_FRIEND }); relSet(target, id, { type: REL_FRIEND }); } // crossing -> auto-accept
  else { relSet(id, target, { type: REL_SENT }); relSet(target, id, { type: REL_RECV }); }
  saveDb();
}
function acceptFriendRequest(id: number, target: number) {
  if ((relFor(id, target)?.type ?? REL_NONE) !== REL_RECV) return; // nothing pending
  relSet(id, target, { type: REL_FRIEND }); relSet(target, id, { type: REL_FRIEND });
  saveDb();
}
function endFriendship(id: number, target: number) { // unfriend / cancel / decline
  relSet(id, target, { type: REL_NONE }); relSet(target, id, { type: REL_NONE });
  saveDb();
}
function makeFriends(id: number, target: number) { // direct add, no pending step
  relSet(id, target, { type: REL_FRIEND }); relSet(target, id, { type: REL_FRIEND });
  saveDb();
}
// Target player id for a mutation: ?playerId=/?id= query first, else the JSON/form body.
async function relTarget(c: Ctx): Promise<number | null> {
  const q = c.query.get("playerId") ?? c.query.get("id");
  if (q != null) { const n = Number.parseInt(q, 10); if (!Number.isNaN(n)) return n; }
  const b = await parseBodyJson(c);
  const v = b.playerId ?? b.id ?? b.PlayerId ?? b.PlayerID;
  if (v != null) { const n = Number.parseInt(String(v), 10); if (!Number.isNaN(n)) return n; }
  return null;
}
route("GET", "/api/relationships/v2/get", (c) => {
  if (!c.authUser) return c.send(401, {});
  c.send(200, relationshipsForPlayer(selfPlayerId(c)));
});
// Mutual friends with ?id= — the intersection of both players' friend sets.
route("GET", "/api/relationships/mutualfriends", async (c) => {
  if (!c.authUser) return c.send(401, {});
  const id = selfPlayerId(c);
  const target = await relTarget(c);
  if (target === null || target === id) return c.send(200, []);
  const friendsOf = (p: number) => new Set(
    relationshipsForPlayer(p).filter((r) => r.RelationshipType === REL_FRIEND).map((r) => r.PlayerID),
  );
  const mine = friendsOf(id), theirs = friendsOf(target);
  c.send(200, [...mine].filter((x) => theirs.has(x)));
});
// The four friend-graph mutations — GET and POST both, target via ?id=, returns caller's DTO.
const relMutation = (fn: (id: number, target: number) => void) => async (c: Ctx) => {
  if (!c.authUser) return c.send(401, {});
  const id = selfPlayerId(c);
  const target = await relTarget(c);
  if (target === null || target === id) return c.send(400, { error: "invalid player id" });
  fn(id, target);
  c.send(200, relDto(id, target));
};
for (const m of ["GET", "POST"]) {
  route(m, "/api/relationships/v2/sendfriendrequest", relMutation(sendFriendRequest));
  route(m, "/api/relationships/v2/acceptfriendrequest", relMutation(acceptFriendRequest));
  route(m, "/api/relationships/v2/removefriend", relMutation(endFriendship));
  route(m, "/api/relationships/v2/addfriend", relMutation(makeFriends));
}
// Per-side flags: ignore/mute/favorite and their inverses. Return {Success, Message}.
const relFlag = (field: "fav" | "ign" | "mut", value: number) => async (c: Ctx) => {
  if (!c.authUser) return c.send(401, {});
  const id = selfPlayerId(c);
  const target = await relTarget(c);
  if (target === null || target === id) return c.send(400, { error: "invalid player id" });
  relSet(id, target, { [field]: value }); saveDb();
  c.send(200, { Success: true, Message: "" });
};
route("POST", "/api/relationships/v1/ignore", relFlag("ign", 1));
route("POST", "/api/relationships/v1/unignore", relFlag("ign", 0));
route("POST", "/api/relationships/v1/mute", relFlag("mut", 1));
route("POST", "/api/relationships/v1/unmute", relFlag("mut", 0));
route("POST", "/api/relationships/v1/favorite", relFlag("fav", 1));
route("POST", "/api/relationships/v1/unfavorite", relFlag("fav", 0));
// Chat threads — none yet.
route("GET", "/thread", (c) => c.send(200, []));
route("GET", "/thread/party", (c) => c.send(200, {}));
// Cached-login batch (plural) — like the singular, nothing linked -> empty list.
route("POST", "/cachedlogin/forplatformids", (c) => c.send(200, []));
// Store catalog (commerce) — empty = no SKUs for sale (store is empty but valid).
route("GET", "/api/catalog/v1/all", (c) => {
  // the reference's live SKU catalog, recorded verbatim from a real boot (raw text keeps
  // the client's exact parse).
  const text = rawStaticText("api-catalog-v1-all.json") ?? "[]";
  c.res.setHeader("content-type", "application/json; charset=utf-8");
  c.res.setHeader("x-uwunet", "uwunet");
  c.res.setHeader("content-length", String(Buffer.byteLength(text, "utf8")));
  c.res.writeHead(200);
  c.res.end(text);
});
route("GET", "/purchase/v1/cleanuppending", (c) => c.send(200, []));
route("POST", "/purchase/v1/cleanuppending", (c) => c.send(200, []));
// Clubs (subscriptions/announcements) — none for a fresh account.
route("GET", "/club/mine/member", (c) => c.send(200, []));
route("GET", "/announcements/v2/mine/unread", (c) => c.send(200, []));
route("GET", "/announcements/v2/subscription/mine/unread", (c) => c.send(200, []));
// Statsig experiments flag — enabled true (matches reference's success bool).
route("POST", "/statsigUserProperties", (c) => c.send(200, { success: true }));
route("GET", "/statsigUserProperties", (c) => c.send(200, { success: true }));
// Referee (anti-cheat) files manifest — none to fetch.
route("GET", "/api/referee/files", (c) => c.send(200, []));
// Data-collection sampling config — the reference returns an ARRAY ([]), not {} (which malforms).
route("GET", "/sampling", (c) => c.send(200, []));

// OAuth token endpoint (IdentityServer-style: /Auth/connect/token)
route("POST", "/Auth/connect/token", async (c) => {
  const b = await parseBodyJson(c);
  const grant = String(b.grant_type ?? b.grantType ?? "password");

  if (grant === "password") {
    const username = String(b.username ?? "");
    const password = String(b.password ?? "");
    const u = db.users[username.toLowerCase()];
    if (!u) return c.send(400, { error: "invalid_grant", error_description: "Unknown account." });
    const salt = Buffer.from(u.SaltB64, "base64");
    if (hashPw(password, salt) !== u.PwHashB64) {
      return c.send(400, { error: "invalid_grant", error_description: "Bad password." });
    }
    const at = newToken("at", u.Id);
    const rt = newToken("rt", u.Id);
    db.refresh[rt] = u.Username.toLowerCase();
    saveDb();
    log({ event: "login", user: u.Username });
    return c.send(200, {
      access_token: at,
      refresh_token: rt,
      token_type: "Bearer",
      expires_in: 3600,
      accountId: u.Id,
      username: u.Username,
    });
  }

  if (grant === "refresh_token") {
    const rt = String(b.refresh_token ?? "");
    const userName = db.refresh[rt];
    const u = userName ? db.users[userName] : null;
    if (!u) return c.send(400, { error: "invalid_grant", error_description: "Bad refresh token." });
    return c.send(200, {
      access_token: newToken("at", u.Id),
      refresh_token: rt,
      token_type: "Bearer",
      expires_in: 3600,
      accountId: u.Id,
      username: u.Username,
    });
  }

  log({ event: "auth-unknown-grant", grant });
  return c.send(501, { error: "unsupported_grant_type" });
});

// Signup (accepts likely path; real path confirmed at harvest)
route("POST", "/Auth/connect/signup", async (c) => {
  return await signup(c);
});
route("POST", "/Accounts/account", async (c) => {
  return await signup(c);
});

// UwUNet account portal: CLAIM an existing (Steam-created) account — give it a real username
// and a password. The game authenticates through Steam and auto-makes a `Player<id>` account,
// so we RENAME that account in place (keeping its numeric Id + the Steam link in
// PlatformType/PlatformId) rather than creating a new, unlinked one the game would never log
// into. First claim sets the password; changing a claimed account's name/password after that
// requires its current password, so a name can't be hijacked. The display name updates in-game
// on the next launch (login resolves the same account by Steam id / cached account id).
route("POST", "/uwunet/claim", async (c) => {
  const b = await parseBodyJson(c);
  const who = String(b.account ?? b.current ?? "").trim();
  const username = String(b.username ?? "").trim();
  const password = String(b.password ?? "");
  const currentPassword = String(b.currentPassword ?? b.current_password ?? "");
  // Resolve the account by its current in-game name (Player####), numeric id, or SteamID64.
  const u =
    db.users[who.toLowerCase()] ??
    (/^\d+$/.test(who) ? userById(Number(who)) : null) ??
    Object.values(db.users).find((x) => x.PlatformId === who) ??
    null;
  if (!u) {
    return c.send(404, {
      Error: "No account matches that. Use the name the game shows you (e.g. Player1000000) or your SteamID64.",
    });
  }
  if (username.length < 3 || username.length > 20 || !/^[A-Za-z0-9_-]+$/.test(username)) {
    return c.send(400, { Error: "Username must be 3-20 characters: letters, numbers, _ or -." });
  }
  if (password.length < 8) return c.send(400, { Error: "Password must be at least 8 characters." });
  const taken = db.users[username.toLowerCase()];
  if (taken && taken.Id !== u.Id) return c.send(409, { Error: "That username is already taken." });
  // Already claimed? Require the current password to change it.
  if (u.PwHashB64 && hashPw(currentPassword, Buffer.from(u.SaltB64, "base64")) !== u.PwHashB64) {
    return c.send(403, { Error: "This account is already claimed — enter its current password to change it." });
  }
  const oldKey = u.Username.toLowerCase();
  u.Username = username;
  u.DisplayName = username;
  u.SaltB64 = crypto.randomBytes(16).toString("base64");
  u.PwHashB64 = hashPw(password, Buffer.from(u.SaltB64, "base64"));
  if (oldKey !== username.toLowerCase()) {
    delete db.users[oldKey];
    db.users[username.toLowerCase()] = u;
    for (const [rt, name] of Object.entries(db.refresh)) if (name === oldKey) db.refresh[rt] = username.toLowerCase();
  }
  saveDb();
  log({ event: "account-claimed", id: u.Id, username });
  c.send(200, { ok: true, accountId: u.Id, username });
});

// Role lookups the client uses to unlock staff/dev UI (the reference auth `/role/*`). Single form
// `/role/{role}/{id}` -> a BARE JSON boolean (or an empty 404 for an account we don't have);
// bulk form `/role/{role}?id=1&id=2` -> the subset of those ids that hold the role. God
// accounts hold developer, moderator and screenshare; everyone else holds none.
const role404 = (c: Ctx) => {
  c.res.setHeader("content-length", "0");
  c.res.writeHead(404);
  c.res.end();
};
const roleSingle = (role: string) => (c: Ctx) => {
  const m = new RegExp(`/role/${role}/(\\d+)$`).exec(c.path);
  if (!m) return role404(c);
  const id = Number.parseInt(m[1], 10);
  if (!userById(id)) return role404(c); // no such account -> 404, like the reference
  c.send(200, isStaff(id)); // bare boolean; true only for opt-in staff accounts
};
const roleBulk = (c: Ctx) => {
  const ids = [...new Set(c.query.getAll("id").map((v) => Number.parseInt(v, 10)).filter(Number.isInteger))];
  c.send(200, ids.filter((id) => isStaff(id)));
};
for (const role of GOD_ROLES) {
  route("GET", `/role/${role}/{id}`, roleSingle(role));
  route("GET", `/role/${role}`, roleBulk);
}

async function signup(c: Ctx) {
  const b = await parseBodyJson(c);
  const username = String(b.username ?? b.Username ?? "").trim();
  const password = String(b.password ?? b.Password ?? "");
  const email = b.email != null ? String(b.email) : undefined;
  const age = b.age ?? b.dateOfBirth ?? b.DateOfBirth;

  if (username.length < 3 || username.length > 20 || !/^[A-Za-z0-9_-]+$/.test(username)) {
    return c.send(400, { Code: 400, Error: "invalid_username" });
  }
  if (password.length < 8) {
    return c.send(400, { Code: 400, Error: "password_too_short" });
  }
  if (db.users[username.toLowerCase()]) {
    return c.send(409, { Code: 409, Error: "username_taken" });
  }
  const u: User = {
    Id: crypto.randomUUID(),
    Username: username,
    DisplayName: username,
    Email: email,
    SaltB64: crypto.randomBytes(16).toString("base64"),
    PwHashB64: "",
    Created: new Date().toISOString(),
  };
  u.PwHashB64 = hashPw(password, Buffer.from(u.SaltB64, "base64"));
  if (age === undefined) u.AgeFlagged = false;
  else {
    const n = Number(age);
    u.AgeFlagged = Number.isFinite(n) ? n < 18 : true;
  }
  db.users[username.toLowerCase()] = u;
  saveDb();
  log({ event: "signup", user: username });
  const at = newToken("at", u.Id);
  const rt = newToken("rt", u.Id);
  db.refresh[rt] = u.Username.toLowerCase();
  saveDb();
  return c.send(201, {
    ...accountJson(u),
    access_token: at,
    refresh_token: rt,
    token_type: "Bearer",
    expires_in: 3600,
  });
}

// Cached platform login (Steam ticket flows etc. — logged for RE)
route("POST", "/Auth/cachedlogin/forplatformids", async (c) => {
  log({ event: "cachedlogin", body: c.body.slice(0, 2000) });
  return c.send(404, { Code: 404, Error: "not_found" });
});

// --- accounts ---
route("GET", "/Accounts/account/me", (c) => {
  const tok = readAuthHeader(c);
  if (!tok) return c.send(401, { Code: 401, Error: "unauthorized" });
  const u = Object.values(db.users).find((x) => x.Id === tok.userId);
  if (!u) return c.send(401, { Code: 401, Error: "unknown_account" });
  return c.send(200, accountJson(u));
});

route("GET", "/Accounts/account/bulk", (c) => {
  const ids = c.query.getAll("id");
  const out = Object.values(db.users)
    .filter((u) => ids.includes(u.Id))
    .map(accountJson);
  return c.send(200, out);
});

// --- rooms / Room_server minimal ---
route("GET", "/Room_server/dormroom/me", (c) => {
  const tok = readAuthHeader(c);
  if (!tok) return c.send(401, { Code: 401 });
  return c.send(200, {
    RoomId: `UWU-${tok.userId.slice(0, 8)}`,
    Name: "UwU Dorm",
  });
});

// ---------------------------------------------------------------- dispatch
async function dispatch(req: http.IncomingMessage, res: http.ServerResponse, useTls: boolean) {
  const host = String(req.headers.host ?? "").toLowerCase();
  // Node 24's URL parser rejects an empty authority: `new URL("/", "http://")` throws, and an
  // unhandled throw here takes the whole edge down. A header-less probe must not kill the
  // server, so fall back to a placeholder authority for parsing only — routing still uses the
  // real `host` captured above.
  const u = new URL(req.url ?? "/", `http://${host || "localhost"}`);
  const p = u.pathname;

  let body = "";
  req.on("data", (c) => {
    body += c;
    if (body.length > 2_000_000) req.destroy();
  });
  await new Promise<void>((r) => req.on("end", r));

  const bearer = req.headers.authorization?.startsWith("Bearer ")
    ? req.headers.authorization.slice(7)
    : undefined;
  const authTok = verifyToken(bearer);
  const ctx: Ctx = {
    req,
    res,
    path: p,
    query: u.searchParams,
    body,
    authUser: authTok ? userById(Number(authTok.userId)) : null,
    send: (status, obj) => {
      // 64-bit numeric ids travel as "__BIG__<digits>__" sentinel strings inside the edge
      // (JS numbers would round them); unquote to raw digit literals on the wire. Also
      // de-quote SMALL digit strings on numeric-typed id fields (the client is strict-typed:
      // RoomId etc. parse as longs, and live rec.net always sent them as bare numbers).
      const bodyStr = JSON.stringify(obj)
        .replace(/"__BIG__(\d+)__"/g, "$1")
        .replace(
          /"(RoomId|SubRoomId|RoomInstanceId|DormRoomId|SubRoomDataSaveId|SavedByAccountId|CreatorAccountId|AccountId|PlayerId|OwnerId|SubjectAccountId)":"(\d{1,15})"/g,
          '"$1":$2',
        );
      const buf = Buffer.from(bodyStr, "utf8");
      // DEBUG: log ALL response bodies (temporary) to trace the room-load "No such room".
      log({ event: "response", host: req.headers.host, method: req.method, url: req.url, path: p, status, body: bodyStr });
      res.setHeader("content-type", "application/json; charset=utf-8");
      // Explicit byte-accurate Content-Length (non-chunked): BestHTTP over our hand-rolled
      // TLS/keep-alive edge mis-reassembled larger chunked bodies (e.g. the ~1.9KB dorm
      // RoomDto) into a "Malformed Response". A fixed length delimits the body cleanly.
      res.setHeader("content-length", String(buf.length));
      res.setHeader("x-uwunet", "uwunet");
      res.writeHead(status);
      res.end(buf);
    },
    empty: () => {
      log({ event: "response", host: req.headers.host, method: req.method, url: req.url, path: p, status: 200, body: "<empty>" });
      res.setHeader("content-length", "0");
      res.setHeader("x-uwunet", "uwunet");
      res.writeHead(200);
      res.end();
    },
  };

  log({
    event: "request",
    protocol: useTls ? "https" : "http",
    host: req.headers.host,
    method: req.method,
    path: p,
    auth: req.headers.authorization?.slice(0, 24) ?? null,
    fmt: req.headers["content-type"] ?? null,
    body: body ? body.slice(0, 3000) : undefined,
  });

  for (const r of routes) {
    if (r.method === req.method && r.re.test(p)) {
      try {
        const out = await r.h(ctx);
        void out;
        return;
      } catch (e) {
        log({ event: "handler-error", path: p, error: String(e) });
        return ctx.send(500, { Code: 500, Error: "internal" });
      }
    }
  }

  // Live fixtures: a static JSON response per path under server/fixtures/,
  // read fresh each request so new endpoints can be filled by just dropping a
  // file (the client's serial queue retries and picks it up — no restart).
  // GET/HEAD only; path "/api/x/y" -> server/fixtures/api/x/y.json
  if (req.method === "GET" || req.method === "HEAD") {
    const rel = p.replace(/^\/+/, "").replace(/\.\./g, "");
    // Prefer an exact-name file (raw bytes, e.g. opaque/binary cdn configs),
    // else a <path>.json fixture served as JSON.
    const exact = rel ? path.join(HERE, "fixtures", rel) : "";
    const asJson = rel ? path.join(HERE, "fixtures", rel + ".json") : "";
    const hit = exact && existsSync(exact) ? exact
              : asJson && existsSync(asJson) ? asJson
              : "";
    if (hit) {
      const ext = hit.slice(hit.lastIndexOf(".")).toLowerCase();
      const data = readFileSync(hit);
      const ctype =
        ext === ".json" ? "application/json; charset=utf-8"
        : ext === ".jpg" || ext === ".jpeg" ? "image/jpeg"
        : ext === ".png" ? "image/png"
        : ext === ".webp" ? "image/webp"
        : ext === ".gif" ? "image/gif"
        // img.rec.net names are often extensionless ("2026-10-26/<guid>"): sniff a JPEG.
        : data[0] === 0xff && data[1] === 0xd8 ? "image/jpeg"
        : "application/octet-stream";
      res.setHeader("content-type", ctype);
      res.setHeader("content-length", String(data.length)); // non-chunked, like c.send
      res.setHeader("x-uwunet", "fixture");
      res.writeHead(200);
      res.end(req.method === "HEAD" ? undefined : data);
      log({ event: "fixture", host: req.headers.host, method: req.method, path: p });
      return;
    }
  }

  // Image requests with no specific fixture: the real img.rec.net CDN is dead, so a custom
  // room shot, another player's profile photo, or a thumbnail we haven't provided would 404
  // and leave a broken/blank tile in the menus. Serve a neutral placeholder instead — a real
  // image always beats a 404 here (same reasoning as the dead-endpoint discipline).
  // On the img host every path is an image, extension or not (a room's ImageName is often a
  // bare "<date>/<guid>").
  if (req.method === "GET" || req.method === "HEAD") {
    if (/\.(jpe?g|png|webp|gif)$/i.test(p) || /^img\./i.test(String(req.headers.host ?? ""))) {
      const ph = path.join(HERE, "fixtures", "_placeholder.jpg");
      if (existsSync(ph)) {
        const data = readFileSync(ph);
        res.setHeader("content-type", "image/jpeg");
        res.setHeader("content-length", String(data.length)); // non-chunked, like c.send
        res.setHeader("x-uwunet", "placeholder");
        res.writeHead(200);
        res.end(req.method === "HEAD" ? undefined : data);
        log({ event: "placeholder-image", host: req.headers.host, path: p });
        return;
      }
    }
  }

  // HEAD on any path the client probes for reachability: 200, empty.
  if (req.method === "HEAD") {
    res.writeHead(200);
    res.end();
    return;
  }

  // catch-all: log loudly (this is our harvest), then a FAST 404. The client
  // treats a definitive 404 as "not there, move on"; a 503 reads as a retryable
  // server error that re-queues and starves the serial request pump (the reference's
  // "dead-endpoint discipline"). Real-but-empty beats a slow/5xx black hole.
  log({ event: "unimplemented", host: req.headers.host, method: req.method, path: p });
  ctx.send(404, {
    Code: 404,
    Error: "UwUNet: path not implemented yet — logged for harvest.",
  });
}

// ---- minimal WebSocket server (RFC 6455) for the SignalR notify hub ----
// The client opens a SignalR Core WebSocket to notify.rec.net/hub/v1 during Auto
// Login; if that transport errors, the whole login fails ("Unable to login (code:
// note)" — the failure propagates through BestHTTP.SignalRCore.HubConnection). We
// complete the WS upgrade and the SignalR JSON handshake so the hub connects; we
// don't push real notifications — a connected, quiet hub is enough to log in.
const WS_MAGIC = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const RS = "\x1e"; // SignalR record separator

const wsAccept = (key: string): string =>
  crypto.createHash("sha1").update(key + WS_MAGIC).digest("base64");

const wsFrame = (payload: string | Buffer, opcode = 0x1): Buffer => {
  const data = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, "utf8");
  const len = data.length;
  let header: Buffer;
  if (len < 126) {
    header = Buffer.from([0x80 | opcode, len]);
  } else if (len < 65536) {
    header = Buffer.from([0x80 | opcode, 126, (len >> 8) & 0xff, len & 0xff]);
  } else {
    header = Buffer.alloc(10);
    header[0] = 0x80 | opcode;
    header[1] = 127;
    header.writeBigUInt64BE(BigInt(len), 2);
  }
  return Buffer.concat([header, data]);
};

// deno-lint-ignore no-explicit-any
const handleWsUpgrade = (req: http.IncomingMessage, socket: any, _head: Buffer) => {
  const key = req.headers["sec-websocket-key"];
  const url = req.url ?? "";
  if (typeof key !== "string" || !/\/hub\//.test(url)) {
    try { socket.write("HTTP/1.1 404 Not Found\r\n\r\n"); socket.end(); } catch { /* */ }
    return;
  }
  log({ event: "ws-open", host: req.headers.host, path: url });
  socket.write(
    "HTTP/1.1 101 Switching Protocols\r\n" +
      "Upgrade: websocket\r\n" +
      "Connection: Upgrade\r\n" +
      `Sec-WebSocket-Accept: ${wsAccept(key)}\r\n\r\n`,
  );

  let buf = Buffer.alloc(0);
  let handshaken = false;
  socket.on("data", (chunk: Buffer) => {
    buf = Buffer.concat([buf, chunk]);
    while (buf.length >= 2) {
      const b1 = buf[1];
      const opcode = buf[0] & 0x0f;
      const masked = (b1 & 0x80) !== 0;
      let len = b1 & 0x7f;
      let off = 2;
      if (len === 126) { if (buf.length < 4) return; len = buf.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (buf.length < 10) return; len = Number(buf.readBigUInt64BE(2)); off = 10; }
      const maskLen = masked ? 4 : 0;
      if (buf.length < off + maskLen + len) return; // wait for the rest of the frame
      let payload = buf.subarray(off + maskLen, off + maskLen + len);
      if (masked) {
        const mask = buf.subarray(off, off + 4);
        const out = Buffer.alloc(len);
        for (let i = 0; i < len; i++) out[i] = payload[i] ^ mask[i & 3];
        payload = out;
      }
      buf = buf.subarray(off + maskLen + len);

      if (opcode === 0x8) { try { socket.end(); } catch { /* */ } return; } // close
      if (opcode === 0x9) { socket.write(wsFrame(payload, 0xa)); continue; } // ping -> pong
      if (opcode === 0xa) continue; // pong
      if (opcode !== 0x1 && opcode !== 0x2) continue;
      const text = payload.toString("utf8");
      if (!handshaken) {
        // First text message is the SignalR handshake request
        // ({"protocol":"json","version":1}\x1e); reply {}\x1e for success.
        handshaken = true;
        socket.write(wsFrame("{}" + RS));
        continue;
      }
      // Keep-alive: SignalR ping {"type":6}; answer with a ping.
      if (text.includes('"type":6')) { socket.write(wsFrame('{"type":6}' + RS)); continue; }
      // Any other hub message is a client->server invocation (SignalR type 1). Party
      // operations (invite / join / leave / travel-together) ride THIS hub, not REST, so
      // log them to the harvest — this is how we learn the party protocol to implement it.
      log({ event: "ws-msg", host: req.headers.host, path: url, text: text.slice(0, 1200) });
    }
  });
  socket.on("error", () => { try { socket.destroy(); } catch { /* */ } });
};

// ---- servers ----
// Every request goes through this wrapper so a throw anywhere in dispatch (even before the
// per-route try/catch — e.g. URL parsing) becomes a logged 500 for that one request instead of
// an unhandled rejection that crash-loops the whole edge.
const safeDispatch = (req: http.IncomingMessage, res: http.ServerResponse, useTls: boolean) =>
  dispatch(req, res, useTls).catch((e) => {
    log({ event: "dispatch-error", url: req.url, error: String((e && (e as Error).stack) || e) });
    try {
      if (!res.headersSent) res.writeHead(500);
      res.end();
    } catch { /* socket already gone */ }
  });
// Absolute last resort: never let a stray error or rejection take the process down.
process.on("uncaughtException", (e) =>
  log({ event: "uncaughtException", error: String((e && e.stack) || e) }),
);
process.on("unhandledRejection", (e) =>
  log({ event: "unhandledRejection", error: String(e) }),
);
const httpServer = http.createServer((req, res) => safeDispatch(req, res, false));
httpServer.on("upgrade", handleWsUpgrade);
httpServer.listen(HTTP_PORT, "0.0.0.0", () =>
  console.log(`[uwunet] plain HTTP on :${HTTP_PORT}`),
);

const cert = readFileSync(path.join(CERT_PATH, "rec.crt"));
const key = readFileSync(path.join(CERT_PATH, "rec.key"));
const ca = readFileSync(path.join(CERT_PATH, "uwunet-ca.crt"));

const sniHosts: Record<string, { cert: Buffer; key: Buffer }> = {
  "": { cert, key },
};
const tlsServer = tls.createServer(
  {
    // Default context for connections with NO SNI — e.g. the client connecting
    // to a bare IP (ApiHost=127.0.0.1), where TLS forbids an IP as SNI. Without
    // this, no-SNI handshakes fail with "handshake failure" and the game sees -1.
    key,
    cert,
    ca,
    SNICallback: (name, cb) => {
      const match = Object.keys(sniHosts).find(
        (h) => h === "" || h === name || name.endsWith(`.${h}`),
      );
      const c = sniHosts[match ?? ""] ?? sniHosts[""];
      log({ event: "tls-sni", host: name });
      try {
        cb(null, tls.createSecureContext({ key: c.key, cert: c.cert, ca }));
      } catch (e) {
        cb(String(e), null as never);
      }
    },
  },
  (plain: tls.TLSSocket) => {
    const s = new http.Server(function (req, res) {
      void safeDispatch(req, res, true);
    });
    s.on("upgrade", handleWsUpgrade);
    s.emit("connection", plain);
  },
);
tlsServer.listen(TLS_PORT, "0.0.0.0", () => {
  console.log(`[uwunet] TLS edge (SNI *.rec.net) on :${TLS_PORT}`);
  console.log(`[uwunet] db: ${DB_FILE}`);
});

process.on("SIGINT", () => {
  flushLog();
  process.exit(0);
});
process.on("exit", () => flushLog());
setInterval(flushLog, 3000);
