// UwUNet TLS edge — M0/M1. Single TLS server (SNI-routed) impersonating all
// rec.net hostnames plus a plain-HTTP backend. Runs on unpriv ports
// (8443/8460); a netns iptables REDIRECT puts 443/80 traffic here.
//
// Implemented for real: signup/login/token + accounts + version/config.
// Everything else: 503 + logged, so harvest teaches us the real surface.

import tls from "node:tls";
import http from "node:http";
import crypto from "node:crypto";
import { mkdirSync, readFileSync, existsSync, writeFileSync } from "node:fs";
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
type Db = { users: Record<string, User>; refresh: Record<string, string>; nextId?: number };
const DB_FILE = path.join(DATA, "uwunet.db.json");
function loadDb(): Db {
  if (existsSync(DB_FILE)) {
    try {
      return JSON.parse(readFileSync(DB_FILE, "utf8"));
    } catch {}
  }
  return { users: {}, refresh: {}, nextId: 1000000 };
}
// RecNet account ids are integers; allocate sequentially (stored as a string).
function allocAccountId(): string {
  const id = db.nextId ?? 1000000;
  db.nextId = id + 1;
  return String(id);
}
const db = loadDb();
function saveDb() {
  try {
    writeFileSync(DB_FILE, JSON.stringify(db, null, 1));
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
// and rejects a token that is only `sub` or non-integer). Mirrors RecFlare's
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
const b64urlJson = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
function signJwt(claims: Record<string, unknown>): string {
  const data = `${b64urlJson({ alg: "HS256", typ: "JWT" })}.${b64urlJson(claims)}`;
  const sig = crypto.createHmac("sha256", UWU_SECRET).update(data).digest("base64url");
  return `${data}.${sig}`;
}
function mintAccessToken(u: User, ver: string): string {
  const now = Math.floor(Date.now() / 1000);
  const plat = Number(u.PlatformType ?? 0);
  return signJwt({
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
    role: [...BASE_ROLES],
    scope: TOKEN_SCOPES,
    jti: crypto.randomUUID(),
  });
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
// bulk/account lookups. Mirrors RecFlare's toAccountDto. Numeric fields are
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
  // Zero-length 200 body (RecFlare's `c.body(null, 200)`). The client treats an empty body as
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
<p class=sub>rec room is dead. this is our replacement. keep it kind.</p>
<form onsubmit="return doSignup(event)">
<label>username</label><input id=u required pattern="[A-Za-z0-9_\-]{3,20}">
<label>password (8+ chars)</label><input id=p type=password required minlength=8>
<label>email (optional)</label><input id=e type=email>
<button>create account</button>
<button type=button class=ghost onclick="return doLogin(event)">log in instead</button>
</form><div id=out></div><div id=tok></div></main>
<script>
const out=document.getElementById('out'),tok=document.getElementById('tok');
async function call(path,body){
  const r=await fetch(path,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
  const j=await r.json().catch(()=>({}));
  if(!r.ok){out.textContent=j.error_description||j.Error||'error '+r.status;out.className='';return null}
  return j;
}
async function doSignup(e){e.preventDefault();out.textContent='...';
  const j=await call('/Auth/connect/signup',{username:u.value,password:p.value,email:e.value});
  if(!j)return false;
  out.textContent='account '+j.Id+' created — you are signed in';
  out.id='ok';tok.textContent='access_token: '+j.access_token;return false}
async function doLogin(e){e.preventDefault();out.textContent='...';
  const j=await call('/Auth/connect/token',{grant_type:'password',username:u.value,password:p.value});
  if(!j)return false;
  out.textContent='welcome back, '+j.username;
  out.className='';out.id='ok';tok.textContent='access_token: '+j.access_token;return false}
</script></body></html>`;

// RecNet nameserver service-discovery map. GET ns.rec.net/ returns this so the
// client learns every service host. We advertise the real *.rec.net subdomains;
// uwudns64 funnels them all to this one edge. Mirrors recflare/server apps/ns.
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
const STATIC = path.join(HERE, "static");
const readStatic = (name: string, fallback: unknown): unknown => {
  try {
    return JSON.parse(readFileSync(path.join(STATIC, name), "utf8"));
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
// The CANONICAL dorm template: RecFlare's room 1 (DORM_TEMPLATE_ROOM_ID), fetched live from
// rooms.recflare.net/rooms/1 — the exact empty-dorm RoomDto real clients accept. getOrCreate-
// DormRoom clones this per account. We spread it and override ONLY the identity fields, so the
// whole shape (ImageName "DormRoom.jpg", CurrentSave: null, no subroom blobs, every flag) is
// verbatim what the client's strict parser expects. Hand-built variants all failed "Malformed
// Response"; this one matches a known-good room byte-for-byte except identity.
const roomTemplate = readStatic("room-template.json", {}) as Record<string, unknown>;
const templateSubRoom = (Array.isArray(roomTemplate.SubRooms) && roomTemplate.SubRooms[0]) || {};
// Orientation (room 13) is a PUBLIC system room, identical for every account, so we serve
// RecFlare's live /rooms/13?include=767277 body verbatim rather than mangling the dorm template.
// This eliminated the room-DTO as a suspect for the `Enumerable.First` abort during room-load:
// the dorm template had IsSandbox:true on its subroom (orientation's is false), which makes the
// client load the maker-pen/circuit/save path and `.First()` an empty save/circuit collection.
const orientationRoomStatic = readStatic("orientation-room.json", {}) as Record<string, unknown>;
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
  c.send(200, {
    ClientForceUpgrade: false,
    ClientOptionalUpgrade: false,
    LatestVersion: c.query.get("v") ?? "20250718.01",
    MinimumVersion: "20250718.01",
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
// which we accept and ignore). Shape per RecFlare: CachedLogin[].
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
    // returned photonRoomId:"" and the client had no room to connect Photon to. RecFlare seeds
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

// ---- post-login wave (shapes mirrored from RecFlare) --------------------
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
// Shapes from recflare/server apps/match/src/{openapi,match.app}.ts.
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
// out-of-sync!" every ~30s. RecFlare stores deviceClass from the token request and replays it.
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

// Session LoginLock, recorded at /player/login and verified on each heartbeat. RecFlare's
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
// heartbeat ... local presence is out-of-sync!" and sticks forever at "preparing". RecFlare's
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
// Room-by-id lookup: Orientation (13) -> the Orientation DTO; everything else is a dorm.
const roomDtoFor = (id: number) =>
  id === ORIENTATION_ROOM_ID ? orientationRoomDto() : dormRoomDto(id, userById(id)?.Username ?? `Player${id}`);
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
    maxCapacity: 1, // Orientation is solo (RecFlare room 13 MaxPlayers 1) — matches orientationRoomDto
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
  c.empty(); // RecFlare acks an EMPTY body here, NOT a PlayerDto
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
  // stops (RecFlare's behavior). The current session's lock always matches, so it gets the
  // presence payload back and stays in sync.
  const posted = parseLoginLock(c);
  const stored = loginLockById.get(id);
  if (posted && stored && posted !== stored) { c.empty(); return; }
  c.send(200, playerDto(id, presenceById.get(id) ?? null));
});
// Status visibility toggle — RecFlare acks with an EMPTY body (not a PlayerDto, not {}).
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
// connection-info: the realtime creds in the {success,value,error} envelope. We have no
// Photon relay yet, so the ids/room are empty strings (valid shape, "in no instance").
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
  c.send(200, {
    success: true,
    value: {
      photonAuthToken: "",
      photonRealtimeAppId: ph.realtimeAppId ?? "",
      photonVoiceAppId: ph.voiceAppId ?? "",
      photonChatAppId: ph.chatAppId ?? "",
      photonRegion,
      photonRoomId,
      voiceConnectionInfo: "",
      voiceServerId: "",
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
// RecFlare's spec: (1) `correlationId` MUST echo the request's CorrelationId or the client
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
// needs an instance but isn't going anywhere in particular. Per RecFlare it must answer the
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

// GET /photon_access_token — the permission table + Photon credentials the client needs to
// SPAWN into a room (RecFlare apps/rooms/src/rooms.app.ts). 404ing this was the dorm's
// `FailedToSpawnPlayer (Code 8700)`: the client awaits it inside JoinRoomLoadWithPhoton, and a
// faulted fetch aborts the whole room load. PhotonAccessToken is always "" — Photon Cloud
// (ours, like RecFlare's) accepts an empty token; the real service signed it with a secret we
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
route("GET", "/photon_access_token", (c) => {
  if (!c.authUser) return c.send(401, {});
  const id = selfPlayerId(c);
  const presence = presenceById.get(id) as Record<string, unknown> | undefined;
  const roomInstanceId =
    presence && typeof presence.roomInstanceId === "number" ? (presence.roomInstanceId as number) : null;
  const roomId = presence && typeof presence.roomId === "number" ? (presence.roomId as number) : null;
  // The caller owns their own dorm (roomId === their account id) → Creator; otherwise a visitor.
  const role = roomId === id ? ROLE_CREATOR : ROLE_NONE;
  c.send(200, photonAccessTokenDto(roomInstanceId, role));
});

// --- rooms.rec.net: the room object the client loads after matchmake ---
// GET /dormroom/me — returns the caller's dorm ROOM ID as a BARE NUMBER (RecFlare's
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
    const id = Number.parseInt((idParam.split(",")[0] ?? "").trim(), 10);
    if (!Number.isNaN(id)) {
      c.send(200, roomDtoFor(id));
      return;
    }
  }
  // Name lookup (e.g. ?name=SocialOrientation&include=... — the new-user onboarding probe).
  // RecFlare's LIVE server returns `{}` (empty object) for a name with no matching room, and
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
    c.send(200, {}); // RecFlare's no-match response for any other unknown named room
    return;
  }
  c.send(200, null); // neither id nor name resolvable
});
// GET /rooms/bulk — rooms by id (?id= repeated and/or comma-separated). Returns a RoomDto
// array (missing ids omitted). MUST be registered before /rooms/** or that catch-all 404s it
// with "no such room" — which the BootSequence surfaces as the fatal "No such room". Every
// room we know is a dorm, so return a dorm DTO per requested id.
route("GET", "/rooms/bulk", (c) => {
  const ids = [...c.query.getAll("id")]
    .flatMap((v) => v.split(","))
    .map((s) => Number.parseInt(s.trim(), 10))
    .filter((n) => !Number.isNaN(n));
  c.send(200, ids.map((rid) => roomDtoFor(rid)));
});
// GET /rooms/{id} — during "preparing", the client fetches the full Room to build the scene
// (subrooms, save). We serve the caller's dorm (roomId == their account id, set in matchmake).
route("GET", "/rooms/**", (c) => {
  // Only the bare `/rooms/<number>` form is a room fetch; sub-paths (boosts, interactions)
  // and non-numeric ids (bulk, named/*) stay tolerated 404s.
  const m = /^\/rooms\/(\d+)$/.exec(c.path);
  if (!m) return c.send(404, { Code: 404, Error: "no such room" });
  const id = Number.parseInt(m[1], 10);
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
  c.send(200, []); // no stored settings; client falls back to its own defaults
});
// PUT upserts settings; RecFlare returns the settings ARRAY ([{PlayerId,Key,Value}]), not {}.
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
  c.send(200, { Items: [], TotalCount: 0, PageToken: null });
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
// in request order (RecFlare apps/api/src/routes/avatar.ts). Unknown ids are simply
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
    // A miss is NOT an error: RecFlare's bulk omits unknown ids and the client reads
    // the items it got back. We USED to synthesize a fake item for a missing default
    // id (e.g. 5726c274 — which RecFlare itself returns "not found" for) by cloning a
    // real one under the requested id. The clone reused the source item's
    // CustomAvatarItemSaveId / UnityAssetId / assetbundle verbatim, so the client
    // received two items sharing one save+asset identity — a collision that corrupted
    // the in-room avatar assembly: the skeleton silently never built (black screen,
    // audible-but-invisible world). Omit misses, exactly like RecFlare.
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
// Shape per recflare/server apps/api/src/openapi.ts (StoredOutfit). LegacyData.SelectionsV1
// is the semicolon-delimited legacy descriptor string (our flat OutfitSelections).
const storedOutfit = () => ({
  LegacyData: {
    SelectionsV1: (defaultAvatar as Record<string, unknown>).OutfitSelections ?? "",
    SelectionsV2: null,
    FaceFeatures: (defaultAvatar as Record<string, unknown>).FaceFeatures ?? "",
    SkinColor: (defaultAvatar as Record<string, unknown>).SkinColor ?? "",
    HairColor: (defaultAvatar as Record<string, unknown>).HairColor ?? "",
  },
  Selections: [],
  DataVersion: 2,
  CustomizationSettings: null,
  ThumbnailFileName: null,
  Name: null,
  Accessibility: 0,
  Slot: 0,
});
// Per-player worn outfit (slot 0). The client builds/normalizes its avatar on spawn and
// PUTs the result here; a 404 on that write left the avatar unestablished (no skeleton, so
// the head-pivot camera renders black). We store it and read it back, like RecFlare's
// `outfit` table. Nothing saved yet → the default outfit.
const storedOutfitById = new Map<number, Record<string, unknown>>();
route("GET", "/outfits/me", (c) => {
  if (!c.authUser) return c.send(401, {});
  c.send(200, storedOutfitById.get(selfPlayerId(c)) ?? storedOutfit());
});
// Save the caller's outfit. RecFlare stores the body verbatim in the slot it names (slot 0 =
// worn, what GET reads) and answers the base envelope WITHOUT a Value — the outfit is not
// echoed. Lenient on an unparseable body: still ack, so the avatar apply never stalls here.
route("PUT", "/outfits/me", (c) => {
  if (!c.authUser) return c.send(401, {});
  try {
    const body = c.body ? (JSON.parse(c.body) as Record<string, unknown>) : null;
    if (body && (typeof body.Slot !== "number" || body.Slot === 0)) {
      storedOutfitById.set(selfPlayerId(c), body);
    }
  } catch { /* unparseable — still ack */ }
  c.send(200, { Success: true, Error: null, error_id: null });
});

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
// PlayerReporting /hile — RecFlare's live server returns a bare `false`. Must be 200: a 404
// here throws during room-load and quits the app (see AI block below).
route("POST", "/api/PlayerReporting/v1/hile", (c) => c.send(200, false));

// --- 2025 AI features (ai.rec.net / lists.rec.net) ---
// The client checks AI access/budget during boot AND during room load
// (GET /gameai/user/access?roomId=13 fires while loading Orientation). RecFlare serves all of
// these as 200s; a 404 throws an unobserved HTTP exception that, inside the room-load critical
// section (OperationContext.PauseNetworking "InitialLoad"), escalates to AppExitState
// Running=>PreparingToExit — the client quit mid-Orientation-load. Shapes are verbatim from
// recflare/server apps/ai/src/ai.app.ts + apps/lists/src/lists.app.ts. No AI backend exists;
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
// The player SPAWN reads room economy data. RecFlare serves these as 200s; a 404 makes
// RecRoom.Systems.Economy.RoomKeys.RoomKeysManager THROW, which RoomLoad reports as
// FailedToSpawnPlayer (Code 8700) — the player never enters and the client loops
// Orientation<->Dorm. Shapes from recflare/server apps/econ/src/econ.app.ts: an empty room is
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

// --- boot/PLAY peripherals (shapes from recflare/server apps/api openapi.ts) ---
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
// Relationships (friends/blocks/etc.) — none for a fresh account.
route("GET", "/api/relationships/v2/get", (c) => c.send(200, []));
// Chat threads — none yet.
route("GET", "/thread", (c) => c.send(200, []));
route("GET", "/thread/party", (c) => c.send(200, []));
// Cached-login batch (plural) — like the singular, nothing linked -> empty list.
route("POST", "/cachedlogin/forplatformids", (c) => c.send(200, []));
// Store catalog (commerce) — empty = no SKUs for sale (store is empty but valid).
route("GET", "/api/catalog/v1/all", (c) => c.send(200, []));
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
// Data-collection sampling config — RecFlare returns an ARRAY ([]), not {} (which malforms).
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
  const u = new URL(req.url ?? "/", `http://${host}`);
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
      const bodyStr = JSON.stringify(obj);
      const buf = Buffer.from(bodyStr, "utf8");
      // DEBUG: log ALL response bodies (temporary) to trace the room-load "No such room".
      log({ event: "response", host: req.headers.host, method: req.method, url: req.url, path: p, status, body: bodyStr.slice(0, 300) });
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
      const ctype =
        ext === ".json" ? "application/json; charset=utf-8"
        : ext === ".jpg" || ext === ".jpeg" ? "image/jpeg"
        : ext === ".png" ? "image/png"
        : ext === ".webp" ? "image/webp"
        : ext === ".gif" ? "image/gif"
        : "application/octet-stream";
      res.setHeader("content-type", ctype);
      res.setHeader("x-uwunet", "fixture");
      res.writeHead(200);
      res.end(req.method === "HEAD" ? undefined : readFileSync(hit));
      log({ event: "fixture", host: req.headers.host, method: req.method, path: p });
      return;
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
  // server error that re-queues and starves the serial request pump (recflare's
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
      // Keep-alive: SignalR ping {"type":6}; answer with a ping, ignore the rest.
      if (text.includes('"type":6')) socket.write(wsFrame('{"type":6}' + RS));
    }
  });
  socket.on("error", () => { try { socket.destroy(); } catch { /* */ } });
};

// ---- servers ----
const httpServer = http.createServer((req, res) => dispatch(req, res, false));
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
      void dispatch(req, res, true);
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
