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

const CERT_PATH = process.env.UWU_CERT_DIR ?? "/home/bloink/UwUNet/certs";
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
};

type Handler = (ctx: Ctx) => Promise<void> | void;

const routes: Array<{ method: string; re: RegExp; h: Handler }> = [];

function route(method: string, pattern: string, h: Handler) {
  const re = new RegExp(
    "^" +
      pattern
        .replace(/[.+?^${}()|[\]\\]/g, "\\$&")
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
route("POST", "/player/login", (c) => c.send(200, {}));     // record session lock; empty ack
route("POST", "/player/logout", (c) => c.send(200, {}));    // clear presence; empty ack
route("POST", "/player/exclusivelogin", (c) => c.send(200, { errorCode: 0 }));
route("POST", "/player/verifylock", (c) => c.send(200, {}));
route("POST", "/player/heartbeat", (c) => c.send(200, {})); // presence keepalive; empty ack
route("GET", "/player/qos", (c) => c.send(200, []));        // region probe list (none)
route("PUT", "/player/photonregionpings", (c) => c.send(200, {}));
route("PUT", "/player/gameserverregionpings", (c) => c.send(200, {}));
// Photon creds: all-null = "not in a room yet" (real creds come when we have a relay).
route("GET", "/player/connection-info", (c) => {
  if (!c.authUser) return c.send(401, {});
  c.send(200, {
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
route("PUT", "/playersettings", (c) => c.send(200, {}));

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
// in request order. Matches come from the real default-avatar item data; unknown
// ids are simply absent (not an error), which the client tolerates. Returning []
// for the client's fixed default-hair set crashes its avatar parser.
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
    if (it) {
      out.push(it);
    } else if (defaultCustomItems.length > 0) {
      // A default-avatar id the data source didn't have (e.g. 5726c274): the client
      // requests it and throws on an empty result. Synthesize a valid item by cloning
      // a real one under the requested id so the JSON parses and login proceeds.
      const tmpl = JSON.parse(JSON.stringify(defaultCustomItems[0])) as Record<string, unknown>;
      tmpl.CustomAvatarItemId = id;
      tmpl.RankedEntityId = id;
      if (Array.isArray(tmpl.CurrentSaves)) {
        for (const s of tmpl.CurrentSaves as Record<string, unknown>[]) s.CustomAvatarItemId = id;
      }
      out.push(tmpl);
    }
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

// outfits/me: empty brand-new-account envelope (flat shape) when nothing saved.
route("GET", "/outfits/me", (c) => {
  if (!c.authUser) return c.send(401, {});
  // DIAGNOSTIC: empty brand-new-account envelope (no worn items) — tests whether
  // the avatar builds without worn-item resolution.
  c.send(200, { FaceFeatures: "", HairColor: "", OutfitSelections: "", SkinColor: "" });
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
      // DEBUG: log avatar/outfit/econ response bodies to pinpoint the avatar parse.
      if (/avatar|outfit|econ|customAvatarItems/i.test(p)) {
        log({ event: "response", path: p, status, body: bodyStr.slice(0, 600) });
      }
      res.setHeader("content-type", "application/json; charset=utf-8");
      res.setHeader("x-uwunet", "uwunet");
      res.writeHead(status);
      res.end(bodyStr);
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
      res.setHeader(
        "content-type",
        hit.endsWith(".json")
          ? "application/json; charset=utf-8"
          : "application/octet-stream",
      );
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

// ---- servers ----
const httpServer = http.createServer((req, res) => dispatch(req, res, false));
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
