// tools/create-archivist.mjs — create the UwUArchivist importer account in the local DB
// (mirrors the signup handler exactly). Prints the resulting account Id.
import crypto from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { pbkdf2Sync } from "node:crypto";
const DB = "data/uwunet.db.json";
const NAME = process.argv[2] ?? "UwUArchivist";
const PW = process.argv[3] ?? "archivist" + crypto.randomBytes(3).toString("hex");
const db = JSON.parse(readFileSync(DB, "utf8"));
const key = NAME.toLowerCase();
const hashPw = (pw, salt) => pbkdf2Sync(pw, salt, 120_000, 32, "sha256").toString("base64");
if (db.users[key]) {
  console.log("exists:", key, db.users[key].Id);
} else {
  const salt = crypto.randomBytes(16).toString("base64");
  db.users[key] = {
    Id: String(Math.max(...Object.values(db.users).map((u) => Number(u.Id) || 0), 1000000) + 1),
    Username: NAME,
    DisplayName: NAME,
    Email: null,
    SaltB64: salt,
    PwHashB64: hashPw(PW, Buffer.from(salt, "base64")),
    Created: new Date().toISOString(),
    AgeFlagged: false,
  };
  db.nextId = Math.max(Number(db.nextId ?? 0), 1) + 1;
  writeFileSync(DB, JSON.stringify(db, null, 1));
  console.log("created:", key, "id:", db.users[key].Id, "password:", PW);
}
