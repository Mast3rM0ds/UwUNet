#!/usr/bin/env node
// Summarize harvest: which hostnames/paths/methods the client attempted,
// body shapes, and TLS SNI stats. Feed to implementers.
import { readFileSync, existsSync } from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const f = path.resolve(
  path.dirname(new URL(import.meta.url).pathname),
  "..",
  "..",
  "data",
  "harvest",
  "requests.jsonl",
);
if (!existsSync(f)) {
  console.log("no harvest yet — run the game against UwUNet first");
  process.exit(0);
}
const evts = readFileSync(f, "utf8")
  .trim()
  .split("\n")
  .filter(Boolean)
  .map((l) => {
    try {
      return JSON.parse(l);
    } catch {
      return null;
    }
  })
  .filter(Boolean);

const paths = new Map();
const hosts = new Map();
for (const e of evts) {
  const hp = e.host ? String(e.host).split(":")[0] : "(none)";
  if (e.path) {
    const k = `${e.method ?? "?"} ${hp}${e.path}`;
    const v = paths.get(k) ?? { n: 0, auth: 0, bodies: [] };
    v.n++;
    if (e.auth) v.auth++;
    if (e.body && v.bodies.length < 3) v.bodies.push(e.body);
    paths.set(k, v);
  }
  hosts.set(hp, (hosts.get(hp) ?? 0) + 1);
}

console.log("== TLS SNI hits (client attempted):");
for (const [h, n] of [...hosts.entries()].sort((a, b) => b[1] - a[1]))
  console.log(`  ${String(n).padStart(4)}  ${h}`);

console.log("\n== endpoints:");
for (const [k, v] of [...paths.entries()].sort()) {
  console.log(`  ${k}  [x${v.n}${v.auth ? ", authed" : ""}]`);
  for (const b of v.bodies) console.log(`     body: ${b.slice(0, 200)}`);
}
