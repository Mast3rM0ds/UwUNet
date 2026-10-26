#!/usr/bin/env node
// Extract things RefereeClientApp.exe touched at boot, from a WINEDEBUG=+file,+reg trace.
import { readFileSync } from "node:fs";
const [, , file = "/tmp/opencode/referee-trace.log"] = process.argv;
const SKIP =
  /^(?:dll|font|nls|Z:\\home.*opencode|chartables|registry|c_\\d)/i;
const paths = new Map();
for (const line of readFileSync(file, "utf8").split("\n")) {
  const m = /(?:open|read|create|load|query|stat|open_object)[^"]*"([^"]+)"/i.exec(
    line,
  );
  let p = m?.[1];
  if (!p) {
    const m2 = /(?:file|reg_key|reg_value|key\s|key) "([^"\\]+(?:\\[^"]*)?)"[\s,)]/i.exec(
      line,
    );
    p = m2?.[1];
  }
  if (!p) continue;
  if (SKIP.test(p)) continue;
  if (paths.has(p)) paths.set(p, paths.get(p) + 1);
  else paths.set(p, 1);
}
const arr = [...paths.entries()].sort((a, b) => b[1] - a[1]);
for (const [p, n] of arr.slice(0, 80)) console.log(String(n).padStart(3), p);
console.log(`(${arr.length} unique paths)`);
