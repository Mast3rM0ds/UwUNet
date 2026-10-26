// UwUNet API server — phases M0/M1.
// Strategy: don't guess. Answer everything, log everything.
// Live traffic is gone; harvest logs + stub responses teach us the real
// request surface, and response schemas grow from logged reality.

import { createServer } from "node:http";
import { mkdirSync, appendFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const LOG_DIR = path.join(HERE, "..", "data", "harvest");
mkdirSync(LOG_DIR, { recursive: true });

const PORT = Number(process.env.PORT ?? 7666);
const HOST = process.env.HOST ?? "0.0.0.0";

export function harvest(evt: Record<string, unknown>) {
  try {
    appendFileSync(
      path.join(LOG_DIR, "requests.jsonl"),
      JSON.stringify({ t: Date.now(), ...evt }) + "\n",
    );
  } catch {}
}

const server = createServer((req, res) => {
  const u = new URL(req.url ?? "/", `http://${req.headers.host}`);
  const p = u.pathname;

  let body = "";
  req.on("data", (c) => {
    body += c;
    if (body.length > 1_000_000) req.destroy();
  });
  req.on("end", () => {
    harvest({
      event: "api-request",
      method: req.method,
      host: req.headers.host,
      path: p,
      query: u.search,
      auth: req.headers.authorization ?? null,
      contentType: req.headers["content-type"] ?? null,
      body: body ? body.slice(0, 4000) : undefined,
    });
  });

  if (p === "/health") {
    res.writeHead(200, { "content-type": "application/json; charset=utf-8" });
    return res.end(JSON.stringify({ ok: true, net: "UwUNet", ts: Date.now() }));
  }

  // Honest stub: every host & path is answered and logged. 503 marks
  // "not yet implemented" so we can grep the harvest real endpoints later.
  res.writeHead(503, {
    "content-type": "application/json; charset=utf-8",
    "x-uwunet": "not-yet-implemented",
  });
  res.end(
    JSON.stringify({
      Code: 503,
      Error: "UwUNet stub — implemented in a later phase; request logged.",
    }),
  );
});

server.listen(PORT, HOST, () => {
  console.log(`UwUNet stub API listening on http://${HOST}:${PORT}`);
  console.log(`Harvest log: ${LOG_DIR}/requests.jsonl`);
});

process.on("SIGINT", () => server.close(() => process.exit(0)));
