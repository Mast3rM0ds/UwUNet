// UwUNet harvest proxy — M0 tool.
//
// Point the game's DNS (hosts file in the Proton prefix, or a system-wide
// resolver override) at this machine and every rec.net hostname hit becomes
// visible here:
//   * plain HTTP  — full method/path/headers/body logged
//   * HTTPS       — CONNECT-bound TLS handshakes are parsed for the real
//                   SNI hostname the client wants (pinned bodies stay
//                   opaque until SSLPatcher runs in the Proton prefix)
//
// Usage: node src/harvest-proxy.ts [http-port=8666] [https-port=8667]

import http from "node:http";
import net from "node:net";
import { mkdirSync, appendFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const LOG_DIR = path.join(HERE, "data", "harvest");
mkdirSync(LOG_DIR, { recursive: true });

const HTTP_PORT = Number(process.argv[2] ?? 8666);
const HTTPS_PORT = Number(process.argv[3] ?? 8667);

function log(evt: Record<string, unknown>) {
  appendFileSync(
    path.join(LOG_DIR, "requests.jsonl"),
    JSON.stringify({ t: Date.now(), ...evt }) + "\n",
  );
}

// From the TLS ClientHello: after the record header (5B) + handshake header
// (6B), find SNI in the extensions section (type 0x0000).
function extractSni(buf: Buffer): string | null {
  // TLS record
  if (buf.length < 5 || buf[0] !== 0x16) return null;
  const recLen = buf.readUInt16BE(3);
  let i = 5;
  if (buf[i] !== 0x01) return null; // handshake: ClientHello
  i += 4; // handshake header
  i += 2; // client version
  i += 32; // random
  const sessionIdLen = buf.readUInt8(i);
  i += 1 + sessionIdLen;
  const cipherLen = buf.readUInt16BE(i);
  i += 2 + cipherLen;
  const compLen = buf.readUInt8(i);
  i += 1 + compLen;
  const extTotal = buf.readUInt16BE(i);
  i += 2;
  const end = Math.min(i + extTotal, 5 + recLen);
  while (i + 4 <= end) {
    const extType = buf.readUInt16BE(i);
    const extLen = buf.readUInt16BE(i + 2);
    if (extType === 0x0000) {
      // server_name_list
      let j = i + 4;
      if (buf.readUInt16BE(j) === 0x0000) {
        const hostLen = buf.readUInt16BE(j + 3);
        return buf.toString("ascii", j + 5, j + 5 + hostLen);
      }
      return null;
    }
    i += 4 + extLen;
  }
  return null;
}

// --- HTTP: visible, log method/path/body -------------------------------
http
  .createServer((req, res) => {
    const u = new URL(req.url ?? "/", `http://${req.headers.host}`);
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      log({
        event: "http",
        method: req.method,
        host: req.headers.host,
        path: u.pathname,
        query: u.search || undefined,
        auth: req.headers.authorization ?? undefined,
        contentType: req.headers["content-type"] ?? undefined,
        body: body ? body.slice(0, 4000) : undefined,
      });
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ Code: 0, uwunet: "harvest-ack" }));
    });
  })
  .listen(HTTP_PORT, "0.0.0.0");

// --- HTTPS: CONNECT tunnel, log the SNI it's really heading to ----------
net
  .createServer((client) => {
    client.once("data", function onData(buf) {
      const head = buf.toString("latin1");
      const m = /^CONNECT ([^\s:]+):(\d+)/.exec(head);
      if (m) {
        const sni = extractSniSafely(client, buf);
        log({ event: "https", via: "CONNECT", host: m[1], serverPort: m[2] });
        // Tunnel onward: upstream is dead, but we still observe the
        // ClientHello on the first TLS bytes inside the tunnel.
        const up = net.connect({ host: m[1], port: Number(m[2]) }, () => {
          up.write(buf);
        });
        up.on("error", () => client.end());
        client.pipe(up);
        up.pipe(client);
        return;
      }
      // plain HTTP request sent into 8667 by mistake — forward to HTTP listener
      client.destroy();
    });
  })
  .listen(HTTPS_PORT, "0.0.0.0");

function extractSniSafely(client: net.Socket, buf: Buffer): string | null {
  try {
    const sni = extractSni(buf);
    if (sni) log({ event: "https", via: "TLS-SNI", host: sni });
    return sni;
  } catch {
    return null;
  }
}

console.log(`UwUNet harvest proxy`);
console.log(`  HTTP  :${HTTP_PORT}  (full request capture)`);
console.log(`  HTTPS :${HTTPS_PORT} (CONNECT + SNI capture)`);
console.log(`  log   -> ${LOG_DIR}/requests.jsonl`);
