#!/usr/bin/env bash
# One-shot UwUNet session: (re)start edge, boot game via Steam, watch harvest.
set -u
UWU=/home/bloink/UwUNet

pkill -f "uwunet-edge" 2>/dev/null
rm -f "$UWU/data/harvest/requests.jsonl"
export TLS_PORT=8443 HTTP_PORT=8460
node "$UWU/server/src/uwunet-edge.ts" > /tmp/opencode/uwunet-edge.log 2>&1 &
echo "[session] edge pid $!"
sleep 1

steam -applaunch 471710 > /tmp/opencode/steam-launch.log 2>&1 &
echo "[session] steam launched pid $!"

for i in $(seq 1 40); do
  sleep 3
  ALIVE=$(pgrep -fc "Recroom_Release" || true)
  HITS=$([ -f "$UWU/data/harvest/requests.jsonl" ] && wc -l < "$UWU/data/harvest/requests.jsonl" || echo 0)
  echo "[session t$((i*3))s] game procs=$ALIVE harvest=$HITS"
  if [ "$HITS" -gt 0 ]; then
    echo "[session] CLIENT HIT UwUNet!"
    grep -oE '"(host|path|auth)":"[^"]*"|"(host|path|auth)":null' "$UWU/data/harvest/requests.jsonl" | paste -d' ' - - 2>/dev/null | head
    if [ "$i" -ge 6 ]; then break; fi   # keep watching a bit
  fi
  if [ "$ALIVE" -eq 0 ] && [ "$i" -gt 4 ]; then
    echo "[session] game died"
    break
  fi
done
