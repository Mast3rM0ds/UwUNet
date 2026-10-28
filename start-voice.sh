#!/bin/sh
# start-voice.sh — launch the UwUNet voice server (Dissonance/LiteNetLib UDP).
# Mirrors start-server.sh: writes voice.pid, logs to voice.log. Stop with:
#   kill "$(cat voice.pid)"
#
# The edge only advertises this server to clients when UWU_VOICE_ADDR is set on the
# EDGE (start-server.sh / its env), e.g. UWU_VOICE_ADDR=51.38.36.86:8470. Until the
# server completes the handshake for real, leave that UNSET so room entry is safe.
#
# On the VPS the voice UDP port must be reachable from players. pf currently redirects
# TCP 443->8443 / 80->8460; add a UDP pass/rdr for the voice port (default 8470) and
# open it in the OVH firewall.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
VOICE_PORT="${VOICE_PORT:-8470}"
export VOICE_PORT
echo "[i] starting UwUNet voice server on UDP :$VOICE_PORT"
nohup node server/src/voice/voice-server.ts > voice.log 2>&1 &
echo $! > voice.pid
echo "[+] voice server pid $(cat voice.pid), logging to voice.log"
echo "[i] tail -f voice.log to watch for the first ConnectRequest (locks ProtocolId)"
