#!/bin/sh
# start-voice.sh — launch the UwUNet voice server (Dissonance/LiteNetLib UDP).
# Mirrors start-server.sh: writes voice.pid, logs to voice.log. Stop with:
#   kill "$(cat voice.pid)"
#
# The edge only advertises this server to clients when UWU_VOICE_ADDR is set on the
# EDGE (start-server.sh / its env), e.g. UWU_VOICE_ADDR=51.38.36.86:8470. Until the
# server completes the handshake for real, leave that UNSET so room entry is safe.
#
# On the VPS the voice UDP port must be reachable from players. The voice server binds
# UDP 8470 directly (no redirect needed). Merge the pf pass rule from
# scripts/pf-voice.conf into /etc/pf.conf and reload — see that file for the exact,
# non-destructive apply steps and the OVH firewall note.
set -eu
HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"
VOICE_PORT="${VOICE_PORT:-8470}"
export VOICE_PORT
# Stop any previous instance first, or the new one hits EADDRINUSE and the log goes
# half-blind (two processes racing for the port).
if [ -f voice.pid ]; then kill "$(cat voice.pid)" 2>/dev/null || true; rm -f voice.pid; fi
pkill -f '[v]oice-server.ts' 2>/dev/null || true
sleep 1
echo "[i] starting UwUNet voice server on UDP :$VOICE_PORT"
nohup node server/src/voice/voice-server.ts > voice.log 2>&1 &
echo $! > voice.pid
echo "[+] voice server pid $(cat voice.pid), logging to voice.log"
echo "[i] tail -f voice.log to watch for the first ConnectRequest (locks ProtocolId)"
