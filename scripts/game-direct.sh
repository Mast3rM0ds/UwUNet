#!/usr/bin/env bash
# Direct-Proton UwUNet boot: no pressure-vessel, portrewriter LD_PRELOAD applies.
set -u
UWU=/home/bloink/UwUNet
STEAM=~/.local/share/Steam
GAME_DIR=$STEAM/steamapps/common/RecRoom
PROTON="$STEAM/steamapps/common/Proton - Experimental"

pkill -f uwunet-edge 2>/dev/null
rm -f "$UWU/data/harvest/requests.jsonl"
python3 "$UWU/scripts/pfx-hosts.py"
TLS_PORT=8443 HTTP_PORT=8460 node "$UWU/server/src/uwunet-edge.ts" > /tmp/opencode/uwunet-edge.log 2>&1 &
SRV=$!
echo "[uwunet-boot] edge pid $SRV on 8443/8460"
sleep 1

cd "$GAME_DIR"
export STEAM_COMPAT_CLIENT_INSTALL_PATH="$STEAM"
export STEAM_COMPAT_DATA_PATH="$STEAM/steamapps/compatdata/471710"
export SteamAppId=471710
export SteamGameId=471710
export PROTON_LOG=1
export LD_PRELOAD="$UWU/lib/portrewriter.so"

echo "[uwunet-boot] launching Recroom_Release.exe via direct Proton + preload + hosts"
"$PROTON/proton" run "./Recroom_Release.exe" +forcemode:vr &
GAME=$!

# serve until the game exits (or 10 min)
for i in $(seq 1 120); do
  sleep 5
  ALIVE=$(pgrep -fc "Recroom_Release" 2>/dev/null || true)
  HITS=$( [ -f "$UWU/data/harvest/requests.jsonl" ] && wc -l < "$UWU/data/harvest/requests.jsonl" || echo 0)
  echo "[t=$((i*5))s] game_procs=${ALIVE:-0} harvest=${HITS}"
  [ "${ALIVE:-0}" -gt 0 ] && [ "$HITS" -gt 0 ] && [ "$i" -ge 12 ] && break
  [ "$i" -ge 40 ] && break
done
echo "[uwunet-boot] last harvest entries:"
tail -20 "$UWU/data/harvest/requests.jsonl" 2>/dev/null
wait $GAME 2>/dev/null || true
kill $SRV 2>/dev/null
