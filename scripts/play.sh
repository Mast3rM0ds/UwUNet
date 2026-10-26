#!/usr/bin/env bash
# UwUNet player launcher — run this instead of "Play" in Steam.
#  1. starts the UwUNet edge (TLS on 8443 + HTTP, with auth)
#  2. writes the rec.net -> 127.0.0.1 redirects into the Wineprefix hosts
#  3. boots Rec Room with the portrewriter LD_PRELOAD (443→8443, 80→8460)
#  4. tails the harvest log so you can watch the client hit UwUNet
#
# Usage:  ./scripts/play.sh            # launcher route  (Referee)
#         ./scripts/play.sh direct     # skip Referee, boot RecRoom.exe
set -u
UWU=/home/bloink/UwUNet
STEAM=~/.local/share/Steam
GAME_DIR="$STEAM/steamapps/common/RecRoom"
MODE=${1:-launcher}

pkill -f uwunet-edge 2>/dev/null
python3 "$UWU/scripts/pfx-hosts.py"
TLS_PORT=8443 HTTP_PORT=8460 nohup node "$UWU/server/src/uwunet-edge.ts" \
  > /tmp/uwunet-edge.log 2>&1 &
echo "UwUNet edge up  (web signup: curl http://127.0.0.1:8460/ in a browser)"
sleep 1

cd "$GAME_DIR"
export STEAM_COMPAT_CLIENT_INSTALL_PATH="$STEAM"
export STEAM_COMPAT_DATA_PATH="$STEAM/steamapps/compatdata/471710"
export SteamAppId=471710 SteamGameId=471710
export LD_PRELOAD="$UWU/lib/uwuhook.so:$UWU/lib/uwuhook32.so"

if [ "$MODE" = "direct" ]; then
  exec "$STEAM/steamapps/common/Proton - Experimental/files/bin/wine" RecRoom.exe +forcemode:vr
else
  exec "$STEAM/steamapps/common/Proton - Experimental/files/bin/wine" Recroom_Release.exe +forcemode:vr
fi

# after the game exits, show what the client tried:
echo "--- UwUNet harvest ---"
node /home/bloink/UwUNet/server/src/harvest-report.ts 2>/dev/null
tail -60 "$UWU/data/harvest/requests.jsonl" 2>/dev/null
