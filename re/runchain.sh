#!/bin/bash
# runchain.sh [winedebug] — boot the real chain via Recroom_Release.exe with our hooks.
# relaunches a fresh wineserver (pkill -x by comm name only — never pkill -f).
pkill -9 -x wineserver 2>/dev/null
sleep 1
cd /tmp/opencode/gamedir2 || exit 1
WINE="$HOME/.local/share/Steam/steamapps/common/Proton - Experimental/files/bin/wine"
WINEPREFIX="$HOME/.local/share/Steam/steamapps/compatdata/471710/pfx"
export WINEPREFIX
export WINEDEBUG="${1:-}"
export LD_PRELOAD="/home/bloink/UwUNet/lib/uwuhook.so:/home/bloink/UwUNet/lib/uwudns64.so"
exec "$WINE" Recroom_Release.exe
