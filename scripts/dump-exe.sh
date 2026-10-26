#!/bin/bash
# Freeze RecRoom.exe the moment its imports are attached (>= decrypted .text)
# and dump the image from /proc/pid/mem.
PFX=~/.local/share/Steam/steamapps/compatdata/471710/pfx
W="$HOME/.local/share/Steam/steamapps/common/Proton - Experimental/files/bin/wine"
OUT="${1:-/tmp/opencode/recroom-dump.bin}"
cd /tmp/opencode/gamedir || exit 1
env WINEPREFIX=$PFX WINEDEBUG=-all LD_PRELOAD=/home/bloink/UwUNet/lib/uwuhook32.so:/home/bloink/UwUNet/lib/uwuhook.so \
  "$W" RecRoom.exe >/tmp/opencode/recroom-dumprun.log 2>&1 &
WP=$!
PID=""
for i in $(seq 1 600); do
  for p in /proc/[0-9]*/maps; do
    if grep -qa "gamedir/RecRoom" "$p" 2>/dev/null && grep -qa "Referee" "$p" 2>/dev/null && grep -qa "^0000000140000000" "$p"; then
      PID=$(dirname "$p" | sed 's|/proc/||'); break 2
    fi
  done
  sleep 0.05
done
if [ -z "$PID" ]; then echo "never caught RecRoom.exe"; kill $WP 2>/dev/null; exit 1; fi
echo "stopped RecRoom pid $PID"
kill -STOP "$PID"
dd if=/proc/$PID/mem of="$OUT" bs=4096 skip=$((0x140000000/4096)) count=$((0xB0)) 2>/dev/null
echo "dump: $OUT ($(stat -c%s "$OUT") bytes)"
# leave stopped; caller decides
echo "$PID" > /tmp/opencode/recroom.pid
