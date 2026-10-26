#!/usr/bin/env bash
# Freeze RefereeClientApp.exe mid-run and dump its address space.
# The service only lives ~2s before it stops itself, so we poll栖 the
# unix-side process table, SIGSTOP wine the instant it appears, then
# dd /proc/PID/mem region by region.
set -u
PFX=~/.local/share/Steam/steamapps/compatdata/471710/pfx
GAME=~/.local/share/Steam/steamapps/common/RecRoom
WINE="$HOME/.local/share/Steam/steamapps/common/Proton - Experimental/files/bin/wine"
UWU=/home/bloink/UwUNet
OUT=/tmp/opencode/referee-dump.bin
rm -f "$OUT"

cd "$GAME"
LD_PRELOAD="/home/bloink/UwUNet/lib/uwuhook.so:$UWU/lib/uwuhook32.so" \
  env WINEPREFIX=$PFX WINEDEBUG=-all \
  STEAM_COMPAT_CLIENT_INSTALL_PATH=$HOME/.local/share/Steam \
  STEAM_COMPAT_DATA_PATH=$HOME/.local/share/Steam/steamapps/compatdata/471710 \
  SteamAppId=471710 SteamGameId=471710 < /dev/null \
  "$WINE" Recroom_Release.exe +forcemode:vr > /tmp/opencode/dumpsrv.log 2>&1 &
winepid=$!

# poll every 20ms for up to 10s
# poll every 20ms for up to 10s — the process must have reached the
# x86_64 loader stage (64-bit PEs pass through a transient 32-bit stage)
victim=""
for i in $(seq 1 500); do
  for d in /proc/[0-9]*; do
    if grep -qs "RefereeClientApp" "$d/cmdline" 2>/dev/null; then
      cand="${d#/proc/}"
      if readlink "/proc/$cand/exe" 2>/dev/null | grep -q "wine64-preloader"; then
        victim="$cand"
        break 2
      fi
    fi
  done
  sleep 0.02
done
if [ -z "$victim" ]; then echo "captured: nothing — service exited before we saw it"; exit 1; fi
if [ -n "${STOP_ON_LOGMATCH:-}" ]; then
  # freeze at the exact moment a pattern appears in the App log; poll hard
  APP_LOG=/home/bloink/.local/share/Steam/steamapps/compatdata/471710/pfx/drive_c/ProgramData/Referee/Referee.App.log
  SZ0=$(stat -c%s "$APP_LOG" 2>/dev/null || echo 0)
  echo "== log-match mode: pattern='$STOP_ON_LOGMATCH' from offset $SZ0"
  for i in $(seq 1 5000); do
    SZ=$(stat -c%s "$APP_LOG" 2>/dev/null || echo 0)
    if [ "$SZ" -gt "$SZ0" ]; then
      LOGSZ0=$SZ0; OFFSET=$(( LOGSZ0 + 1 ))
      while read -r line; do :; done < /dev/null
      if tail -c +"$OFFSET" "$APP_LOG" | grep -q "$STOP_ON_LOGMATCH"; then
        kill -STOP "$victim" 2>/dev/null
        break
      fi
    fi
    sleep 0.003
  done
  echo "== frozen on log match after t=$i polls (state=$(awk '{print $3}' /proc/$victim/stat 2>/dev/null))"
else
  kill -STOP "$victim" 2>/dev/null
  echo "== target=$victim exe=$(readlink /proc/$victim/exe 2>/dev/null)"
  sleep "${FREEZE_DELAY:-1.9}"
  kill -STOP "$victim" 2>/dev/null   # ensure still stopped (belt & suspenders)
  echo "== state=$(awk '{print $3}' /proc/$victim/stat 2>/dev/null)"
fi
echo "stopped pid $victim at t=$(grep -c LOADED /tmp/opencode/uwuhook.log 2>/dev/null)"

# dump all readable regions (commit cards for private anon + file-backed)
python3 - "$victim" >> "$OUT" <<'EOF'
import sys
pid = int(sys.argv[1])
with open(f"/proc/{pid}/maps") as f:
    maps = [l.split() for l in f if " r" in " ".join(l.split()[1:2]) + l]
    maps = [l for l in map(str.split, open(f"/proc/{pid}/maps"))
            if l[1].startswith("r")]
mem = open(f"/proc/{pid}/mem", "rb", buffering=0)
count = 0
for m in maps:
    start, end = (int(x, 16) for x in m[0].split("-"))
    if end - start > 512 * 1024 * 1024:
        continue
    if "[v" in m[-1] or "[stack" in m[-1] and False:
        pass
    try:
        mem.seek(start)
        data = mem.read(end - start)
    except (OSError, ValueError):
        continue
    sys.stdout.buffer.write(f"\n@@REGION {start:x}-{end:x} {m[1]} {m[-1]}\n".encode())
    sys.stdout.buffer.write(data)
    count += 1
import sys as s
s.stderr.write(f"dumped {count} regions\n")
EOF
echo "dump size: $(stat -c%s "$OUT")"
kill -CONT "$victim" 2>/dev/null; sleep 0.3
kill -TERM "$victim" 2>/dev/null
tail -2 /home/bloink/.local/share/Steam/steamapps/compatdata/471710/pfx/drive_c/ProgramData/Referee/Referee.App.log
