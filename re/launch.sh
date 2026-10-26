#!/bin/bash
# launch.sh — one-shot relaunch of the dump session (idempotent):
#   edge (if down), freezer, memory watcher, boot chain.
# All artifacts under /home/bloink/UwUNet/re/{logs,dumps} so server restarts
# can't wipe them. Run detached: setsid nohup ./launch.sh >launch.out &
LOGS=/home/bloink/UwUNet/re/logs
DUMPS=/home/bloink/UwUNet/re/dumps
mkdir -p "$LOGS" "$DUMPS"

# recreate gamedir2 symlinks if tmp got wiped
if [ ! -e /tmp/opencode/gamedir2/Recroom_Release.exe ]; then
    mkdir -p /tmp/opencode/gamedir2
    for f in "/home/bloink/.local/share/Steam/steamapps/common/RecRoom/"*; do
        ln -sfn "$f" "/tmp/opencode/gamedir2/$(basename "$f")"
    done
fi

# edge, only if not listening
if ! ss -ltn | grep -q ':8443'; then
    cd /home/bloink/UwUNet/server
    setsid nohup node --experimental-strip-types src/uwunet-edge.ts \
        >> "$LOGS/uwunet-edge.log" 2>&1 < /dev/null &
    disown
    sleep 3
fi

# freezer (holds the last RefereeClientApp so the launcher proceeds to the game)
setsid nohup /home/bloink/UwUNet/re/freeze-svc4 "$LOGS" \
    > "$LOGS/freeze4.log" 2>&1 < /dev/null &
disown

# memory watcher (dumps Referee* modules of any live process)
setsid nohup env DUMPTIMEOUT=500 DUMPDIR="$DUMPS" \
    python3 /home/bloink/UwUNet/re/dumpmod.py 'Referee' \
    > "$LOGS/dumpmod.log" 2>&1 < /dev/null &
disown
sleep 2

# fresh wineserver, relay-logged boot chain
setsid nohup timeout 220 /home/bloink/UwUNet/re/runchain.sh +relay \
    > "$LOGS/chain-relay.log" 2>&1 < /dev/null &
disown
echo "launched: $(date +%T)"
