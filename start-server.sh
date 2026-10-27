#!/bin/sh
set -eu

UWU="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
LOG="$UWU/edge.log"
PIDFILE="$UWU/edge.pid"

cd "$UWU"

if [ -f "$PIDFILE" ]; then
    PID="$(cat "$PIDFILE")"
    if kill -0 "$PID" 2>/dev/null; then
        echo "[run] edge already running (pid $PID)"
        exit 0
    fi
    rm -f "$PIDFILE"
fi

export TLS_PORT="${TLS_PORT:-8443}"
export HTTP_PORT="${HTTP_PORT:-8460}"

nohup node "$UWU/server/src/uwunet-edge.ts" \
    >> "$LOG" 2>&1 < /dev/null &
PID=$!
echo "$PID" > "$PIDFILE"

sleep 1

if kill -0 "$PID" 2>/dev/null; then
    echo "[run] edge started (pid $PID)"
    echo "[run] TLS port: $TLS_PORT"
    echo "[run] HTTP port: $HTTP_PORT"
    echo "[run] log: $LOG"
else
    rm -f "$PIDFILE"
    echo "[error] edge failed to start; inspect $LOG"
    exit 1
fi

