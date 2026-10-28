#!/usr/bin/env bash
# run.sh — launch the patched 20250718 client under Proton.
#   Injector.exe is started first (it waits for Recroom_Release.exe, then for
#   GameAssembly.dll + Referee.dll, then attaches 2025Patch.dll), then the game.
# Modeled on scripts/game-direct.sh. Iterate here once the depot exists.
#
#   ./run.sh [screen|vr]      (default: screen)
set -u
MODE="${1:-screen}"
UWU=/home/bloink/UwUNet
BUILD="$UWU/client2025/depot"
STEAM=~/.local/share/Steam
PROTON="$STEAM/steamapps/common/Proton - Experimental"
LOG="$UWU/client2025/logs"
mkdir -p "$LOG"

[ -f "$BUILD/Recroom_Release.exe" ] || { echo "[!] build not found at $BUILD — download depot + run stage-patch.sh first"; exit 1; }
[ -f "$BUILD/Injector.exe" ]        || { echo "[!] patch not staged — run ./stage-patch.sh first"; exit 1; }

# Redirect ALL *.rec.net to the UwUNet edge at the DNS + port layer:
#   uwudns64.so  : getaddrinfo(*.rec.net) -> 127.0.0.1  (works for both the
#                  game's BestHTTP AND its .NET HttpClient, which the patch's
#                  URL-rewrite hook does NOT cover — that was the stall)
#   portrewriter : loopback :443->8443, :80->8460 (edge on unpriv ports)
# ApiHost in 2025patch.ini is left EMPTY so the patch does no URL rewriting and
# every rec.net host (ns/api/accounts/rooms/...) lands on us uniformly.
PRELOAD="$UWU/lib/uwudns64.so:$UWU/lib/portrewriter.so"
if [ "${EDGE_EXTERNAL:-0}" != "1" ]; then
  VPS_HOST="vps-caa6c6fd.vps.ovh.net"

  # Stop a locally running edge, if present.
  pkill -f '[u]wunet-edge.ts' 2>/dev/null || true

  # Forward the local HTTPS edge port to the VPS.
  socat TCP4-LISTEN:8443,bind=127.0.0.1,reuseaddr,fork \
    "TCP4:${VPS_HOST}:8443" > "$LOG/forward-https.log" 2>&1 &
  HTTPS_FORWARD_PID=$!

  # Forward the local HTTP edge port to the VPS.
  socat TCP4-LISTEN:8460,bind=127.0.0.1,reuseaddr,fork \
    "TCP4:${VPS_HOST}:8460" > "$LOG/forward-http.log" 2>&1 &
  HTTP_FORWARD_PID=$!

  cleanup() {
    kill "$HTTPS_FORWARD_PID" "$HTTP_FORWARD_PID" 2>/dev/null || true
  }
  trap cleanup EXIT INT TERM

  echo "[run] forwarding local 8443 -> ${VPS_HOST}:8443"
  echo "[run] forwarding local 8460 -> ${VPS_HOST}:8460"
  sleep 1
else
  echo "[run] using externally managed edge forwarding"
fi

cd "$BUILD"
export STEAM_COMPAT_CLIENT_INSTALL_PATH="$STEAM"
export STEAM_COMPAT_DATA_PATH="$STEAM/steamapps/compatdata/471710"
export SteamAppId=471710 SteamGameId=471710 PROTON_LOG=1
[ -n "$PRELOAD" ] && export LD_PRELOAD="$PRELOAD"

# Rec Room forces OpenVR at ENGINE STARTUP via boot.config's xrsdk-pre-init-library line.
# That line is required for VR, but in screen mode it hangs the game forever at
# "GfxDevice: creating device client" waiting on a VR compositor that never comes up
# (process alive, no window). So regenerate boot.config to match the launch mode: keep
# every other line from the pristine .orig, and only re-add the xrsdk line for vr.
BOOTCFG="$BUILD/Recroom_Release_Data/boot.config"
if [ -f "$BOOTCFG" ]; then
  [ -f "$BOOTCFG.orig" ] || cp "$BOOTCFG" "$BOOTCFG.orig"
  grep -v '^xrsdk-pre-init-library=' "$BOOTCFG.orig" > "$BOOTCFG"
  if [ "$MODE" = "vr" ]; then
    echo 'xrsdk-pre-init-library=XRSDKOpenVR' >> "$BOOTCFG"
    echo "[run] boot.config: OpenVR pre-init ENABLED (VR — SteamVR auto-starts on VR_Init)"
  else
    echo "[run] boot.config: OpenVR pre-init removed (flat desktop window)"
  fi
fi

echo "[run] starting Injector.exe"
"$PROTON/proton" run "./Injector.exe" > "$LOG/injector.log" 2>&1 &
sleep 2
echo "[run] launching Recroom_Release.exe +forcemode:$MODE"
"$PROTON/proton" run "./Recroom_Release.exe" "+forcemode:$MODE" > "$LOG/game.log" 2>&1 &
GAME=$!
echo "[run] watch: tail -f '$BUILD/2025patch.log'  (confirms patch attached)"
echo "[run] watch: tail -f '$UWU/data/harvest/requests.jsonl'  (real API requests)"
wait $GAME 2>/dev/null || true
