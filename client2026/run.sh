#!/usr/bin/env bash
# run.sh — launch the patched 20260323.14 client under Proton.
#   Same layout as client2025/run.sh: the shims + socat forward to the VPS edge, then the
#   patch's Injector.exe (check-install, start, wait-ready — what its RecRoomScreen.bat
#   does), then RecRoom.exe.
#
#   ./run.sh [screen|vr]      (default: screen)
set -u
MODE="${1:-screen}"
UWU=/home/bloink/Work/UwUNet
BUILD="$UWU/client2026/depot"
STEAM=~/.local/share/Steam
PROTON="$STEAM/steamapps/common/Proton - Experimental"
LOG="$UWU/client2026/logs"
mkdir -p "$LOG"

[ -f "$BUILD/RecRoom.exe" ]  || { echo "[!] build not found at $BUILD — download depot + run stage-patch.sh first"; exit 1; }
[ -f "$BUILD/Injector.exe" ] || { echo "[!] patch not staged — run ./stage-patch.sh first"; exit 1; }

# *.rec.net -> 127.0.0.1 and loopback :443->8443 / :80->8460 (see client2025/run.sh).
PRELOAD="$UWU/lib/uwudns64.so:$UWU/lib/portrewriter.so"
if [ "${EDGE_EXTERNAL:-0}" != "1" ]; then
  VPS_HOST="vps-caa6c6fd.vps.ovh.net"

  # Stop a locally running edge, if present.
  pkill -f '[u]wunet-edge.ts' 2>/dev/null || true

  socat TCP4-LISTEN:8443,bind=127.0.0.1,reuseaddr,fork \
    "TCP4:${VPS_HOST}:8443" > "$LOG/forward-https.log" 2>&1 &
  HTTPS_FORWARD_PID=$!
  socat TCP4-LISTEN:8460,bind=127.0.0.1,reuseaddr,fork \
    "TCP4:${VPS_HOST}:8460" > "$LOG/forward-http.log" 2>&1 &
  HTTP_FORWARD_PID=$!

  cleanup() {
    kill "$HTTPS_FORWARD_PID" "$HTTP_FORWARD_PID" 2>/dev/null || true
  }
  trap cleanup EXIT INT TERM

  echo "[run] forwarding local 8443/8460 -> ${VPS_HOST}"
  sleep 1
else
  echo "[run] using externally managed edge forwarding"
fi

cd "$BUILD"
export STEAM_COMPAT_CLIENT_INSTALL_PATH="$STEAM"
export STEAM_COMPAT_DATA_PATH="$STEAM/steamapps/compatdata/471710"
export SteamAppId=471710 SteamGameId=471710 PROTON_LOG=1
[ -n "$PRELOAD" ] && export LD_PRELOAD="$PRELOAD"

# Screen mode must not pre-init OpenVR (hangs at "GfxDevice: creating device client" —
# see client2025/run.sh). Regenerate boot.config from the pristine .orig per mode.
BOOTCFG="$BUILD/RecRoom_Data/boot.config"
if [ -f "$BOOTCFG" ]; then
  [ -f "$BOOTCFG.orig" ] || cp "$BOOTCFG" "$BOOTCFG.orig"
  grep -v '^xrsdk-pre-init-library=' "$BOOTCFG.orig" > "$BOOTCFG"
  if [ "$MODE" = "vr" ]; then
    echo 'xrsdk-pre-init-library=XRSDKOpenVR' >> "$BOOTCFG"
    echo "[run] boot.config: OpenVR pre-init ENABLED (VR)"
  else
    echo "[run] boot.config: OpenVR pre-init removed (flat desktop window)"
  fi
fi

"$PROTON/proton" run "./Injector.exe" --check-install > "$LOG/injector-check.log" 2>&1 \
  || { echo "[!] Injector --check-install failed:"; cat "$LOG/injector-check.log"; exit 1; }
echo "[run] starting Injector.exe"
"$PROTON/proton" run "./Injector.exe" > "$LOG/injector.log" 2>&1 &
"$PROTON/proton" run "./Injector.exe" --wait-ready >> "$LOG/injector.log" 2>&1 \
  || { echo "[!] Injector never became ready — see $LOG/injector.log"; exit 1; }
echo "[run] launching RecRoom.exe +forcemode:$MODE"
"$PROTON/proton" run "./RecRoom.exe" "+forcemode:$MODE" > "$LOG/game.log" 2>&1 &
GAME=$!
echo "[run] watch: tail -f '$BUILD/2026patch.log'  (confirms patch attached)"
wait $GAME 2>/dev/null || true
