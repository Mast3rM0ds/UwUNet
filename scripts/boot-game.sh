#!/usr/bin/env bash
# UwUNet game-boot orchestrator.
#
# Spins up a user-owned network namespace (no sudo), NAT-redirects any
# target :443 / :80 the game opens to UwUNet's TLS/HTTP edge, then boots
# Rec Room via Proton directly. TLS/SNI server needs no root and binds
# unpriv ports; netns iptables handles the redirect.
set -u

UWU=/home/bloink/UwUNet
STEAM=~/.local/share/Steam
GAME_DIR=$STEAM/steamapps/common/RecRoom
COMPAT=$STEAM/steamapps/compatdata/471710

# keep the game's /etc/hosts out of the way of wine-specific overrides
python3 "$UWU/scripts/pfx-hosts.py"

exec unshare -Urn bash -c '
set -u
UWU='"$UWU"'
COMPAT='"$COMPAT"'
GAME_DIR='"$GAME_DIR"'
STEAM='"$STEAM"'

# loopback up + redirect rules (we are root *inside this namespace*)
ip link set lo up
iptables -t nat -A OUTPUT -p tcp --dport 443 -j REDIRECT --to-ports 8443
iptables -t nat -A OUTPUT -p tcp --dport 80  -j REDIRECT --to-ports 8460
echo "[uwunet-netns] NAT: any tcp/443 -> 8443 (TLS edge), tcp/80 -> 8460"

# launch the TLS edge
TLS_PORT=8443 HTTP_PORT=8460 UWU_DEBUG=1 node "$UWU/server/src/uwunet-edge.ts" &
SRV=$!
sleep 1

# boot the game under Proton
export STEAM_COMPAT_CLIENT_INSTALL_PATH="$STEAM"
export STEAM_COMPAT_DATA_PATH="$COMPAT"
export STEAM_COMPAT_APP_ID=471710
export PROTON_LOG=1
export WINEDLLOVERRIDES="mscoree,mshtml="
export WINEDBG="-all -debug"
printf "[uwunet-netns] launching Proton + RecRoom.exe against UwUNet TLS ...\n"
"$STEAM/steamapps/common/Proton - Experimental/proton" run "$GAME_DIR/RecRoom.exe" &
GAME=$!

# keep the namespace alive as long as the game runs; server stays up
trap "kill $SRV $GAME 2>/dev/null" EXIT INT TERM
wait $GAME 2>/dev/null || true
echo "[uwunet-netns] game exited"
wait $SRV 2>/dev/null || true
'
