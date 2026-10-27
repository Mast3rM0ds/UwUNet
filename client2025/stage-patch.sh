#!/usr/bin/env bash
# stage-patch.sh — copy the 2025 client patch into the downloaded 20250718
# build and write a UwUNet-pointed 2025patch.ini. Run AFTER the depot download.
#
#   ./stage-patch.sh [ApiHost]
#
# ApiHost defaults to empty (pure Referee-bypass boot test: client talks to its
# own dead hosts, proves it gets past the anti-cheat wall). Pass a host to point
# the game's API at a backend, e.g. ./stage-patch.sh <our-edge-host>.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BUILD="$HERE/depot"                                   # DepotDownloader output
PATCH="$HERE/../tools/patch2025-dl/extracted"
APIHOST="${1:-}"

[ -f "$BUILD/Recroom_Release.exe" ] || { echo "[!] $BUILD/Recroom_Release.exe missing — download the depot first (see README-run.md)"; exit 1; }

cp -v "$PATCH/2025Patch.dll" "$PATCH/Injector.exe" "$BUILD/"
# write ini (do NOT clobber an existing hand-edited one)
if [ ! -f "$BUILD/2025patch.ini" ]; then
  sed "s/^ApiHost=.*/ApiHost=$APIHOST/" "$PATCH/2025patch.ini" > "$BUILD/2025patch.ini"
  echo "[+] wrote $BUILD/2025patch.ini (ApiHost='$APIHOST')"
else
  echo "[=] kept existing $BUILD/2025patch.ini"
fi
echo "[+] staged. Next: $HERE/run.sh"
