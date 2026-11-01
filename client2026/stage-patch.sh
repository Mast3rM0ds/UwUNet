#!/usr/bin/env bash
# stage-patch.sh — copy the 2026 client patch (recflare/patch-2026 v0.0.3) into the
# downloaded 20260323.14 build and write a UwUNet-pointed 2026patch.ini. Run AFTER the
# depot download (see README-run.md).
#
#   ./stage-patch.sh
#
# ApiHost stays EMPTY: run.sh's uwudns64 shim already sends every *.rec.net host to the
# edge, so the patch needs no URL rewriting. ServerDomain=rec.net scopes the patch's
# certificate-pin bypass to the hosts our edge impersonates (our own CA, not rec.net's).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BUILD="$HERE/depot"                                   # DepotDownloader output
PATCH="$HERE/../tools/patch2026-dl/extracted"

[ -f "$BUILD/RecRoom.exe" ] || { echo "[!] $BUILD/RecRoom.exe missing — download the depot first (see README-run.md)"; exit 1; }
[ -f "$PATCH/2026patch.dll" ] || { echo "[!] patch missing — gh release download v0.0.3 -R recflare/patch-2026 into tools/patch2026-dl and unzip to extracted/"; exit 1; }

cp -v "$PATCH/2026patch.dll" "$PATCH/Injector.exe" "$BUILD/"
# write ini (do NOT clobber an existing hand-edited one)
if [ ! -f "$BUILD/2026patch.ini" ]; then
  sed -e "s/^ServerDomain=.*/ServerDomain=rec.net/" \
      -e "s/^DisableCertificatePinning=.*/DisableCertificatePinning=true/" \
      -e "s/^AllowUnsignedImages=.*/AllowUnsignedImages=true/" \
      "$PATCH/2026patch.ini" > "$BUILD/2026patch.ini"
  echo "[+] wrote $BUILD/2026patch.ini (ServerDomain=rec.net, ApiHost empty)"
else
  echo "[=] kept existing $BUILD/2026patch.ini"
fi
echo "[+] staged. Next: $HERE/run.sh"
