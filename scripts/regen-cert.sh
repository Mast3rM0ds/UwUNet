#!/usr/bin/env bash
# regen-cert.sh — re-issue the edge leaf certificate (certs/rec.crt) with extra SAN
# entries, so clients that reach the edge by a name/address not already in the cert
# stop rejecting the TLS handshake (the "failed to connect / summer" symptom when a
# client connects by bare IP).
#
# It REUSES the existing private key (certs/rec.key) — so the public key / SPKI is
# unchanged and any certificate pinning still matches — and signs with the existing
# UwUNet CA (certs/uwunet-ca.*), so clients that already trust the CA trust the new
# cert immediately. Every SAN already in the cert is preserved; the entries you pass
# as arguments are added (de-duplicated).
#
#   sh scripts/regen-cert.sh IP:51.38.36.86
#   sh scripts/regen-cert.sh IP:51.38.36.86 DNS:vps-caa6c6fd.vps.ovh.net
#
# After it runs, restart the edge so it serves the new cert.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
C="$HERE/certs"
for f in rec.key rec.crt uwunet-ca.crt uwunet-ca.key; do
  [ -f "$C/$f" ] || { echo "[!] missing certs/$f"; exit 1; }
done

# Preserve the current SAN list (openssl prints IPs as "IP Address:"; the config
# directive wants "IP:"), then append the entries passed as arguments, de-duplicated
# in first-seen order.
cur="$(openssl x509 -in "$C/rec.crt" -noout -ext subjectAltName 2>/dev/null \
  | grep -v 'Subject Alternative' \
  | tr ',' '\n' \
  | sed 's/^[[:space:]]*//; s/[[:space:]]*$//; s/^IP Address:/IP:/' \
  | grep .)"
list="$(printf '%s\n' $cur "$@" | awk 'NF && !seen[$0]++')"
san="$(printf '%s\n' "$list" | paste -sd, -)"
echo "[i] SAN -> $san"

ext="$(mktemp)"; csr="$(mktemp)"
cat > "$ext" <<EOF
subjectAltName = $san
basicConstraints = CA:FALSE
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EOF

cp -f "$C/rec.crt" "$C/rec.crt.bak-$(date +%s)"
openssl req -new -key "$C/rec.key" -subj "/CN=rec.net/O=UwUNet/C=US" -out "$csr"
openssl x509 -req -in "$csr" -CA "$C/uwunet-ca.crt" -CAkey "$C/uwunet-ca.key" \
  -CAcreateserial -days 3650 -sha256 -extfile "$ext" -out "$C/rec.crt"
rm -f "$ext" "$csr"

echo "[+] re-issued certs/rec.crt"
openssl verify -CAfile "$C/uwunet-ca.crt" "$C/rec.crt"
echo "[i] now restart the edge so it serves the new cert."
