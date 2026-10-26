#!/usr/bin/env bash
# smoke-test UwUNet auth: signup -> login -> /Accounts/account/me
set -u
cd /home/bloink/UwUNet
pkill -f "uwunet-edge" 2>/dev/null
TLS_PORT=8443 HTTP_PORT=8460 node server/src/uwunet-edge.ts > /tmp/opencode/uwunet-edge-test.log 2>&1 &
SRV=$!
sleep 1.3
BASE="https://test.rec.net:8443"
C="curl -sk --resolve test.rec.net:8443:127.0.0.1"

echo "== health:"
$C "$BASE/health"; echo
echo "== signup:"
$C -X POST "$BASE/Auth/connect/signup" -H 'content-type: application/json' \
  -d '{"username":"bloink","password":"uwunet1234"}' | head -c 400; echo
TOK=$($C -X POST "$BASE/Auth/connect/token" -H 'content-type: application/json' \
  -d '{"grant_type":"password","username":"bloink","password":"uwunet1234"}')
AT=$(node -e "let d=process.argv[1];try{console.log(JSON.parse(d).access_token)}catch(e){console.log('')}" "$TOK")
echo "== login token len: ${#AT}"
echo "== /Accounts/account/me:"
$C "$BASE/Accounts/account/me" -H "Authorization: Bearer $AT" | head -c 400; echo
echo "== bad password:"
$C -X POST "$BASE/Auth/connect/token" -H 'content-type: application/json' \
  -d '{"grant_type":"password","username":"bloink","password":"nope"}'; echo
kill $SRV 2>/dev/null
