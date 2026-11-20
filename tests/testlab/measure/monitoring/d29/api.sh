#!/bin/sh
# TEST ONLY: api.sh METHOD PATH [JSON]  dashboard API with a stored session.
# Env: DPORT (dashboard port, default 19288), PW (dashboard password of the test instance).
DPORT=${DPORT:-19288}
C=/tmp/m21d36/c/cj-$DPORT.txt
B=http://127.0.0.1:$DPORT/api/v0
if [ "$1" = login ]; then
  curl -s -c $C -X POST -H 'Content-Type: application/json' -d "{\"password\":\"$PW\"}" $B/auth/setup | grep -q csrf_token ||
  curl -s -c $C -X POST -H 'Content-Type: application/json' -d "{\"password\":\"$PW\"}" $B/auth/login
  echo; exit 0
fi
CSRF=$(curl -s -b $C $B/auth/session | python3 -c "import sys,json;print(json.load(sys.stdin).get('csrf_token',''))")
if [ -n "${3:-}" ]; then
  curl -s -w '\nHTTP %{http_code}\n' -b $C -X "$1" -H 'Content-Type: application/json' -H "X-CSRF-Token: $CSRF" -d "$3" "$B$2"
else
  curl -s -w '\nHTTP %{http_code}\n' -b $C -X "$1" -H "X-CSRF-Token: $CSRF" "$B$2"
fi
