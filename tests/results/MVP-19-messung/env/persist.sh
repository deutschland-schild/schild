#!/bin/sh
# Host side: local state across a restart (MVP-19 measure "reload/restart").
# 1. fresh schild (autoblock, trusted proxy for X-Forwarded-For), dashboard
#    password via localhost, allowlist entry via CLI, one blocked request
#    unblocked via the dashboard API (exception), learning end recorded;
# 2. container restart; 3. the same checks again. Data dir is a named
# volume (bind mounts from macOS broke SQLite locking in an earlier run).
cd "$(dirname "$0")" && . ./env.sh
D=m19-persist; docker volume rm -f $D >/dev/null 2>&1
ingress_rm; ingress_schild $ST/d-stock $D $E/Caddyfile.schild $E/schild-fp.yaml; wait_https shop.example.de
api() { docker exec m19-cap curl -s -b /tmp/cj -c /tmp/cj -H 'Content-Type: application/json' "$@"; }
X='/?q=%3Cscript%3Ealert(1)%3C/script%3E'
req() { t curl -s -o /dev/null -w '%{http_code}' --cacert /st/pebble-root.pem --resolve shop.example.de:443:$ING -H "X-Forwarded-For: $1" "https://shop.example.de$2"; }
api -X POST -d '{"password":"m19-measure-only-passwort"}' http://127.0.0.1:8788/api/v0/auth/setup >/dev/null
api -X POST -d '{"password":"m19-measure-only-passwort"}' http://127.0.0.1:8788/api/v0/auth/login >/dev/null
CSRF=$(api http://127.0.0.1:8788/api/v0/auth/session | jq -r .csrf_token)
docker exec ingress schild allow 198.51.100.50 -ttl never -label m19-allow
sleep 6
echo "before: allowlisted attack $(req 198.51.100.50 "$X")  other attack $(req 198.51.100.60 "$X")"
INC=$(docker exec m19-cap sh -c "curl -s -b /tmp/cj 'http://127.0.0.1:8788/api/v0/events?limit=20'" | jq -r '[.items[]? // .events[]? | select(.incident != null and .incident != "" and .ip == "198.51.100.60")][0].incident')
echo "incident $INC unblock: $(api -X POST -H "X-CSRF-Token: $CSRF" -d '{"false_positive":true,"allow_ip":false}' http://127.0.0.1:8788/api/v0/incidents/$INC/unblock | head -c 300)"
echo "after unblock: same attack from 198.51.100.60 $(req 198.51.100.60 "$X")"
L1=$(api http://127.0.0.1:8788/api/v0/distributed/settings | jq -c '{learning_until,learning_days}')
A1=$(docker exec ingress schild allow list | grep -c m19-allow)
docker restart ingress >/dev/null; wait_https shop.example.de
api -X POST -d '{"password":"m19-measure-only-passwort"}' http://127.0.0.1:8788/api/v0/auth/login >/dev/null
L2=$(api http://127.0.0.1:8788/api/v0/distributed/settings | jq -c '{learning_until,learning_days}')
A2=$(docker exec ingress schild allow list | grep -c m19-allow)
echo "learning before $L1 after $L2"
echo "allowlist entries before $A1 after $A2"
echo "after restart: allowlisted attack $(req 198.51.100.50 "$X")  unblocked client $(req 198.51.100.60 "$X")  new client $(req 198.51.100.61 "$X")"
echo "dashboard login after restart: $(docker exec m19-cap curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -d '{"password":"m19-measure-only-passwort"}' http://127.0.0.1:8788/api/v0/auth/login)"
docker logs ingress 2>&1 | grep -c malformed | sed 's/^/malformed-db log lines: /'
