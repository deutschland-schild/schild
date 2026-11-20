#!/bin/bash
# TEST ONLY: evening re-measurement 2026-10-29, item 9d. Saves API responses of OUR running schild
# (agent API with bearer token, dashboard API with a session cookie) for the privacy search with
# d36n-a/privacy_a.py (spec21 replay ranges) or d36n/privacy_d36.py (10.0.0.0/8, traffic.mjs).
#   priv_collect.sh <dashboard base> <agent base> <token file> <out dir> <site,site,...>
#   e.g. priv_collect.sh http://127.0.0.1:22588 http://127.0.0.1:22589 /tmp/abend/k/exact/token priv shop.test,down.test,slow.test
set -u
DASH=$1; AG=$2; TOK=$(cat $3); OUT=$4; SITES=$5
PW=${PW:-schild-abend-messung-TESTONLY}
mkdir -p $OUT; J=$(mktemp)
curl -s -c $J -X POST -H 'Content-Type: application/json' -d "{\"password\":\"$PW\"}" $DASH/api/v0/auth/login > /dev/null
to=$(date -u +%Y-%m-%dT%H:%M:%SZ); from=$(date -u -v-6H +%Y-%m-%dT%H:%M:%SZ); q="from=$from&to=$to"
a() { curl -s -o $OUT/$1.json -w "$1 %{http_code}\n" -H "Authorization: Bearer $TOK" "$AG/agent/v0$2"; }
d() { curl -s -b $J -o $OUT/$1.json -w "$1 %{http_code}\n" "$DASH/api/v0$2"; }
a ag-status /status; a ag-now /monitoring/now; a ag-server /monitoring/server; a ag-websites /websites
a ag-events "/events?$q"; a ag-incidents "/incidents?$q"
for r in 10s 1m 10m; do a ag-buckets-$r "/monitoring/buckets?resolution=$r&$q"; done
for by in country asn net_class path referrer rule site status_class browser ua_class; do a ag-bd-$by "/monitoring/traffic/breakdown?by=$by&$q&top=50"; done
d overview /overview; d now /monitoring/now; d websites /websites; d events "/events?limit=200"; d incidents "/incidents?limit=200"
d alerts "/monitoring/alerts?limit=200"; d series "/monitoring/series?metric=traffic.requests:sum&$q&resolution=1m"
for s in ${SITES//,/ }; do
  a ag-website-$s /websites/$s; d website-$s /websites/$s; d kpis-$s "/websites/$s/kpis?$q"; d realtime-$s /websites/$s/realtime
  d annotations-$s "/websites/$s/annotations?$q"
  for by in country asn path referrer net_class; do d bd-$s-$by "/monitoring/traffic/breakdown?by=$by&$q&site=$s&top=50"; done
done
rm -f $J
