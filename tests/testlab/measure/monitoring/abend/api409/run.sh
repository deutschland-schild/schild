#!/bin/sh
# TEST ONLY: abend api409 measurement (commit c54de1b, after a34c2a6 "no avoidable 409s").
# Two native instances behind one spec21 backend (127.0.0.1:22699):
#   on  = monitoring on (request ring: MVP-22 absent, so /requests always 409 requests_off)
#         gateway 22610, dashboard 22688, metrics 22611
#   off = monitoring.enabled false; gateway 22620, dashboard 22689, metrics 22621
# Traffic: ../../ui36n/traffic.mjs (-offset 16: attack wave 2-7 min after start).
# Then uiseq.py replays the dashboard's API calls per page load and records every status.
# Usage: run.sh start | seq LABEL | stop
# Env: W (work dir, default /tmp/abend/dd), BIN (schild), MEASURE_BIN, PW (TEST ONLY password).
set -eu
W=${W:-/tmp/abend/dd}; BIN=${BIN:-/tmp/abend/bin/schild}; MEASURE_BIN=${MEASURE_BIN:-/tmp/abend/bin/spec21}
PW=${PW:-abend-TEST-ONLY-pw-2026}; H=$(cd "$(dirname "$0")" && pwd)
case "$1" in
start)
  nohup "$MEASURE_BIN" backend -listen 127.0.0.1:22699 > "$W/backend.log" 2>&1 & echo $! > "$W/backend.pid"
  for m in on off; do
    mkdir -p "$W/$m"; cp "$H/$m-Caddyfile" "$W/$m/Caddyfile"; cp "$H/$m-schild.yaml" "$W/$m/schild.yaml"
    # geo.mmdb: the ui36n TEST ONLY database (copy from a previous run, e.g. /tmp/d36n/off/geo.mmdb)
    SCHILD_LOG_FORMAT=json nohup "$BIN" run -config "$W/$m/schild.yaml" > "$W/$m/schild.log" 2>&1 & echo $! > "$W/$m/schild.pid"
  done
  sleep 4
  for P in 22688 22689; do
    curl -s -c "$W/cj-$P.txt" -X POST -H 'Content-Type: application/json' -d "{\"password\":\"$PW\"}" http://127.0.0.1:$P/api/v0/auth/setup > /dev/null
  done
  for m in on off; do P=22610; [ $m = off ] && P=22620
    nohup node "$H/../../ui36n/traffic.mjs" -target http://127.0.0.1:$P -minutes 30 -log "$W/$m/traffic-log.jsonl" -offset 16 > "$W/$m/traffic.out" 2>&1 & echo $! > "$W/$m/traffic.pid"
  done ;;
seq)
  mkdir -p "$W/api409"
  for m in on off; do P=22688; [ $m = off ] && P=22689
    python3 -I "$H/uiseq.py" --base http://127.0.0.1:$P/api/v0 --cookies "$W/cj-$P.txt" --out "$W/api409/calls-$m-$2.jsonl" --label "$m-$2"
  done ;;
stop)
  for f in on/traffic on/schild off/traffic off/schild backend; do [ -f "$W/$f.pid" ] && kill "$(cat "$W/$f.pid")" 2>/dev/null || true; done ;;
esac
