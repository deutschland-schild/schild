#!/bin/sh
# TEST ONLY: start/stop the D29 measurement instance (native macOS).
# abend copy of ../../d29n/ctl.sh (commit c54de1b, ports 22700-22799, W=/tmp/abend/dd/d29).
# Usage: ctl.sh backend|start|stop|stop-all|backdate|rss|kept
# Env: INST (instance dir name under W, default inst), MPORT (its metrics port), W (work dir, default /tmp/abend/dd/d29), BIN (schild binary), MEASURE_BIN (harness binary)
set -eu
W=${W:-/tmp/abend/dd/d29}
BIN=${BIN:-/tmp/abend/bin/schild}
MEASURE_BIN=${MEASURE_BIN:-/tmp/abend/bin/spec21}
INST=${INST:-inst}
MPORT=${MPORT:-22791}
I=$W/$INST
DB=$I/data/schild.db
case "$1" in
backend)
  nohup "$MEASURE_BIN" backend -listen 127.0.0.1:22699 >"$W/backend.log" 2>&1 &
  echo $! >"$W/backend.pid" ;;
start)
  SCHILD_LOG_FORMAT=json nohup "$BIN" run -config "$I/schild.yaml" >>"$W/$INST.log" 2>&1 &
  echo $! >"$W/$INST.pid"
  for i in $(seq 1 100); do
    curl -fsS -o /dev/null http://127.0.0.1:$MPORT/readyz 2>/dev/null && { echo "ready after ${i}x0.2s pid $(cat "$W/$INST.pid")"; exit 0; }
    sleep 0.2
  done
  echo "not ready"; tail -20 "$W/$INST.log"; exit 1 ;;
stop)
  [ -f "$W/$INST.pid" ] && kill "$(cat "$W/$INST.pid")" 2>/dev/null || true
  for i in $(seq 1 100); do kill -0 "$(cat "$W/$INST.pid")" 2>/dev/null || { echo stopped; exit 0; }; sleep 0.1; done
  echo "still running" ; exit 1 ;;
stop-all)
  "$0" stop || true
  [ -f "$W/backend.pid" ] && kill "$(cat "$W/backend.pid")" 2>/dev/null || true ;;
backdate)
  # Learning period (MVP-17/18, >= 14 days from installed_at_v1): move the
  # first start of this TEST data directory 20 days back (instance stopped).
  T=$(date -u -v-20d +%Y-%m-%dT%H:%M:%SZ)
  sqlite3 "$DB" "UPDATE kv SET v = CAST('$T' AS BLOB) WHERE k = 'installed_at_v1'; SELECT k, CAST(v AS TEXT) FROM kv WHERE k = 'installed_at_v1';" ;;
rss)
  ps -o pid=,rss=,vsz= -p "$(cat "$W/$INST.pid")" ;;
kept)
  sqlite3 -header -column "$DB" "SELECT client_key, key_bits, net_class, source, level, duration_s, datetime(since_ms/1000,'unixepoch') since, datetime(until_ms/1000,'unixepoch') until, incident FROM kept_blocks ORDER BY until_ms" ;;
esac
