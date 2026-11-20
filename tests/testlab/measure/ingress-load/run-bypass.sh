#!/bin/sh
# MVP-19 measurement 2026-10-29 evening: runtime check of accepted validator
# variants. Starts `schild run` natively (autoblock, network off) per variant
# (configs from run-validate-dir.sh in <workdir>), sends attack and benign
# requests, reads what the echo backend got (method, URI, X- headers, body)
# and, after stopping, the events from schild.db.
# Usage: run-bypass.sh <schild> <workdir> <variant> <spec>...
#   spec: host|path[|extra curl args]
set -u
BIN=$1; WORK=$2; n=$3; shift 3
H=$(cd "$(dirname "$0")" && pwd)
LOG=$WORK/echo.log; : > $LOG
python3 -I $H/echo_backend.py 18081 $LOG & e1=$!
python3 -I $H/echo_backend.py 18082 $LOG & e2=$!
sleep 0.5
[ -f "$WORK/$n.yaml" ] || { echo "== $n (no config)"; kill $e1 $e2; exit 0; }
rm -rf "$WORK/data"; "$BIN" run -config "$WORK/$n.yaml" > "$WORK/$n.run.log" 2>&1 & pid=$!
up=0; for i in $(seq 1 80); do curl -s -o /dev/null -m 1 http://127.0.0.1:18080/ && { up=1; break; }; kill -0 $pid 2>/dev/null || break; sleep 0.2; done
echo "== $n (started=$up)"
if [ $up = 1 ]; then
  sleep 0.3
  for spec in "$@"; do
    host=${spec%%|*}; rest=${spec#*|}; p=${rest%%|*}; extra=${rest#*|}; [ "$extra" = "$rest" ] && extra=""
    : > $LOG
    code=$(eval curl -s -o /dev/null -w '%{http_code}' -H "\"Host: $host\"" $extra "\"http://127.0.0.1:18080$p\"")
    sleep 0.1
    seen=$(wc -l < $LOG | tr -d ' ')
    att=$(grep -ci 'script\|OR%201\|OR 1=1\|%27\|union' $LOG)
    echo "  status $code backend_seen=$seen attack_at_backend=$att  host=$host $p $extra"
    sed 's/^/      backend: /' $LOG | cut -c1-260
  done
fi
kill $pid 2>/dev/null; wait $pid 2>/dev/null
echo "  events: $(sqlite3 "$WORK/data/schild.db" "SELECT rules||'|'||type||' '||method||' '||path||' '||status||' '||outcome FROM events ORDER BY seq" 2>/dev/null | tr '\n' ';')"
kill $e1 $e2 2>/dev/null; wait $e1 $e2 2>/dev/null
