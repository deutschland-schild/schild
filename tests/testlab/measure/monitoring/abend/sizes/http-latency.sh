#!/bin/bash
# TEST ONLY: HTTP latency through /tmp/abend/bin/schild on a copy of the W=32 worst-case metrics.db (ports 22288/22211/22290)
S=$(cd "$(dirname "$0")" && pwd); H=/tmp/abend/s/http; B=http://127.0.0.1:22288; tag=$1
until [ ! -e /tmp/abend/heavy.lock ]; do sleep 0.5; done
echo "c-sizes http latency W=32 $(date)" > /tmp/abend/heavy.lock
cd $H; rm -f data/metrics.db-wal data/metrics.db-shm; cp /tmp/abend/s/db-w32-utf8-plain/metrics.db data/metrics.db; /tmp/abend/bin/schild run -config $H/schild.yaml >> schild.log 2>&1 & echo $! > schild.pid; sleep 8
curl -s -c jar -b jar -H 'Content-Type: application/json' -H "Origin: $B" -X POST $B/api/v0/auth/login -d '{"password":"abend-c-sizes-TESTONLY-pw"}' -o /dev/null -w "login %{http_code}\n"
python3 -I $S/metrics_api_latency.py $B $H/jar 2026-10-29T17:27:00Z app0.example.org /tmp/abend/s/http-latency-w32-$tag.json 20 app0.example.org
kill $(cat schild.pid); sleep 2
grep -q "^c-sizes" /tmp/abend/heavy.lock && rm -f /tmp/abend/heavy.lock
