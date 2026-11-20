#!/bin/bash
# TEST ONLY: timed snapshots of the D36 re-measurement (API against truth, UI screenshots) around both restarts.
U=$(cd "$(dirname "$0")" && pwd); D=/tmp/d36n/d; R="$(cd "$U/../../../.." && pwd)/results/D36-nachmessung/ui"; mkdir -p "$R"
export PW=schild-d36n-messung-TESTONLY UI_ROOT=/tmp/d36n/src/dashboard
cd $D
at() { local now; while true; do now=$(date +%H:%M:%S); [[ "$now" < "$1" ]] || break; sleep 1; done; echo "$(date +%T) $2" >> $D/snaps.log; }
truth() { node $U/api-truth.mjs -dash http://127.0.0.1:20388 -logs $D/base-log.jsonl,$D/wave1-log.jsonl,$D/wave2-log.jsonl -out $R/$1.json \
  -win "wave1-bucket=2026-10-29T14:30:00Z/2026-10-29T14:40:00Z" -win "wave2-bucket=2026-10-29T14:50:00Z/2026-10-29T15:00:00Z" -win "run=2026-10-29T14:20:00Z/2026-10-29T15:10:00Z" -last 1h,6h,24h > $R/$1.txt 2>&1; }
touch $D/wave1-log.jsonl $D/wave2-log.jsonl
at 15:34:40 "truth pre1"; truth r00-truth-before-graceful
at 15:36:00 "graceful in bucket"; truth r01a-truth-graceful-inbucket; TAG=r01a-graceful-inbucket node $U/ui36n-check.mjs restart http://127.0.0.1:20388 $R > $D/r01a.out 2>&1
at 15:41:00 "graceful after bucket"; truth r01-truth-graceful; TAG=r01-graceful node $U/ui36n-check.mjs restart http://127.0.0.1:20388 $R > $D/r01.out 2>&1
at 15:54:40 "truth pre2"; truth r00-truth-before-hard
at 15:56:00 "hard in bucket"; truth r02a-truth-hard-inbucket; TAG=r02a-hard-inbucket node $U/ui36n-check.mjs restart http://127.0.0.1:20388 $R > $D/r02a.out 2>&1
at 16:01:00 "hard after bucket"; truth r02-truth-hard; TAG=r02-hard node $U/ui36n-check.mjs restart http://127.0.0.1:20388 $R > $D/r02.out 2>&1
at 16:03:00 "markers"; TAG=r03-markers node $U/ui36n-check.mjs markers http://127.0.0.1:20388 $R > $D/r03.out 2>&1
echo "$(date +%T) snaps done" >> $D/snaps.log
