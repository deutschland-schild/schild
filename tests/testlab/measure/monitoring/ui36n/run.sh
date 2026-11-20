#!/bin/bash
# TEST ONLY: how the D36 re-measurement after fix round 1 (results/D36-nachmessung/ui) was run, native macOS,
# commit ac9c543. Binaries: /tmp/d36n/bin/schild (darwin, UI embedded from ac9c543) and /tmp/d36n/bin/spec21.
# Playwright from UI_ROOT=/tmp/d36n/src/dashboard. Ports 20300-20399 only. Stop processes only by recorded PID.
set -e
U=$(cd "$(dirname "$0")" && pwd); D=/tmp/d36n/d; R=$U/../../../results/D36-nachmessung/ui
export PW=schild-d36n-messung-TESTONLY UI_ROOT=/tmp/d36n/src/dashboard
mkdir -p $D && cp $U/Caddyfile $U/schild.yaml $D/ && cd $D
/tmp/d36n/bin/spec21 geo -out geo.mmdb -table geo.json
/tmp/d36n/bin/spec21 backend -listen 127.0.0.1:20399 & echo $! > backend.pid
# first start creates schild.db; then the installation is dated back (older than learning_days 14), second start
/tmp/d36n/bin/schild run -config $D/schild.yaml & echo $! > schild.pid; sleep 5; kill $(cat schild.pid); sleep 3
sqlite3 data/schild.db "update kv set v='2026-09-29T12:00:00Z' where k='installed_at_v1'"
/tmp/d36n/bin/schild run -config $D/schild.yaml & echo $! > schild.pid; sleep 5
curl -s -X POST -H 'Content-Type: application/json' -d "{\"password\":\"$PW\"}" http://127.0.0.1:20388/api/v0/auth/setup
# 15:24 local: baseline on four sites (no wave; the built-in shop spike x5 runs at minute 12-16 = 15:36-15:40), every answer logged
node $U/traffic.mjs -target http://127.0.0.1:20390 -nowave -logall -minutes 75 -seed 3636 -log $D/base-log.jsonl > base.out & echo $! > base.pid
# wall-clock timeline (local CET = UTC+1; 10 min buckets 14:30-14:40Z and 14:50-15:00Z):
#   15:31-15:37 wave 1 (-attackonly -arate 12, 240 addresses), 15:35:00 SIGTERM, start again after 3 s
#   15:42 longblocks.mjs (4 addresses up the ladder via dashboard release)
#   15:51-15:57 wave 2, 15:55:00 SIGKILL, start again after 3 s
$U/timeline.sh > timeline.out 2>&1 &
# timed snapshots: api-truth.mjs (API vs sent-side log) + ui36n-check.mjs restart (KPIs light/dark, 1440/375)
#   at 15:34:40, 15:36 (in bucket), 15:41 (bucket closed), 15:54:40, 15:56, 16:01; markers at 16:03
$U/snaps.sh > snaps.out 2>&1 &
# monitoring-off instance (ports 20378/20380/20312), 12 min baseline traffic, phase off (pages, 409s, polling 75 s)
#   mkdir /tmp/d36n/off; cp Caddyfile.off -> Caddyfile, schild-off.yaml -> schild.yaml, geo.mmdb; schild run; auth/setup
#   node $U/traffic.mjs -target http://127.0.0.1:20380 -nowave -minutes 12 -seed 4242 -log /tmp/d36n/off/off-log.jsonl
#   TAG=r05-off node $U/ui36n-check.mjs off http://127.0.0.1:20378 $R
# afterwards on the main instance:
#   node $U/find-incidents.mjs > $R/r04-incidents-list.txt
#   INCIDENTS="hosting7d=6DY5-JTYZ,residential24h=XWUB-9V43,released-l2=EACC-4TXU,waf=SRKU-XJ6R" TAG=r04-incident node $U/ui36n-check.mjs incident http://127.0.0.1:20388 $R
#   TAG=r04b node $U/ui36n-check.mjs tabs http://127.0.0.1:20388 $R
#   TAG=r06-filters node $U/ui36n-check.mjs filters http://127.0.0.1:20388 $R
#   TAG=r07-pages node $U/ui36n-check.mjs pages http://127.0.0.1:20388 $R
#   TAG=r08-watch WATCH_S=70 node $U/ui36n-check.mjs watch http://127.0.0.1:20388 $R
#   node $U/api-truth.mjs ... -out $R/r09-truth-final.json (fixed windows, see r09-truth-final.txt)
#   python3 $U/copycheck.py $R $R/r10-copycheck.json
# stop: kill $(cat base.pid) $(cat schild.pid) $(cat backend.pid); off instance: kill $(cat /tmp/d36n/off/schild.pid)
