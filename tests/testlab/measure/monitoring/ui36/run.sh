#!/bin/bash
# TEST ONLY: how the D36 dashboard measurement (MVP-21-D36-messung/ui) was run, native macOS.
# Binaries: schild (UI embedded, main 8c8ed3d) and spec21 from /tmp/m21d36/bin. Ports 19300-19399.
# Stop processes only by their recorded PIDs, never by pattern.
set -e
U=$(cd "$(dirname "$0")" && pwd); D=/tmp/m21d36/d; R=$U/../../../results/MVP-21-D36-messung/ui
mkdir -p $D && cp $U/Caddyfile $U/schild.yaml $D/ && cd $D
/tmp/m21d36/bin/spec21 geo -out geo.mmdb -table geo.json
/tmp/m21d36/bin/spec21 backend -listen 127.0.0.1:19399 & echo $! > backend.pid
# first start creates schild.db; then the installation is dated 30 days back (older than learning_days 14)
/tmp/m21d36/bin/schild-ui2 run -config $D/schild.yaml & echo $! > schild.pid; sleep 4; kill $(cat schild.pid); sleep 2
sqlite3 data/schild.db "update kv set v='2026-09-29T12:00:00Z' where k='installed_at_v1'"
/tmp/m21d36/bin/schild-ui2 run -config $D/schild.yaml & echo $! > schild.pid; sleep 4
curl -s -X POST -H 'Content-Type: application/json' -d '{"password":"schild-d36-messung-TESTONLY"}' http://127.0.0.1:19388/api/v0/auth/setup
node $U/traffic.mjs -target http://127.0.0.1:19390 -minutes 34 -log $D/traffic-log.jsonl > traffic.out &
# minute 12-16: extra spike on shop; minute 18.5: ladder via longblocks.mjs; minute 24-31: slow blog; minute 26: restart (kill PID, start again)
#   node $U/traffic.mjs -only shop.test -mult 7 -minutes 4 -seed 4141
#   PW=schild-d36-messung-TESTONLY node $U/longblocks.mjs
#   node $U/traffic.mjs -only blog.test -mult 0.5 -delay 2500 -minutes 7 -seed 5151
# snapshots during events: TAG=s1-incident SNAP_SITE=api.test node $U/ui36-check.mjs snap http://127.0.0.1:19388 $R
# afterwards: ui36-check.mjs main | mobile | watch | extra, then a second instance with monitoring.enabled: false (ports 19378/19380): off
