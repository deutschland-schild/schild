#!/bin/bash
# TEST ONLY: UI part of the evening measurement 2026-10-29 (commit c54de1b, fixes a34c2a6, 703e616, 28e29ce).
# Native macOS. Binaries: /tmp/abend/bin/schild (darwin, UI embedded from c54de1b), /tmp/abend/bin/spec21
# (built from tests/testlab/measure/monitoring at c54de1b). Playwright from UI_ROOT=/tmp/abend/src/dashboard.
# Ports 23000-23999 only. Processes are stopped only by their recorded PID (stop.sh).
#
#   ./run.sh setup        backend, main instance (autoblock, monitoring on), off instance (observe, monitoring off),
#                         base traffic on both
#   ./run.sh timeline     wave with SIGKILL in the middle, long blocks with a dashboard release (wall clock, env W1/K1/LB)
#   checks (afterwards):  see abend-check.mjs phases; copycheck.py over the texts
set -e
U=$(cd "$(dirname "$0")" && pwd); W=/tmp/abend/uirun; D=$W/d; O=$W/off; B=/tmp/abend/bin
export PW=schild-abend-messung-TESTONLY
case "$1" in
setup)
  mkdir -p $D $O
  cp $U/Caddyfile $U/schild.yaml $D/; cp $U/Caddyfile.off $O/Caddyfile; cp $U/schild-off.yaml $O/schild.yaml
  (cd $D && $B/spec21 geo -out geo.mmdb -table geo.json) && cp $D/geo.mmdb $O/
  (nohup $B/spec21 backend -listen 127.0.0.1:23099 > $W/backend.log 2>&1 & echo $! > $W/backend.pid)
  for X in $D $O; do
    (cd $X; nohup $B/schild run -config $X/schild.yaml > $X/schild-1.log 2>&1 & echo $! > $X/schild.pid); sleep 5
    kill $(cat $X/schild.pid); while kill -0 $(cat $X/schild.pid) 2>/dev/null; do sleep 0.2; done
    # installation older than learning_days 14
    sqlite3 $X/data/schild.db "update kv set v='2026-09-29T12:00:00Z' where k='installed_at_v1'"
    (cd $X; nohup $B/schild run -config $X/schild.yaml > $X/schild-2.log 2>&1 & echo $! > $X/schild.pid); sleep 5
  done
  curl -s -X POST -H 'Content-Type: application/json' -d "{\"password\":\"$PW\"}" http://127.0.0.1:23088/api/v0/auth/setup; echo
  curl -s -X POST -H 'Content-Type: application/json' -d "{\"password\":\"$PW\"}" http://127.0.0.1:23078/api/v0/auth/setup; echo
  (nohup node $U/traffic.mjs -target http://127.0.0.1:23090 -nowave -logall -minutes ${BASE_MIN:-55} -seed 2929 -log $D/base-log.jsonl > $D/base.out 2>&1 & echo $! > $W/base.pid)
  (nohup node $U/traffic.mjs -target http://127.0.0.1:23080 -nowave -minutes 20 -seed 4242 -log $O/off-log.jsonl > $O/base.out 2>&1 & echo $! > $W/offbase.pid)
  ;;
timeline)
  at() { local now; while true; do now=$(date +%H:%M:%S); [[ "$now" < "$1" ]] || break; sleep 1; done; echo "$(date +%T) $2" >> $W/timeline.log; }
  at $W1 "wave start (main), 6 min"
  (nohup node $U/traffic.mjs -target http://127.0.0.1:23090 -attackonly -arate 12 -minutes 6 -seed 7202 -logall -log $D/wave-log.jsonl > $D/wave.out 2>&1 & echo $! > $W/wave.pid)
  # attacks on the observe instance (would_block events, "Erkannt")
  (nohup node $U/traffic.mjs -target http://127.0.0.1:23080 -attackonly -arate 2 -minutes 3 -seed 7303 -log $O/wave-log.jsonl > $O/wave.out 2>&1 & echo $! > $W/offwave.pid)
  at $K1 "SIGKILL schild pid $(cat $D/schild.pid)"
  kill -KILL $(cat $D/schild.pid); sleep 3
  (cd $D; nohup $B/schild run -config $D/schild.yaml > $D/schild-3.log 2>&1 & echo $! > $D/schild.pid)
  echo "$(date +%T) started schild pid $(cat $D/schild.pid)" >> $W/timeline.log
  at $LB "longblocks"
  node $U/longblocks.mjs -dash http://127.0.0.1:23088 -target http://127.0.0.1:23090 -out $D/longblocks.json > $D/longblocks.out 2>&1
  echo "$(date +%T) longblocks done" >> $W/timeline.log
  ;;
stop)
  for p in $W/base.pid $W/offbase.pid $W/wave.pid $W/offwave.pid $D/schild.pid $O/schild.pid $W/backend.pid; do
    [ -f $p ] && kill $(cat $p) 2>/dev/null && echo "stopped $p $(cat $p)" || true
  done
  ;;
esac
