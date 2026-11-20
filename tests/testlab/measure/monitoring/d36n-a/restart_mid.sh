#!/bin/bash
# D36 re-measurement (TEST ONLY): replay (mix, 4 min) with a restart of OUR schild
# instance in the middle of minute 2. SIG=TERM (graceful) or KILL (hard).
# Stops/starts only the PID recorded in $D/schild.pid.
#   SIG=TERM D=/tmp/d36n/a/exact OUT=truth-restart-term.json restart_mid.sh
set -u
D=${D:-/tmp/d36n/a/exact}; SIG=${SIG:-TERM}; OUT=${OUT:-truth-restart.json}; SEED=${SEED:-31}; OFF=${OFF:-200000}
cd $D
/tmp/d36n/bin/spec21 replay -target http://127.0.0.1:20090 -phase mix -minutes 4 -rps 250 -seed $SEED -clientoffset $OFF -out $OUT > replay-$SIG.log 2>&1 &
RP=$!
# replay starts at second 3 of the next minute; restart at second 33 of minute 2
now=$(date +%s); start=$(( (now/60+1)*60 )); t=$(( start + 2*60 + 33 ))
sleep $(( t - $(date +%s) ))
echo "restart $SIG at $(date -u +%H:%M:%S)" | tee restart-$SIG.txt
kill -$SIG $(cat schild.pid)
while kill -0 $(cat schild.pid) 2>/dev/null; do sleep 0.1; done
echo "stopped at $(date -u +%H:%M:%S.%N)" | tee -a restart-$SIG.txt
SCHILD_ALLOW_TEST_KEYS=1 nohup /tmp/d36n/bin/schild run -config $D/schild.yaml >> schild.log 2>&1 & echo $! > schild.pid
echo "started pid $(cat schild.pid) at $(date -u +%H:%M:%S)" | tee -a restart-$SIG.txt
wait $RP
