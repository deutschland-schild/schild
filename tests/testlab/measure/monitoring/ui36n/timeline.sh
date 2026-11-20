#!/bin/bash
# TEST ONLY: wall-clock timeline of the D36 re-measurement (restart in the middle of an attack wave).
# Waits for HH:MM:SS (local time) and runs the step. Stops only its own schild by the PID in schild.pid.
U=$(cd "$(dirname "$0")" && pwd); D=/tmp/d36n/d; B=/tmp/d36n/bin
cd $D
at() { local now; while true; do now=$(date +%H:%M:%S); [[ "$now" < "$1" ]] || break; sleep 1; done; echo "$(date +%T) $2" >> $D/timeline.log; }
start_schild() { (nohup $B/schild run -config $D/schild.yaml > $D/schild-$1.log 2>&1 & echo $! > $D/schild.pid); echo "$(date +%T) started schild pid $(cat $D/schild.pid)" >> $D/timeline.log; }
W1=${W1:-15:31:00}; R1=${R1:-15:35:00}; E1=${E1:-15:37:00}
W2=${W2:-15:51:00}; R2=${R2:-15:55:00}; E2=${E2:-15:57:00}
LB=${LB:-15:42:00}
at $W1 "wave 1 start (graceful restart wave)"
node $U/traffic.mjs -target http://127.0.0.1:20390 -attackonly -arate 12 -minutes 6 -seed 7101 -logall -log $D/wave1-log.jsonl > $D/wave1.out 2>&1 &
at $R1 "SIGTERM schild pid $(cat $D/schild.pid)"
kill -TERM $(cat $D/schild.pid); P=$(cat $D/schild.pid); while kill -0 $P 2>/dev/null; do sleep 0.2; done
echo "$(date +%T) pid $P exited" >> $D/timeline.log
sleep 3; start_schild 3
at $LB "longblocks"
PW=schild-d36n-messung-TESTONLY node $U/longblocks.mjs -dash http://127.0.0.1:20388 -target http://127.0.0.1:20390 -out $D/longblocks.json > $D/longblocks.out 2>&1
echo "$(date +%T) longblocks done" >> $D/timeline.log
at $W2 "wave 2 start (hard kill wave)"
node $U/traffic.mjs -target http://127.0.0.1:20390 -attackonly -arate 12 -minutes 6 -seed 7202 -logall -log $D/wave2-log.jsonl > $D/wave2.out 2>&1 &
at $R2 "SIGKILL schild pid $(cat $D/schild.pid)"
kill -KILL $(cat $D/schild.pid); sleep 3; start_schild 4
at $E2 "timeline done"
