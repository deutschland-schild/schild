#!/bin/bash
# TEST ONLY: evening re-measurement 2026-10-29, item 3 (template: d36n-a/restart_mid.sh, ui36n/timeline.sh).
# Restart of OUR schild in the middle of a 10 min bucket during an attack wave, with sent-side
# truth (ui36n/traffic.mjs -logall: every answered request with time, host and app=false when
# schild answered). Stops/starts only the PID in $D/schild.pid and its own traffic PIDs.
#   NAME=kill SIG=KILL P=223 BK=<epoch of the 10 min bucket to kill in> run.sh
#   NAME=term SIG=TERM P=224 BK=... run.sh
# Timeline (relative to BK): baseline traffic from now until BK+12:00, attack wave BK+1:00..BK+8:00,
# signal at BK+5:30, start again 3 s after the process is gone. Check (check.mjs) after BK+13:00.
set -u
U=$(cd "$(dirname "$0")" && pwd); B=/tmp/abend/bin; T=$U/../../ui36n/traffic.mjs
NAME=${NAME:-kill}; SIG=${SIG:-KILL}; P=${P:-223}; BK=${BK:?epoch of the 10 min bucket}
D=/tmp/abend/k/$NAME; cd $D
log() { echo "$(date -u +%H:%M:%S) $*  | load $(uptime | sed 's/.*averages: //')" >> $D/timeline.log; }
until_t() { while [ $(date +%s) -lt $1 ]; do sleep 0.2; done; }
now=$(date +%s); mins=$(( (BK + 720 - now + 59) / 60 ))
log "baseline start, $mins min"
node $T -target http://127.0.0.1:${P}90 -nowave -logall -minutes $mins -seed 3636 -log $D/base-log.jsonl > base.out 2>&1 & echo $! > base.pid
until_t $((BK + 60)); log "wave start"
node $T -target http://127.0.0.1:${P}90 -attackonly -arate 12 -minutes 7 -seed 7202 -logall -log $D/wave-log.jsonl > wave.out 2>&1 & echo $! > wave.pid
until_t $((BK + 330))
PID=$(cat schild.pid); kill -$SIG $PID; log "SIG$SIG schild pid $PID"; node -e "console.log(new Date().toISOString()+' sig')" > sig.time
while kill -0 $PID 2>/dev/null; do sleep 0.05; done; log "pid $PID gone"
sleep 3
SCHILD_ALLOW_TEST_KEYS=1 nohup $B/schild run -config $D/schild.yaml > schild-2.log 2>&1 & echo $! > schild.pid
node -e "console.log(new Date().toISOString()+' start')" >> sig.time
log "started schild pid $(cat schild.pid)"
wait $(cat base.pid) $(cat wave.pid)   # only the traffic; the restarted schild keeps running
log "traffic done"
