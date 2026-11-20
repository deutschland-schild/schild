#!/bin/bash
# TEST ONLY: in-process latency on the filled dirs, one config per lock slot
cd /tmp/abend/s
tag=$1; shift
for n in "$@"; do
  w=${n#w}; w=${w%%-*}
  until [ ! -e /tmp/abend/heavy.lock ]; do sleep 5; done
  echo "c-sizes latency $n $(date)" > /tmp/abend/heavy.lock
  { echo "uptime_before: $(uptime)"; D36N_W=$w D36N_DIR=/tmp/abend/s/db-$n D36N_REPS=20 ./sizes.test -test.run TestD36NLatencyOnly -test.v 2>&1 | grep -v "^=== "; echo "uptime_after: $(uptime)"; } > lat-$tag-$n.txt
  grep -q "^c-sizes" /tmp/abend/heavy.lock && rm -f /tmp/abend/heavy.lock
  sleep 3
done
