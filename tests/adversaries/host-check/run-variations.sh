#!/usr/bin/env bash
# MVP-11 re-measure variations the builder may not have covered. Each calls
# remeasure-run.sh with one attack config. Run on a live t1 AFTER the
# documented runs (one attack load at a time against the lab).
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
export NS=${NS:?} AF=${AF:?} OUT=${OUT:-/tmp/schild-remeasure}
run(){ echo "=== $1 $(date) ==="; bash "$here/remeasure-run.sh"; echo; }

# 1) slow-header flood, full metric set (comparison to the documented 70x8).
TAG=v-slowloris SHAPE1=slowloris N1=70 CONNS1=8 DUR=60 PROBES=24 run v-slowloris

# 2) keep-young: connections kept too young (<500 ms) to ever be evicted.
TAG=v-keepyoung SHAPE1=keep-young N1=70 CONNS1=8 KNOB1=300 DUR=60 PROBES=24 run v-keepyoung

# 3) complete headers, body trickled just above MinBodyRate (busy, un-evictable).
TAG=v-slowbodymin SHAPE1=slowbody-min N1=70 CONNS1=8 KNOB1=66560 DUR=60 PROBES=24 run v-slowbodymin

# 4) mixed slow-header + many-short-connection churn.
TAG=v-mixed SHAPE1=slowloris N1=40 CONNS1=8 SHAPE2=conn-churn N2=30 CONNS2=16 DUR=60 PROBES=24 run v-mixed

# 5) >= 128 distinct source addresses (static IPs), under the per-peer cap.
TAG=v-manyaddr IPMODE=static SHAPE1=slowloris N1=130 CONNS1=5 DUR=60 PROBES=24 run v-manyaddr

# 6) keep-young from >= 128 distinct addresses (hardest lock-out attempt).
TAG=v-keepyoung-manyaddr IPMODE=static SHAPE1=keep-young N1=130 CONNS1=5 KNOB1=300 DUR=60 PROBES=24 run v-keepyoung-manyaddr

echo "### VARIATIONS DONE $(date)"
