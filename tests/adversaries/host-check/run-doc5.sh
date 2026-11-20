#!/usr/bin/env bash
# Run the documented distributed-slowloris.sh N times (default 5).
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
runs=${RUNS:-5}
for i in $(seq 1 "$runs"); do
  echo "### documented run $i $(date)"
  NS=${NS:?} AF=${AF:?} OUT=/tmp/schild-remeasure/doc-$i \
    ATTACKERS=${ATTACKERS:-70} CONNS=${CONNS:-8} DUR=${DUR:-60} PROBES=${PROBES:-20} \
    bash "$here/distributed-slowloris.sh" || echo "### run $i exit $?"
  echo "### end run $i $(date)"
done
echo "### ALLDOC DONE $(date)"
