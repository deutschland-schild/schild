#!/usr/bin/env bash
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
export NS=${NS:?} AF=${AF:?} OUT=${OUT:-/tmp/schild-remeasure}
echo "=== v-manyaddr $(date) ==="
TAG=v-manyaddr IPMODE=static SHAPE1=slowloris N1=130 CONNS1=5 DUR=60 PROBES=24 bash "$here/remeasure-run.sh"
echo "=== v-keepyoung-manyaddr $(date) ==="
TAG=v-keepyoung-manyaddr IPMODE=static SHAPE1=keep-young N1=130 CONNS1=5 KNOB1=300 DUR=60 PROBES=24 bash "$here/remeasure-run.sh"
echo "### MANYADDR DONE $(date)"
