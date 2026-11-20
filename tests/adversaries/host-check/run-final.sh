#!/usr/bin/env bash
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
export NS=${NS:?} AF=${AF:?} OUT=${OUT:-/tmp/schild-remeasure}
echo "=== v-keepyoung-confirm $(date) ==="
TAG=v-keepyoung-confirm SHAPE1=keep-young N1=70 CONNS1=8 KNOB1=300 DUR=90 PROBES=60 bash "$here/remeasure-run.sh"
echo "=== v-evictlegit $(date) ==="
TAG=v-evictlegit DUR=80 DELAYMS=300 PROBES=24 bash "$here/evict-legit.sh"
echo "### FINAL DONE $(date)"
