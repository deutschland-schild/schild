#!/bin/sh
# batch.sh <schild|stock> <memory> <scenario...>
H=$(cd "$(dirname "$0")" && pwd)
v=$1; m=$2; shift 2
for s in "$@"; do sh $H/run-scen.sh $v $s $m; done
