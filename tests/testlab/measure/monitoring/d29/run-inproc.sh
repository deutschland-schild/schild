#!/bin/sh
# TEST ONLY: run the fake-clock ladder measurement in a scratch copy of the
# client source (never in the repo). Usage: run-inproc.sh SRC WORK GEO OUT
set -eu
SRC=$1 W=$2 GEO=$3 OUT=$4
H=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$W/scratch"
rsync -a --delete --exclude ui --exclude results --exclude node_modules --exclude .git "$SRC/" "$W/scratch/"
cp "$H/inproc/zz_d29_ladder_test.go" "$W/scratch/gateway/internal/app/"
cp "$H/inproc/zz_d29_flood_test.go" "$W/scratch/gateway/internal/behaviour/"
cd "$W/scratch/gateway"
D29_DIR="$W/inproc-data" D29_GEO="$GEO" D29_OUT="$OUT" go test -count=1 -run TestD29Ladder -v ./internal/app/ 2>&1 | tail -20
D29_FLOOD_OUT="$(dirname "$OUT")/inproc-flood.json" go test -count=1 -run TestD29FloodKeepsLongBlocks -v ./internal/behaviour/ 2>&1 | tail -30
