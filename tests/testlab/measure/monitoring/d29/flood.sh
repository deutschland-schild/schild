#!/bin/sh
# TEST ONLY: D29 flood against instance inst2 (port 19210): 1M distinct
# addresses (one request each) then 40k addresses with two WAF-matching
# requests each (waf_repeat blocks, 2.4x the block table capacity 16384).
# RSS of schild is sampled every 2 s. Usage: flood.sh OUTDIR
set -eu
W=${W:-/tmp/m21d36/c}
OUT=$1
PID=$(cat "$W/inst2.pid")
( while kill -0 "$PID" 2>/dev/null; do echo "$(date -u +%H:%M:%S) $(ps -o rss= -p "$PID")"; sleep 2; done ) > "$OUT/flood-rss-kb.txt" &
S=$!
"$W/d29" flood -url http://127.0.0.1:19210 -n 1000000 -c 64 -base 10.128.0.0 | tee "$OUT/flood-phaseA-1M-distinct.json"
"$W/d29" flood -url http://127.0.0.1:19210 -n 40000 -c 64 -base 10.64.0.0 -waf | tee "$OUT/flood-phaseB-40k-waf-repeat.json"
sleep 4
kill $S
