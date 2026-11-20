#!/bin/bash
# TEST ONLY (D36 evening re-measurement, item 7): listAlerts path:/search on shop.test 7d, N calls after one warm-up,
# curl time_total, p50/p95/max, uptime first. usage: path_alerts_timing.sh <dashboard base> <cookie jar> [N]
B=$1; J=$2; N=${3:-20}
F=$(date -u -v-7d +%Y-%m-%dT%H:%M:%SZ); T=$(date -u +%Y-%m-%dT%H:%M:%SZ)
U="$B/api/v0/websites/shop.test/alerts?from=$F&to=$T&filter=path%3A%2Fsearch"
uptime
curl -s -o /dev/null -b $J "$U"
for i in $(seq 1 $N); do curl -s -o /dev/null -b $J -w '%{time_total}\n' "$U"; done | sort -n | awk '{a[NR]=$1*1000} END {printf "path:/search n=%d p50 %.1f ms p95 %.1f ms max %.1f ms\n", NR, a[int(NR*0.5+0.5)], a[int(NR*0.95+0.5)], a[NR]}'
