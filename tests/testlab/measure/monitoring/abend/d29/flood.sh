#!/bin/sh
# TEST ONLY: D29 flood against instance inst2 (gateway 22710, metrics 22792),
# abend copy of ../../d29n/flood.sh for commit c54de1b (fix 3ae0348: the
# "incident queue full" warning is rate-limited to one line per 10 s).
# Phases as in the D36 re-measurement (about 3 min in total):
#   A 1M distinct addresses, one request each (10.128.0.0/9, residential)
#   B 40k addresses x 2 WAF-matching requests (10.64.0.0, hosting; waf_repeat blocks)
#   C 200k addresses x 2 WAF-matching requests (10.65.0.0)
# A 7-day kept block of 10.1.0.20 (hosting) must stay active (403) throughout.
# Records: RSS every 2 s, schild_events_dropped_total, log size and
# "incident queue full" line count before/after, flood results.
# Prerequisites: inst2 running (ctl.sh with INST=inst2 MPORT=22792), backend on 22699,
# kept row for 10.1.0.20 injected before its start (see notes.txt).
# Usage: W=/tmp/abend/dd/d29 flood.sh OUTDIR
set -eu
W=${W:-/tmp/abend/dd/d29}
OUT=$1
U=http://127.0.0.1:22710
PID=$(cat "$W/inst2.pid")
LOG=$W/inst2.log
snap() { # label
  echo "## $1 $(date -u +%H:%M:%S) load: $(uptime | sed 's/.*load averages*: //')"
  echo "rss_kb $(ps -o rss= -p "$PID")"
  echo "log_bytes $(wc -c < "$LOG" | tr -d ' ') log_lines $(wc -l < "$LOG" | tr -d ' ')"
  echo "queue_full_lines $(grep -c 'incident queue full' "$LOG" || true)"
  curl -s http://127.0.0.1:22792/metrics | grep -E '^schild_events_dropped_total|^schild_incidents_dropped|^process_resident_memory_bytes' || true
  "$W/d29" status -url $U 10.1.0.20
}
( while kill -0 "$PID" 2>/dev/null; do echo "$(date -u +%H:%M:%S) $(ps -o rss= -p "$PID")"; sleep 2; done ) > "$OUT/flood-rss-kb.txt" &
S=$!
snap before > "$OUT/snapshots.txt"
"$W/d29" flood -url $U -n 1000000 -c 64 -base 10.128.0.0 | tee "$OUT/flood-phaseA-1M-distinct.json"
snap after-A >> "$OUT/snapshots.txt"
"$W/d29" flood -url $U -n 40000 -c 64 -base 10.64.0.0 -waf | tee "$OUT/flood-phaseB-40k-waf-repeat.json"
snap after-B >> "$OUT/snapshots.txt"
"$W/d29" flood -url $U -n 200000 -c 64 -base 10.65.0.0 -waf | tee "$OUT/flood-phaseC-200k-waf-repeat.json"
snap after-C >> "$OUT/snapshots.txt"
sleep 12   # one more drop-log interval (10 s) for the tail line
snap after-C+12s >> "$OUT/snapshots.txt"
kill $S
