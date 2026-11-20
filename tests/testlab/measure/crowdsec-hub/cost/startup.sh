#!/bin/bash
# TEST ONLY: MVP-26. Time to ready and RSS after the start, with the hub rules off and on, alternating.
#   startup.sh <out.tsv> <rounds>
set -u
U=$(cd "$(dirname "$0")" && pwd); M=$U/..; OUT=$1; R=${2:-6}
MODE=autoblock STATE=off HUBURL=http://127.0.0.1:9/none HUBAUTO=false bash "$M/inst.sh" start sa 295
MODE=autoblock STATE=detect HUBURL=http://127.0.0.1:9/none HUBAUTO=false bash "$M/inst.sh" start sd 296
bash "$M/inst.sh" stop sa; bash "$M/inst.sh" stop sd
echo -e "round\tstate\tready_ms\trss_kb_ready\trss_kb_10s" > "$OUT"
one() { # name state port
  local D=/tmp/m26/i/$1
  local t0 t1 p
  t0=$(python3 -c 'import time;print(time.time())')
  SCHILD_CROWDSEC_HUB_URL=http://127.0.0.1:9/none SCHILD_ALLOW_TEST_KEYS=1 /tmp/m26/bin/schild run -config "$D/schild.yaml" > "$D/st.log" 2>&1 &
  p=$!
  until curl -sf -m 1 "http://127.0.0.1:$3/readyz" >/dev/null 2>&1; do python3 -c 'import time;time.sleep(0.02)'; done
  t1=$(python3 -c 'import time;print(time.time())')
  local r0; r0=$(ps -o rss= -p $p)
  python3 -c 'import time;time.sleep(10)'
  local r1; r1=$(ps -o rss= -p $p)
  kill $p; wait $p 2>/dev/null
  python3 -c "print('$4\t$2\t%d\t$r0\t$r1' % ((float('$t1')-float('$t0'))*1000))" >> "$OUT"
}
for r in $(seq 1 "$R"); do
  one sa off 29588 "$r"
  one sd detect 29688 "$r"
done
cat "$OUT"
