#!/bin/bash
# TEST ONLY: MVP-29 cost measurement. Two instances from inst.sh (c and d) run side by side under the same request
# stream (testlab/measure/crowdsec-hub/load, mix light: browser user agents), one with the crawler policy block_ai_training plus
# impersonators block on shop.test and one with an empty policy. Roles swap every round through the dashboard API, so
# machine noise and instance differences hit both. One TSV line per instance and round.
#   cost.sh <outdir> <rounds> <rps> <seconds>
set -u
U=$(cd "$(dirname "$0")" && pwd); B=/tmp/m29/bin; OUT=$1; R=${2:-4}; RPS=${3:-500}; SEC=${4:-60}
mkdir -p "$OUT"
POL='{"preset":"block_ai_training","impersonators":"block"}'
cpu() { ps -o cputime= -p "$(cat /tmp/m29/i/$1/schild.pid)" | awk -F'[:.]' '{ if (NF==4) print $1*3600+$2*60+$3+$4/100; else print $1*60+$2+$3/100 }'; }
[ -f "$OUT/cost.tsv" ] || echo -e "round\trps\tinst\tpolicy\tcpu_s\tn\tp50_ms\tp95_ms\tp99_ms\tnon200\tdropped\tload" > "$OUT/cost.tsv"
for r in $(seq 1 "$R"); do
  if [ $((r % 2)) = 1 ]; then pc=on; pd=off; else pc=off; pd=on; fi
  for i in c d; do
    p=$pc; [ $i = d ] && p=$pd
    if [ $p = on ]; then "$U/dash.sh" $i PUT /websites/shop.test/crawlers "$POL" > /dev/null; else "$U/dash.sh" $i PUT /websites/shop.test/crawlers '{}' > /dev/null; fi
  done
  sleep 5
  c0=$(cpu c); d0=$(cpu d)
  $B/load -target http://127.0.0.1:29390 -host shop.test -mix light -rps "$RPS" -duration "${SEC}s" -seed 29 -workers 128 -out "$OUT/r$r-$RPS-c.json" > /dev/null &
  p1=$!
  $B/load -target http://127.0.0.1:29490 -host shop.test -mix light -rps "$RPS" -duration "${SEC}s" -seed 29 -workers 128 -out "$OUT/r$r-$RPS-d.json" > /dev/null &
  p2=$!
  wait $p1 $p2
  sleep 1
  c1=$(cpu c); d1=$(cpu d)
  L=$(uptime | sed 's/.*averages: //; s/ /,/g')
  for i in c d; do
    p=$pc; a=$c0; b=$c1; [ $i = d ] && { p=$pd; a=$d0; b=$d1; }
    python3 -I - "$r" "$RPS" "$i" "$p" "$a" "$b" "$OUT/r$r-$RPS-$i.json" "$L" >> "$OUT/cost.tsv" <<'E'
import json, sys
r, rps, i, p, a, b, f, l = sys.argv[1:]
d = json.load(open(f)); x = d["classes"]["_all"]
non = sum(v for k, v in x["Status"].items() if k != "200")
print(r, rps, i, p, round(float(b) - float(a), 2), x["N"], round(x["P50"], 3), round(x["P95"], 3), round(x["P99"], 3), non, d["dropped"], l, sep="\t")
E
  done
  tail -2 "$OUT/cost.tsv"
done
