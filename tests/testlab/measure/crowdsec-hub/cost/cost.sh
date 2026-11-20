#!/bin/bash
# TEST ONLY: MVP-26 cost measurement. Two identical instances run side by side under the same request stream, one with
# the hub rules off and one with detect, so machine noise hits both. Every second round the two swap roles through the
# switch, which also controls for a difference between the instances. Numbers per phase go to one TSV.
#   cost.sh <outdir> <rounds>
set -u
U=$(cd "$(dirname "$0")" && pwd); M=$U/..; B=/tmp/m26/bin; OUT=$1; R=${2:-4}
mkdir -p "$OUT"
start() { MODE=autoblock STATE=$2 EXTRA=$U/extra.yaml HUBURL=http://127.0.0.1:9/none HUBAUTO=false bash "$M/inst.sh" start "$1" "$3"; }
start ca off 293
start cb detect 294
snap() { # name -> cpu_seconds rss_kb waf_sum waf_count
  local D=/tmp/m26/i/$1 P; P=$(cat "$D/port")
  local cpu rss
  read -r rss cpu < <(ps -o rss=,cputime= -p "$(cat "$D/schild.pid")")
  cpu=$(echo "$cpu" | awk -F'[:.]' '{ if (NF==4) print $1*3600+$2*60+$3+$4/100; else print $1*60+$2+$3/100 }')
  local m; m=$(curl -s -m 5 http://127.0.0.1:${P}11/metrics)
  local s c
  s=$(echo "$m" | awk '/^schild_waf_seconds_sum/{print $2}')
  c=$(echo "$m" | awk '/^schild_waf_seconds_count/{print $2}')
  echo "$cpu $rss $s $c"
}
sw() { local D=/tmp/m26/i/$1 P; P=$(cat "$D/port"); curl -s -o /dev/null -b "$D/cj" -H "X-CSRF-Token: $(cat "$D/csrf")" -H 'Content-Type: application/json' -X PATCH -d "{\"state\":\"$2\"}" http://127.0.0.1:${P}88/api/v0/rules/crowdsec-hub; }
echo -e "round\tmix\tinst\tstate\tcpu_s\trss_kb_end\twaf_s\twaf_n\tload" > "$OUT/cost.tsv"
phase() { # round mix stateA stateB
  local r=$1 mix=$2 sa=$3 sb=$4
  local a0 b0 a1 b1
  sleep 2
  a0=$(snap ca); b0=$(snap cb)
  if [ "$mix" = replay ]; then
    $B/spec21 replay -target http://127.0.0.1:29390 -seed 21 -rps 250 -phase mix -minutes 2 -out "$OUT/truth-$r-a.json" > /dev/null 2>&1 &
    p1=$!
    $B/spec21 replay -target http://127.0.0.1:29490 -seed 21 -rps 250 -phase mix -minutes 2 -out "$OUT/truth-$r-b.json" > /dev/null 2>&1 &
    p2=$!
  else
    $B/load -target http://127.0.0.1:29390 -mix body -rps 150 -duration 75s -seed 26 -out "$OUT/body-$r-a.json" &
    p1=$!
    $B/load -target http://127.0.0.1:29490 -mix body -rps 150 -duration 75s -seed 26 -out "$OUT/body-$r-b.json" &
    p2=$!
  fi
  wait $p1 $p2
  sleep 2
  a1=$(snap ca); b1=$(snap cb)
  L=$(uptime | sed 's/.*averages: //; s/ /,/g')
  python3 -I - "$r" "$mix" ca "$sa" "$a0" "$a1" "$L" >> "$OUT/cost.tsv" <<'E'
import sys
r, mix, i, s, x, y, l = sys.argv[1:]
a = [float(v or 0) for v in x.split()]; b = [float(v or 0) for v in y.split()]
print(r, mix, i, s, round(b[0]-a[0], 2), int(b[1]), round(b[2]-a[2], 3), int(b[3]-a[3]), l, sep='\t')
E
  python3 -I - "$r" "$mix" cb "$sb" "$b0" "$b1" "$L" >> "$OUT/cost.tsv" <<'E'
import sys
r, mix, i, s, x, y, l = sys.argv[1:]
a = [float(v or 0) for v in x.split()]; b = [float(v or 0) for v in y.split()]
print(r, mix, i, s, round(b[0]-a[0], 2), int(b[1]), round(b[2]-a[2], 3), int(b[3]-a[3]), l, sep='\t')
E
}
for r in $(seq 1 "$R"); do
  if [ $((r % 2)) = 1 ]; then sa=off; sb=detect; else sa=detect; sb=off; fi
  sw ca $sa; sw cb $sb; sleep 8
  phase "$r" replay $sa $sb
  phase "$r" body $sa $sb
  tail -4 "$OUT/cost.tsv"
done
echo finished
