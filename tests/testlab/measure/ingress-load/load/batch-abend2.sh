#!/bin/sh
# Evening measurement, second batch: interleaved A/B against the image of measurement 3
# (schild:spec19-m3, 9217a54), a third waiting page pair, and CPU-starved runs
# (--cpus 2 with GOMAXPROCS=12: neighbours take the CPU, as on a shared Kamal host).
H=$(cd "$(dirname "$0")" && pwd)
r() { echo "### $*"; sh $H/locked.sh "load $*" env "$@"; }
r SY=$H/schild-wp-on.yaml TAGX=wpon3 sh $H/run-scen.sh schild wpnav-m 4g
r SY=$H/schild-wp-off.yaml TAGX=wpoff3 sh $H/run-scen.sh schild wpnav-m 4g
for i in 1 2; do
  for m in 1g 2g; do
    r TAGX=ab$i sh $H/run-scen.sh schild stress-m $m
    r IMG=schild:spec19-m3 TAGX=m3img-ab$i sh $H/run-scen.sh schild stress-m $m
  done
done
r SCHILD_ENV="--cpus 2 -e GOMAXPROCS=12" TAGX=cpu2 sh $H/run-scen.sh schild stress-m 1g
r IMG=schild:spec19-m3 SCHILD_ENV="--cpus 2 -e GOMAXPROCS=12" TAGX=m3img-cpu2 sh $H/run-scen.sh schild stress-m 1g
