#!/bin/sh
# Evening measurement: every load run under the shared heavy-run lock.
H=$(cd "$(dirname "$0")" && pwd)
r() { echo "### $*"; sh $H/locked.sh "load $*" env "$@"; }
for m in 4g 2g 1g 512m; do r sh $H/run-scen.sh schild stress-m $m; done
r IMG=schild:spec19-m3 TAGX=m3img sh $H/run-scen.sh schild stress-m 2g
r IMG=schild:spec19-m3 TAGX=m3img sh $H/run-scen.sh schild stress-m 1g
r sh $H/run-scen.sh schild q30k200-m 1g
for i in 1 2; do
  r SY=$H/schild-wp-on.yaml TAGX=wpon$i sh $H/run-scen.sh schild wpnav-m 4g
  r SY=$H/schild-wp-off.yaml TAGX=wpoff$i sh $H/run-scen.sh schild wpnav-m 4g
done
