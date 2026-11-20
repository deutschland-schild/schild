#!/bin/sh
# Evening measurement, third batch: CPU limits. cpus2: --cpus 2 (Go picks GOMAXPROCS 2 itself);
# cpus4g12: --cpus 4 with GOMAXPROCS=12 (a 12-core host whose neighbours leave 4 cores).
H=$(cd "$(dirname "$0")" && pwd)
r() { echo "### $*"; sh $H/locked.sh "load $*" env "$@"; }
r SCHILD_ENV="--cpus 2" TAGX=cpus2 sh $H/run-scen.sh schild stress-m 1g
r IMG=schild:spec19-m3 SCHILD_ENV="--cpus 2" TAGX=m3img-cpus2 sh $H/run-scen.sh schild stress-m 1g
r SCHILD_ENV="--cpus 4 -e GOMAXPROCS=12" TAGX=cpus4g12 sh $H/run-scen.sh schild stress-m 2g
r IMG=schild:spec19-m3 SCHILD_ENV="--cpus 4 -e GOMAXPROCS=12" TAGX=m3img-cpus4g12 sh $H/run-scen.sh schild stress-m 2g
r SCHILD_ENV="--cpus 4 -e GOMAXPROCS=12" TAGX=cpus4g12 sh $H/run-scen.sh schild stress-m 4g
