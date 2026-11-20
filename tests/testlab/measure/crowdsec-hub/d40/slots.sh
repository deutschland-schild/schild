#!/bin/bash
# TEST ONLY: MVP-26 / D40 review item 2.3. Expensive requests from one IPv6 /48 against a second /48.
#   slots.sh <geo binary> <out>
set -u
U=$(cd "$(dirname "$0")" && pwd); M=$U/..; G=$1; OUT=$2
one() { # label evals attack-prefix workers
  local Y=/tmp/m26/d40/slots-$1.yaml
  : > "$Y"
  if [ "$2" != 0 ]; then printf 'waf:\n  max_concurrent_evals: %s\n' "$2" > "$Y"; fi
  GEOBIN=$G MODE=observe STATE=off MON=false HUBURL=http://127.0.0.1:9/none HUBAUTO=false EXTRA=$Y bash "$M/inst.sh" start sl 345 > /dev/null
  r=$(/tmp/m26/bin/floodtool slots -target http://127.0.0.1:34590 -attack "$3" -victim 2001:db8:b -workers "$4" -duration 15s -kib 128)
  echo "$1 evals=$2 attack=$3 workers=$4 $r" | tee -a "$OUT"
  bash "$M/inst.sh" stop sl
}
: > "$OUT"
one baseline-no-attack 0 2001:db8:a 0
one one-64 0 2001:db8:a 1
one default-48 0 2001:db8:a 24
one evals40-48 40 2001:db8:a 40
one evals40-mobile 40 2001:db8:c 40
one evals40-cgnat 40 2001:db8:d 40
one evals40-other48-control 40 2001:db8:a 6
