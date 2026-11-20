#!/bin/bash
# TEST ONLY: as slots.sh, one case, with the reasons of the 503 from the metrics and the running counts from the status.
#   slots2.sh <geo binary> <evals> <attack prefix> <workers> <kib>
set -u
U=$(cd "$(dirname "$0")" && pwd); M=$U/..; G=$1
Y=/tmp/m26/d40/slots2.yaml; : > "$Y"
if [ "$2" != 0 ]; then printf 'waf:\n  max_concurrent_evals: %s\n' "$2" > "$Y"; fi
GEOBIN=$G MODE=observe STATE=off MON=false HUBURL=http://127.0.0.1:9/none HUBAUTO=false EXTRA=$Y bash "$M/inst.sh" start sl 345 > /dev/null
/tmp/m26/bin/floodtool slots -target http://127.0.0.1:34590 -attack "$3" -victim 2001:db8:b -workers "$4" -duration 15s -kib "$5" &
F=$!
python3 -c 'import time;time.sleep(8)'
python3 -c 'import json,sys;d=json.load(sys.stdin);print({k:v for k,v in d.items() if "eval" in k.lower() or "waf" in k.lower()})' <<<"$(curl -s -b /tmp/m26/i/sl/cj http://127.0.0.1:34588/api/v0/overview)" | cut -c1-400
wait $F
curl -s http://127.0.0.1:34511/metrics | grep -E '^schild_(hard_limit|requests_total|eval|waf_(busy|client|cancel))' | cut -c1-120
bash "$M/inst.sh" stop sl
