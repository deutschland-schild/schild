#!/bin/bash
# TEST ONLY (d29n): timed check that Art. 17 delete, `schild allow` and the
# dashboard allowlist end restored 7-day blocks. Instance inst2 must be
# stopped; inserts three kept_blocks rows, starts, acts, polls status every
# 0.2 s until 200. Env: W, PW (dashboard password of the test instance).
# Usage: end-blocks.sh > OUT.txt
set -u
W=${W:-/tmp/d36n/c}; H=$(cd "$(dirname "$0")" && pwd)
export INST=inst2 MPORT=20292 DPORT=20289 W
U=http://127.0.0.1:20210
N=$(($(date +%s)*1000)); DY=86400000; W7=$((7*DY))
for ip in 10.1.0.50 10.1.0.51 10.1.0.52; do
  sqlite3 $W/inst2/data/schild.db "INSERT INTO kept_blocks VALUES('$ip',32,'hosting','behaviour:path_probing',4,604800,$((N-DY)),$((N-DY+W7)),'TEST-${ip##*.}');"
done
sh $H/ctl.sh start
sh $H/ctl.sh kept
"$W/d29" status -url $U 10.1.0.50 10.1.0.51 10.1.0.52
sh $H/api.sh login >/dev/null
wait200() { # ip t0(ns)
  for i in $(seq 1 100); do
    s=$("$W/d29" status -url $U "$1" | python3 -c "import sys,json;print(json.load(sys.stdin)['status'])")
    if [ "$s" = 200 ]; then echo "$1 -> 200 after $(( ($(python3 -c 'import time;print(time.time_ns())') - $2)/1000000 )) ms"; return; fi
    sleep 0.2
  done; echo "$1 still $s after 20 s"; }
now() { python3 -c 'import time;print(time.time_ns())'; }
echo "# Art. 17 POST /privacy/delete 10.1.0.50"; t=$(now); sh $H/api.sh POST /privacy/delete '{"ip":"10.1.0.50","confirm":true}'; wait200 10.1.0.50 $t
echo "# schild allow 10.1.0.51 -config"; t=$(now); /tmp/d36n/bin/schild allow 10.1.0.51 -config $W/inst2/schild.yaml -label d29n-cli2 -ttl 24h; wait200 10.1.0.51 $t
echo "# dashboard POST /allowlist 10.1.0.52"; t=$(now); sh $H/api.sh POST /allowlist '{"ip":"10.1.0.52","label":"d29n dashboard 2","level":"no_block","ttl":"24h"}'; wait200 10.1.0.52 $t
sleep 1; echo "# kept after"; sh $H/ctl.sh kept
