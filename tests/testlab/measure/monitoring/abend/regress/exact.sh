#!/bin/bash
# TEST ONLY: evening re-measurement 2026-10-29, item 9a: exactness instance (shop/down/slow, ports 225xx) + replay mix 5 min
# + compare.py. Config from results/messung-2026-10-29-abend/d/exactness/{schild.yaml,Caddyfile} (paths /tmp/abend/k/exact).
# Run 2 used waiting_page: enabled: false (the D37 waiting page has no X-Schild-Incident header, which the replay
# classifier counts as unknown). Stop: kill $(cat schild.pid backend.pid).
#   exact.sh [clientoffset]
set -eu
U=$(cd "$(dirname "$0")" && pwd); B=/tmp/abend/bin; D=/tmp/abend/k/exact; OFF=${1:-300000}
cd $D
nohup $B/spec21 backend -listen 127.0.0.1:22599 > backend.log 2>&1 & echo $! > backend.pid
SCHILD_ALLOW_TEST_KEYS=1 nohup $B/schild run -config $D/schild.yaml >> schild.log 2>&1 & echo $! > schild.pid
sleep 6
[ -s token ] || { $B/schild token add --scope agent:read --expires 7d --label abend-exact -config $D/schild.yaml > tok.out; head -1 tok.out | tr -d '\n' > token; }
$B/spec21 replay -target http://127.0.0.1:22590 -phase mix -minutes 5 -rps 250 -clientoffset $OFF -out truth-mix.json > replay-mix.log 2>&1
sleep 75   # last minute written
python3 -I $U/../../compare.py --truth truth-mix.json --api http://127.0.0.1:22589 --token-file token --out compare-mix.json > /dev/null
python3 -I $U/../../d36n-a/clients_summary.py compare-mix.json | tee summary-mix.txt
