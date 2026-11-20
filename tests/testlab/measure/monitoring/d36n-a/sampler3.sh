#!/bin/sh
# TEST ONLY: D36 re-measurement (ac9c543) - sampler cost around the new /proc/net/tcp
# scan limit (5 000 sockets) and at 19 800 / 50 000 sockets. N = connections; the
# client and server ends both live in the container, so sockets = 2 N.
# Usage: N=2400 sampler3.sh   (container d36n-samp, removed at the end)
C=d36n-samp; N=${N:-2400}
docker rm -f $C >/dev/null 2>&1
docker run -d --name $C --network d36n-net --ip 10.231.37.61 --cpus 2 --memory 1g -e SCHILD_LOG_LEVEL=warn d36n-run:local /m/schild-linux run -config /m/schild-on.yaml -data /m/data-on >/dev/null
sleep 8
TOK=$(docker exec $C /m/schild-linux token add --scope agent:read --expires 1d --label s -config /m/schild-on.yaml 2>/dev/null | head -1 | awk '{print $1}')
[ "$N" -gt 0 ] && docker exec -d $C /m/spec21-linux sockets -n $N -hold 170s
sleep 25
docker exec $C sh -c 'ss -s | sed -n 2p'
cpu() { docker exec $C sh -c 'awk "{print \$14+\$15}" /proc/1/stat'; }
a=$(cpu)
for i in 1 2 3 4 5 6; do
  docker exec $C curl -s -H "Authorization: Bearer $TOK" http://127.0.0.1:18789/agent/v0/monitoring/server | python3 -I -c "import json,sys; d=json.load(sys.stdin); t=d.get('tcp') or {}; print('sampler_ms', d['schild'].get('sampler_ms'), 'source', t.get('source'), 'estab', t.get('established'), 'listen', t.get('listen'))" 2>&1
  sleep 10
done
b=$(cpu)
echo "N=$N ($((2*N)) sockets), 60 s: process CPU $(( (b-a)*10 )) ms"
docker rm -f $C >/dev/null
