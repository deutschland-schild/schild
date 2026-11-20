#!/bin/sh
# TEST ONLY: sampler cost just under the 20 000-socket scan threshold (19 800 sockets).
C=m21-samp2
docker rm -f $C >/dev/null 2>&1
docker run -d --name $C --network m21net --ip 10.231.36.61 --cpus 2 --memory 1g -e SCHILD_LOG_LEVEL=warn m21d36-run:local /m/schild-linux run -config /m/schild-on.yaml -data /m/data-on >/dev/null
sleep 8
TOK=$(docker exec $C /m/schild-linux token add --scope agent:read --expires 1d --label s -config /m/schild-on.yaml 2>/dev/null | head -1)
docker exec -d $C /m/spec21-linux sockets -n ${N:-9900} -hold 150s
sleep 25
docker exec $C sh -c 'ss -s | sed -n 2p'
cpu() { docker exec $C sh -c 'awk "{print \$14+\$15}" /proc/1/stat'; }
a=$(cpu)
for i in 1 2 3 4 5 6; do
  docker exec $C curl -s -H "Authorization: Bearer $TOK" http://127.0.0.1:18789/agent/v0/monitoring/server | python3 -I -c "import json,sys; d=json.load(sys.stdin); print('sampler_ms', d['schild']['sampler_ms'], 'source', d['tcp']['source'], 'estab', d['tcp']['established'], 'listen', d['tcp']['listen'])"
  sleep 10
done
b=$(cpu)
echo "$((2*${N:-9900})) sockets, 60 s: process CPU $(( (b-a)*10 )) ms"
docker rm -f $C >/dev/null
