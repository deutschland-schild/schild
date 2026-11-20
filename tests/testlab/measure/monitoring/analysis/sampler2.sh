#!/bin/sh
# TEST ONLY: MVP-21 re-measurement - sampler cost and network namespace detection.
# Bridge container (own network namespace), --cpus 2 --memory 1g; 60 s idle CPU
# without and with 50 000 TCP sockets; server snapshots through the agent API.
# Then the same binary with --network host (the Docker VM's namespace).
C=m21-samp
docker rm -f $C >/dev/null 2>&1
docker run -d --name $C --network m21net --ip 10.231.36.60 --cpus 2 --memory 1g -e SCHILD_LOG_LEVEL=warn m21d36-run:local /m/schild-linux run -config /m/schild-on.yaml -data /m/data-on >/dev/null
sleep 8
TOK=$(docker exec $C /m/schild-linux token add --scope agent:read --expires 1d --label samp -config /m/schild-on.yaml 2>/dev/null | head -1)
snap() { docker exec $C curl -s -H "Authorization: Bearer $TOK" http://127.0.0.1:18789/agent/v0/monitoring/server; }
cpu() { docker exec $C sh -c 'awk "{print \$14+\$15}" /proc/1/stat'; }
sleep 20
echo "== bridge, idle"
snap > server-bridge-idle.json
a=$(cpu); sleep 60; b=$(cpu); echo "idle 60 s: process CPU $(( (b-a)*10 )) ms"
docker exec -d $C /m/spec21-linux sockets -n 25000 -hold 200s
sleep 25
echo "== bridge, 50000 sockets"
docker exec $C sh -c 'ss -s | head -3'
a=$(cpu); for i in 1 2 3 4 5 6; do snap >> server-bridge-sock.jsonl; echo >> server-bridge-sock.jsonl; sleep 10; done; b=$(cpu)
echo "with 50000 sockets 60 s: process CPU $(( (b-a)*10 )) ms"
docker rm -f $C >/dev/null 2>&1
echo "== host network namespace"
docker run -d --name $C --network host --cpus 2 --memory 1g -e SCHILD_LOG_LEVEL=warn m21d36-run:local /m/schild-linux run -config /m/schild-host.yaml -data /m/data-host >/dev/null
sleep 8
TOK=$(docker exec $C /m/schild-linux token add --scope agent:read --expires 1d --label samp -config /m/schild-host.yaml 2>/dev/null | head -1)
sleep 20
docker exec $C curl -s -H "Authorization: Bearer $TOK" http://127.0.0.1:28789/agent/v0/monitoring/server > server-host.json
docker exec $C sh -c 'ls /sys/class/net | tr "\n" " "'; echo
docker rm -f $C >/dev/null 2>&1
