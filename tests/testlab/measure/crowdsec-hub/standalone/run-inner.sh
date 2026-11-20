#!/bin/sh
# TEST ONLY: runs inside the container (no network, or an internal one). Own files under /m26.
cd /m26
mkdir -p out
caddy file-server --listen 127.0.0.1:8099 --root /m26/www > out/backend.log 2>&1 &
SCHILD_ALLOW_TEST_KEYS=1 ./$1 run -config /m26/schild.yaml > out/schild.log 2>&1 &
P=$!
i=0
until wget -q -O /dev/null http://127.0.0.1:8788/readyz; do i=$((i+1)); [ $i -gt 100 ] && break; sleep 0.2; done
sleep 0.5
T=$(./$1 token add -config /m26/schild.yaml --scope agent:read --expires 1d --label standalone | head -1)
sleep ${2:-80}
wget -q -O out/status.json --header "Authorization: Bearer $T" http://127.0.0.1:8789/agent/v0/crowdsec-hub
for p in /index.html /.env /password.htm; do
  wget -q -S -O /dev/null --header 'Host: shop.test' --header 'X-Forwarded-For: 198.51.100.77' "http://127.0.0.1:8080$p" 2>&1 | head -1 >> out/probes.txt
done
sleep 2
F=$(date -u -d @$(($(date +%s)-900)) +%Y-%m-%dT%H:%M:%SZ)
E=$(date -u -d @$(($(date +%s)+60)) +%Y-%m-%dT%H:%M:%SZ)
wget -q -O out/events.json --header "Authorization: Bearer $T" "http://127.0.0.1:8789/agent/v0/events?from=$F&to=$E&limit=5"
grep -c . out/schild.log > out/loglines.txt
grep -E '"level":"(WARN|ERROR)"' out/schild.log > out/warn.txt
grep -i 'crowdsec' out/schild.log > out/hub-lines.txt
kill $P
sleep 1
touch out/done
sleep 600
