#!/bin/bash
# TEST ONLY: MVP-26 / D40 item 3.4. Linux container, because every 127.a.b.c is a local address there: more than
# 10,000 peers fail against the first-password route, which spends no hash work, and one client near its limit watches.
#   login.sh <linux schild> <floodtool-linux> <out>
set -u
T=/tmp/m26/login; rm -rf "$T"; mkdir -p "$T"
cat > "$T/schild.yaml" <<EOF
# TEST ONLY
config_version: 0
profile: production
mode: observe
node_name: m26-login
upstream:
  url: "http://127.0.0.1:8099"
listen:
  proxy: "127.0.0.1:8080"
  dashboard: "127.0.0.1:8788"
  metrics: "127.0.0.1:9101"
storage:
  path: /m26/data
crowdsec_hub:
  state: "off"
EOF
cp "$1" "$T/schild"; cp "$2" "$T/floodtool"
cat > "$T/inner.sh" <<'EOF'
#!/bin/sh
cd /m26
SCHILD_ALLOW_TEST_KEYS=1 ./schild run -config /m26/schild.yaml > schild.log 2>&1 &
until wget -q -O /dev/null http://127.0.0.1:8788/readyz; do sleep 0.2; done
./floodtool setup -port 8788 -keys ${KEYS:-12000} > flood.txt 2>&1
ps -o rss,comm | grep schild >> flood.txt
touch done
sleep 300
EOF
docker rm -f m26-login > /dev/null 2>&1
docker create --name m26-login --network none --entrypoint /bin/sh caddy:2-alpine /m26/inner.sh > /dev/null
docker cp "$T" m26-login:/m26
docker start m26-login > /dev/null
for i in $(seq 1 120); do docker exec m26-login test -f /m26/done 2>/dev/null && break; python3 -c 'import time;time.sleep(2)'; done
docker cp m26-login:/m26/flood.txt "$3"
docker rm -f m26-login > /dev/null
cat "$3"
