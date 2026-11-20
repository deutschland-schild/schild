#!/bin/bash
# TEST ONLY: MVP-26 standalone. Linux build of schild in a container. Case none: no network at all. Case capture: an
# internal network without a route, tcpdump in the same network namespace, shows every packet that tries to leave.
#   standalone.sh <linux dir with schild, schild-release> <out dir>
set -u
L=$1; OUT=$2; U=$(cd "$(dirname "$0")" && pwd); mkdir -p "$OUT"
T=/tmp/m26/sa; rm -rf "$T"; mkdir -p "$T/www"
echo 'TEST ONLY' > "$T/www/index.html"
cat > "$T/Caddyfile" <<EOF
# TEST ONLY
{
	admin off
	http_port 8080
	https_port 8443
	auto_https off
}
http://shop.test:8080 {
	schild
	reverse_proxy 127.0.0.1:8099
}
EOF
cat > "$T/schild.yaml" <<EOF
# TEST ONLY
config_version: 0
profile: production
mode: observe
node_name: m26-sa
ingress:
  caddyfile: /m26/Caddyfile
  storage: /m26/caddy
  trusted_proxies: ["127.0.0.1/32"]
  client_ip_headers: ["X-Forwarded-For"]
listen:
  dashboard: "127.0.0.1:8788"
  metrics: "127.0.0.1:9101"
geo:
  db_path: /m26/geo.mmdb
storage:
  path: /m26/data
monitoring:
  enabled: true
agent_api:
  enabled: true
  listen: "127.0.0.1:8789"
EOF
/tmp/m26/bin/spec21 geo -out "$T/geo.mmdb" > /dev/null
cp "$L/schild" "$L/schild-release" "$T/"; cp "$U/run-inner.sh" "$T/run-inner.sh"
one() { # name network binary seconds extra-docker-args
  local n=$1
  docker rm -f "$n" > /dev/null 2>&1
  docker create --name "$n" --network "$2" --entrypoint /bin/sh $5 caddy:2-alpine /m26/run-inner.sh "$3" "$4" > /dev/null
  docker cp "$T" "$n:/m26"
  docker start "$n" > /dev/null
}
wait_done() { local n=$1; for i in $(seq 1 90); do docker exec "$n" test -f /m26/out/done 2>/dev/null && return 0; python3 -c 'import time;time.sleep(2)'; done; return 1; }
one m26-sa none schild 80 ""
wait_done m26-sa
docker cp m26-sa:/m26/out "$OUT/none"
docker rm -f m26-sa > /dev/null
[ "${ONLY:-}" = none ] && exit 0
# capture
docker pull -q nicolaka/netshoot > /dev/null
one m26-eg m26-cs-int schild 80 "-e SCHILD_X=1"
docker run -d --name m26-eg-cap --net container:m26-eg nicolaka/netshoot tcpdump -n -l -i any -w /tmp/c.pcap > /dev/null
wait_done m26-eg
docker exec m26-eg-cap tcpdump -n -r /tmp/c.pcap > "$OUT/capture.txt" 2>&1
docker cp m26-eg:/m26/out "$OUT/capture-out"
docker rm -f m26-eg m26-eg-cap > /dev/null
# release build: the test variable must be ignored
one m26-rel m26-cs-int schild-release 75 "-e SCHILD_CROWDSEC_HUB_URL=http://m26-cs-front:7422/from-env"
docker run -d --name m26-rel-cap --net container:m26-rel nicolaka/netshoot tcpdump -n -l -i any -w /tmp/c.pcap > /dev/null
wait_done m26-rel
docker exec m26-rel-cap tcpdump -n -r /tmp/c.pcap > "$OUT/capture-release.txt" 2>&1
docker cp m26-rel:/m26/out "$OUT/release-out"
docker rm -f m26-rel m26-rel-cap > /dev/null
echo finished
