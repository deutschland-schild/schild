#!/bin/sh
# MVP-19 independent measurement environment (TEST ONLY, local arm64 Docker).
# Source it: . env.sh; then net_up, ingress_schild <data> <schilddata>, ingress_stock <data>, ...
# One netns holder owns the ingress address 10.219.19.10, so schild and stock
# Caddy swap without changing the address and a tcpdump sidecar sees every
# packet of whichever ingress runs.
E=${E:-$(cd "$(dirname "$0")" && pwd)}
ST=${ST:-$(cd "$E/../.." && pwd)/tmp/mvp19/state}
SCHILD_IMAGE=${SCHILD_IMAGE:-schild:mvp19-measure}
CADDY_IMAGE=${CADDY_IMAGE:-caddy:2.11.4}
BIN=${BIN:-$(cd "$E/../.." && pwd)/tmp/mvp19/bin}
NET=m19net
ING=10.219.19.10

net_up() {
  mkdir -p "$ST/cap" "$ST/logs"
  docker network create --subnet 10.219.19.0/24 $NET >/dev/null
  docker run -d --name m19-dns --network $NET --ip 10.219.19.3 ghcr.io/letsencrypt/pebble-challtestsrv:latest \
    -defaultIPv4 $ING -defaultIPv6 "" -http01 "" -https01 "" -tlsalpn01 "" -doh "" >/dev/null
  docker run -d --name pebble --network $NET --ip 10.219.19.2 -e PEBBLE_VA_NOSLEEP=1 -e PEBBLE_WFE_NONCEREJECT=0 \
    -v "$E/pebble-config.json:/cfg.json:ro" ghcr.io/letsencrypt/pebble:latest -config /cfg.json -dnsserver 10.219.19.3:8053 >/dev/null
  docker run -d --name hostrouter --network $NET --ip 10.219.19.4 -e HOSTROUTER_APPS="shop.example.de=shop,www.shop.example.de=shop,portal.example.de=portal,booking.example.de=booking,academy.example.de=academy,api.example.de=api" \
    -v "$BIN/hostrouter-linux:/hostrouter:ro" alpine:3 /hostrouter -listen 0.0.0.0:8080 >/dev/null
  docker run -d --name netholder --network $NET --ip $ING alpine:3 sleep infinity >/dev/null
  docker run -d --name m19-cap --network container:netholder -v "$ST/cap:/cap" m19-tools:local \
    tcpdump -i any -nn -U -w /cap/ingress.pcap >/dev/null
  docker run -d --name m19-tools --network $NET --ip 10.219.19.5 -v "$E:/e:ro" -v "$BIN:/bin2:ro" -v "$ST:/st" m19-tools:local sleep infinity >/dev/null
  sleep 2
  docker exec m19-tools sh -c 'curl -sk https://pebble:15000/roots/0 > /st/pebble-root.pem; curl -sk https://pebble:15000/intermediates/0 >> /st/pebble-root.pem; grep -c BEGIN /st/pebble-root.pem'
}

net_down() {
  docker rm -f ingress m19-tools m19-cap netholder hostrouter pebble m19-dns >/dev/null 2>&1
  docker network rm $NET >/dev/null 2>&1
}

# ingress_schild <caddy data dir> <schild data dir> [caddyfile] [schild.yaml]
ingress_schild() {
  mkdir -p "$1" "$ST/logs"; case "$2" in /*) mkdir -p "$2";; esac
  docker run -d --name ingress --network container:netholder --user 0:0 $INGRESS_EXTRA \
    -v "${3:-$E/Caddyfile.schild}:/etc/caddy/Caddyfile:ro" -v "${4:-$E/schild.yaml}:/etc/schild/schild.yaml:ro" \
    -v "$E/pebble.minica.pem:/etc/pebble/pebble.minica.pem:ro" -v "$1:/data" -v "$2:/var/lib/schild" \
    -v "$ST/logs:/var/log/caddy" -v "$E/storage:/srv/storage:ro" "$SCHILD_IMAGE" >/dev/null
}

# ingress_stock <caddy data dir> [caddyfile]
ingress_stock() {
  mkdir -p "$1" "$ST/logs"
  docker run -d --name ingress --network container:netholder $INGRESS_EXTRA \
    -v "${2:-$E/Caddyfile.stock}:/etc/caddy/Caddyfile:ro" \
    -v "$E/pebble.minica.pem:/etc/pebble/pebble.minica.pem:ro" -v "$1:/data" \
    -v "$ST/logs:/var/log/caddy" -v "$E/storage:/srv/storage:ro" "$CADDY_IMAGE" >/dev/null
}

ingress_rm() { docker rm -f ingress >/dev/null 2>&1; }

# wait_https <host>: seconds until https://<host>/ answers through the ingress
wait_https() {
  docker exec m19-tools sh -c "for i in \$(seq 1 600); do curl -s -o /dev/null --cacert /st/pebble-root.pem --resolve $1:443:$ING https://$1/ && exit 0; sleep 0.1; done; exit 1"
}

# certs: serial and sha256 fingerprint per host as served
certs() {
  for h in shop.example.de www.shop.example.de portal.example.de booking.example.de academy.example.de api.example.de; do
    docker exec m19-tools sh -c "echo | openssl s_client -connect $ING:443 -servername $h 2>/dev/null | openssl x509 -noout -serial -fingerprint -sha256 -enddate" | tr '\n' ' ' | sed "s/^/$h /"; echo
  done
}

t() { docker exec m19-tools "$@"; }
