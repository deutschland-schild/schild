#!/bin/bash
# TEST ONLY: evening re-measurement 2026-10-29 (commit c54de1b, fix 703e616), item 3.
# Sets up one native schild instance with four websites (shop, blog, api, status .test,
# the ui36n layout) plus the agent API, for the hard-kill / graceful-restart check.
#   NAME=kill P=223 setup.sh     -> /tmp/abend/k/kill, ports 22388 (dashboard), 22389 (agent API),
#                                    22390 (http ingress), 22393 (https), 22399 (backend), 22311 (metrics)
#   NAME=term P=224 setup.sh     -> /tmp/abend/k/term, ports 224xx
# Binaries: /tmp/abend/bin/schild (darwin-arm64), /tmp/abend/bin/spec21. Geo: spec21 geo (TEST ONLY fixture).
# Stops nothing; run.sh drives the timeline, stop with kill $(cat backend.pid schild.pid).
set -eu
U=$(cd "$(dirname "$0")" && pwd); B=/tmp/abend/bin
NAME=${NAME:-kill}; P=${P:-223}; D=/tmp/abend/k/$NAME
export PW=schild-abend-messung-TESTONLY
mkdir -p $D && cd $D
cat > Caddyfile <<EOF
# TEST ONLY: four apps behind one schild ingress (evening re-measurement, item 3)
{
	admin off
	http_port ${P}90
	https_port ${P}93
	auto_https off
}

(schild) {
	schild
}

http://shop.test:${P}90, http://www.shop.test:${P}90 {
	import schild
	reverse_proxy 127.0.0.1:${P}99
}

http://blog.test:${P}90 {
	import schild
	reverse_proxy 127.0.0.1:${P}99
}

http://api.test:${P}90 {
	import schild
	reverse_proxy 127.0.0.1:${P}99
}

http://status.test:${P}90 {
	import schild
	reverse_proxy 127.0.0.1:${P}99
}
EOF
cat > schild.yaml <<EOF
# TEST ONLY: evening re-measurement item 3 (native macOS, ports ${P}xx)
config_version: 0
profile: production
mode: autoblock
node_name: abend-$NAME
network:
  enabled: false
ingress:
  caddyfile: $D/Caddyfile
  storage: $D/caddy
  trusted_proxies: ["127.0.0.1/32"]
  client_ip_headers: ["X-Forwarded-For"]
listen:
  dashboard: "127.0.0.1:${P}88"
  metrics: "127.0.0.1:${P}11"
geo:
  db_path: $D/geo.mmdb
storage:
  path: $D/data
monitoring:
  enabled: true
behaviour:
  presets: [generic]
  preset_limits: observe
  scenarios:
    login_bruteforce: { mode: block }
    path_probing: { mode: block }
    aggressive_crawl: { mode: block }
    waf_repeat: { mode: block }
agent_api:
  enabled: true
  listen: "127.0.0.1:${P}89"
  requests_per_minute: 600
  max_concurrent: 8
EOF
$B/spec21 geo -out geo.mmdb -table geo.json > geo.out 2>&1
nohup $B/spec21 backend -listen 127.0.0.1:${P}99 > backend.log 2>&1 & echo $! > backend.pid
# first start creates schild.db; date the installation back (older than learning_days), second start
SCHILD_ALLOW_TEST_KEYS=1 nohup $B/schild run -config $D/schild.yaml > schild-0.log 2>&1 & echo $! > schild.pid
sleep 6; kill $(cat schild.pid); while kill -0 $(cat schild.pid) 2>/dev/null; do sleep 0.2; done
sqlite3 data/schild.db "update kv set v='2026-09-29T12:00:00Z' where k='installed_at_v1'"
$B/schild token add --scope agent:read --expires 7d --label abend-$NAME -config $D/schild.yaml > tok.out 2>&1
head -1 tok.out | tr -d '\n' > token
SCHILD_ALLOW_TEST_KEYS=1 nohup $B/schild run -config $D/schild.yaml > schild-1.log 2>&1 & echo $! > schild.pid
sleep 6
curl -s -X POST -H 'Content-Type: application/json' -d "{\"password\":\"$PW\"}" http://127.0.0.1:${P}88/api/v0/auth/setup; echo
echo "instance $NAME ready, schild pid $(cat schild.pid), backend pid $(cat backend.pid)"
