#!/bin/bash
# TEST ONLY: MVP-29 measurement (base 8eb64b7b). One native schild (darwin-arm64) behind its own Caddy ingress, data in
# /tmp/m29/i/NAME. Stops only the PIDs it recorded.
#   MODE=autoblock [EXTRA=file] [MON=true] inst.sh start NAME P     ports P88 dashboard, P89 agent, P90 ingress, P99 backend, P11 metrics
#   inst.sh restart NAME     keep data and config
#   inst.sh stop NAME
set -u
B=${BIN_DIR:-/tmp/m29/bin}
export PW=schild-m29-TESTONLY-pw
wait_ready() { for i in $(seq 1 ${2:-200}); do curl -sf -m 1 http://127.0.0.1:$1/readyz >/dev/null 2>&1 && return 0; sleep 0.1; done; return 1; }
run_schild() {
  local D=$1 L=$2 env=()
  env ${env[@]+"${env[@]}"} SCHILD_ALLOW_TEST_KEYS=1 ${GOMEMLIMIT:+GOMEMLIMIT=$GOMEMLIMIT} ${GOGC:+GOGC=$GOGC} ${SCHILD_BIN:-$B/schild} run -config "$D/schild.yaml" > "$L" 2>&1 &
  echo $! > "$D/schild.pid"
  disown
}
stop_pid() { [ -f "$1" ] || return 0; local p; p=$(cat "$1"); kill "$p" 2>/dev/null; for i in $(seq 1 100); do kill -0 "$p" 2>/dev/null || break; sleep 0.1; done; rm -f "$1"; }
case ${1:?} in
start)
  NAME=$2; P=$3; D=/tmp/m29/i/$NAME
  MODE=${MODE:-autoblock}; MON=${MON:-true}
  stop_pid "$D/schild.pid"; stop_pid "$D/backend.pid"
  rm -rf "$D"; mkdir -p "$D"
  echo "$P" > "$D/port"
  cat > "$D/Caddyfile" <<EOF
# TEST ONLY
{
	admin off
	http_port ${P}90
	https_port ${P}93
	auto_https off
}

(schild) {
	schild
}

http://shop.test:${P}90 {
	import schild
	reverse_proxy 127.0.0.1:${P}99
}

http://blog.test:${P}90 {
	import schild
	reverse_proxy 127.0.0.1:${P}99
}
EOF
  cat > "$D/schild.yaml" <<EOF
# TEST ONLY: MVP-29 measurement instance $NAME
config_version: 0
profile: production
mode: $MODE
node_name: m29-$NAME
ingress:
  caddyfile: $D/Caddyfile
  storage: $D/caddy
  trusted_proxies: ${TRUSTED:-["127.0.0.1/32"]}
  client_ip_headers: ["X-Forwarded-For"]
listen:
  dashboard: "127.0.0.1:${P}88"
  metrics: "127.0.0.1:${P}11"
geo:
  db_path: $D/geo.mmdb
storage:
  path: $D/data
monitoring:
  enabled: $MON
agent_api:
  enabled: true
  listen: "127.0.0.1:${P}89"
  requests_per_minute: 600
  max_concurrent: 8
$( [ -n "${EXTRA:-}" ] && cat "$EXTRA" )
EOF
  $B/spec21 geo -out "$D/geo.mmdb" -table "$D/geo.json" > "$D/geo.out" 2>&1
  $B/spec21 backend -listen 127.0.0.1:${P}99 > "$D/backend.log" 2>&1 &
  echo $! > "$D/backend.pid"; disown
  run_schild "$D" "$D/schild-0.log"
  wait_ready ${P}88 || { echo "not ready"; tail -3 "$D/schild-0.log"; exit 1; }
  stop_pid "$D/schild.pid"
  sqlite3 "$D/data/schild.db" "update kv set v='2026-09-29T12:00:00Z' where k='installed_at_v1'"
  run_schild "$D" "$D/schild-1.log"
  wait_ready ${P}88 || { echo "not ready"; tail -3 "$D/schild-1.log"; exit 1; }
  CODE=$(grep -ho '"setup_code":"[^"]*"' "$D"/schild-*.log | tail -1 | cut -d'"' -f4)
  curl -s -o /dev/null -c "$D/cj" -X POST -H 'Content-Type: application/json' -d "{\"password\":\"$PW\",\"setup_code\":\"$CODE\"}" http://127.0.0.1:${P}88/api/v0/auth/setup
  python3 -c 'import json,sys;print(json.load(sys.stdin)["csrf_token"])' <<<"$(curl -s -b "$D/cj" http://127.0.0.1:${P}88/api/v0/auth/session)" > "$D/csrf"
  echo "instance $NAME up, schild $(cat "$D/schild.pid"), ports ${P}xx"
  ;;
restart)
  NAME=$2; D=/tmp/m29/i/$NAME; P=$(cat "$D/port")
  stop_pid "$D/schild.pid"
  run_schild "$D" "$D/schild-r$(date +%s).log"
  wait_ready ${P}88 || { echo "not ready"; exit 1; }
  python3 -c 'import json,sys;print(json.load(sys.stdin).get("csrf_token",""))' <<<"$(curl -s -b "$D/cj" http://127.0.0.1:${P}88/api/v0/auth/session)" > "$D/csrf"
  ;;
stop)
  D=/tmp/m29/i/$2
  stop_pid "$D/schild.pid"; stop_pid "$D/backend.pid"
  ;;
esac
