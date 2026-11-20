#!/usr/bin/env bash
# Runs the REAL backends natively on the host (no Docker) for UI work against
# real APIs: one schild gateway (standalone) in front of the test-lab site-api,
# and for the lab dashboard three labs of three operators (TLS with a test CA,
# co-signing peers) and two relays. The gateway has no connection to them.
# TEST ONLY: public test keys (contracts/testkeys) and a test CA for the labs;
# the labs run the test profile, the gateway the production profile (all modes
# selectable).
#
#   dashboard/scripts/dev-backends.sh up      # build, write config, start everything
#   dashboard/scripts/dev-backends.sh down    # stop everything (keeps the data dir)
#   dashboard/scripts/dev-backends.sh reset   # down + delete the data dir
#   dashboard/scripts/dev-backends.sh status
#
# Then fill it with dashboard/scripts/seed-dev.sh.
#
# Ports (127.0.0.1 only, override the base with DEV_PORT_BASE, default 41):
#   client dashboard  http://127.0.0.1:41788   (user admin)
#   client proxy      http://127.0.0.1:41080 -> site-api :41081
#   lab-a / b / c     http://127.0.0.1:41789 / 42789 / 43789   (users carol, alice, bob)
#   relays            http://127.0.0.1:41480, :41481
# Password of every TEST ONLY account: $DEV_PASSWORD (default schild-dev-passwort).
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)  # repository root
tmp=${TMPDIR:-/tmp}
dir=${SCHILD_DEV_DIR:-${tmp%/}/schild-ui-dev}
b=${DEV_PORT_BASE:-41}
password=${DEV_PASSWORD:-schild-dev-passwort}
labs=(lab-a lab-b lab-c)

labport() { # lab suffix -> port prefix (41, 42, 43)
  case $1 in lab-a) echo "$b";; lab-b) echo "$((b + 1))";; lab-c) echo "$((b + 2))";; esac
}
opof() { echo "op-test-${1#lab-}"; }
pub() { (cd "$root/contract" && go run ./cmd/testkeyfile -name "$1" -public | cut -d' ' -f2); }

stop_all() {
  [ -d "$dir/pids" ] || return 0
  for f in "$dir"/pids/*.pid; do
    [ -f "$f" ] || continue
    pid=$(cat "$f")
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 30); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
    rm -f "$f"
  done
}

start() { # name, then the command; env is inherited
  local name=$1; shift
  "$@" >>"$dir/logs/$name.log" 2>&1 &
  echo $! >"$dir/pids/$name.pid"
}

wait_http() { # url what
  for _ in $(seq 1 100); do curl -sf -o /dev/null "$1" && return 0; sleep 0.2; done
  echo "dev-backends: $2 not ready ($1), see $dir/logs" >&2; return 1
}

build() {
  mkdir -p "$dir/bin"
  (cd "$root/gateway" && go build -o "$dir/bin/schild" ./cmd/schild)
  (cd "$root/lab" && go build -o "$dir/bin/schild-lab" ./cmd/schild-lab)
  (cd "$root/relay" && go build -o "$dir/bin/schild-relay" ./cmd/schild-relay)
  (cd "$root/tests/testlab" && go build -o "$dir/bin/site-api" ./cmd/site-api)
}

write_config() {
  [ -f "$dir/cfg/ca.pem" ] && return 0
  mkdir -p "$dir/cfg"
  "$dir/bin/schild-lab" dev-certs -out "$dir/cfg/certs" -hosts lab-a,lab-b,lab-c >/dev/null
  cp "$dir/cfg/certs/ca.pem" "$dir/cfg/ca.pem"
  local site_a site_b site_c evil
  site_a=$(pub site-a) site_b=$(pub site-b) site_c=$(pub site-c) evil=$(pub evil)
  for lab in "${labs[@]}"; do
    local d="$dir/cfg/$lab" n; n=$(labport "$lab")
    mkdir -p "$d/keys" "$d/tls" "$dir/data/$lab"
    (cd "$root/contract" && go run ./cmd/testkeyfile -name "$lab") >"$d/keys/lab.key"
    chmod 0600 "$d/keys/lab.key"
    cp "$dir/cfg/certs/$lab/cert.pem" "$dir/cfg/certs/$lab/key.pem" "$d/tls/"
    {
      echo "# TEST ONLY: test keys, test CA. Written by dashboard/scripts/dev-backends.sh."
      echo "config_version: 0"
      echo "profile: test"
      echo "identity: { operator: $(opof "$lab"), lab: $lab }"
      echo "listen: { ingest: \"127.0.0.1:${n}443\", feed: \"127.0.0.1:${n}444\", dashboard: \"127.0.0.1:${n}789\", metrics: \"127.0.0.1:${n}102\" }"
      echo "tls: { cert_file: $d/tls/cert.pem, key_file: $d/tls/key.pem }"
      echo "channel: schild-main"
      echo "keys:"
      echo "  - { keyid: test-$lab, private_key_file: $d/keys/lab.key, purposes: [ack, rules, checkpoint] }"
      echo "issuers: [ { id: issuer-test-1 }, { id: issuer-test-2 }, { id: issuer-test-3 }, { id: issuer-test-evil } ]"
      echo "clients:"
      echo "  - { keyid: test-site-a, public_key: \"$site_a\", issuer: issuer-test-1 }"
      echo "  - { keyid: test-site-b, public_key: \"$site_b\", issuer: issuer-test-2 }"
      echo "  - { keyid: test-site-c, public_key: \"$site_c\", issuer: issuer-test-3 }"
      echo "  - { keyid: test-evil, public_key: \"$evil\", issuer: issuer-test-evil }"
      echo "scoring: { min_issuers: 3, max_issuer_share: 0.34 }"
      echo "publish: { bundle_validity_hours: 168, checkpoint_interval_s: 10, checkpoint_ttl_s: 120 }"
      echo "storage: { path: $dir/data/$lab }"
      echo "retention: { signals_days: 30 }"
      echo "peers:"
      for p in "${labs[@]}"; do
        [ "$p" = "$lab" ] && continue
        echo "  - lab: $p"
        echo "    operator: $(opof "$p")"
        echo "    endpoint: \"https://localhost:$(labport "$p")444\""
        echo "    keys: [ { keyid: test-$p, public_key: \"$(pub "$p")\", purposes: [ack, rules, checkpoint] } ]"
      done
    } >"$d/lab.yaml"
    SCHILD_LAB_CONFIG="$d/lab.yaml" "$dir/bin/schild-lab" check-config >/dev/null
    for user in carol alice bob; do
      printf '%s\n' "$password" | SCHILD_LAB_CONFIG="$d/lab.yaml" "$dir/bin/schild-lab" user add -name "$user" >/dev/null
    done
  done

  local c="$dir/cfg/client"
  mkdir -p "$c/rules.d" "$dir/data/client"
  "$dir/bin/schild" geo-fixture -out "$c/geo.mmdb" >/dev/null
  {
    echo "# TEST ONLY dev gateway. Profile production so every mode can be chosen"
    echo "# (the test profile allows observe only)."
    echo "# Written by dashboard/scripts/dev-backends.sh."
    echo "config_version: 0"
    echo "profile: production"
    echo "mode: observe"
    echo "node_name: dev-shop"
    echo "listen: { proxy: \"127.0.0.1:${b}080\", dashboard: \"127.0.0.1:${b}788\", metrics: \"127.0.0.1:${b}101\" }"
    echo "upstream: { url: \"http://127.0.0.1:${b}081\", timeout_ms: 30000 }"
    echo "ingress:"
    echo "  # seed-dev.sh acts like a CDN on 127.0.0.1: X-Forwarded-For carries the"
    echo "  # simulated visitor (documentation ranges only)."
    echo "  trusted_proxies: [\"127.0.0.1/32\"]"
    echo "  client_ip_headers: [X-Forwarded-For]"
    echo "rules:"
    echo "  crs: { state: block, paranoia_level: 1, inbound_anomaly_threshold: 5 }"
    echo "  local: { dir: \"$c/rules.d\" }"
    echo "waf:"
    echo "  request_body_limit_bytes: 13107200"
    echo "  eval_timeout_ms: 1000"
    echo "geo: { db_path: $c/geo.mmdb }"
    echo "storage: { path: $dir/data/client }"
    echo "retention: { raw_ip_days: 7, events_days: 14 }"
  } >"$c/schild.yaml"
}

up() {
  mkdir -p "$dir/logs" "$dir/pids"
  stop_all
  build
  write_config
  # TEST ONLY keys and test CA of the labs: the D24 preflight needs the test lab override.
  export SCHILD_ALLOW_TEST_KEYS=1
  export SCHILD_TEST_CA="$dir/cfg/ca.pem" SCHILD_LOG_FORMAT=text SCHILD_LOG_LEVEL=${SCHILD_LOG_LEVEL:-info}
  SITE_API_LISTEN="127.0.0.1:${b}081" start site-api "$dir/bin/site-api"
  for lab in "${labs[@]}"; do
    SCHILD_LAB_CONFIG="$dir/cfg/$lab/lab.yaml" start "$lab" "$dir/bin/schild-lab" run
  done
  for lab in "${labs[@]}"; do wait_http "http://127.0.0.1:$(labport "$lab")789/healthz" "$lab"; done
  for r in 1 2; do
    SCHILD_RELAY_ID=relay-dev-$r SCHILD_RELAY_LISTEN="127.0.0.1:${b}48$((r - 1))" SCHILD_RELAY_METRICS="127.0.0.1:${b}10$((r + 2))" \
      SCHILD_RELAY_UPSTREAMS="https://localhost:${b}444,https://localhost:$((b + 1))444,https://localhost:$((b + 2))444" \
      start relay-$r "$dir/bin/schild-relay"
  done
  wait_http "http://127.0.0.1:${b}480/readyz" relay-1
  wait_http "http://127.0.0.1:${b}481/readyz" relay-2
  SCHILD_CONFIG="$dir/cfg/client/schild.yaml" SCHILD_DATA_DIR="$dir/data/client" \
    start schild "$dir/bin/schild" run
  wait_http "http://127.0.0.1:${b}788/api/v0/auth/session" schild
  echo "dev-backends: up (data and logs in $dir)"
  echo "  client dashboard  http://127.0.0.1:${b}788   (admin)"
  echo "  lab-a / b / c     http://127.0.0.1:${b}789 / $((b + 1))789 / $((b + 2))789   (carol, alice, bob)"
  echo "  TEST ONLY password: $password"
  echo "  next: dashboard/scripts/seed-dev.sh"
}

status() {
  for f in "$dir"/pids/*.pid; do
    [ -f "$f" ] || { echo "dev-backends: nothing running"; return 0; }
    n=$(basename "$f" .pid)
    if kill -0 "$(cat "$f")" 2>/dev/null; then echo "$n running (pid $(cat "$f"))"; else echo "$n stopped"; fi
  done
}

case ${1:-up} in
  up) up ;;
  down) stop_all; echo "dev-backends: stopped (data kept in $dir)" ;;
  reset) stop_all; rm -rf "$dir"; echo "dev-backends: stopped, $dir removed" ;;
  status) status ;;
  *) echo "usage: $0 up|down|reset|status" >&2; exit 2 ;;
esac
