#!/usr/bin/env bash
# Fills the native dev backends (dashboard/scripts/dev-backends.sh up) with realistic
# content for UI work against the REAL APIs:
#
#   1. client: first password (with the setup code from logs/schild.log) or login; mode
#      $SEED_MODE (default review = "Freigeben", so the local CRS blocks and
#      incidents exist); two allowlist entries
#   2. traffic through the client's proxy: browsing and API use from
#      198.51.100.0/24 (DE), 192.0.2.0/24 (DE) and 2001:db8::/32, attacks from
#      203.0.113.0/24 (NL) and 2001:db8:bad::/48 (SQL injection, XSS, path
#      traversal, scanners, command injection). Documentation ranges only
#      (RFC 5737, RFC 3849); X-Forwarded-For from 127.0.0.1, the trusted proxy.
#   3. lab dashboard only (the gateway is standalone and sends nothing): signals
#      of three TEST ONLY sites to every lab, so patterns reach the observe level
#      (>= 3 issuers) and one pattern shows a dominant issuer
#   4. lab: proposal by carol with reproduction and negative corpus, approved by
#      alice and bob (two organisations), bundle assembled by alice, co-signed
#      by bob on lab-b and lab-c -> published -> relays
#   5. a second proposal stays open for review in the lab dashboard
#
#   dashboard/scripts/seed-dev.sh            # all of the above
#   dashboard/scripts/seed-dev.sh traffic    # just one more round of traffic
#   dashboard/scripts/seed-dev.sh bulk 10000 # N more rule-matching requests (performance checks)
#
# Idempotent enough to run twice (a second run adds traffic and one more proposal).
set -euo pipefail
b=${DEV_PORT_BASE:-41}
password=${DEV_PASSWORD:-schild-dev-passwort}
mode=${SEED_MODE:-review}
tmp=${TMPDIR:-/tmp}
dir=${SCHILD_DEV_DIR:-${tmp%/}/schild-ui-dev}
client="http://127.0.0.1:${b}788/api/v0"
proxy="http://127.0.0.1:${b}080"
lab_a="http://127.0.0.1:${b}789/api/v0"
lab_b="http://127.0.0.1:$((b + 1))789/api/v0"
lab_c="http://127.0.0.1:$((b + 2))789/api/v0"
jar="$dir/seed-cookies"
mkdir -p "$jar"
command -v jq >/dev/null || { echo "seed-dev: needs jq" >&2; exit 1; }
[ -x "$dir/bin/schild-lab" ] || { echo "seed-dev: start the backends first: dashboard/scripts/dev-backends.sh up" >&2; exit 1; }
export SCHILD_TEST_CA="$dir/cfg/ca.pem" SCHILD_ALLOW_TEST_KEYS=1   # TEST ONLY, for schild-lab dev-send (D24 preflight override)

log() { printf 'seed-dev: %s\n' "$*"; }

# api NAME METHOD URL [JSON]: request with the session cookie and CSRF token of NAME.
api() {
  local name=$1 method=$2 url=$3 body=${4:-} csrf=""
  [ -f "$jar/$name.csrf" ] && csrf=$(cat "$jar/$name.csrf")
  local args=(-sS -X "$method" -b "$jar/$name.txt" -c "$jar/$name.txt" -H 'Accept: application/json' -w '\n%{http_code}')
  [ -n "$csrf" ] && args+=(-H "X-CSRF-Token: $csrf")
  [ -n "$body" ] && args+=(-H 'Content-Type: application/json' --data "$body")
  local out code
  out=$(curl "${args[@]}" "$url")
  code=${out##*$'\n'}
  out=${out%$'\n'*}
  if [ "${code:0:1}" != 2 ]; then
    echo "seed-dev: $method $url -> $code $out" >&2
    return 1
  fi
  printf '%s' "$out"
}

session_from() { # NAME JSON: keep the CSRF token
  local t; t=$(jq -r '.csrf_token // empty' <<<"$2")
  [ -n "$t" ] && printf '%s' "$t" >"$jar/$1.csrf"
  return 0
}

client_login() {
  rm -f "$jar/client.txt" "$jar/client.csrf"
  local s; s=$(api client GET "$client/auth/session")
  if [ "$(jq -r .first_run <<<"$s")" = true ]; then
    local code; code=$(grep -o '"setup_code":"[^"]*"' "$dir/logs/schild.log" | tail -1 | cut -d'"' -f4 || true)
    s=$(api client POST "$client/auth/setup" "$(jq -nc --arg p "$password" --arg c "$code" '{password:$p,setup_code:$c}')")
    log "client: first password set with the setup code from the log"
  else
    s=$(api client POST "$client/auth/login" "$(jq -nc --arg p "$password" '{password:$p}')")
  fi
  session_from client "$s"
}

lab_login() { # NAME BASE USER
  rm -f "$jar/$1.txt" "$jar/$1.csrf"
  session_from "$1" "$(api "$1" POST "$2/auth/login" "$(jq -nc --arg u "$3" --arg p "$password" '{user:$u,password:$p}')")"
}

# eventually SECONDS WHAT CMD...: poll CMD every second until it succeeds.
eventually() {
  local t=$1 what=$2; shift 2
  for _ in $(seq 1 "$t"); do "$@" >/dev/null 2>&1 && return 0; sleep 1; done
  echo "seed-dev: $what not within ${t}s" >&2; return 1
}

client_setup() {
  client_login
  local cur; cur=$(api client GET "$client/settings" | jq -r .mode)
  if [ "$cur" != "$mode" ]; then
    api client PATCH "$client/settings" "$(jq -nc --arg m "$mode" '{mode:$m}')" >/dev/null
    log "client: mode $cur -> $mode"
  fi
  if ! api client GET "$client/allowlist?limit=100" | jq -e '.items[] | select(.ip=="192.0.2.10")' >/dev/null; then
    api client POST "$client/allowlist" '{"ip":"192.0.2.10","label":"Büro Hamburg","level":"no_block","ttl":"never"}' >/dev/null || true
    api client POST "$client/allowlist" '{"cidr":"198.51.100.0/28","label":"Monitoring","level":"bypass_waf","ttl":"30d","confirm_bypass":true}' >/dev/null || true
    log "client: allowlist entries added"
  fi
}

UA_BROWSER=(
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Safari/605.1.15"
  "Mozilla/5.0 (iPhone; CPU iPhone OS 18_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.1 Mobile/15E148 Safari/604.1"
  "Mozilla/5.0 (X11; Linux x86_64; rv:132.0) Gecko/20100101 Firefox/132.0"
)

# send IP UA METHOD TARGET [BODY]
send() {
  local args=(-s -o /dev/null -w '%{http_code}' -X "$3" -H 'Host: shop.example' -H "X-Forwarded-For: $1" -H "User-Agent: $2" -H 'Accept: text/html,application/json')
  [ -n "${5:-}" ] && args+=(-H 'Content-Type: application/json' --data "$5")
  curl "${args[@]}" "$proxy$4" || true
}

legit_round() {
  local i ip ua n=0
  for i in $(seq 1 "${1:-60}"); do
    case $((i % 5)) in
      0) ip="192.0.2.$((20 + i % 30))" ;;
      1) ip="2001:db8:4::$((i % 50 + 1))" ;;
      *) ip="198.51.100.$((20 + i % 200))" ;;
    esac
    ua=${UA_BROWSER[$((i % ${#UA_BROWSER[@]}))]}
    case $((i % 6)) in
      0) send "$ip" "$ua" GET "/" ;;
      1) send "$ip" "$ua" GET "/api/items?page=$((i % 7 + 1))&sort=name" ;;
      2) send "$ip" "$ua" GET "/api/items/$((i % 12 + 1))" ;;
      3) send "$ip" "$ua" GET "/api/items?q=lampe" ;;
      4) send "$ip" "$ua" POST "/api/items" "{\"name\":\"Stehlampe $i\",\"owner\":\"kunde-$((i % 9))\"}" ;;
      5) send "$ip" "$ua" GET "/healthz" ;;
    esac >/dev/null
    n=$((n + 1))
    sleep 0.06 # below the client's 20/s recording rate for unremarkable requests
  done
  log "traffic: $n ordinary requests"
}

attack_round() {
  local r=${1:-0} n=0 blocked=0 code
  local -a specs=(
    "203.0.113.51|sqlmap/1.8.11#stable (https://sqlmap.org)|GET|/api/items?id=1%27%20OR%20%271%27%3D%271"
    "203.0.113.51|sqlmap/1.8.11#stable (https://sqlmap.org)|GET|/api/items?q=x%27%20UNION%20SELECT%20username%2Cpassword%20FROM%20users--"
    "203.0.113.52|python-requests/2.32.3|GET|/api/items?sort=name%3BDROP%20TABLE%20items--"
    "203.0.113.52|python-requests/2.32.3|GET|/api/items?filter=1%20AND%201%3D1%20UNION%20ALL%20SELECT%20NULL%2CNULL%2Cversion()--"
    "203.0.113.60|Go-http-client/1.1|GET|/api/items?cat=%27%20OR%201%3D1%20LIMIT%201%20--%20-"
    "2001:db8:bad::7|curl/8.7.1|GET|/api/items?ref=1)%3B%20SELECT%20pg_sleep(5)--"
    "203.0.113.61|Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0 Safari/537.36|GET|/api/items?q=%3Cscript%3Ealert(document.cookie)%3C%2Fscript%3E"
    "203.0.113.61|Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0 Safari/537.36|GET|/api/items?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E"
    "203.0.113.70|Nikto/2.5.0|GET|/api/items?file=..%2F..%2F..%2F..%2Fetc%2Fpasswd"
    "203.0.113.70|Nikto/2.5.0|GET|/.env"
    "203.0.113.70|Nikto/2.5.0|GET|/.git/config"
    "203.0.113.71|Mozilla/5.0 (Windows NT 10.0; Win64; x64)|GET|/wp-login.php?redirect_to=%2Fwp-admin%2F"
    "203.0.113.71|Mozilla/5.0 (Windows NT 10.0; Win64; x64)|GET|/wp-admin/admin-ajax.php?action=revslider_show_image&img=..%2Fwp-config.php"
    "2001:db8:bad::9|python-requests/2.31.0|GET|/api/items?host=127.0.0.1%3Bcat%20%2Fetc%2Fpasswd"
    "203.0.113.80|masscan/1.3|GET|/cgi-bin/luci/;stok=/locale?form=country&operation=write&country=\$(id)"
  )
  local s ip ua m t
  for s in "${specs[@]}"; do
    IFS='|' read -r ip ua m t <<<"$s"
    [ "$r" -gt 0 ] && t="$t$([[ $t == *\?* ]] && echo '&' || echo '?')r=$r"
    code=$(send "$ip" "$ua" "$m" "$t")
    [ "$code" = 403 ] && blocked=$((blocked + 1))
    n=$((n + 1))
    sleep 0.05
  done
  # A false positive: a real customer writes SQL-like text into a search field.
  code=$(send "198.51.100.77" "${UA_BROWSER[1]}" GET "/api/items?q=$(printf 'select%%20from%%20the%%20union%%20of%%20lamps%%20and%%20tables%%20or%%201%%3D1')")
  [ "$code" = 403 ] && blocked=$((blocked + 1))
  log "traffic: $((n + 1)) attack-like requests ($blocked answered 403)"
}

bulk() { # N rule-matching requests in parallel (performance checks of the event table)
  local n=${1:-10000}
  log "bulk: $n requests (16 in parallel) ..."
  seq 1 "$n" | xargs -P 16 -I{} sh -c 'i={}; curl -s -o /dev/null -H "Host: shop.example" -H "X-Forwarded-For: 203.0.113.$((i % 200 + 1))" -H "User-Agent: python-requests/2.32.3" "'"$proxy"'/api/items?id=$i%27%20OR%20%27$i%27%3D%27$i&n=$i"'
  log "bulk: done"
}

lab_signals() { # signals of TEST ONLY sites (issuer-test-1, -2, -3, -evil) for the lab dashboard
  local sigs="sqli/api xss/api lfi/api scan/dotfile" sig lab port
  for lab in lab-a lab-b lab-c; do
    case $lab in lab-a) port=$b ;; lab-b) port=$((b + 1)) ;; lab-c) port=$((b + 2)) ;; esac
    for sig in $sigs; do
      "$dir/bin/schild-lab" dev-send -url "https://localhost:${port}443" -lab "$lab" -site site-a -n 6 -action "$sig" >/dev/null
      "$dir/bin/schild-lab" dev-send -url "https://localhost:${port}443" -lab "$lab" -site site-b -n 5 -action "$sig" >/dev/null
      case $sig in sqli/* | xss/* | lfi/*)
        "$dir/bin/schild-lab" dev-send -url "https://localhost:${port}443" -lab "$lab" -site site-c -n 4 -action "$sig" >/dev/null ;;
      esac
    done
    # A pattern only one issuer pushes (dominant issuer, never reaches the observe level).
    "$dir/bin/schild-lab" dev-send -url "https://localhost:${port}443" -lab "$lab" -site evil -n 24 -action "rce/wp-admin" >/dev/null
    "$dir/bin/schild-lab" dev-send -url "https://localhost:${port}443" -lab "$lab" -site site-b -n 2 -action "rce/wp-admin" >/dev/null
  done
  log "labs: signals of issuer-test-1, -2, -3 and -evil sent to lab-a, lab-b, lab-c"
}

pattern_id() { # ACTION_SIG prefix -> pattern id on lab-a
  api carol GET "$lab_a/patterns?sort=issuers&limit=200" | jq -r --arg p "$1" '[.items[] | select(.action_sig|startswith($p))] | sort_by(-.issuers) | .[0].pattern_id // empty'
}

has_pattern() { [ -n "$(pattern_id "$1")" ]; }

lab_flow() {
  lab_login carol "$lab_a" carol
  lab_login alice "$lab_a" alice
  lab_login bob "$lab_a" bob
  lab_login bob_b "$lab_b" bob
  lab_login bob_c "$lab_c" bob
  eventually 60 "sqli pattern on lab-a" has_pattern sqli/
  local pid rid rule p version until
  pid=$(pattern_id sqli/)
  rid=$(printf '770%04d' $(($(date +%s) % 10000)))
  rule="SecRule ARGS \"@detectSQLi\" \"id:$rid,phase:2,deny,status:403,severity:CRITICAL,msg:'SQL injection in request arguments'\""
  p=$(api carol POST "$lab_a/proposals" "$(jq -nc --arg pid "$pid" --arg r "$rule" '{pattern_id:$pid,class:"virtual_patch",stage:"general",requested_max_action:"challenge",seclang:$r,target:{software:"dev-shop/site-api",versions:"*"}}')")
  local id; id=$(jq -r .id <<<"$p")
  api carol POST "$lab_a/proposals/$id/evidence" "$(jq -nc '{kind:"reproduction",image:"schild-testlab:dev site-api",version:"0.1.0-alpha",result:"reproduced",request:"GET /api/items?id=1%27%20OR%20%271%27%3D%271 HTTP/1.1\r\nHost: shop.example\r\n\r\n"}')" >/dev/null
  api carol POST "$lab_a/proposals/$id/evidence" '{"kind":"negative_corpus","corpus_version":"corpus-2026.10","corpus_matches":0}' >/dev/null
  until=$(date -u -v+72H +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '+72 hours' +%Y-%m-%dT%H:%M:%SZ)
  api alice POST "$lab_a/proposals/$id/approve" "$(jq -nc --arg u "$until" '{max_action:"challenge",max_action_until:$u,org:"Betreiber A",note:"Reproduktion nachvollzogen, Negativkorpus sauber."}')" >/dev/null
  api bob POST "$lab_a/proposals/$id/approve" "$(jq -nc --arg u "$until" '{max_action:"challenge",max_action_until:$u,org:"Betreiber B",note:"Gegengeprüft."}')" >/dev/null
  log "lab-a: proposal $id ($pid) by carol, approved by alice (Betreiber A) and bob (Betreiber B)"
  version=$(api alice POST "$lab_a/bundles" "$(jq -nc --arg id "$id" '{add:[$id],remove:[]}')" | jq -r .version)
  log "lab-a: bundle v$version assembled, waiting for the peers"
  for peer in bob_b:"$lab_b" bob_c:"$lab_c"; do
    local who=${peer%%:*} base=${peer#*:}
    eventually 60 "$who sees bundle v$version" api "$who" GET "$base/bundles/$version"
    api "$who" POST "$base/bundles/$version/cosign" "$(jq -nc --arg p "$password" '{password:$p}')" >/dev/null
  done
  eventually 60 "bundle v$version published" sh -c "curl -sf -b '$jar/alice.txt' '$lab_a/bundles/$version' | jq -e '.status==\"published\"'"
  log "lab-a: bundle v$version published (3 operators)"

  # A second proposal stays open for review in the dashboard (XSS pattern).
  local xp; xp=$(pattern_id xss/)
  if [ -n "$xp" ]; then
    rid=$(printf '779%04d' $(($(date +%s) % 10000)))
    rule="SecRule ARGS \"@detectXSS\" \"id:$rid,phase:2,deny,status:403,severity:CRITICAL,msg:'XSS in request arguments'\""
    p=$(api carol POST "$lab_a/proposals" "$(jq -nc --arg pid "$xp" --arg r "$rule" '{pattern_id:$pid,class:"virtual_patch",stage:"general",requested_max_action:"block",seclang:$r,target:{software:"dev-shop/site-api",versions:"*"}}')")
    id=$(jq -r .id <<<"$p")
    api carol POST "$lab_a/proposals/$id/evidence" "$(jq -nc '{kind:"reproduction",image:"schild-testlab:dev site-api",version:"0.1.0-alpha",result:"reproduced",request:"GET /api/items?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E HTTP/1.1\r\nHost: shop.example\r\n\r\n"}')" >/dev/null
    log "lab-a: proposal $id ($xp) open for review"
  fi
}

all() {
  client_setup
  legit_round 90
  attack_round 0
  legit_round 30
  attack_round 1
  lab_signals
  lab_flow
  legit_round 30
  log "done. Dashboards: client http://127.0.0.1:${b}788, lab-a http://127.0.0.1:${b}789 (TEST ONLY password: $password)"
}

case ${1:-all} in
  all) all ;;
  traffic) client_login; legit_round 60; attack_round "$(date +%s)" ;;
  bulk) bulk "${2:-10000}" ;;
  *) echo "usage: $0 [all|traffic|bulk N]" >&2; exit 2 ;;
esac
