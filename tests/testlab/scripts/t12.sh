#!/usr/bin/env bash
# T12 / M1 "the site stays reachable when the client crashes, and nothing
# passes uninspected when it hangs", measured live on the t0 test lab.
#
#   make testlab-up PROFILE=t0 && make testlab-t12      (or testlab/scripts/t12.sh)
#
# Brings up the compose profile t12 (front-api = `schild front`, schild-t12 in
# the front's network namespace, stripper-t12), then drives constant load at the
# front proxy while it
#   A  baseline       schild up                         -> 2xx, no bypass
#   B  kill           docker kill schild-t12 under load -> transition errors only
#   C  down           schild dead                       -> 2xx via fail-open (bypass)
#   D  restarted      docker start schild-t12           -> 2xx, no further bypass
#   E  hung           docker pause schild-t12           -> 503 after the front timeout,
#                                                          no bypass (never passes on timeout)
#   F  resumed        docker unpause                    -> 2xx, no bypass
# Bypass = the front's "fail-open" log line per request sent around schild.
# Report: tests/results/runs/t12/t12.json. The t12 services are left running
# (make testlab-down PROFILE=t0 removes them with the rest of the stack).
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)  # repository root
docker=${DOCKER:-docker}
: "${SCHILD_LABEL_SECRET:?set SCHILD_LABEL_SECRET}"
rps=${T12_RPS:-100}
dur=${T12_DURATION:-10s}
project=schild-testlab-t0
compose=("$docker" compose -p "$project" -f "$root/tests/testlab/compose/docker-compose.t0.yaml" --profile t12)
out="$root/tests/results/runs/t12"
mkdir -p "$out"
command -v jq >/dev/null || { echo "t12: needs jq" >&2; exit 1; }

"${compose[@]}" ps --status running --services 2>/dev/null | grep -qx site-api || { echo "t12: t0 is not up (make testlab-up PROFILE=t0)" >&2; exit 1; }
"${compose[@]}" up -d --wait --wait-timeout 120 stripper-t12 front-api schild-t12 >/dev/null
cid=$("${compose[@]}" ps -q schild-t12)
fid=$("${compose[@]}" ps -q front-api)

load() { # phase [rps] [duration] -> JSON on stdout
  "$docker" run --rm --network "${project}_sites" schild-testlab:dev /usr/local/bin/measure latency \
    -target http://front-api:8090 -label "t12-$1" -rps "${2:-$rps}" -duration "${3:-$dur}" -warmup 0s -workers 256
}
bypass() { "$docker" logs "$fid" 2>&1 | grep -c 'fail-open' || true; }
wait_ready() {
  for _ in $(seq 1 120); do
    [ "$("$docker" inspect -f '{{.State.Health.Status}}' "$cid" 2>/dev/null)" = healthy ] && return 0
    sleep 0.5
  done
  echo "t12: schild-t12 not healthy again" >&2; return 1
}
phase() { # name json bypass_before bypass_after
  jq -c --arg n "$1" --argjson b0 "$3" --argjson b1 "$4" '{phase:$n, statuses, stats, offered_rps, achieved_rps, duration_s, bypassed:($b1-$b0)}' <<<"$2"
}

wait_ready
results=()

b0=$(bypass); r=$(load baseline); b1=$(bypass)
results+=("$(phase A-baseline "$r" "$b0" "$b1")"); echo "A baseline   ${results[${#results[@]}-1]}"

b0=$(bypass)
load kill "$rps" 12s >"$out/kill.json" &
lp=$!
sleep 4
"$docker" kill "$cid" >/dev/null
wait "$lp"; b1=$(bypass)
results+=("$(phase B-kill-under-load "$(cat "$out/kill.json")" "$b0" "$b1")"); echo "B kill       ${results[${#results[@]}-1]}"

b0=$(bypass); r=$(load down); b1=$(bypass)
results+=("$(phase C-schild-down "$r" "$b0" "$b1")"); echo "C down       ${results[${#results[@]}-1]}"

"$docker" start "$cid" >/dev/null
wait_ready
b0=$(bypass); r=$(load restarted); b1=$(bypass)
results+=("$(phase D-restarted "$r" "$b0" "$b1")"); echo "D restarted  ${results[${#results[@]}-1]}"

"$docker" pause "$cid" >/dev/null
b0=$(bypass); r=$(load hung 20 8s); b1=$(bypass)
"$docker" unpause "$cid" >/dev/null
results+=("$(phase E-schild-hung "$r" "$b0" "$b1")"); echo "E hung       ${results[${#results[@]}-1]}"

wait_ready
b0=$(bypass); r=$(load resumed); b1=$(bypass)
results+=("$(phase F-resumed "$r" "$b0" "$b1")"); echo "F resumed    ${results[${#results[@]}-1]}"

printf '%s\n' "${results[@]}" | jq -s --arg at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --arg rps "$rps" \
  --arg img "$("$docker" image inspect -f '{{.Id}}' schild:dev)" '
  def ok: ([.statuses | to_entries[] | select(.key|test("^[23]")) | .value] | add // 0);
  def total: (.stats.n + .stats.errors);
  {test:"T12", hypothesis:"M1", at:$at, image_schild:$img, offered_rps:($rps|tonumber), front_timeout:"3s", phases:.,
   verdict:{
     down_served_via_failopen: ((.[] | select(.phase=="C-schild-down")) as $c | ($c|ok) == ($c|total) and $c.bypassed >= ($c|total)),
     hung_never_passed: ((.[] | select(.phase=="E-schild-hung")) as $e | $e.bypassed == 0 and ($e.statuses["503"] // 0) == ($e|total)),
     no_bypass_while_up: ([.[] | select(.phase|test("A-|D-|F-")) | .bypassed] | add) == 0,
     up_phases_all_2xx: ([.[] | select(.phase|test("A-|D-|F-")) | (ok == total)] | all)
   }} | .pass = (.verdict | all)' >"$out/t12.json"
jq '{pass, verdict}' "$out/t12.json"
jq -e .pass "$out/t12.json" >/dev/null
