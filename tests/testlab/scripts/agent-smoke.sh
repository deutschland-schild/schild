#!/usr/bin/env bash
# MVP-11 agent smoke on a running t1 stack (part of make smoke PROFILE=t1,
# or directly after the main smoke). Brings up the agents overlay
# (compose/docker-compose.t1.agents.yaml), then proves step by step:
#
#   enrolment with a one-time code (fingerprint compared, wrong one refused),
#   first report of the app VM via the dashboard API (planted findings, no secret),
#   signed deliveries: replay / expired / wrong gateway / impersonation /
#     unknown key / revoked key / forbidden content / oversize / malformed refused,
#   unenrolled agent (real binary, test key agent-b) rejected and not listed,
#   agent revoked in the dashboard, its next delivery rejected with `revoked`,
#   gateway unreachable: the agent keeps running, retries with backoff and
#     delivers once the network is back; traffic unchanged under an agent flood,
#   host report canaries: at the gateway, never in any lab's data;
#     secret canaries nowhere,
#   optional (SCHILD_AGENTS_SILENT=1, ~11 min): "meldet sich nicht" after 2x interval.
#
# Re-runs on the same lab are fine: when the app VMs already hold an
# enrolment from an earlier run, their enrolled agents are revoked at the
# gateway ("retired"), the VMs forget key and agent.json and enrol again
# with a fresh key id; the steps then look at the newest agent of each name.
#
# Steps are "pending" while the schild image does not support MVP-11 yet
# (dashboard /hosts 404, no agent listener, or no `schild-agent` binary).
# Pending fails the run only with SCHILD_AGENTS_REQUIRE=1 (scripts/smoke.sh
# sets it by default). Report: results/runs/smoke-t1/agents.json
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)  # repository root
docker=${DOCKER:-docker}
: "${SCHILD_LABEL_SECRET:?set SCHILD_LABEL_SECRET}"
export SMOKE_PASSWORD=${SMOKE_PASSWORD:-schild-testlab-passwort}
project=schild-testlab-t1
compose=("$docker" compose -p "$project" -f "$root/tests/testlab/compose/docker-compose.t1.yaml" -f "$root/tests/testlab/compose/docker-compose.t1.agents.yaml" --profile agents --profile jobs)
state="$root/tests/results/runs/smoke-t1/agents"
steps="$state/steps.ndjson"
rm -rf "$state"; mkdir -p "$state"
canary_host=app-vm-canary-k4p8z2   # internal/hostcanary.Hostname

now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
jstr() { printf '%s' "$1" | tr -d '\000-\037' | cut -c1-600 | sed 's/\\/\\\\/g; s/"/\\"/g'; }
record() { # status name detail
  printf '{"name":"%s","status":"%s","seconds":0,"detail":"%s"}\n' "$(jstr "$2")" "$1" "$(jstr "$3")" >> "$steps"
  printf '%-7s %-72s %s\n' "$(tr '[:lower:]' '[:upper:]' <<<"$1")" "$2" "$3"
}
phase() { "${compose[@]}" run --rm --no-deps -T agent-smoke "$@"; }
# Signed deliveries from their own address (see agent-smoke-deliveries in the
# compose file): a re-run within 15 minutes must not meet the flood's budget.
phase_deliveries() { "${compose[@]}" run --rm --no-deps -T agent-smoke-deliveries "$@"; }
vm() { local svc=$1; shift; "${compose[@]}" exec -T "$svc" "$@"; }
finish() {
  local req=()
  [ "${SCHILD_AGENTS_REQUIRE:-0}" = 1 ] && req=(-require)
  phase report -out /results/runs/smoke-t1/agents.json "${req[@]}"
}

all_steps=(
  "enrolment: one-time code for app-vm"
  "enrolment: schild-agent enrol on app-vm (key created locally)"
  "enrolment: agent key stays on the VM with mode 0600"
  "enrolment: fingerprint compared, wrong one refused, agent confirmed"
  "first report of app-vm visible via the dashboard API"
  "signed deliveries (replay, expired, channel, unknown, revoked, forbidden content, ...)"
  "unenrolled agent (test-agent-b, real binary) rejected with signature"
  "unenrolled agent not listed at the gateway"
  "revoked agent: enrolled, delivered, revoked, next delivery rejected with revoked"
  "gateway unreachable: agent keeps running and retries with backoff"
  "traffic unaffected while the agent listener is flooded"
  "gateway reachable again: agent delivers without help"
  "host report canaries: at the gateway, absent from every lab"
)

# ---- images and stack ---------------------------------------------------------
if ! "$docker" image inspect schild-testlab-app-vm:dev >/dev/null 2>&1; then
  echo "agent-smoke: building schild-testlab-app-vm:dev (make testlab-app-vm-image)"
  "$docker" build -f "$root/tests/testlab/dockerfiles/app-vm.Dockerfile" -t schild-testlab-app-vm:dev "$root/tests/testlab/dockerfiles/app-vm"
fi
"$root/tests/testlab/scripts/gen-agent-secrets.sh"
code=$("${compose[@]}" logs --no-color schild-api 2>/dev/null | grep -o '"setup_code":"[^"]*"' | tail -1 | cut -d'"' -f4 || true)
export SMOKE_SETUP_CODE_API=$code
# Recreates schild-api with the host_check config, starts gw-host-check and the app VMs.
"${compose[@]}" up -d --wait --wait-timeout 240 schild-api gw-host-check app-vm app-revoked app-unenrolled

# ---- support probe -----------------------------------------------------------------
gw_ok=1; phase probe || gw_ok=0
cli_ok=1; vm app-vm schild-testlab-agent supported || cli_ok=0
if [ $gw_ok = 0 ] || [ $cli_ok = 0 ]; then
  why="gateway MVP-11 API/listener: $([ $gw_ok = 1 ] && echo yes || echo no); schild-agent and schild check: $([ $cli_ok = 1 ] && echo yes || echo no)"
  for s in "${all_steps[@]}"; do record pending "$s" "$why"; done
  finish; exit $?
fi

# ---- re-run on the same lab: retire earlier enrolments ------------------------------
# keyid is empty on a fresh lab (default <hostname>/agent/<yyyy-mm>); on a
# re-run the old key id is still known at the gateway, so a fresh one is used.
rerun_keyid() { :; }
rerun=0
for svc in app-vm app-revoked; do vm "$svc" schild-testlab-agent enrolled 2>/dev/null && rerun=1; done
if [ $rerun = 1 ]; then
  echo "agent-smoke: the app VMs hold an enrolment of an earlier run; retiring it and enrolling anew"
  phase retire -hostname "$canary_host"
  phase retire -hostname app-revoked
  for svc in app-vm app-revoked; do vm "$svc" schild-testlab-agent reset; done
  # The daemon on app-vm still holds the old key in memory: restart it, the
  # entrypoint waits for the new enrolment.
  "${compose[@]}" restart app-vm >/dev/null
  run_suffix=r$(date -u +%Y%m%d%H%M%S)
  rerun_keyid() { printf '%s/agent/%s' "$1" "$run_suffix"; }
fi

# ---- enrolment with a one-time code (app-vm) -----------------------------------------
enrol() { # service hostname label
  local svc=$1 host=$2 lbl=$3 out rc=0 fp
  phase enrol-code -name "enrolment: one-time code for $lbl" -label "$lbl" || return 1
  out=$(vm "$svc" schild-testlab-agent enrol "$(tr -d '\n' < "$state/code-$lbl")" $(rerun_keyid "$host") 2>&1) || rc=$?
  printf '%s\n' "$out" > "$state/enrol-$lbl.log"
  fp=$(grep -i fingerprint <<<"$out" | grep -o 'sha256:[0-9a-f]\{64\}' | head -1 || true)
  if [ $rc -ne 0 ] || [ -z "$fp" ]; then
    record fail "enrolment: schild-agent enrol on $lbl (key created locally)" "exit $rc, fingerprint '${fp}': $(tail -3 <<<"$out")"
    return 1
  fi
  record pass "enrolment: schild-agent enrol on $lbl (key created locally)" "printed $fp; gateway answered pending"
  # The private key never leaves the VM and is 0600 (host-check.md section 5).
  local keys
  keys=$(vm "$svc" sh -c 'grep -rls "ed25519-seed:" /var/lib/schild-agent /etc/schild* /root 2>/dev/null | xargs -r stat -c "%a %n"' || true)
  if [ -n "$keys" ] && ! grep -vq '^600 ' <<<"$keys"; then
    record pass "enrolment: agent key stays on the VM with mode 0600" "$(tr '\n' ' ' <<<"$keys")"
  else
    record fail "enrolment: agent key stays on the VM with mode 0600" "key files: '$(tr '\n' ' ' <<<"$keys")'"
  fi
  phase enrol-confirm -name "enrolment: fingerprint compared, wrong one refused, agent confirmed ($lbl)" -hostname "$host" -fingerprint "$fp"
}
t_enrol=$(now)
if enrol app-vm "$canary_host" app-vm; then
  phase wait-report -name "first report of app-vm visible via the dashboard API" -hostname "$canary_host" -after "$t_enrol" -timeout 4m -planted || true
fi

# ---- signed deliveries with the TEST ONLY keys ------------------------------------------
phase_deliveries forged || true

# ---- unenrolled agent (real binary, key agent-b) ------------------------------------
rc=0; out=$(vm app-unenrolled schild-testlab-agent once 2>&1) || rc=$?
printf '%s\n' "$out" > "$state/unenrolled.log"
if [ $rc -ne 0 ] && grep -q 'signature' <<<"$out"; then
  record pass "unenrolled agent (test-agent-b, real binary) rejected with signature" "agent exit $rc"
else
  record fail "unenrolled agent (test-agent-b, real binary) rejected with signature" "agent exit $rc: $(tail -3 <<<"$out")"
fi
phase expect-host -name "unenrolled agent not listed at the gateway" -hostname app-unenrolled -absent || true

# ---- revoked agent ---------------------------------------------------------------------
name="revoked agent: enrolled, delivered, revoked, next delivery rejected with revoked"
t_rev=$(now)
if enrol app-revoked app-revoked app-revoked; then
  rc=0; vm app-revoked schild-testlab-agent once > "$state/revoked-1.log" 2>&1 || rc=$?
  if [ $rc -ne 0 ]; then
    record fail "$name" "first delivery after confirm failed (exit $rc): $(tail -3 "$state/revoked-1.log")"
  elif phase wait-report -name "revoked agent: first report accepted" -hostname app-revoked -after "$t_rev" -timeout 1m \
       && phase revoke -name "revoked agent: revoked in the dashboard" -hostname app-revoked; then
    t_rev2=$(now); sleep 1
    rc=0; out=$(vm app-revoked schild-testlab-agent once 2>&1) || rc=$?
    printf '%s\n' "$out" > "$state/revoked-2.log"
    if [ $rc -ne 0 ] && grep -q 'revoked' <<<"$out"; then
      record pass "$name" "agent exit $rc after revocation"
    else
      record fail "$name" "agent exit $rc after revocation: $(tail -3 <<<"$out")"
    fi
    phase expect-host -name "revoked agent: rejection shown in the dashboard" -hostname app-revoked -after "$t_rev2" -rejected revoked -status revoked || true
  fi
else
  record fail "$name" "enrolment of app-revoked failed"
fi

# ---- gateway unreachable: retries with backoff; traffic unaffected ---------------------
cid=$("${compose[@]}" ps -q app-vm)
net="${project}_sites"
t_down=$(now)
"$docker" network disconnect "$net" "$cid"
"${compose[@]}" restart app-vm >/dev/null        # the daemon starts with a run that cannot deliver
phase traffic -n 120 || true                      # ~20 s of traffic under an agent-listener flood
sleep 110                                         # start delay up to 60 s, then 30 s backoff doubling
logs=$("$docker" logs --since "$t_down" "$cid" 2>&1 || true)
printf '%s\n' "$logs" > "$state/gateway-down.log"
attempts=$(grep -ciE 'retry|backoff|unreachable|no route|connection refused|dial tcp' <<<"$logs" || true)
exits=$(grep -c 'schild-agent exited' <<<"$logs" || true)
if [ "${attempts:-0}" -ge 2 ] && [ "${exits:-0}" -eq 0 ]; then
  record pass "gateway unreachable: agent keeps running and retries with backoff" "$attempts retry lines in ~130 s, agent never exited"
else
  record fail "gateway unreachable: agent keeps running and retries with backoff" "$attempts retry lines, $exits agent exits (log: results/runs/smoke-t1/agents/gateway-down.log)"
fi
"$docker" network connect "$net" "$cid"
phase wait-report -name "gateway reachable again: agent delivers without help" -hostname "$canary_host" -after "$t_down" -timeout 5m || true

# ---- canaries ---------------------------------------------------------------------------
phase canaries \
  -lab-dirs /scan/lab-a,/scan/lab-b,/scan/lab-c,/scan/lab-d \
  -gateway-dirs /scan/gateway-data,/scan/gateway-host-check || true

# ---- optional: "meldet sich nicht" after twice the interval (5 min) ------------------------
if [ "${SCHILD_AGENTS_SILENT:-0}" = 1 ]; then
  "${compose[@]}" stop app-vm >/dev/null
  sleep 660
  phase expect-host -name "silent agent shows as not reporting; baseline protection unchanged" -hostname "$canary_host" -silent || true
  "${compose[@]}" start app-vm >/dev/null
else
  printf '{"name":"silent agent shows as not reporting (opt-in: SCHILD_AGENTS_SILENT=1, ~11 min)","status":"skipped","seconds":0,"detail":"not run"}\n' >> "$steps"
fi

finish
