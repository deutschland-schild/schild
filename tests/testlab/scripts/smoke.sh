#!/usr/bin/env bash
# End-to-end smoke test of a running test lab (make smoke PROFILE=t0|t1).
# Reads the one-time setup codes of the gateway dashboards from the schild logs
# (first run only), runs the smoke driver inside the stack (inet + federation),
# the evaluator on the gateways' NDJSON event exports and the browser check of every
# dashboard through the gateway (SKIP_BROWSER=1 skips it). Reports:
#   tests/results/runs/smoke-<profile>/smoke.json   (steps, evidence, timings)
#   tests/results/runs/smoke-<profile>/eval/        (evaluator output)
#   tests/results/runs/smoke-<profile>/browser/     (screenshots, browser-check.json)
set -euo pipefail
profile=${1:?profile t0|t1}
root=$(cd "$(dirname "$0")/../../.." && pwd)  # repository root
docker=${DOCKER:-docker}
: "${SCHILD_LABEL_SECRET:?set SCHILD_LABEL_SECRET}"
export SMOKE_PASSWORD=${SMOKE_PASSWORD:-schild-testlab-passwort}
compose=("$docker" compose -p "schild-testlab-$profile" -f "$root/tests/testlab/compose/docker-compose.$profile.yaml")
case $profile in t0) sites="api";; t1) sites="api shop";; *) echo "unknown profile $profile"; exit 2;; esac
mkdir -p "$root/tests/results/runs/smoke-$profile"
for site in $sites; do
  code=$("${compose[@]}" logs --no-color "schild-$site" 2>/dev/null | grep -o '"setup_code":"[^"]*"' | tail -1 | cut -d'"' -f4 || true)
  var="SMOKE_SETUP_CODE_$(tr '[:lower:]-' '[:upper:]_' <<<"$site")"
  export "$var=$code"
done
status=0
"${compose[@]}" run --rm smoke || status=$?
echo "== evaluator (ground truth x gateway NDJSON events)"
"${compose[@]}" run --rm evaluator && echo "evaluator: OK" || { echo "evaluator: FAILED"; status=1; }
if [ "${SKIP_BROWSER:-0}" != 1 ]; then
  echo "== browser check (real binaries via the gateway, Playwright/Chromium)"
  if command -v node >/dev/null 2>&1; then
    node "$root/tests/testlab/scripts/browser-check.mjs" "$profile" || status=1
  else
    echo "browser check: node not found (SKIP_BROWSER=1 to skip explicitly)"; status=1
  fi
fi
# MVP-11 agent steps (t1 only, on by default; SCHILD_AGENTS=0 skips them).
# Pending steps fail the run (SCHILD_AGENTS_REQUIRE=0 tolerates them).
if [ "$profile" = t1 ] && [ "${SCHILD_AGENTS:-1}" = 1 ]; then
  export SCHILD_AGENTS_REQUIRE=${SCHILD_AGENTS_REQUIRE:-1}
  echo "== agent smoke (MVP-11: enrolment, delivery, replay, unknown and revoked keys, gateway unreachable, canaries)"
  bash "$root/tests/testlab/scripts/agent-smoke.sh" || status=1
  echo "report: results/runs/smoke-$profile/agents.json"
elif [ "$profile" = t1 ]; then
  echo "agent smoke: skipped (SCHILD_AGENTS=0)"
fi
echo "report: results/runs/smoke-$profile/smoke.json"
exit $status
