#!/usr/bin/env bash
# Brings up the test lab for one profile: TEST ONLY secrets, dashboard users
# of every lab (alice, bob, carol; created while the labs are stopped), then
# the stack, waiting until every service with a health check is healthy.
#
#   testlab/scripts/up.sh t0|t1
#
# Env: DOCKER (docker), SMOKE_PASSWORD (TEST ONLY password of the lab users and
# the client dashboards; default below), SCHILD_LABEL_SECRET (required).
set -euo pipefail
profile=${1:?profile t0|t1}
root=$(cd "$(dirname "$0")/../../.." && pwd)  # repository root
docker=${DOCKER:-docker}
: "${SCHILD_LABEL_SECRET:?set SCHILD_LABEL_SECRET}"
export SMOKE_PASSWORD=${SMOKE_PASSWORD:-schild-testlab-passwort}
compose=("$docker" compose -p "schild-testlab-$profile" -f "$root/tests/testlab/compose/docker-compose.$profile.yaml")
# MVP-11 agent lab overlay (t1, on by default; SCHILD_AGENTS=0 leaves it out):
# gateway with host_check, app VMs.
if [ "$profile" = t1 ] && [ "${SCHILD_AGENTS:-1}" = 1 ]; then
  compose+=(-f "$root/tests/testlab/compose/docker-compose.t1.agents.yaml" --profile agents)
fi
case $profile in t0) labs="lab-a lab-b lab-c";; t1) labs="lab-a lab-b lab-c lab-d";; *) echo "unknown profile $profile"; exit 2;; esac

bash "$root/tests/testlab/scripts/preflight.sh" "$docker"
for img in schild-testlab:dev schild:dev schild-lab:dev schild-relay:dev; do
  "$docker" image inspect "$img" >/dev/null 2>&1 || { echo "testlab-up: image $img missing (make images)"; exit 1; }
done
"$root/tests/testlab/scripts/gen-secrets.sh"
if [ "$profile" = t1 ] && [ "${SCHILD_AGENTS:-1}" = 1 ] && ! "$docker" image inspect schild-testlab-app-vm:dev >/dev/null 2>&1; then
  "$docker" build -f "$root/tests/testlab/dockerfiles/app-vm.Dockerfile" -t schild-testlab-app-vm:dev "$root/tests/testlab/dockerfiles/app-vm"
fi

# Lab users: only while the labs are stopped (the store is single-writer).
running=$("${compose[@]}" ps --status running --services 2>/dev/null || true)
for lab in $labs; do
  if grep -qx "$lab" <<<"$running"; then continue; fi
  for user in carol alice bob; do
    printf '%s\n' "$SMOKE_PASSWORD" | "${compose[@]}" run --rm --no-deps -T "$lab" user add -name "$user" >/dev/null
  done
  echo "testlab-up: $lab users carol, alice, bob (TEST ONLY password)"
done

"${compose[@]}" up -d --remove-orphans --wait --wait-timeout 240
"${compose[@]}" ps --format 'table {{.Service}}\t{{.Status}}'
echo "testlab-up: $profile is up. Dashboards via the gateway container (TEST ONLY password \$SMOKE_PASSWORD):"
if [ "$profile" = t0 ]; then
  echo "  Schild Gateway (site api)  http://127.0.0.1:18788  (admin; first run: setup code from the schild-api log)"
  echo "  lab-a / b / c      http://127.0.0.1:18789 / 18790 / 18791  (users carol, alice, bob)"
else
  echo "  Schild Gateway api / shop  http://127.0.0.1:28788 / 28798"
  echo "  lab-a / b / c / d  http://127.0.0.1:28789 / 28790 / 28791 / 28792"
fi
