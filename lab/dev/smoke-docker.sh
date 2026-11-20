#!/usr/bin/env bash
# Docker smoke test of the images schild-lab:dev and schild-relay:dev on an
# internal network: TEST ONLY client -> lab-a ingest (TLS), relay -> watcher
# verifying every event like a client. Removes its containers and network.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)  # repository root
# Inside the repo (git-ignored): Docker Desktop shares the project path,
# not necessarily /tmp or other folders.
mkdir -p "$root/lab/dev/.run"
work=$(mktemp -d "$root/lab/dev/.run/smoke.XXXXXX")
compose=(docker compose -p schild-dev-lab -f "$root/lab/dev/compose.yaml")
export SCHILD_DEV_CFG="$work/cfg"
cleanup() { "${compose[@]}" --profile smoke down --remove-orphans >/dev/null 2>&1 || true; rm -rf "$work"; rmdir "$root/lab/dev/.run" 2>/dev/null || true; }
trap cleanup EXIT
for img in schild-lab:dev schild-relay:dev; do
  docker image inspect "$img" >/dev/null 2>&1 || { echo "image $img missing: run make images (or docker build -f lab/Dockerfile ...)"; exit 1; }
done
(cd "$root/lab" && go build -o "$work/schild-lab" ./cmd/schild-lab)
SCHILD_LAB_BIN="$work/schild-lab" "$root/lab/dev/gen-config.sh" "$work/cfg" docker
"${compose[@]}" up -d lab-a lab-b lab-c relay-1
sleep 8
"${compose[@]}" run --rm send
"${compose[@]}" run --rm watch > "$work/watch.jsonl" || true
labs=$(grep '"verified":true' "$work/watch.jsonl" | grep -o '"lab":"lab-[abc]"' | sort -u | wc -l | tr -d ' ')
bad=$(grep -c '"verified":false' "$work/watch.jsonl" || true)
echo "relay forwarded verified checkpoints of $labs labs, $bad events failed verification"
"${compose[@]}" ps --format '{{.Name}} {{.Status}}'
[ "$labs" = 3 ] && [ "$bad" = 0 ] || { "${compose[@]}" logs --tail 30; exit 1; }
echo "smoke-docker: OK"
