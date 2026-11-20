#!/usr/bin/env bash
# Smoke test of a schild image with the shipped quickstart (deploy/quickstart):
# starts it locked down as the compose file says, waits for the health check
# and asks the dashboard on the host's loopback. Used by CI and by the release
# workflow before anything is pushed; run it locally the same way:
#
#   gateway/deploy/release/smoke.sh schild:local
#   EXPECT_VERSION=0.1.0-alpha.1 gateway/deploy/release/smoke.sh schild:local
#
# EXPECT_VERSION: the first line of `schild version` must be exactly "schild <version> (release)"
# and the image must carry real geo data (label de.deutschland-schild.geo=dbip).
# Ports 8080 and 8788 on the host must be free. Everything it starts is removed.
# SMOKE_NETWORK_MODE=bridge runs it on Docker's default bridge.
set -euo pipefail

image=${1:?usage: smoke.sh IMAGE}
here=$(cd "$(dirname "$0")" && pwd)
quickstart=$here/../quickstart
project=schild-smoke-$$
# The work directory is bind-mounted, so Docker must be able to see it
# (Docker Desktop: a path below your home, e.g. SMOKE_TMPDIR=$PWD/bin).
base=${SMOKE_TMPDIR:-${TMPDIR:-/tmp}}
mkdir -p "$base"
work=$(mktemp -d "${base%/}/schild-smoke.XXXXXX")
compose=(docker compose -p "$project" --project-directory "$work" -f "$work/compose.yaml")

cleanup() {
  "${compose[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

cp "$quickstart/compose.yaml" "$quickstart/schild.yaml" "$work/"
chmod 0644 "$work/schild.yaml"

# The first line names version and build kind, the others list linked modules.
# Read all of it: cutting the pipe early makes schild fail on a closed stdout.
version=$(docker run --rm "$image" version)
version=${version%%$'\n'*}
echo "smoke: $version"
if [ -n "${EXPECT_VERSION:-}" ]; then
  if [ "$version" != "schild $EXPECT_VERSION (release)" ]; then
    echo "smoke: expected \"schild $EXPECT_VERSION (release)\"" >&2
    exit 1
  fi
  geo=$(docker image inspect -f '{{index .Config.Labels "de.deutschland-schild.geo"}}' "$image")
  if [ "$geo" != dbip ]; then
    echo "smoke: a release image needs real geo data, label de.deutschland-schild.geo is \"$geo\"" >&2
    exit 1
  fi
fi

# SMOKE_NETWORK_MODE=bridge: use Docker's default bridge instead of a project
# network (for a machine whose address pools are used up).
if [ -n "${SMOKE_NETWORK_MODE:-}" ]; then
  printf 'services:\n  schild:\n    network_mode: %s\n' "$SMOKE_NETWORK_MODE" > "$work/override.yaml"
  compose+=(-f "$work/override.yaml")
fi

SCHILD_IMAGE=$image "${compose[@]}" up -d
id=$("${compose[@]}" ps -q schild)
status=starting
for _ in $(seq 1 60); do
  status=$(docker inspect -f '{{.State.Health.Status}}' "$id")
  if [ "$status" = healthy ]; then break; fi
  sleep 2
done
if [ "$status" != healthy ]; then
  echo "smoke: container is $status" >&2
  "${compose[@]}" logs >&2
  exit 1
fi

# The dashboard answers on the host's loopback and is the built application,
# not the placeholder page of a binary without a dashboard build.
page=$(curl -fsS --max-time 10 http://127.0.0.1:8788/)
if ! grep -q '<div id="app"' <<<"$page" || ! grep -q '/assets/' <<<"$page"; then
  echo "smoke: http://127.0.0.1:8788/ is not the built dashboard" >&2
  head -c 600 <<<"$page" >&2
  exit 1
fi

# The dashboard port is published on loopback only.
bind=$(docker port "$id" 8788/tcp)
if [ "$bind" != "127.0.0.1:8788" ]; then
  echo "smoke: dashboard published on \"$bind\", expected 127.0.0.1:8788 only" >&2
  exit 1
fi

# Locked down as documented.
hardening=$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}} {{.HostConfig.CapDrop}} {{.HostConfig.SecurityOpt}} {{.Config.User}}' "$id")
if [ "$hardening" != "true [ALL] [no-new-privileges:true] 65532:65532" ]; then
  echo "smoke: unexpected hardening: $hardening" >&2
  exit 1
fi

# The proxy port answers (the quickstart upstream does not exist here, so any
# HTTP status is fine; no answer at all is not).
code=$(curl -s -o /dev/null --max-time 15 -w '%{http_code}' http://127.0.0.1:8080/ || true)
if [ "$code" = 000 ] || [ -z "$code" ]; then
  echo "smoke: the proxy port 8080 does not answer" >&2
  "${compose[@]}" logs >&2
  exit 1
fi
echo "smoke: OK (healthy, dashboard on 127.0.0.1:8788, proxy answered $code)"
