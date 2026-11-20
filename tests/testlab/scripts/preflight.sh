#!/usr/bin/env bash
# Preflight for the test lab: report which required images exist so the stack
# can degrade gracefully. The schild / schild-lab / schild-relay images are
# built by other agents; until they exist those services will not start, but
# the test-lab infrastructure (site-api, ground-truth, stripper) still runs.
set -u
DOCKER="${1:-docker}"
missing=0
for img in schild-testlab:dev schild:dev schild-lab:dev schild-relay:dev; do
  if "$DOCKER" image inspect "$img" >/dev/null 2>&1; then
    echo "preflight: OK   $img"
  else
    echo "preflight: MISSING $img"
    missing=1
  fi
done
if [ "$missing" -ne 0 ]; then
  echo "preflight: some images are missing."
  echo "  build the test-lab image:  make images   (or: make testlab-image traffic-image)"
  echo "  schild/schild-lab/schild-relay are built by the client/lab/relay agents."
  echo "  the stack will start the parts whose images exist."
fi
exit 0
