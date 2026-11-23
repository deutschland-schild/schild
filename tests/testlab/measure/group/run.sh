#!/bin/sh
# Reruns the MVP-27 group measurement: builds a development schild and the adversary tool into a temporary
# directory, runs the harness (about 15 minutes, 127.0.0.1 only) and writes tests/results/MVP-27.json.
# Raw numbers: $OUT/raw.json (default /tmp/sg27-out).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../../.." && pwd)
out=${OUT:-/tmp/sg27-out}
bin=$(mktemp -d /tmp/sg27-bin.XXXXXX)
trap 'rm -rf "$bin"' EXIT
(cd "$repo/gateway" && go build -o "$bin/schild" ./cmd/schild)
(cd "$here/hostile" && go build -o "$bin/hostile" .)
python3 "$here/run.py" --bin "$bin/schild" --hostile "$bin/hostile" --out "$out" --results "$repo/tests/results/MVP-27.json" "$@"
