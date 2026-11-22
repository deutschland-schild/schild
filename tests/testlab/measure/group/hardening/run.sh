#!/bin/sh
# Reruns the MVP-27 hardening measurement (faults, crashes, load, 2 and 16 gateways, long absence, clocks, mixed
# versions): builds a development schild, the helper tool, the clock shim and schild of the commit before HEAD
# into a temporary directory, runs the scenarios (about 50 minutes, 127.0.0.1 only) and writes
# tests/results/MVP-27-hardening.json and MVP-27-hardening-checks.json.
#   run.sh                  every scenario
#   run.sh --only s1,s5     single scenarios (s1 faults, s2 crashes, s3 load, s4 sizes, s5 absence, s6 clocks,
#                           s7 versions); the results file is written again from every scenario file in $OUT
#   OUT=DIR                 where the per-scenario files lie (default /tmp/sg27h-out)
#   OLD_REV=COMMIT          the older commit of scenario 7 (default HEAD~1)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../../../../.." && pwd)
out=${OUT:-/tmp/sg27h-out}
old_rev=$(git -C "$repo" rev-parse --short=12 "${OLD_REV:-HEAD~1}")
bin=$(mktemp -d /tmp/sg27h-bin.XXXXXX)
trap 'rm -rf "$bin"' EXIT
(cd "$repo/gateway" && go build -o "$bin/schild" ./cmd/schild)
(cd "$here/tool" && go build -o "$bin/tool" .)
shim=""
if [ "$(uname)" = Darwin ] && command -v cc >/dev/null 2>&1; then
	cc -dynamiclib -O2 -o "$bin/clockshim.dylib" "$here/clockshim/shim.c" && shim="$bin/clockshim.dylib"
fi
# the older commit, from git archive (no worktree, nothing of the checkout changes)
mkdir "$bin/old-src"
git -C "$repo" archive "$old_rev" | tar -x -C "$bin/old-src"
(cd "$bin/old-src/gateway" && go build -o "$bin/schild-old" ./cmd/schild)
rm -rf "$bin/old-src"
python3 "$here/harden.py" --bin "$bin/schild" --tool "$bin/tool" --out "$out" --old-bin "$bin/schild-old" --old-rev "$old_rev" \
	--clock-shim "$shim" --results "$repo/tests/results/MVP-27-hardening.json" "$@"
