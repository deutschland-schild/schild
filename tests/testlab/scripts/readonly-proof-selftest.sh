#!/usr/bin/env bash
# Self-test of the read-only proof (runs without the MVP-11 backend): a fake
# `schild check` that only writes its report must pass, one that also runs
# `apt list --upgradable` as root (rewrites /var/cache/apt/*.bin on a VM) and
# touches /etc must fail. Fakes live in results/runs/readonly-proof-fakes
# (gitignored; Docker Desktop shares the repo, not /tmp).
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)  # repository root
fakes="$root/tests/results/runs/readonly-proof-fakes"
rm -rf "$fakes"; mkdir -p "$fakes/good" "$fakes/bad"
# A valid gateway host report from the golden vectors.
vec=$(grep -l '"role\\":\\"gateway\\"' "$root"/contracts/vectors/host-report/valid/*.json | head -1)
python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["input_raw"], end="")' "$vec" > "$fakes/good/report.json"
cp "$fakes/good/report.json" "$fakes/bad/report.json"; touch "$fakes/bad/BAD"
for v in good bad; do cat > "$fakes/$v/schild" <<'FAKE'
#!/bin/sh
# TEST ONLY fake `schild` for the read-only proof self-test.
case "$1" in
  help) echo "schild check ..." ;;
  check)
    dir=$3; id=$(sed 's/.*"report_id":"\([^"]*\)".*/\1/' /opt/schild/report.json)
    umask 027; cp /opt/schild/report.json "$dir/20261027T000000Z-$id.json"
    if [ -f /opt/schild/BAD ]; then apt list --upgradable >/dev/null 2>&1; touch /etc/schild-bad 2>/dev/null; fi; true ;;
esac
FAKE
chmod 755 "$fakes/$v/schild"; done
ok=1
PROOF_SCHILD_DIR="$fakes/good" "$root/tests/testlab/scripts/readonly-proof.sh" || { echo "selftest: the clean fake did not pass"; ok=0; }
if PROOF_SCHILD_DIR="$fakes/bad" "$root/tests/testlab/scripts/readonly-proof.sh"; then
  echo "selftest: the writing fake was not caught"; ok=0
elif ! grep -q 'pkgcache.bin' "$root/tests/results/runs/readonly-proof/readonly-proof.json" || ! grep -q '/etc/schild-bad' "$root/tests/results/runs/readonly-proof/readonly-proof.json"; then
  echo "selftest: the writing fake failed, but not for the planted writes"; ok=0
fi
rm -rf "$fakes" "$root/tests/results/runs/readonly-proof"
[ $ok = 1 ] && echo "readonly-proof selftest: OK (clean fake passes; apt cache rewrite and /etc write caught)"
[ $ok = 1 ]
