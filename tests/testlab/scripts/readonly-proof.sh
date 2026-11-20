#!/usr/bin/env bash
# MVP-11 read-only proof (kill criterion "the check changes system state"):
# runs `schild check` in a disposable app VM container (no network) as root
# and as an unprivileged user and shows that nothing changed except the
# report directories:
#
#   1. sha256 of every file in /etc, /var/lib/apt, /var/lib/dpkg, /var/cache/apt,
#      /var/cache/debconf, /var/www, /root and metadata (mode, owner, size,
#      mtime) of everything under /etc /usr /var /root /home /opt, before and after;
#   2. every path on the container's root filesystem newer than a marker set
#      right before the run (catches writes anywhere, also /tmp, /run, caches);
#   3. `docker diff` of the container before and after;
#   4. each report validated by cmd/hostreport-check (contract, no secret
#      canary, file name), file mode 0640.
#
# Allowed changes: the report directories only. The app VM is the realistic
# target (apt lists with pending updates, MariaDB, sshd, PHP 8.1; see
# testlab/dockerfiles/app-vm.Dockerfile). Nothing runs on this machine as a
# target, nothing with sudo; the container is removed at the end.
#
# Needs schild:dev and schild-testlab-app-vm:dev (built if missing).
# Result: results/runs/readonly-proof/readonly-proof.json (+ manifests, diffs).
# Exit 0 = proven or pending (schild has no `check` yet; REQUIRE=1 makes
# pending a failure), 1 = a change outside the report dirs or a bad report.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)  # repository root
docker=${DOCKER:-docker}
out="$root/tests/results/runs/readonly-proof"
rm -rf "$out"; mkdir -p "$out"
name="schild-readonly-proof-$$"
rdir_root=/var/lib/schild/host-check
rdir_user=/var/lib/schild/host-check-nobody

result() { # status detail
  printf '{"spec":"MVP-11","proof":"read-only","status":"%s","finished":"%s","detail":"%s"}\n' \
    "$1" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(printf '%s' "$2" | tr -d '\000-\037' | sed 's/\\/\\\\/g; s/"/\\"/g')" > "$out/readonly-proof.json"
  echo "readonly-proof: $1: $2"
}

"$docker" image inspect schild:dev >/dev/null 2>&1 || { result fail "image schild:dev missing (make images)"; exit 1; }
if ! "$docker" image inspect schild-testlab-app-vm:dev >/dev/null 2>&1; then
  "$docker" build -f "$root/tests/testlab/dockerfiles/app-vm.Dockerfile" -t schild-testlab-app-vm:dev "$root/tests/testlab/dockerfiles/app-vm"
fi

# PROOF_SCHILD_DIR=<dir with a `schild` executable> replaces the schild:dev
# binary: only for testing this proof itself with a fake check that writes
# where it must not (negative control).
if [ -n "${PROOF_SCHILD_DIR:-}" ]; then
  bin_mount=(--mount "type=bind,source=$PROOF_SCHILD_DIR,target=/opt/schild,readonly")
else
  bin_mount=(--mount "type=image,source=schild:dev,image-subpath=usr/local/bin,target=/opt/schild")
fi
cleanup() { "$docker" rm -f "$name" >/dev/null 2>&1 || true; }
trap cleanup EXIT
# sshd only: the other services write on their own (logs, InnoDB) and would
# blur the diff; the check still sees a realistic system.
"$docker" run -d --name "$name" --network none --label schild.testlab=readonly-proof \
  "${bin_mount[@]}" \
  -e APP_VM_MODE=idle -e APP_VM_SERVICES=sshd -e SCHILD_ALLOW_TEST_KEYS=1 \
  -e APP_SECRET_TOKEN=schild-secret-canary-env-t6w1y5 \
  schild-testlab-app-vm:dev > "$out/docker-run.log" 2>&1 || { result fail "docker run: $(tail -2 "$out/docker-run.log" | tr '\n' ' ')"; exit 1; }
x() { "$docker" exec -u 0 "$name" sh -c "$1"; }
sleep 2

if ! x 'schild-testlab-agent supported check' >/dev/null 2>&1; then
  result pending "schild:dev has no 'schild check' yet (MVP-11 backend not built); nothing to prove"
  [ "${REQUIRE:-0}" = 1 ] && exit 1
  exit 0
fi

# Report dirs as on a gateway host (root:65532, setgid) and one for nobody.
x "mkdir -p $rdir_root $rdir_user && chown root:65532 $rdir_root && chmod 2750 $rdir_root && chown nobody:nogroup $rdir_user && chmod 0750 $rdir_user"

manifest() {
  x 'find /etc /usr /var /root /home /opt -xdev \( -path '"$rdir_root"' -o -path '"$rdir_user"' \) -prune -o -printf "%p %y %m %U %G %s %T@\n" 2>/dev/null | sort
     find /etc /var/lib/apt /var/lib/dpkg /var/cache/apt /var/cache/debconf /var/www /root -xdev -type f -print0 2>/dev/null | sort -z | xargs -0 sha256sum'
}
manifest > "$out/manifest-before.txt"
"$docker" diff "$name" | sort > "$out/docker-diff-before.txt"
x 'touch /run/schild-proof-marker'
sleep 1   # mtime granularity: everything after this is newer than the marker

rc_root=0; "$docker" exec -u 0 "$name" schild-testlab-agent check "$rdir_root" > "$out/check-root.log" 2>&1 || rc_root=$?
rc_user=0; "$docker" exec -u nobody "$name" schild-testlab-agent check "$rdir_user" > "$out/check-nobody.log" 2>&1 || rc_user=$?

x 'find / -xdev -newer /run/schild-proof-marker ! -path /run/schild-proof-marker -printf "%p\n" 2>/dev/null | sort' > "$out/newer-than-marker.txt"
manifest > "$out/manifest-after.txt"
"$docker" diff "$name" | sort > "$out/docker-diff-after.txt"

allowed() { grep -vE "^(${rdir_root}|${rdir_user})(/|$)" || true; }
problems=()
# sha256sum lines are "<hash>  <path>", find lines "<path> <type> ...".
changed=$(diff "$out/manifest-before.txt" "$out/manifest-after.txt" | grep -E '^[<>] ' | sed 's/^[<>] //' |
  awk '{ if ($1 ~ /^[0-9a-f]{64}$/) print $2; else print $1 }' | sort -u | allowed || true)
[ -z "$changed" ] || problems+=("manifest: $(tr '\n' ' ' <<<"$changed")")
newer=$(allowed < "$out/newer-than-marker.txt" | grep -vE '^/var/lib/schild$' || true)
[ -z "$newer" ] || problems+=("written after the marker: $(tr '\n' ' ' <<<"$newer")")
ddiff=$(diff "$out/docker-diff-before.txt" "$out/docker-diff-after.txt" | grep -E '^> ' | sed 's/^> [ACD] //' | allowed | grep -vE '^/run/schild-proof-marker$|^/var/lib/schild$' || true)
[ -z "$ddiff" ] || problems+=("docker diff: $(tr '\n' ' ' <<<"$ddiff")")
[ $rc_root -eq 0 ] || problems+=("schild check as root exited $rc_root: $(tail -2 "$out/check-root.log" | tr '\n' ' ')")
[ $rc_user -eq 0 ] || problems+=("schild check as nobody exited $rc_user: $(tail -2 "$out/check-nobody.log" | tr '\n' ' ')")

# Reports: count, mode 0640, contract + secret canaries (independent checker).
modes=$(x "stat -c '%a %n' $rdir_root/*.json $rdir_user/*.json 2>/dev/null" || true)
printf '%s\n' "$modes" > "$out/report-modes.txt"
n_root=$(grep -c " $rdir_root/" <<<"$modes" || true)
n_user=$(grep -c " $rdir_user/" <<<"$modes" || true)
[ "$n_root" -eq 1 ] || problems+=("$n_root reports as root, want 1")
[ "$n_user" -eq 1 ] || problems+=("$n_user reports as nobody, want 1")
bad_mode=$(grep -v '^640 ' <<<"$modes" | grep . || true)
[ -z "$bad_mode" ] || problems+=("report mode not 0640: $(tr '\n' ' ' <<<"$bad_mode")")
mkdir -p "$out/reports/root" "$out/reports/nobody"
"$docker" cp "$name:$rdir_root/." "$out/reports/root/" >/dev/null 2>&1 || true
"$docker" cp "$name:$rdir_user/." "$out/reports/nobody/" >/dev/null 2>&1 || true
if ! (cd "$root/tests/testlab" && go run ./cmd/hostreport-check -json "$out/reports/root" "$out/reports/nobody") > "$out/hostreport-check.json" 2>&1; then
  problems+=("hostreport-check: $(tr '\n' ' ' < "$out/hostreport-check.json" | cut -c1-400)")
fi

if [ ${#problems[@]} -gt 0 ]; then
  result fail "$(printf '%s; ' "${problems[@]}")"
  exit 1
fi
result pass "schild check as root and as nobody: no change outside the report dirs (manifest $(wc -l < "$out/manifest-after.txt" | tr -d ' ') entries, docker diff, newer-than-marker); reports valid, 0640, no secret canary"
