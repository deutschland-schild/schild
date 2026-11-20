#!/usr/bin/env bash
# MVP-11 review probe (kill criterion "the check changes system state") on
# distributions the testlab read-only proof does not cover: Rocky 9 (dnf,
# needs-restarting, rpm) and Debian 12 with Java/Node/PHP in PATH.
#
#   BUILDX_BUILDER=desktop-linux docker build -f rocky9.Dockerfile -t schild-review-rocky9:dev .
#   BUILDX_BUILDER=desktop-linux docker build -f debian-java.Dockerfile -t schild-review-debian-java:dev .
#   SCHILD_BIN=/path/to/linux/schild ./readonly-distros.sh
#
# Each image runs as a disposable container with --network none; `schild check`
# runs once as root and once as nobody into its own report dir; everything
# newer than a marker outside the report dirs and the docker diff are printed.
# Exit 1 when anything outside the report dirs changed. Containers are removed.
set -uo pipefail
bin=${SCHILD_BIN:?SCHILD_BIN=<linux schild binary>}
out=${OUT:-/tmp/schild-review/readonly}
mkdir -p "$out"
rc=0
for img in schild-review-rocky9:dev schild-review-debian-java:dev; do
  name="schild-review-ro-$(echo "$img" | cut -d: -f1 | sed 's/schild-review-//')-$$"
  docker run -d --rm --name "$name" --network none --label schild.testlab=review \
    "$img" sleep 600 >/dev/null || { echo "run $img failed"; rc=1; continue; }
  docker exec -u 0 "$name" mkdir -p /opt/schild && docker cp "$bin" "$name:/opt/schild/schild" >/dev/null
  x() { docker exec -u "$1" "$name" sh -c "$2"; }
  x 0 'mkdir -p /var/lib/schild/hc-root /var/lib/schild/hc-nobody && chown nobody /var/lib/schild/hc-nobody'
  # The marker goes in before the first diff, so its own entry (and the
  # parent /run) are part of the baseline.
  x 0 'touch /run/marker'; sleep 1
  docker diff "$name" | sort > "$out/$name.diff-before"
  x 0 '/opt/schild/schild check --dir /var/lib/schild/hc-root' > "$out/$name.root.log" 2>&1
  x nobody '/opt/schild/schild check --dir /var/lib/schild/hc-nobody' > "$out/$name.nobody.log" 2>&1
  x 0 'find / -xdev -newer /run/marker ! -path /run/marker ! -path "/var/lib/schild/hc-*" ! -path /proc 2>/dev/null | sort' > "$out/$name.newer"
  docker diff "$name" | sort > "$out/$name.diff-after"
  changed=$(diff "$out/$name.diff-before" "$out/$name.diff-after" | grep '^> ' | grep -vE ' /var/lib/schild/hc-|/run/marker' || true)
  newer=$(grep -vE '^/var/lib/schild/hc-|^/var/lib/schild$' "$out/$name.newer" || true)
  echo "== $img"
  echo "-- docker diff (new entries):"; echo "${changed:-<none>}"
  echo "-- newer than marker:"; echo "${newer:-<none>}"
  docker cp "$name:/var/lib/schild/hc-root" "$out/$name-reports-root" >/dev/null 2>&1
  docker cp "$name:/var/lib/schild/hc-nobody" "$out/$name-reports-nobody" >/dev/null 2>&1
  [ -z "$changed$newer" ] || rc=1
  docker rm -f "$name" >/dev/null 2>&1
done
exit $rc
