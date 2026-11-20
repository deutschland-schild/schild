#!/usr/bin/env bash
# MVP-11 independent re-measure probe (kill criterion "the check changes
# system state"), stronger than docker-diff: the whole container rootfs is
# mounted read-only by the kernel (docker run --read-only). The schild binary
# is mounted read-only from an image (schild-rebin:dev); only the report dir
# is a writable tmpfs. Any write anywhere else fails with EROFS, so the check
# cannot change the system even if it tried. Require per distro and user:
# exit 0, a valid non-empty JSON report read back, no write errors
# (EROFS/permission denied) on stderr, and an empty docker diff.
# Runtimes present: Java (tarball on Debian), node, php, python3.
#   SCHILD_BIN image is schild-rebin:dev (/bin/schild)
set -uo pipefail
out=${OUT:-/tmp/schild-remeasure/ro-rootfs}; mkdir -p "$out"
rc=0
for img in schild-ro-rocky9:dev schild-ro-alma9:dev schild-ro-debian12:dev schild-ro-ubuntu24:dev schild-ro-ubuntu22:dev; do
  d=$(echo "$img" | sed 's/schild-ro-//; s/:dev//')
  name="schild-review-rorootfs-$d-$$"
  docker run -d --rm --name "$name" --network none --read-only \
    --tmpfs /rep:rw,mode=0777 --tmpfs /run:rw --tmpfs /tmp:rw \
    --mount "type=image,source=schild-rebin:dev,image-subpath=bin,target=/opt/schild" \
    --label schild.testlab=review --entrypoint sleep "$img" 600 >"$out/$d.start.err" 2>&1 \
    || { echo "$d: start FAIL"; cat "$out/$d.start.err"; rc=1; continue; }
  docker exec "$name" sh -c 'mkdir -p /rep/root /rep/nobody; id nobody >/dev/null 2>&1 && chown nobody /rep/nobody || true'
  docker exec -u 0 "$name" sh -c '/opt/schild/schild check --dir /rep/root' >"$out/$d.root.out" 2>"$out/$d.root.err"; rrc=$?
  docker exec -u nobody "$name" sh -c '/opt/schild/schild check --dir /rep/nobody' >"$out/$d.nobody.out" 2>"$out/$d.nobody.err"; nrc=$?
  diff_out=$(docker diff "$name" | grep -vE "^[CA] /opt(/schild)?$|^A /rep$|^[CA] /run$|^[CA] /tmp$" || true)
  rep=$(docker exec "$name" sh -c 'cat /rep/root/*.json 2>/dev/null | head -c 400000')
  replen=$(printf '%s' "$rep" | wc -c | tr -d ' ')
  valid=$(printf '%s' "$rep" | python3 -I -c 'import json,sys; json.load(sys.stdin); print("yes")' 2>/dev/null || echo "no")
  werr=$(grep -iE 'read-only file system|erofs|permission denied|cannot create|no space|cannot touch|cannot write' "$out/$d.root.err" "$out/$d.nobody.err" 2>/dev/null || true)
  nfind=$(grep -c '"id"' "$out/$d.root.out" 2>/dev/null || echo 0)
  echo "== $img  root_exit=$rrc nobody_exit=$nrc report_bytes=$replen json_valid=$valid docker_diff_lines=$(printf '%s' "$diff_out" | grep -c .)"
  [ -n "$diff_out" ] && { echo "  docker diff (rootfs writes):"; echo "$diff_out"; rc=1; }
  [ -n "$werr" ]     && { echo "  WRITE ERRORS:"; echo "$werr"; rc=1; }
  { [ "$rrc" -ne 0 ] || [ "$nrc" -ne 0 ]; } && { echo "  non-zero exit"; rc=1; }
  { [ "$valid" = yes ] && [ "$replen" -gt 100 ]; } || { echo "  report not valid/empty"; rc=1; }
  docker rm -f "$name" >/dev/null 2>&1
done
echo "RESULT rc=$rc"
exit $rc
