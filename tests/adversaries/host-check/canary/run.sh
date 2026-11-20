#!/usr/bin/env bash
# MVP-11 review probe (kill criterion "a report leaks a secret"): runs
# `schild check` (root and nobody, --json and into a dir, with --app and
# --cert pointing at planted secrets) in a disposable app VM container with
# --network none and searches the reports AND the command output for every
# canary (the image's own: testlab/internal/hostcanary, and plant.sh's
# "rvwcanary-*"). Exit 1 on any hit. The container is removed.
#   SCHILD_BIN=<linux schild> ./run.sh
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
bin=${SCHILD_BIN:?}
out=${OUT:-/tmp/schild-review/canary}; rm -rf "$out"; mkdir -p "$out"
name=schild-review-canary-$$
docker run -d --rm --name "$name" --network none --label schild.testlab=review \
  -e APP_VM_MODE=idle -e APP_VM_SERVICES="sshd mariadb nginx php-fpm" -e APP_SECRET_TOKEN=schild-secret-canary-env-t6w1y5 \
  -e RVW_SECRET=rvwcanary-container-env-h1 schild-testlab-app-vm:dev >/dev/null || exit 1
trap 'docker rm -f "$name" >/dev/null 2>&1' EXIT
docker exec "$name" mkdir -p /opt/review && docker cp "$bin" "$name:/opt/review/schild" >/dev/null
tmp=$(mktemp -d)
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 20 -subj /CN=review-canary-site.test \
  -keyout "$tmp/key.pem" -out "$tmp/cert.pem" >/dev/null 2>&1
{ cat "$tmp/cert.pem"; echo "# rvwcanary-tls-comment-c2"; cat "$tmp/key.pem"; } > "$tmp/site.pem"
docker exec "$name" mkdir -p /etc/ssl/review && docker cp "$tmp/site.pem" "$name:/etc/ssl/review/site.pem" >/dev/null
docker exec "$name" chmod 600 /etc/ssl/review/site.pem; rm -rf "$tmp"
docker cp "$here/plant.sh" "$name:/opt/review/plant.sh" >/dev/null
docker exec -u 0 "$name" sh /opt/review/plant.sh
sleep 3
args='--app /var/www/html --app /var/www/laravel --cert /etc/ssl/review/*.pem --cert /etc/letsencrypt/live/*/cert.pem'
docker exec -u 0 -e DB_PASSWORD=rvwcanary-exec-env-h2 "$name" sh -c "/opt/review/schild check --json $args" > "$out/root.json" 2> "$out/root.stderr"
docker exec -u nobody "$name" sh -c "/opt/review/schild check --json $args" > "$out/nobody.json" 2> "$out/nobody.stderr"
docker exec -u 0 "$name" sh -c "mkdir -p /tmp/rd && /opt/review/schild check --dir /tmp/rd $args && cat /tmp/rd/*.json" > "$out/dir.json" 2> "$out/dir.stderr"
pat='rvwcanary|schild-secret-canary|PRIVATE KEY|BEGIN CERT|MII'
echo "report sizes: $(wc -c < "$out/root.json") $(wc -c < "$out/nobody.json") $(wc -c < "$out/dir.json")"
python3 -I -c 'import json,sys; [json.load(open(f)) for f in sys.argv[1:]]' "$out/root.json" "$out/nobody.json" "$out/dir.json" || { echo "report not JSON"; exit 1; }
# Positive controls: the planted things were seen (else absence proves nothing).
for want in '"tcp/8099"' '"tcp/3306"' '"review-canary-site.test"' '"laravel"' '"rvw-plugin"' '"/var/www/laravel"'; do
  grep -q "$want" "$out/root.json" && echo "control ok: $want" || echo "control MISSING: $want"
done
if grep -EHno "$pat" "$out"/*; then echo "LEAK"; exit 1; fi
echo "no canary in reports or output"
