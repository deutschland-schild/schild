#!/usr/bin/env bash
# Writes the TEST ONLY secrets of the test lab into testlab/compose/secrets/
# (gitignored), shared by profiles t0 and t1:
#
#   ca.pem                         test CA (labs serve TLS with it; relays trust it)
#   labs/<lab>/keys/lab.key        lab keys from contracts/testkeys (public seeds)
#   labs/lab-d/keys/online.key     deterministic test-lab key of lab-d (ack, checkpoint):
#                                  seed = sha256("schild/testlab/v0/lab-d-online")
#   labs/<lab>/tls/{cert,key}.pem  server certificate for host <lab>
#   geo/geo.mmdb                   `schild geo-fixture` (documentation ranges + 10.66.0.0/16)
#   sites/api/agent-tls/, agents/  MVP-11 agent lab: scripts/gen-agent-secrets.sh
#
# Keys are world-readable on purpose: they are public test keys, and the
# containers read them as uid 65532 through a bind mount. Idempotent: existing
# files are kept unless FORCE=1.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)  # repository root
out="$root/tests/testlab/compose/secrets"
if [ -f "$out/ca.pem" ] && [ "${FORCE:-0}" != 1 ]; then
  echo "testlab secrets: present in $out (FORCE=1 regenerates)"
  "$root/tests/testlab/scripts/gen-agent-secrets.sh"   # MVP-11 agent lab (added later: fills in existing setups)
  exit 0
fi
rm -rf "$out"
mkdir -p "$out"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
(cd "$root/lab" && go build -o "$tmp/schild-lab" ./cmd/schild-lab)
"$tmp/schild-lab" dev-certs -out "$tmp/certs" -hosts lab-a,lab-b,lab-c,lab-d >/dev/null
cp "$tmp/certs/ca.pem" "$out/ca.pem"
keyfile() { (cd "$root/contract" && go run ./cmd/testkeyfile -name "$1"); }
for lab in lab-a lab-b lab-c lab-d; do
  mkdir -p "$out/labs/$lab/keys" "$out/labs/$lab/tls"
  keyfile "$lab" > "$out/labs/$lab/keys/lab.key"
  cp "$tmp/certs/$lab/cert.pem" "$tmp/certs/$lab/key.pem" "$out/labs/$lab/tls/"
done
seed=$(printf '%s' 'schild/testlab/v0/lab-d-online' | shasum -a 256 | cut -d' ' -f1)
printf 'ed25519-seed:%s\n' "$seed" > "$out/labs/lab-d/keys/online.key"
# D72: the gateway holds no site key (it sends no signals), so none is written.
mkdir -p "$out/geo"
(cd "$root/gateway" && go run ./cmd/schild geo-fixture -out "$out/geo/geo.mmdb")
chmod -R a+rX "$out"
find "$out" -type f -name '*.key' -exec chmod 0644 {} +
find "$out" -type f -name 'key.pem' -exec chmod 0644 {} +
echo "testlab secrets: written to $out (TEST ONLY)"
"$root/tests/testlab/scripts/gen-agent-secrets.sh"
