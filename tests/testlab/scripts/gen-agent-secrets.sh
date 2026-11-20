#!/usr/bin/env bash
# TEST ONLY secrets of the MVP-11 agent lab (profile t1), written next to the
# other test-lab secrets into testlab/compose/secrets/ (gitignored):
#
#   sites/api/agent-tls/{cert,key}.pem   TLS certificate of the gateway's agent
#                                        listener (host schild-api, own dev CA:
#                                        agents pin the certificate, not a CA)
#   sites/api/agent-tls/pin              sha256:<hex of the DER certificate>
#   agents/app-unenrolled/agent.key      TEST ONLY key agent-b (never enrolled)
#
# The keys of the code-enrolled agents (app-vm, app-revoked) are created by
# `schild-agent enrol` inside their containers and never leave them. The
# config-enrolled test keys agent-a (enrolled) and agent-c (revoked) are only
# used by the smoke driver (contract/testkeys) and named in
# compose/config/t1/api/schild.yaml.
#
# Idempotent: existing files are kept unless FORCE=1.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)  # repository root
out="$root/tests/testlab/compose/secrets"
tlsdir="$out/sites/api/agent-tls"
if [ -f "$tlsdir/pin" ] && [ -f "$out/agents/app-unenrolled/agent.key" ] && [ "${FORCE:-0}" != 1 ]; then
  echo "testlab agent secrets: present (FORCE=1 regenerates)"
  exit 0
fi
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
(cd "$root/lab" && go build -o "$tmp/schild-lab" ./cmd/schild-lab)
"$tmp/schild-lab" dev-certs -out "$tmp/certs" -hosts schild-api >/dev/null
mkdir -p "$tlsdir" "$out/agents/app-unenrolled"
cp "$tmp/certs/schild-api/cert.pem" "$tmp/certs/schild-api/key.pem" "$tlsdir/"
# The pin is the sha256 of the DER certificate (host-check.md section 3).
pin=$(openssl x509 -in "$tlsdir/cert.pem" -outform DER | shasum -a 256 | cut -d' ' -f1)
printf 'sha256:%s\n' "$pin" > "$tlsdir/pin"
(cd "$root/contract" && go run ./cmd/testkeyfile -name agent-b) > "$out/agents/app-unenrolled/agent.key"
printf 'test-agent-b\n' > "$out/agents/app-unenrolled/keyid"
chmod -R a+rX "$out/sites/api/agent-tls" "$out/agents"
chmod 0644 "$tlsdir/key.pem" "$out/agents/app-unenrolled/agent.key"
echo "testlab agent secrets: written (TEST ONLY), gateway pin sha256:$pin"
