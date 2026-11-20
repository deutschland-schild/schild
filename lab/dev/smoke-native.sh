#!/usr/bin/env bash
# Native smoke test of the real binaries (no Docker): three labs with TLS and
# peers, one relay; a TEST ONLY client submits signals; a watcher verifies
# what the relay forwards like a client would. Leaves nothing behind.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)  # repository root
work=$(mktemp -d)
pids=()
cleanup() { for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; rm -rf "$work"; }
trap cleanup EXIT
(cd "$root/lab" && go build -o "$work/schild-lab" ./cmd/schild-lab)
(cd "$root/relay" && go build -o "$work/schild-relay" ./cmd/schild-relay)
SCHILD_LAB_BIN="$work/schild-lab" "$root/lab/dev/gen-config.sh" "$work/cfg" native
export SCHILD_ALLOW_TEST_KEYS=1   # TEST ONLY keys and CA (D24 preflight override)
export SCHILD_TEST_CA="$work/cfg/ca.pem" SCHILD_LOG_FORMAT=text SCHILD_LOG_LEVEL=warn
for lab in lab-a lab-b lab-c; do
  SCHILD_LAB_CONFIG="$work/cfg/$lab/lab.yaml" "$work/schild-lab" run >"$work/$lab.log" 2>&1 &
  pids+=($!)
done
SCHILD_RELAY_ID=relay-1 SCHILD_RELAY_LISTEN=127.0.0.1:17480 SCHILD_RELAY_METRICS=127.0.0.1:19103 \
SCHILD_RELAY_UPSTREAMS=https://localhost:17444,https://localhost:27444,https://localhost:37444 \
  "$work/schild-relay" >"$work/relay.log" 2>&1 &
pids+=($!)
for i in $(seq 1 50); do curl -sf http://127.0.0.1:17480/readyz >/dev/null && break; sleep 0.2; done
"$work/schild-lab" dev-send -url https://localhost:17443 -lab lab-a -site site-a -n 8
"$work/schild-lab" dev-send -url https://localhost:17443 -lab lab-a -site site-c -n 8
"$work/schild-relay" watch -url http://127.0.0.1:17480 -test-keys lab-a,lab-b,lab-c -for 7s > "$work/watch.jsonl" || true
labs=$(grep '"verified":true' "$work/watch.jsonl" | grep -o '"lab":"lab-[abc]"' | sort -u | wc -l | tr -d ' ')
bad=$(grep -c '"verified":false' "$work/watch.jsonl" || true)
curl -s http://127.0.0.1:19102/metrics | grep -E '^schild_lab_ingest_envelopes_total' || true
echo "relay forwarded verified checkpoints of $labs labs, $bad events failed verification"
[ "$labs" = 3 ] && [ "$bad" = 0 ] || { tail -n 20 "$work"/*.log; exit 1; }
echo "smoke-native: OK"
