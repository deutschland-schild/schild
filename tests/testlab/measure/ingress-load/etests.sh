#!/bin/sh
E="$(cd "$(dirname "$0")/../../.." && pwd)/results/messung-2026-10-29-abend/e"; mkdir -p "$E"
cd /tmp/abend/src
echo "make test start $(date +%T) load $(uptime | sed 's/.*averages: //')"
make test > $E/make-test.log 2>&1; echo "make test exit $? $(date +%T)"
echo "pnpm check start $(date +%T)"
(cd ui && pnpm check) > $E/pnpm-check.log 2>&1; echo "pnpm check exit $? $(date +%T)"
for i in 1 2 3 4 5 6 7 8 9 10; do
  echo "burst run $i load $(uptime | sed 's/.*averages: //')"
  (cd lab && go test -count=1 -run TestBurstAckLatency -v ./internal/ingest/ 2>&1) | grep -E -- '--- |rate_limited|429|p99|ok |FAIL' | head -20
done
