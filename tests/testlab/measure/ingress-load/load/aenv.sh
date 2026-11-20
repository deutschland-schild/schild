#!/bin/sh
# Evening measurement 2026-10-29 environment: the MVP-19 env.sh with the
# image of c54de1b (schild:abend, local arm64 test image) and the state and
# payloads of measurement 3. Source from a script: H=<this dir>; . $H/aenv.sh
M=$(cd "$H/../../../.." && pwd)
E=$M/results/MVP-19-messung/env
ST=$M/results/tmp/spec19m3/state
BIN=$M/results/tmp/spec19m3/bin
SCHILD_IMAGE=${IMG:-schild:abend}
OUTA=$M/results/messung-2026-10-29-abend/a; mkdir -p "$OUTA"
. $E/env.sh
metrics() { docker exec m19-cap sh -c 'curl -s 127.0.0.1:19101/metrics' | grep -E "^schild_hard_limit_rejects_total|^schild_waf|^schild_traffic|^schild_requests_total|^schild_http_requests_total|^schild_http_waiting_page|^process_cpu_seconds|^process_resident|^go_goroutines|^go_memstats_heap_inuse|^go_gc_gomemlimit|^go_memstats_sys" ; }
net_up_a() {
  net_up
  docker rm -f m19-tools m19-cap >/dev/null
  # no packet capture in this measurement (egress was measured before); the
  # container only gives metrics access inside the ingress network namespace
  docker run -d --name m19-cap --network container:netholder m19-tools:local sleep infinity >/dev/null
  docker run -d --name m19-tools --network $NET --ip 10.219.19.5 -v "$E:/e:ro" -v "$H:/e3:ro" -v "$BIN:/bin2:ro" -v "$ST:/st" m19-tools:local sleep infinity >/dev/null
}
