#!/bin/sh
# TEST ONLY: MVP-21 re-measurement - CPU and latency of schild with monitoring on vs off.
# Docker Desktop VM (12 cores, arm64): schild pinned to cores 0-5, load generator 6-9,
# backend 10-11. Other containers of the VM are not pinned (recorded before and after).
REPS=${REPS:-5}; DUR=${DUR:-60}
docker stats --no-stream --format '{{.Name}} {{.CPUPerc}}' > vm-others-before.txt
docker rm -f spec21-backend m21-backend-cpu >/dev/null 2>&1
docker run -d --name spec21-backend --network m21net --ip 10.231.36.11 --cpuset-cpus 10-11 m21d36-run:local /m/spec21-linux backend -listen 0.0.0.0:18099 >/dev/null
echo "rep mode rps cores_used achieved_rps p50_ms p99_ms p999_ms non200"
for rep in $(seq 1 $REPS); do
  order="on off"; [ $((rep % 2)) -eq 0 ] && order="off on"
  for rps in 1000 5000; do
    for mode in $order; do
      docker rm -f m21-cpu >/dev/null 2>&1
      docker run -d --name m21-cpu --network m21net --ip 10.231.36.50 --cpuset-cpus 0-5 -e SCHILD_LOG_FORMAT=json -e SCHILD_LOG_LEVEL=warn m21d36-run:local /m/schild-linux run -config /m/schild-$mode.yaml -data /m/data-$mode >/dev/null
      sleep 6
      docker run --rm --network m21net --cpuset-cpus 6-9 m21d36-run:local /m/spec21-linux flood -n 0 -target http://10.231.36.50:18090 -host shop.test -duration 15s -rps $rps -workers 64 -paths 40 -addrs 5000 >/dev/null 2>&1
      u0=$(docker exec m21-cpu sh -c "awk '/usage_usec/{print \$2}' /sys/fs/cgroup/cpu.stat")
      out=$(docker run --rm --network m21net --cpuset-cpus 6-9 m21d36-run:local /m/spec21-linux flood -n 0 -target http://10.231.36.50:18090 -host shop.test -duration ${DUR}s -rps $rps -workers 64 -paths 40 -addrs 5000 -offset 100000)
      u1=$(docker exec m21-cpu sh -c "awk '/usage_usec/{print \$2}' /sys/fs/cgroup/cpu.stat")
      echo "$out" > cpuoh-r$rep-$mode-$rps.json
      echo "$rep $mode $rps $(python3 -c "import json;d=json.loads('''$out''');print(round(($u1-$u0)/1e6/d['seconds'],4), round(d['rps'],1), d['p50_ms'], d['p99_ms'], d['p999_ms'], d['requests']-d['status'].get('200',0))")"
    done
  done
done
docker rm -f m21-cpu spec21-backend >/dev/null 2>&1
docker stats --no-stream --format '{{.Name}} {{.CPUPerc}}' > vm-others-after.txt
