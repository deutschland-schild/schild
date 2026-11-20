#!/bin/sh
# TEST ONLY: D36 re-measurement (ac9c543) - distinct long paths (32 KiB) plus distinct
# user agents and referrers against a 1 GiB container, monitoring on or off.
# Like analysis/oomtest2.sh, but image d36n-run:local, network d36n-net (10.231.37.0/24,
# trusted_proxies set, so the 50 000 X-Forwarded-For addresses count as clients).
# Usage: oomtest3.sh on|off N    (container names d36n-mem-*, removed at the end)
MODE=${1:-on}; N=${2:-65536}
C=d36n-mem-$MODE
docker rm -f $C >/dev/null 2>&1
docker run -d --name $C --network d36n-net --ip 10.231.37.42 --cpus 4 --memory 1g -e SCHILD_LOG_FORMAT=json -e SCHILD_LOG_LEVEL=warn d36n-run:local /m/schild-linux run -config /m/schild-$MODE.yaml -data /m/data-$MODE >/dev/null
sleep 5
docker run --rm --name d36n-load-oom --network d36n-net --cpuset-cpus 4-7 d36n-run:local /m/spec21-linux flood -target http://10.231.37.42:18090 -host shop.test -n $N -workers 32 -paths $N -pathlen 32768 -uas $N -refs $N -addrs 50000 -spread > longpath32-$MODE-1g.json 2>&1 &
i=0
while :; do
  i=$((i+1)); sleep 10
  st=$(docker inspect -f '{{.State.Status}} oom={{.State.OOMKilled}} exit={{.State.ExitCode}}' $C)
  m=$(docker exec $C sh -c 'grep VmRSS /proc/1/status | tr -s " "; grep oom_kill /sys/fs/cgroup/memory.events' 2>/dev/null | tr '\n' ' ')
  p=$(docker run --rm --network d36n-net d36n-run:local curl -s -o /dev/null -m 5 -w "%{http_code} %{time_total}" -H "Host: shop.test" http://10.231.37.42:18090/about 2>/dev/null)
  echo "t=${i}0s $st | $m | probe $p"
  case "$st" in exited*) break;; esac
  docker ps --format '{{.Names}}' | grep -q '^d36n-load-oom$' || break
done
wait
cat longpath32-$MODE-1g.json
sleep 30
echo "60 s after the flood: $(docker exec $C sh -c 'grep VmRSS /proc/1/status | tr -s " "' 2>/dev/null)"
docker inspect -f '{{.State.Status}} oom={{.State.OOMKilled}}' $C
docker rm -f $C >/dev/null 2>&1
