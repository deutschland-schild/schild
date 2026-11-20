#!/bin/sh
# TEST ONLY: MVP-21 re-measurement - distinct long paths (32 KiB) plus distinct
# user agents and referrers against a 1 GiB container, monitoring on or off.
# Usage: oomtest2.sh on|off N   (image m21d36-run:local, network m21net)
MODE=${1:-on}; N=${2:-65536}
C=m21-mem-$MODE
docker rm -f $C >/dev/null 2>&1
docker run -d --name $C --network m21net --ip 10.231.36.42 --cpus 4 --memory 1g -e SCHILD_LOG_FORMAT=json -e SCHILD_LOG_LEVEL=warn m21d36-run:local /m/schild-linux run -config /m/schild-$MODE.yaml -data /m/data-$MODE >/dev/null
sleep 5
docker run --rm --name m21-load-oom --network m21net --cpuset-cpus 4-7 m21d36-run:local /m/spec21-linux flood -target http://10.231.36.42:18090 -host shop.test -n $N -workers 32 -paths $N -pathlen 32768 -uas $N -refs $N -addrs 50000 -spread > longpath32-$MODE-1g.json 2>&1 &
i=0
while :; do
  i=$((i+1)); sleep 10
  st=$(docker inspect -f '{{.State.Status}} oom={{.State.OOMKilled}} exit={{.State.ExitCode}}' $C)
  m=$(docker exec $C sh -c 'grep VmRSS /proc/1/status | tr -s " "; grep oom_kill /sys/fs/cgroup/memory.events' 2>/dev/null | tr '\n' ' ')
  p=$(docker run --rm --network m21net m21d36-run:local curl -s -o /dev/null -m 5 -w "%{http_code} %{time_total}" -H "Host: shop.test" http://10.231.36.42:18090/about 2>/dev/null)
  echo "t=${i}0s $st | $m | probe $p"
  case "$st" in exited*) break;; esac
  docker ps --format '{{.Names}}' | grep -q m21-load-oom || break
done
wait
cat longpath32-$MODE-1g.json
sleep 30
echo "60 s after the flood: $(docker exec $C sh -c 'grep VmRSS /proc/1/status | tr -s " "' 2>/dev/null)"
docker inspect -f '{{.State.Status}} oom={{.State.OOMKilled}}' $C
docker rm -f $C >/dev/null 2>&1
