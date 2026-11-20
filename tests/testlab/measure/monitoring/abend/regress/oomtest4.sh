#!/bin/bash
# TEST ONLY: evening re-measurement 2026-10-29 (commit c54de1b), item 9b. Adapted from d36n-a/oomtest3.sh.
# Distinct long paths (32 KiB) plus distinct user agents and referrers from 50 000 X-Forwarded-For
# addresses (trusted proxy net, so they count as clients) against schild:abend in a 1 GiB / 4 CPU
# container, monitoring on or off.
# schild:abend is distroless (no shell): RSS is read from /proc/1/status by a helper container that
# shares the PID namespace (--pid container:...). Data lives in the image's anonymous volume.
# Docker Desktop does not share /tmp, so configs and tool go into two local TEST ONLY images, built in
# /tmp/abend/k/mem (Caddyfile, geo.mmdb, schild-on/off.yaml, spec21-linux = linux-arm64 build of cmd/measure):
#   docker build -f Dockerfile.schild -t abc-k-schild:local .   (FROM schild:abend, COPY configs to /m/)
#   docker build -f Dockerfile.tool -t abc-k-tool:local .       (FROM spec21-measure:local, COPY spec21-linux /b/)
# Every container/network is named abc-k-*; removed at the end (network: NET_RM=1).
#   oomtest4.sh on 65536 > oom-on.log;  oomtest4.sh off 65536 > oom-off.log
MODE=${1:-on}; N=${2:-65536}
M=/tmp/abend/k/mem; BIN=/tmp/abend/k/bin; NET=abc-k-net; TOOL=abc-k-tool:local; IMG=abc-k-schild:local
C=abc-k-mem-$MODE
docker network inspect $NET >/dev/null 2>&1 || docker network create --subnet 10.231.97.0/24 $NET >/dev/null
if ! docker ps --format '{{.Names}}' | grep -q '^abc-k-backend$'; then
  docker rm -f abc-k-backend >/dev/null 2>&1
  docker run -d --name abc-k-backend --network $NET --ip 10.231.97.10 $TOOL /b/spec21-linux backend -listen 0.0.0.0:18099 >/dev/null
fi
docker rm -f -v $C >/dev/null 2>&1
docker run -d --name $C --network $NET --ip 10.231.97.42 --cpus 4 --memory 1g -e SCHILD_ALLOW_TEST_KEYS=1 \
  -e SCHILD_LOG_FORMAT=json -e SCHILD_LOG_LEVEL=warn $IMG run -config /m/schild-$MODE.yaml >/dev/null
sleep 6
rss() { docker run --rm --pid container:$C $TOOL sh -c 'grep VmRSS /proc/1/status | tr -s " \t" " "; grep oom_kill /sys/fs/cgroup/memory.events 2>/dev/null' 2>/dev/null | tr '\n' ' '; }
echo "start: $(rss) | load $(uptime | sed 's/.*averages: //')"
docker run --rm --name abc-k-load-oom --network $NET --cpuset-cpus 4-7 $TOOL /b/spec21-linux flood -target http://10.231.97.42:18090 -host shop.test -n $N -workers 32 -paths $N -pathlen 32768 -uas $N -refs $N -addrs 50000 -spread > $M/longpath32-$MODE-1g.json 2>&1 &
i=0
while :; do
  i=$((i+1)); sleep 10
  st=$(docker inspect -f '{{.State.Status}} oom={{.State.OOMKilled}} exit={{.State.ExitCode}}' $C)
  m=$(rss)
  ms=$(docker stats --no-stream --format '{{.MemUsage}}' $C 2>/dev/null)
  p=$(docker run --rm --network $NET $TOOL curl -s -o /dev/null -m 5 -w "%{http_code} %{time_total}" -H "Host: shop.test" http://10.231.97.42:18090/about 2>/dev/null)
  echo "t=${i}0s $st | $m | cgroup $ms | probe $p | load $(uptime | sed 's/.*averages: //')"
  case "$st" in exited*) break;; esac
  docker ps --format '{{.Names}}' | grep -q '^abc-k-load-oom$' || break
done
wait
cat $M/longpath32-$MODE-1g.json
sleep 30
echo "60 s after the flood: $(rss)"
docker inspect -f '{{.State.Status}} oom={{.State.OOMKilled}}' $C
docker logs $C 2>&1 | tail -3
docker rm -f -v $C >/dev/null 2>&1
if [ "${NET_RM:-0}" = 1 ]; then docker rm -f abc-k-backend >/dev/null 2>&1; docker network rm $NET >/dev/null 2>&1; fi
