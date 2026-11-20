#!/bin/sh
# TEST ONLY: long distinct paths against a 1 GiB container with monitoring on (MVP-21 measurement)
docker rm -f spec21-mem-on spec21-mem-off >/dev/null 2>&1
docker run -d --name spec21-mem-on1g --network spec21net --ip 10.231.21.42 --cpus 4 --memory 1g -e SCHILD_LOG_FORMAT=json spec21-run:local /m/schild-linux run -config /m/schild-on.yaml -data /m/data-on >/dev/null
sleep 5
docker run --rm --name spec21-load-oom --network spec21net --cpuset-cpus 4-7 spec21-run:local /m/spec21-linux flood -target http://10.231.21.42:18090 -host shop.test -n 32768 -workers 32 -paths 32768 -pathlen 32768 -spread > longpath32-on1g.json 2>&1 &
for i in $(seq 1 36); do
  sleep 10
  st=$(docker inspect -f '{{.State.Status}} oom={{.State.OOMKilled}} exit={{.State.ExitCode}}' spec21-mem-on1g)
  m=$(docker exec spec21-mem-on1g sh -c 'grep VmRSS /proc/1/status | tr -s " "; grep oom_kill /sys/fs/cgroup/memory.events' 2>/dev/null | tr '\n' ' ')
  p=$(docker run --rm --network spec21net spec21-run:local curl -s -o /dev/null -m 5 -w "%{http_code} %{time_total}" -H "Host: shop.test" http://10.231.21.42:18090/about 2>/dev/null)
  echo "t=${i}0s $st | $m | probe $p"
  case "$st" in exited*) break;; esac
done
wait
cat longpath32-on1g.json
docker logs spec21-mem-on1g 2>&1 | tail -5 | cut -c1-300
