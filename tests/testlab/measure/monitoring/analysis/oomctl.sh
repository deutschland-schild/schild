#!/bin/sh
# TEST ONLY: control run of oomtest.sh with monitoring off (MVP-21 measurement)
docker rm -f spec21-mem-on1g spec21-mem-off1g >/dev/null 2>&1
docker run -d --name spec21-mem-off1g --network spec21net --ip 10.231.21.43 --cpus 4 --memory 1g -e SCHILD_LOG_FORMAT=json spec21-run:local /m/schild-linux run -config /m/schild-off.yaml -data /m/data-off >/dev/null
sleep 5
docker run --rm --name spec21-load-oomctl --network spec21net --cpuset-cpus 4-7 spec21-run:local /m/spec21-linux flood -target http://10.231.21.43:18090 -host shop.test -n 32768 -workers 32 -paths 32768 -pathlen 32768 -spread > longpath32-off1g.json 2>&1 &
for i in $(seq 1 30); do
  sleep 10
  st=$(docker inspect -f '{{.State.Status}} oom={{.State.OOMKilled}} exit={{.State.ExitCode}}' spec21-mem-off1g)
  m=$(docker exec spec21-mem-off1g sh -c 'grep VmRSS /proc/1/status | tr -s " "; grep oom_kill /sys/fs/cgroup/memory.events' 2>/dev/null | tr '\n' ' ')
  echo "t=${i}0s $st | $m"
  case "$st" in exited*) break;; esac
done
docker rm -f spec21-load-oomctl >/dev/null 2>&1
wait
cat longpath32-off1g.json
docker rm -f spec21-mem-off1g >/dev/null 2>&1
