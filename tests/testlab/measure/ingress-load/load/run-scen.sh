#!/bin/sh
# Host side: run-scen.sh <schild|stock> <scenario> [memory]
# Fresh ingress, docker stats every ~2 s during the 60 s load and 30 s after,
# metrics before/after, OOM state, one GET after recovery.
H=$(cd "$(dirname "$0")" && pwd); . $H/aenv.sh
v=$1; s=$2; mem=${3:-4g}; tag=ab-$v-$mem-$s${TAGX:+-$TAGX}; OUT=$OUTA/load; mkdir -p $OUT
sh $H/start.sh $v $mem >/dev/null || { echo "start failed"; exit 1; }
docker exec m19-tools sh -c 'for i in 1 2 3 4 5; do curl -s -o /dev/null --cacert /st/pebble-root.pem --resolve shop.example.de:443:10.219.19.10 https://shop.example.de/; done'
[ $v = schild ] && { metrics > $OUT/$tag.metrics-before.txt; docker logs ingress 2>&1 | grep -E '"go memory limit"|"waf evaluation slots"' > $OUT/$tag.startlog.txt; }
( t0=$(date +%s); while [ $(( $(date +%s) - t0 )) -lt 95 ]; do sleep 1.5; e=$(( $(date +%s) - t0 )); if [ "$(docker inspect -f '{{.State.Running}}' ingress)" = true ]; then docker stats --no-stream --format "${e}s {{.CPUPerc}} {{.MemUsage}}" ingress; else echo "${e}s exited oom=$(docker inspect -f '{{.State.OOMKilled}}' ingress)"; fi; done > $OUT/$tag.stats ) &
sp=$!
docker exec m19-tools sh /e3/scen.sh $s $tag
sleep 1
wait $sp
docker exec m19-tools sh -c "cat /st/$tag-*.json" > $OUT/$tag.jsonl
[ $v = schild ] && metrics > $OUT/$tag.metrics-after.txt 2>/dev/null
after=$(docker exec m19-tools sh -c 'curl -s -o /dev/null -w "%{http_code} %{time_total}" -m 30 --cacert /st/pebble-root.pem --resolve shop.example.de:443:10.219.19.10 https://shop.example.de/')
st=$(docker inspect ingress --format 'state={{.State.Status}} oom={{.State.OOMKilled}} restarts={{.RestartCount}}')
echo "== $tag  $st  get-after-recovery: $after" | tee $OUT/$tag.summary
python3 -I $H/summ.py $OUT/$tag.jsonl $OUT/$tag.stats | tee -a $OUT/$tag.summary
