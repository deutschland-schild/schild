#!/bin/sh
# Host side: start an ingress with a 4 GiB memory limit, run flood.sh, report
# CPU/memory every 10 s, answers, hangs and whether the container was OOM-killed.
# Usage: run-flood.sh <schild|stock> <rate> <n> <body>
cd "$(dirname "$0")" && . ./env.sh
v=$1; rate=$2; n=$3; body=$4; tag=fl-$v-$rate-$body
ingress_rm
if [ "$v" = schild ]; then INGRESS_EXTRA="--memory 4g" ingress_schild $ST/d-stock $ST/s-flood $E/Caddyfile.schild $E/schild.yaml
else INGRESS_EXTRA="--memory 4g" ingress_stock $ST/d-stock $E/Caddyfile.stock; fi
wait_https shop.example.de
( for i in $(seq 1 12); do sleep 10; if [ "$(docker inspect -f '{{.State.Running}}' ingress)" = true ]; then docker stats --no-stream --format "${i}0s {{.CPUPerc}} {{.MemUsage}}" ingress; else echo "${i}0s exited oom=$(docker inspect -f '{{.State.OOMKilled}}' ingress)"; fi; done | tr '\n' ';' > $ST/$tag.stats ) &
docker exec m19-tools sh /e/flood.sh $tag $rate $n $body >/dev/null 2>&1
wait
echo "== $v rate=$rate body=$body stats: $(cat $ST/$tag.stats)"
for f in flood normal; do python3 -c "import json;d=json.load(open('$ST/$tag-$f.json'));print('  ',d['label'],d['status'],'hangs',d['hangs'],'errors',sum(d['errors'].values()),'p50',d['p50_ms'],'p99',d['p99_ms'])"; done
docker inspect ingress --format '  state={{.State.Status}} oom={{.State.OOMKilled}}'
