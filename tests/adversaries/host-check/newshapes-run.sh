#!/usr/bin/env bash
# MVP-11 re-measure (d): new attack shapes against the agent listener while a
# latency probe measures the site behind the same schild. Shapes from
# newshapes.go (conn-churn, tls-flood, slowloris, slowbody) plus agent-flood
# enrol. One JSON line per shape to $OUT/shapes.jsonl.
#   NS=<linux newshapes> AF=<linux agent-flood> REPORT=<report.json> ./newshapes-run.sh
set -uo pipefail
ns=${NS:?}; af=${AF:?}; report=${REPORT:?}
net=${NET:-schild-testlab-t1_sites}; api=schild-testlab-t1-schild-api-1; img=schild-testlab-app-vm:dev
out=${OUT:-/tmp/schild-remeasure/shapes}; mkdir -p "$out"; jl=$out/shapes.jsonl
n=${N:-4}; w=${W:-64}; dur=${DUR:-40}
names=(); trap 'for x in "${names[@]}"; do docker rm -f "$x" >/dev/null 2>&1; done' EXIT
mk(){ docker run -d --rm --name "$1" --network "$net" --label schild.testlab=review --cpus 0.5 --entrypoint sleep "$img" 3600 >/dev/null
      docker cp "$ns" "$1:/usr/local/bin/newshapes" >/dev/null; docker cp "$af" "$1:/usr/local/bin/agent-flood" >/dev/null; docker cp "$report" "$1:/tmp/report.json" >/dev/null; names+=("$1"); }
for shape in ${SHAPES:-conn-churn tls-flood slowloris slowbody enrol}; do
  r0=$(docker inspect "$api" --format '{{.RestartCount}}')
  docker restart "$api" >/dev/null; for i in $(seq 1 30); do [ "$(docker inspect "$api" --format '{{.State.Health.Status}}')" = healthy ] && break; sleep 1; done
  p="schild-review-sp-$shape-$$"; mk "$p"; gens=()
  for i in $(seq 1 "$n"); do g="schild-review-sg-$shape-$i-$$"; mk "$g"; gens+=("$g"); done
  docker exec "$p" agent-flood latency -url http://schild-api:8080/ -rps 40 -dur "$((dur+10))s" -tag "$shape" > "$out/$shape.lat.json" & lp=$!
  sleep 5
  for g in "${gens[@]}"; do
    if [ "$shape" = enrol ]; then docker exec "$g" agent-flood flood -gw https://schild-api:8790 -mode enrol -c 16 -dur "${dur}s" -gateway site-api > "$out/$shape.$g.json" 2>&1 &
    else docker exec "$g" newshapes "$shape" schild-api:8790 "$w" "$dur" > "$out/$shape.$g.json" 2>&1 & fi
  done
  ( for k in $(seq 1 $((dur/3))); do docker stats --no-stream --format '{{.MemUsage}}' "$api" | awk '{print $1}'; sleep 3; done ) > "$out/$shape.mem" & sp=$!
  wait "$lp"; wait; 
  hl=$(docker exec "$p" sh -c 'curl -sk -o /dev/null -w "%{http_code}" https://schild-api:8790/healthz' 2>/dev/null || echo err)
  peak=$(awk '{s=$1; if(s~/GiB/){gsub(/GiB/,"",s);s*=1024}else{gsub(/MiB/,"",s)} if(s+0>pk)pk=s+0} END{printf "%.1f",pk}' "$out/$shape.mem")
  r1=$(docker inspect "$api" --format '{{.RestartCount}}')
  gen=$(cat "$out/$shape".schild-review-sg-*.json | tr '\n' ' ')
  python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); ok=d["codes"].get("200",0); print(json.dumps({"shape":sys.argv[2],"site_requests":d["n"],"failed":d["n"]-ok,"codes":d["codes"],"p50_ms":d["p50_ms"],"p95_ms":d["p95_ms"],"p99_ms":d["p99_ms"],"max_ms":d["max_ms"],"mem_peak_mib":float(sys.argv[3]),"restarts":int(sys.argv[4]),"listener_healthz_after":sys.argv[5],"generators":sys.argv[6]}))' \
    "$out/$shape.lat.json" "$shape" "$peak" "$((r1-r0))" "$hl" "$gen" | tee -a "$jl"
  for x in "${gens[@]}" "$p"; do docker rm -f "$x" >/dev/null 2>&1; done
done
