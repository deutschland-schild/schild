#!/usr/bin/env bash
# MVP-11 independent re-measure of kill criterion (d) "agent/check failures
# affect request handling". Leaner, statistically-shaped driver around the
# agent-flood binary: a fixed baseline (no flood, 10 runs) vs flood runs, so
# flood-caused stalls can be told apart from host noise. Each run restarts
# schild-api, records load average + a docker-stats sample, runs a 40s latency
# probe against the protected site while N generators (fresh addresses) flood
# the agent listener, and reports: failed/503 site requests, p50/p95/p99/max,
# schild-api memory peak, restarts. One JSON line per run to $OUT/driver.jsonl.
#   BIN=<linux agent-flood> REPORT=<schild check --json> ./flood-driver.sh
set -uo pipefail
bin=${BIN:?}; report=${REPORT:?}
net=${NET:-schild-testlab-t1_sites}
api=schild-testlab-t1-schild-api-1
img=schild-testlab-app-vm:dev
out=${OUT:-/tmp/schild-remeasure/flood}; mkdir -p "$out"
jl="$out/driver.jsonl"
mode=${MODE:-hold}; n=${N:-6}; c=${C:-100}; dur=${DUR:-40}; cpus=${CPUS:-0.5}; tag=${TAG:-run}; flood=${FLOOD:-1}
names=()
mk(){ docker run -d --rm --name "$1" --network "$net" --label schild.testlab=review ${2:+--cpus "$2"} --entrypoint sleep "$img" 3600 >/dev/null
      docker cp "$bin" "$1:/usr/local/bin/agent-flood" >/dev/null; docker cp "$report" "$1:/tmp/report.json" >/dev/null; names+=("$1"); }
cleanup(){ for x in "${names[@]}"; do docker rm -f "$x" >/dev/null 2>&1; done; }
trap cleanup EXIT
r0=$(docker inspect "$api" --format '{{.RestartCount}}')
docker restart "$api" >/dev/null
# wait healthy
for i in $(seq 1 30); do [ "$(docker inspect "$api" --format '{{.State.Health.Status}}')" = healthy ] && break; sleep 1; done
la=$(uptime | sed 's/.*load average[s]*: //')
probe="schild-review-probe-$tag-$$"; mk "$probe"
gens=()
if [ "$flood" = 1 ]; then
  for i in $(seq 1 "$n"); do g="schild-review-gen-$tag-$i-$$"; mk "$g" "$cpus"; gens+=("$g"); done
fi
docker stats --no-stream --format '{{.MemUsage}}' "$api" > "$out/$tag.mem-before"
docker exec "$probe" agent-flood latency -url http://schild-api:8080/ -rps 40 -dur "$((dur+10))s" -tag "$tag" > "$out/$tag.latency.json" 2>"$out/$tag.latency.err" &
lp=$!
sleep 5
for g in "${gens[@]}"; do docker exec "$g" agent-flood flood -gw "https://schild-api:8790" -mode "$mode" -c "$c" -dur "${dur}s" -report /tmp/report.json -gateway site-api > "$out/$tag.$g.json" 2>&1 & done
peak=0
( for k in $(seq 1 $((dur/3))); do m=$(docker stats --no-stream --format '{{.MemUsage}}' "$api" 2>/dev/null | awk '{print $1}'); echo "$m"; sleep 3; done ) > "$out/$tag.mem-during" &
sp=$!
wait "$lp"
kill "$sp" 2>/dev/null; wait "$sp" 2>/dev/null
# memory peak in MiB from samples like 104.1MiB
peak=$(awk 'function v(s){ if(s ~ /GiB/){gsub(/GiB/,"",s);return s*1024} gsub(/MiB/,"",s);return s+0 } {m=v($1); if(m>pk)pk=m} END{printf "%.1f",pk}' "$out/$tag.mem-during" 2>/dev/null)
r1=$(docker inspect "$api" --format '{{.RestartCount}}')
# parse latency json
python3 -I - "$out/$tag.latency.json" "$tag" "$mode" "$n" "$c" "$la" "$peak" "$((r1-r0))" "$flood" >> "$jl" <<'PY'
import json,sys
f,tag,mode,n,c,la,peak,restarts,flood=sys.argv[1:]
d=json.load(open(f))
codes=d.get("codes",{})
nreq=d.get("n",0)
ok=codes.get("200",0)
failed=nreq-ok
rec={"tag":tag,"mode":mode if flood=="1" else "baseline","gen":f"{n}x{c}" if flood=="1" else "none",
 "site_requests":nreq,"ok_200":ok,"failed":failed,"codes":codes,
 "p50_ms":d.get("p50_ms"),"p95_ms":d.get("p95_ms"),"p99_ms":d.get("p99_ms"),"max_ms":d.get("max_ms"),
 "mem_peak_mib":float(peak) if peak else None,"restarts":int(restarts),"load_avg":la.strip()}
print(json.dumps(rec))
PY
tail -1 "$jl"
for g in "${gens[@]}"; do docker rm -f "$g" >/dev/null 2>&1; done
docker rm -f "$probe" >/dev/null 2>&1
