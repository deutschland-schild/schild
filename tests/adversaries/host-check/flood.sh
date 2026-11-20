#!/usr/bin/env bash
# MVP-11 review probe (kill criterion "agent/check failures affect request
# handling"): floods the agent listener of schild-api in a running t1 test lab
# (make testlab-up PROFILE=t1 && make smoke PROFILE=t1) from N throwaway
# containers on the sites network (fresh addresses per run, CPU-capped so the
# generators do not starve the Docker VM) while one more container measures
# the latency of the site behind the same schild. A control run sends the
# same flood to a sink container instead of schild.
#   AGENT_FLOOD=<linux agent-flood binary> REPORT=<schild check --json output> MODE=signed|big|hold|enrol ./flood.sh
# Results: one JSON line per probe in $OUT. All containers are removed.
# The gateway allows 120 requests per 15 min per address and keeps that in
# memory: restart schild-api before a run (docker restart
# schild-testlab-t1-schild-api-1) or reused container addresses only get 429.
# Memory repro (review finding): docker update --memory 512m --memory-swap 512m
# schild-testlab-t1-schild-api-1, then N=4 C=100 DUR=45 MODE=hold: schild is
# killed and restarted, and site requests fail meanwhile.
set -uo pipefail
bin=${AGENT_FLOOD:?}; report=${REPORT:?}; mode=${MODE:-signed}
n=${N:-6}; c=${C:-8}; dur=${DUR:-40}; cpus=${CPUS:-0.5}
net=${NET:-schild-testlab-t1_sites}
out=${OUT:-/tmp/schild-review/flood}; mkdir -p "$out"
img=schild-testlab-app-vm:dev
names=()
mk() { # name [cpus]
  docker run -d --rm --name "$1" --network "$net" --label schild.testlab=review ${2:+--cpus "$2"} --entrypoint sleep "$img" 3600 >/dev/null
  docker cp "$bin" "$1:/usr/local/bin/agent-flood" >/dev/null; docker cp "$report" "$1:/tmp/report.json" >/dev/null
  names+=("$1")
}
cleanup() { for x in "${names[@]}"; do docker rm -f "$x" >/dev/null 2>&1; done; }
trap cleanup EXIT
run() { # tag target
  local tag=$1 target=$2 gens=()
  for i in $(seq 1 "$n"); do mk "schild-review-gen-$tag-$i-$$" "$cpus"; gens+=("schild-review-gen-$tag-$i-$$"); done
  docker stats --no-stream --format '{{.Name}} {{.CPUPerc}} {{.MemUsage}}' schild-testlab-t1-schild-api-1 > "$out/$tag.stats-before"
  docker exec "$probe" agent-flood latency -url http://schild-api:8080/ -rps 40 -dur "$((dur+10))s" -tag "$tag" > "$out/$tag.latency.json" &
  local lp=$!
  sleep 5
  for g in "${gens[@]}"; do docker exec "$g" agent-flood flood -gw "$target" -mode "$mode" -c "$c" -dur "${dur}s" -report /tmp/report.json -gateway site-api > "$out/$tag.$g.json" 2>&1 & done
  ( for k in 1 2 3 4; do sleep $((dur/4)); docker stats --no-stream --format '{{.Name}} {{.CPUPerc}} {{.MemUsage}}' schild-testlab-t1-schild-api-1; done ) > "$out/$tag.stats-during"
  wait
  cat "$out/$tag.latency.json"; cat "$out/$tag".schild-review-gen-*.json | head -3; cat "$out/$tag.stats-during"
  for g in "${gens[@]}"; do docker rm -f "$g" >/dev/null 2>&1; done
}
probe=schild-review-probe-$$; mk "$probe"
mk "schild-review-sink-$$"; docker exec -d "schild-review-sink-$$" agent-flood sink -listen :8790
docker exec "$probe" agent-flood latency -url http://schild-api:8080/ -rps 40 -dur 30s -tag "baseline" | tee "$out/baseline.latency.json"
run "control-$mode" "https://schild-review-sink-$$:8790"
run "schild-$mode" "https://schild-api:8790"
docker logs --since 5m schild-testlab-t1-schild-api-1 2>&1 | grep -c '"agent report rejected"' | sed 's/^/gateway reject log lines: /'
