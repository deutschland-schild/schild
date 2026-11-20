#!/usr/bin/env bash
# MVP-11 repro of re-measure observation 2 (results/MVP-11-remeasure.md):
# distributed slowloris against the gateway's agent listener from ATTACKERS
# addresses x CONNS connections each (default 70 x 8 = 560 > MaxConns 512),
# on a running t1 (make testlab-up PROFILE=t1, agents overlay up).
#
# While the attack runs it measures
#   - fresh-address reachability: PROBES x `curl https://schild-api:8790/healthz`
#     from a container that is not attacking (before the fix: 12/20);
#   - a real enrolled agent: `schild-testlab-agent once` on app-vm (delivery
#     accepted, seconds until done);
#   - the protected site: 40 rps through schild-api:8080 (failed requests, p99);
# and afterwards AFTER more healthz probes. One JSON object to $OUT/result.json.
#
#   NS=<linux newshapes> AF=<linux agent-flood> ./distributed-slowloris.sh
#   (build: GOOS=linux GOARCH=arm64 go build -o /tmp/ns ./spec11/newshapes;
#           GOOS=linux GOARCH=arm64 go build -o /tmp/af ./cmd/agent-flood)
set -uo pipefail
ns=${NS:?NS=<linux newshapes binary>}; af=${AF:?AF=<linux agent-flood binary>}
net=${NET:-schild-testlab-t1_sites}
project=${PROJECT:-schild-testlab-t1}
api=$project-schild-api-1
img=${IMG:-schild-testlab-app-vm:dev}
attackers=${ATTACKERS:-70}; conns=${CONNS:-8}; dur=${DUR:-60}
probes=${PROBES:-20}; after=${AFTER:-5}
out=${OUT:-/tmp/schild-slowloris}; mkdir -p "$out"
names=()
cleanup(){ for x in "${names[@]}"; do docker rm -f "$x" >/dev/null 2>&1; done; }
trap cleanup EXIT
mk(){ docker run -d --rm --name "$1" --network "$net" --label schild.testlab=review --cpus "${2:-0.25}" --entrypoint sleep "$img" 3600 >/dev/null || return 1
      names+=("$1"); }

r0=$(docker inspect "$api" --format '{{.RestartCount}}')
probe=schild-review-slp-probe-$$; mk "$probe" 1; docker cp "$af" "$probe:/usr/local/bin/agent-flood" >/dev/null
gens=()
for i in $(seq 1 "$attackers"); do
  g=schild-review-slp-$i-$$; mk "$g" 0.1 || { echo "could not start attacker $i" >&2; exit 1; }
  docker cp "$ns" "$g:/usr/local/bin/newshapes" >/dev/null; gens+=("$g")
done
echo "slowloris: $attackers attackers x $conns connections for ${dur}s against schild-api:8790"

docker exec "$probe" agent-flood latency -url http://schild-api:8080/ -rps 40 -dur "$((dur + 5))s" -tag slowloris > "$out/site.json" 2>"$out/site.err" & lp=$!
for g in "${gens[@]}"; do
  docker exec "$g" newshapes slowloris schild-api:8790 "$conns" "$dur" > "$out/gen-$g.json" 2>&1 &
done
sleep 10   # let the attack saturate the listener (each connection lives up to the 5 s header timeout)

hz(){ docker exec "$probe" sh -c 'curl -sk -o /dev/null -m 5 -w "%{http_code} %{time_total}" https://schild-api:8790/healthz' 2>/dev/null || echo "err 0"; }
ok=0; : > "$out/probes-during.txt"
for i in $(seq 1 "$probes"); do r=$(hz); echo "$r" >> "$out/probes-during.txt"; [ "${r%% *}" = 200 ] && ok=$((ok + 1)); sleep 1; done

# A real enrolled agent delivers during the attack.
t0=$(date +%s); arc=0
docker compose -p "$project" exec -T app-vm schild-testlab-agent once > "$out/agent-once.log" 2>&1 || arc=$?
agent_s=$(( $(date +%s) - t0 ))
attack_running=$(docker exec "${gens[0]}" sh -c 'pgrep newshapes >/dev/null && echo yes || echo no' 2>/dev/null || echo no)

wait "$lp"; wait
okafter=0; : > "$out/probes-after.txt"
for i in $(seq 1 "$after"); do r=$(hz); echo "$r" >> "$out/probes-after.txt"; [ "${r%% *}" = 200 ] && okafter=$((okafter + 1)); sleep 1; done
r1=$(docker inspect "$api" --format '{{.RestartCount}}')
gen_ops=$(cat "$out"/gen-*.json | python3 -I -c 'import json,sys; t=[json.loads(l) for l in sys.stdin if l.startswith("{")]; print(json.dumps({"generators":len(t),"ops":sum(x["ops"] for x in t),"errs":sum(x["errs"] for x in t)}))')
python3 -I - "$out/site.json" "$ok" "$probes" "$okafter" "$after" "$arc" "$agent_s" "$attack_running" "$((r1 - r0))" "$gen_ops" "$attackers" "$conns" "$dur" <<'PY' | tee "$out/result.json"
import json, sys
a = sys.argv
site = json.load(open(a[1]))
ok200 = site["codes"].get("200", 0)
print(json.dumps({
    "shape": "distributed-slowloris", "attackers": int(a[11]), "conns_per_attacker": int(a[12]), "seconds": int(a[13]),
    "healthz_during": f"{a[2]}/{a[3]}", "healthz_after": f"{a[4]}/{a[5]}",
    "agent_once_exit": int(a[6]), "agent_once_seconds": int(a[7]), "attack_still_running_after_agent": a[8],
    "site_requests": site["n"], "site_failed": site["n"] - ok200, "site_codes": site["codes"],
    "site_p50_ms": site["p50_ms"], "site_p99_ms": site["p99_ms"], "site_max_ms": site["max_ms"],
    "schild_api_restarts": int(a[9]), "generators": json.loads(a[10]),
}, indent=1))
PY
