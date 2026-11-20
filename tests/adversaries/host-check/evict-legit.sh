#!/usr/bin/env bash
# MVP-11: does eviction close a legitimate, slow in-flight connection?
# Saturates the listener with evictable slow-header connections AND a constant
# churn of NEW connections (so Accept() keeps evicting the oldest waiting one),
# then opens legitimate requests over a 300 ms-delayed link (netem) so each
# handshake+headers takes > evictMinAge (500 ms). If the fix is safe, the slow
# legit request still completes (200); if eviction kills slow legit traffic,
# it is reset. The fast enrolled app-vm agent is the control.
set -uo pipefail
ns=${NS:?}; af=${AF:?}
net=${NET:-schild-testlab-t1_sites}
project=${PROJECT:-schild-testlab-t1}
api=$project-schild-api-1
img=${IMG:-schild-testlab-app-vm:dev}
dur=${DUR:-70}; delayms=${DELAYMS:-300}; probes=${PROBES:-20}
out=${OUT:-/tmp/schild-remeasure}; tag=${TAG:-v-evictlegit}; mkdir -p "$out"
names=()
cleanup(){ for x in "${names[@]:-}"; do docker rm -f "$x" >/dev/null 2>&1 || true; done; }
trap cleanup EXIT
mk(){ local extra=(); [ -n "${3:-}" ] && extra=("${3}"); docker run -d --rm --name "$1" --network "$net" "${extra[@]}" \
    --label schild.testlab=review --cpus "${2:-0.1}" --entrypoint sleep "$img" 3600 >/dev/null || return 1; names+=("$1"); }

r0=$(docker inspect "$api" --format '{{.RestartCount}}')

# Saturate: 64 slow-header peers x 8 = 512 evictable waiting conns.
for i in $(seq 1 64); do
  g=schild-review-el-slp-$i-$$; mk "$g" 0.05
  docker cp "$ns" "$g:/usr/local/bin/newshapes" >/dev/null
  docker exec -d "$g" newshapes slowloris schild-api:8790 8 "$dur"
done
# Churn: constant new connections so eviction fires continuously.
for i in $(seq 1 20); do
  g=schild-review-el-chn-$i-$$; mk "$g" 0.05
  docker cp "$ns" "$g:/usr/local/bin/newshapes" >/dev/null
  docker exec -d "$g" newshapes conn-churn schild-api:8790 16 "$dur"
done

# Delayed legit probe: its own container with NET_ADMIN + 300 ms egress delay.
probe=schild-review-el-probe-$$; mk "$probe" 1 "--cap-add=NET_ADMIN"
docker exec "$probe" tc qdisc add dev eth0 root netem delay "${delayms}ms" 2>&1 | head -1 || true
echo "[$tag] 512 slow + 20 churn; legit probe over ${delayms}ms-delayed link"
sleep 10

ok=0; : > "$out/$tag.probes.txt"
for i in $(seq 1 "$probes"); do
  r=$(docker exec "$probe" sh -c 'curl -sk -o /dev/null -m 8 -w "%{http_code} %{time_total}" https://schild-api:8790/healthz' 2>/dev/null || echo "000 0")
  echo "$r" >> "$out/$tag.probes.txt"; [ "${r%% *}" = 200 ] && ok=$((ok+1)); sleep 1
done
# Fast enrolled agent control (app-vm, undelayed link).
arc=0; docker compose -p "$project" exec -T app-vm schild-testlab-agent once > "$out/$tag.agent.log" 2>&1 || arc=$?
accepted=no; grep -q '"status":"accepted"' "$out/$tag.agent.log" && accepted=yes
r1=$(docker inspect "$api" --format '{{.RestartCount}}')

python3 -I - "$ok" "$probes" "$arc" "$accepted" "$delayms" "$((r1-r0))" "$tag" <<'PY' | tee "$out/$tag.json"
import json,sys
a=sys.argv
print(json.dumps({"tag":a[7],"legit_delayed_healthz_200":f"{a[1]}/{a[2]}","delay_ms":int(a[5]),
  "agent_once_exit":int(a[3]),"agent_once_accepted":a[4],"schild_api_restarts":int(a[6])},indent=1))
PY
