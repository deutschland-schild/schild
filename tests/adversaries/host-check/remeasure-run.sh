#!/usr/bin/env bash
# MVP-11 independent re-measure harness (listener eviction fix, commit 946996f).
# Runs one attack configuration against the running t1 gateway's agent listener
# (schild-api:8790) and measures, in one pass:
#   - fresh-address healthz reachability (PROBES curls from a non-attacking box),
#   - a real enrolled agent delivery (app-vm `schild-testlab-agent once`),
#   - the protected site at 40 rps (failed, p50/p95/p99/max), via agent-flood,
#   - schild-api memory peak (MiB) and restart count across the run.
# Two attacker groups (G1, G2) may run at once (e.g. slow-header + churn).
# Writes one JSON object to $OUT/<TAG>.json.
#
# Env (all optional except TAG):
#   TAG         result name (file $OUT/<TAG>.json)
#   SHAPE1 N1 CONNS1 KNOB1   group 1 shape, attacker count, conns each, knob
#   SHAPE2 N2 CONNS2 KNOB2   group 2 (default N2=0, off)
#   DUR         attack seconds (default 60)
#   PROBES      healthz probes during attack (default 24)
#   IPMODE      auto (docker assigns) | static (distinct IPs from a free pool)
#   NS AF       linux/arm64 newshapes and agent-flood binaries
set -uo pipefail
ns=${NS:?NS=<linux newshapes>}; af=${AF:?AF=<linux agent-flood>}
net=${NET:-schild-testlab-t1_sites}
project=${PROJECT:-schild-testlab-t1}
api=$project-schild-api-1
img=${IMG:-schild-testlab-app-vm:dev}
tag=${TAG:?set TAG}
s1=${SHAPE1:-slowloris}; n1=${N1:-0}; c1=${CONNS1:-8}; k1=${KNOB1:-0}
s2=${SHAPE2:-conn-churn}; n2=${N2:-0}; c2=${CONNS2:-8}; k2=${KNOB2:-0}
dur=${DUR:-60}; probes=${PROBES:-24}; ipmode=${IPMODE:-auto}
out=${OUT:-/tmp/schild-remeasure}; mkdir -p "$out"
names=()
cleanup(){ for x in "${names[@]:-}"; do docker rm -f "$x" >/dev/null 2>&1 || true; done; }
trap cleanup EXIT

# Build a pool of free static IPs in the sites /24 if needed.
pool=(); if [ "$ipmode" = static ]; then
  used=$(docker network inspect "$net" --format '{{range .Containers}}{{.IPv4Address}} {{end}}' | tr ' ' '\n' | cut -d/ -f1 | sort -u)
  for last in $(seq 8 250); do ip="10.66.17.$last"; grep -qx "$ip" <<<"$used" || pool+=("$ip"); done
fi
pick_ip(){ local n=$1; echo "${pool[$n]}"; }

mk(){ # name cpus [ip]
  local extra=(); [ -n "${3:-}" ] && extra=(--ip "$3")
  docker run -d --rm --name "$1" --network "$net" "${extra[@]}" --label schild.testlab=review \
    --cpus "${2:-0.1}" --entrypoint sleep "$img" 3600 >/dev/null || return 1
  names+=("$1")
}

r0=$(docker inspect "$api" --format '{{.RestartCount}}')
probe=schild-review-probe-$$; mk "$probe" 1
docker cp "$af" "$probe:/usr/local/bin/agent-flood" >/dev/null

# Launch attacker containers for a group.
pidx=0
static_placed=0
launch_group(){ # shape n conns knob prefix
  local shape=$1 n=$2 conns=$3 knob=$4 pfx=$5 i g ip ok tries
  [ "$n" -le 0 ] && return 0
  for i in $(seq 1 "$n"); do
    g="schild-review-$pfx-$i-$$"
    if [ "$ipmode" = static ]; then
      ok=0
      for tries in $(seq 1 30); do
        ip=$(pick_ip "$pidx"); pidx=$((pidx+1))
        [ -z "$ip" ] && { echo "static IP pool exhausted at $pfx-$i" >&2; break; }
        if mk "$g" 0.05 "$ip" 2>/dev/null; then ok=1; static_placed=$((static_placed+1)); break; fi
      done
      [ "$ok" = 1 ] || { echo "could not place attacker $pfx-$i" >&2; exit 1; }
    else
      mk "$g" 0.05 || { echo "could not start attacker $pfx-$i" >&2; exit 1; }
    fi
    docker cp "$ns" "$g:/usr/local/bin/newshapes" >/dev/null
    docker exec -d "$g" newshapes "$shape" schild-api:8790 "$conns" "$dur" "$knob"
  done
}

echo "[$tag] G1=$s1 x$n1 x$c1 (knob $k1)  G2=$s2 x$n2 x$c2 (knob $k2)  ${dur}s ipmode=$ipmode"
launch_group "$s1" "$n1" "$c1" "$k1" g1
launch_group "$s2" "$n2" "$c2" "$k2" g2

# Site latency probe (40 rps) for the whole attack window.
docker exec "$probe" agent-flood latency -url http://schild-api:8080/ -rps 40 -dur "$((dur + 6))s" -tag "$tag" > "$out/$tag.site.json" 2>"$out/$tag.site.err" & lp=$!

# Memory sampler: peak RSS of schild-api (MiB) over the run.
: > "$out/$tag.mem.txt"
( for i in $(seq 1 "$((dur + 6))"); do
    m=$(docker stats --no-stream --format '{{.MemUsage}}' "$api" 2>/dev/null | awk '{print $1}')
    echo "$m" >> "$out/$tag.mem.txt"; sleep 1
  done ) & mp=$!

sleep 10  # let the listener saturate (connections live up to the 5 s header timeout)

hz(){ docker exec "$probe" sh -c 'curl -sk -o /dev/null -m 5 -w "%{http_code} %{time_total}" https://schild-api:8790/healthz' 2>/dev/null || echo "000 0"; }
ok=0; : > "$out/$tag.probes.txt"
for i in $(seq 1 "$probes"); do r=$(hz); echo "$r" >> "$out/$tag.probes.txt"; [ "${r%% *}" = 200 ] && ok=$((ok+1)); sleep 1; done

# Real enrolled agent during the attack.
t0=$(date +%s); arc=0
docker compose -p "$project" exec -T app-vm schild-testlab-agent once > "$out/$tag.agent.log" 2>&1 || arc=$?
agent_s=$(( $(date +%s) - t0 ))
accepted=no; grep -q '"status":"accepted"' "$out/$tag.agent.log" && accepted=yes

wait "$lp" 2>/dev/null; wait "$mp" 2>/dev/null; wait 2>/dev/null
r1=$(docker inspect "$api" --format '{{.RestartCount}}')

python3 -I - "$out/$tag.site.json" "$out/$tag.mem.txt" "$ok" "$probes" "$arc" "$agent_s" "$accepted" \
  "$((r1 - r0))" "$tag" "$s1" "$n1" "$c1" "$s2" "$n2" "$c2" "$dur" "$ipmode" "$static_placed" <<'PY' | tee "$out/$tag.json"
import json, sys, re
a = sys.argv
try:
    site = json.load(open(a[1]))
except Exception:
    site = {"n":0,"codes":{},"p50_ms":0,"p95_ms":0,"p99_ms":0,"max_ms":0}
ok200 = site["codes"].get("200", 0)
def mib(s):
    s=s.strip()
    m=re.match(r'([0-9.]+)([KMGi]+)', s)
    if not m: return 0.0
    v=float(m.group(1)); u=m.group(2)
    return v/1024 if u.startswith('K') else v*1024 if u.startswith('G') else v
mems=[mib(l) for l in open(a[2]) if l.strip()]
peak=round(max(mems),1) if mems else 0.0
print(json.dumps({
 "tag": a[9],
 "group1": {"shape": a[10], "attackers": int(a[11]), "conns": int(a[12])},
 "group2": {"shape": a[13], "attackers": int(a[14]), "conns": int(a[15])},
 "seconds": int(a[16]), "ipmode": a[17], "distinct_static_ips": int(a[18]),
 "healthz_during": f"{a[3]}/{a[4]}",
 "agent_once_exit": int(a[5]), "agent_once_seconds": int(a[6]), "agent_once_accepted": a[7],
 "site_requests": site["n"], "site_failed": site["n"]-ok200, "site_codes": site["codes"],
 "site_p50_ms": site["p50_ms"], "site_p95_ms": site.get("p95_ms"), "site_p99_ms": site["p99_ms"], "site_max_ms": site["max_ms"],
 "schild_api_mem_peak_mib": peak, "schild_api_restarts": int(a[8]),
}, indent=1))
PY
