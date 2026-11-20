#!/bin/bash
# TEST ONLY: MVP-26. Copies the raw results out of /tmp/m26 into the repository. No logs with setup codes, no generated
# request bodies (gen_cases.py rebuilds them from the snapshot), no index variants.
#   collect.sh <results dir>
set -u
R=$1; U=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$R"/{cost,diff,fp,hub,effect,d40,standalone}
cp /tmp/m26/cost/r1/cost.tsv /tmp/m26/cost/r1/summary.json /tmp/m26/cost/startup.tsv /tmp/m26/cost/bench.txt "$R/cost/"
for i in 1 2 3 4; do cp /tmp/m26/cost/r1/body-$i-a.json /tmp/m26/cost/r1/body-$i-b.json "$R/cost/"; done
cp /tmp/m26/diff/res2.json /tmp/m26/diff/bodies-off.json /tmp/m26/diff/bodies-detect.json /tmp/m26/diff/score_eq.json /tmp/m26/diff/rules.json "$R/diff/"
python3 "$U/diff/analyse.py" /tmp/m26/diff/cases.json /tmp/m26/diff/res2.json > "$R/diff/analyse.txt"
python3 "$U/fp/weak_rules.py" "$U/../../../gateway/internal/hub/snapshot.json" > "$R/fp/weak_rules.txt"
python3 "$U/census.py" "$U/../../../gateway/internal/hub/snapshot.json" > "$R/diff/census.txt"
cp /tmp/m26/fp/benign.json "$R/fp/"
cp /tmp/m26/hub/scen.json /tmp/m26/hub/persist.json /tmp/m26/hub/extra.json /tmp/m26/hub/access.log /tmp/m26/hub/iv-load.log "$R/hub/"
cp /tmp/m26/hub/host1/hostile.json "$R/hub/"
python3 -I -c "
import json
d=json.load(open('/tmp/m26/hub/iv-load.json'))
json.dump({k:d[k] for k in ('mix','rps','duration_s','dropped','errors','classes')}, open('$R/hub/iv-load-summary.json','w'), indent=1)"
cp /tmp/m26/effect/matrix.json "$R/effect/"; cp /tmp/m26/effect/sw/switch.json /tmp/m26/effect/sw/token-log.txt "$R/effect/"
cp /tmp/m26/d40/func.json /tmp/m26/d40/func2.json /tmp/m26/d40/func3.json /tmp/m26/d40/ingress.json /tmp/m26/d40/relay.json /tmp/m26/d40/slots.txt /tmp/m26/d40/net48.txt /tmp/m26/d40/agg.txt /tmp/m26/d40/stall.json /tmp/m26/d40/login.txt "$R/d40/"
cp /tmp/m26/standalone/capture.txt /tmp/m26/standalone/capture-release.txt "$R/standalone/"
cp /tmp/m26/standalone2/none/status.json /tmp/m26/standalone2/none/events.json /tmp/m26/standalone2/none/probes.txt "$R/standalone/" 2>/dev/null
grep -v setup_code /tmp/m26/standalone2/none/warn.txt > "$R/standalone/warn.txt"
du -sh "$R"
