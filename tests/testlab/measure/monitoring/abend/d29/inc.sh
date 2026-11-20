#!/bin/sh
# TEST ONLY (abend d29): print incidents of the last 2 h (list) and the detail of each
# as "incident status ip block.until duration_s unblocked_at", list vs detail.
# Env: W, PW, DPORT (see api.sh). Usage: inc.sh > OUT.txt
H=$(cd "$(dirname "$0")" && pwd)
F=$(date -u -v-2H +%Y-%m-%dT%H:%M:%SZ); T=$(date -u -v+1M +%Y-%m-%dT%H:%M:%SZ)
echo "# now $(date -u +%Y-%m-%dT%H:%M:%SZ)"
sh $H/api.sh GET "/incidents?from=$F&to=$T&limit=100" | sed '$d' > /tmp/abend/dd/inc-list.json
python3 -I -c '
import json,subprocess,sys,os
d=json.load(open("/tmp/abend/dd/inc-list.json"))
for i in d["items"]:
    if not (i.get("block")): continue
    out=subprocess.run(["sh",sys.argv[1]+"/api.sh","GET","/incidents/"+i["incident"]],capture_output=True,text=True).stdout.rsplit("\nHTTP",1)[0]
    j=json.loads(out)
    b=i.get("block") or {}; bd=j.get("block") or {}
    print("list  ",i["incident"],i["status"],i["request"].get("ip"),b.get("until"),b.get("duration_s"),i.get("unblocked_at"))
    print("detail",j["incident"],j["status"],j["request"].get("ip"),bd.get("until"),bd.get("duration_s"),j.get("unblocked_at"))
' "$H"
