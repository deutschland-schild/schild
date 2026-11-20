#!/usr/bin/env python3
# TEST ONLY: MVP-29 measurement. Reads every request ring record of one website in a window from the dashboard API of an
# instance (inst.sh) and compares outcomes with a replay run (replay/main.go) by (ip, user agent).
#   ringcheck.py NAME site run.jsonl scenario from to       scenario as analyse.py (which requests must be blocked)
import collections
import json
import subprocess
import sys
import urllib.parse

name, site, path, scen, frm, to = sys.argv[1:7]
D = f"/tmp/m29/i/{name}"
port = open(f"{D}/port").read().strip()
csrf = open(f"{D}/csrf").read().strip()


def get(q):
    out = subprocess.run(["curl", "-s", "-b", f"{D}/cj", "-H", f"X-CSRF-Token: {csrf}",
                          f"http://127.0.0.1:{port}88/api/v0{q}"], capture_output=True, text=True, check=True).stdout
    return json.loads(out)


recs, cur = [], None
while True:
    q = {"from": frm, "to": to, "site": site, "limit": "200"}
    if cur:
        q["cursor"] = cur
    d = get("/requests?" + urllib.parse.urlencode(q))
    recs += d["items"]
    cur = d.get("next_cursor")
    if not cur:
        break
print(f"ring records of {site}: {len(recs)} (sample_rate {d.get('sample_rate')}, scan_capped {d.get('scan_capped')})")



def expect_block(r):  # as analyse.py; observe records what preset_imp would block
    ai = r["category"] == "ai_training"
    if scen == "none":
        return False
    if scen == "preset":
        return ai
    return ai or (r["ranges"] and not r["inside"])

rows = [json.loads(l) for l in open(path)]
want = {}
for r in rows:
    want[(r["ip"], r["ua"].strip())] = r
seen = collections.Counter()
bad = []
for x in recs:
    k = (x["ip"], (x.get("user_agent") or "").strip())
    r = want.get(k)
    if r is None:
        continue
    seen[x["outcome"]] += 1
    blocked_by_policy = x["outcome"] in ("would_block", "blocked_crawler")
    if blocked_by_policy != expect_block(r) and not (x["outcome"] == "would_block" and r["class"] == "other_crawler" and r["category"] == "security_scanner"):
        bad.append((r["class"], r["bot"], x["outcome"], x.get("bot"), x.get("verification"), r["ua"][:80]))
print("matched records by outcome:", dict(seen))
print("deviations:", len(bad))
for b in bad[:30]:
    print("  ", b)
