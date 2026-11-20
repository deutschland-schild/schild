#!/usr/bin/env python3
# TEST ONLY: MVP-29 measurement. Compares one replay run (replay/main.go output) with the ground truth of a scenario.
#   analyse.py <scenario> run.jsonl      scenario: none | preset | preset_imp | observe
# Prints blocked/passed per class and every request whose outcome differs from what the scenario demands.
import collections
import json
import sys

scen, path = sys.argv[1], sys.argv[2]


def expect_block(r):
    if scen in ("none", "observe"):
        return False
    ai = r["category"] == "ai_training"
    if scen == "preset":
        return ai
    if scen == "preset_imp":
        return ai or (r["ranges"] and not r["inside"])
    raise SystemExit("unknown scenario")


rows = [json.loads(l) for l in open(path)]
per = collections.defaultdict(lambda: collections.Counter())
bad = []
other = collections.Counter()
for r in rows:
    blk = r["crawler_blocked"]
    per[r["class"]]["blocked" if blk else "passed"] += 1
    if r.get("err"):
        per[r["class"]]["error"] += 1
    if not blk and r["status"] != 200:
        other[(r["class"], r["status"])] += 1
    if blk != expect_block(r):
        bad.append(r)
print(f"scenario {scen}: {len(rows)} requests")
print(f"{'class':20} {'n':>5} {'blocked':>8} {'passed':>7}")
for c in sorted(per):
    x = per[c]
    print(f"{c:20} {x['blocked'] + x['passed']:5} {x['blocked']:8} {x['passed']:7}" + (f"  errors {x['error']}" if x["error"] else ""))
if other:
    print("non-200 answers that are not the crawler block:", dict(other))
print(f"deviations from ground truth: {len(bad)}")
for r in bad[:40]:
    print("  ", r["class"], r["bot"], r["category"], "inside" if r["inside"] else "outside", r["status"], repr(r["ua"][:90]), r.get("note", ""))
