#!/usr/bin/env python3
"""D36 re-measurement (TEST ONLY): human-readable summary of the output of
scratch/zz_d36_derive_test.go.

usage: derive_summary.py <derive-out.json>   (prints MATCH/MISS per case and counts per set)
"""
import json
import sys
import collections

outs = json.load(open(sys.argv[1]))
cnt = collections.Counter()


def ws(l):
    return [(w["id"], w["protection"], w["tracked"]) for w in (l or [])]


for o in outs:
    s = o["case"][0]  # n, r, v
    cnt[(s, o["match"])] += 1
    print(("MATCH " if o["match"] else "MISS  ") + o["case"])
    if not o["match"] or o["case"].startswith("n"):
        print("   caddy/prepare error:", o.get("prepare_err") or "-", "| gateway err:", o.get("gateway_err") or "-")
        print("   gateway blocks:", [(b["Addresses"], b["Schild"], b["Proxies"]) for b in (o.get("gateway_blocks") or [])])
        print("   gateway :", ws(o.get("gateway_websites")), o.get("gateway_resolve"))
        print("   expected:", ws(o.get("expected_websites")), o.get("expected_resolve"), o.get("expected_err") or "")
for s in sorted({k[0] for k in cnt}):
    print(f"set {s}: {cnt[(s, True)]} match / {cnt[(s, True)] + cnt[(s, False)]}")
print(f"total: {sum(v for k, v in cnt.items() if k[1])} / {sum(cnt.values())}")
