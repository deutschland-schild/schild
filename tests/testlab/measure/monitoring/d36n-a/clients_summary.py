#!/usr/bin/env python3
"""D36 re-measurement (TEST ONLY): one line per minute from a compare.py report:
exact diffs, visitors / new visitors / bot clients relative error, top-list violations.
  python3 -I clients_summary.py compare.json"""
import json, sys
d = json.load(open(sys.argv[1]))
print("exact_diffs", d["summary"]["exact_diffs"], "requests", d["summary"]["truth_totals"]["requests"])
def pct(x): return "n/a" if x is None else f"{x*100:+.1f} %"
for m in d["minutes"]:
    c = m.get("clients", {})
    v = " ".join(f"{k}:viol={e['n_violations']},top10={e['top10_overlap']}" for k, e in m["estimates"].items())
    print(m["minute"], "partial", m.get("partial"), "| visitors", c.get("visitors_truth"), "->", c.get("visitors_schild"), pct(c.get("visitors_rel_err")),
          "| new", c.get("visitors_new_truth"), "->", c.get("visitors_new_schild"), pct(c.get("visitors_new_rel_err")),
          "| bots", c.get("bot_clients_truth"), "->", c.get("bot_clients_schild"), pct(c.get("bot_clients_rel_err")), "|", v,
          "| counter_diffs", len(m["counter_diffs"]), "dim_diffs", len(m["dim_diffs"]))
for k, b in d["breakdowns"].items():
    print("breakdown", k, "exact_flag", b.get("exact_flag"), "diffs", len(b.get("diffs", {})), "violations", b.get("n_violations"))
