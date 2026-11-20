#!/usr/bin/env python3
"""D36 re-measurement (TEST ONLY), finding (a): getWebsiteKpis and
getTrafficBreakdown(by=status_class) with filter status_class:Nxx against
the ground truth of d36drive.

usage: filter_check_n.py <truth.json> <dashboard base> <cookie jar> <from> <to> <out.json>

Truth per website over the minutes in [from, to): requests per status
class, stopped (blocked_waf + rate_limited + rejected_limit + behaviour:
answered 403/429/413 by schild, all 4xx), fail_closed (503). Expected
under status_class:4xx: stopped = truth stopped; under 5xx: stopped 0 (fail
closed is not "stopped" in the counters) - the API's own rule "fail_closed
503, every other stop 4xx" is reported next to it.
"""
import json
import subprocess
import sys
import urllib.parse
from datetime import datetime, timezone


def parse(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def get(base, jar, path, params):
    url = base + "/api/v0" + path + "?" + urllib.parse.urlencode(params, doseq=True)
    out = subprocess.run(["curl", "-s", "-b", jar, "-w", "\n%{http_code}", url], capture_output=True, text=True).stdout
    body, code = out.rsplit("\n", 1)
    try:
        return int(code), json.loads(body)
    except ValueError:
        return int(code), body


def main():
    truth = json.load(open(sys.argv[1]))
    base, jar, frm, to, out = sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6]
    a, b = parse(frm), parse(to)
    per = {}
    for m in truth["minutes"]:
        if not (a <= parse(m["start"]) < b):
            continue
        for h, c in m["sites"].items():
            h = "shop.test" if h == "www.shop.test" else h
            t = per.setdefault(h, {"requests": 0, "stopped": 0, "fail_closed": 0, "status": {}})
            t["requests"] += c["requests"]
            t["stopped"] += c["stopped"]
            t["fail_closed"] += c["fail_closed"]
            for k, v in c["status"].items():
                t["status"][k] = t["status"].get(k, 0) + v
    res = []
    for site in sorted(per):
        if site == "legacy.test":
            continue
        t = per[site]
        for cls in ("2xx", "4xx", "5xx"):
            code, k = get(base, jar, f"/websites/{site}/kpis", {"from": frm, "to": to, "filter": f"status_class:{cls}"})
            cur = k.get("current", k) if isinstance(k, dict) else {}
            st, rq, wb = cur.get("stopped", {}), cur.get("requests", {}), cur.get("would_block", {})
            exp_stopped = t["stopped"] if cls == "4xx" else 0
            row = {"site": site, "filter": f"status_class:{cls}", "http": code,
                   "requests": rq.get("value"), "requests_exact": rq.get("exact"), "truth_requests": t["status"].get(cls, 0),
                   "stopped": st.get("value"), "stopped_exact": st.get("exact"), "truth_stopped": exp_stopped,
                   "truth_fail_closed_503": t["fail_closed"] if cls == "5xx" else 0,
                   "would_block": wb.get("value"), "would_block_unavailable": wb.get("unavailable")}
            res.append(row)
            print(row)
        code, bd = get(base, jar, "/monitoring/traffic/breakdown", {"by": "status_class", "from": frm, "to": to, "site": site, "top": 10})
        items = {i.get("key"): i for i in (bd.get("items", []) if isinstance(bd, dict) else [])}
        row = {"site": site, "breakdown_status_class_http": code, "exact": bd.get("exact") if isinstance(bd, dict) else None,
               "items": {k: {"requests": v.get("requests"), "stopped": v.get("stopped")} for k, v in items.items()},
               "truth": {"status": t["status"], "stopped": t["stopped"], "fail_closed": t["fail_closed"]}}
        res.append(row)
        print(row)
    json.dump(res, open(out, "w"), indent=1)


if __name__ == "__main__":
    main()
