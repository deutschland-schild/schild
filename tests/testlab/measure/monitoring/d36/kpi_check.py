#!/usr/bin/env python3
"""D36 measurement (TEST ONLY): getWebsiteKpis, getWebsite traffic_24h,
queryMetricSeries with site and getTrafficBreakdown with site (collected by
collect_api.py) against the ground truth of d36drive.

usage: kpi_check.py <truth.json> <responses dir> <from> <mid> <to> <out.json> [hostmap JSON]
"""
import json
import os
import sys
from datetime import datetime, timezone


def parse(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def load(d, n):
    p = os.path.join(d, n + ".json")
    try:
        return json.load(open(p))
    except (OSError, ValueError):
        return None


def main():
    truth = json.load(open(sys.argv[1]))
    rd, frm, mid, to, out = sys.argv[2], parse(sys.argv[3]), parse(sys.argv[4]), parse(sys.argv[5]), sys.argv[6]
    hostmap = json.loads(sys.argv[7]) if len(sys.argv) > 7 else {}
    ignore = set(hostmap.get("_ignore", []))

    def period(a, b):
        per = {}
        for m in truth["minutes"]:
            t = parse(m["start"])
            if not (a <= t < b):
                continue
            for h, c in m["sites"].items():
                if h in ignore:
                    continue
                s = hostmap.get(h, h)
                x = per.setdefault(s, {"requests": 0, "stopped": 0, "page_views": 0, "s5xx": 0, "minutes": 0})
                x["requests"] += c["requests"]
                x["stopped"] += c["stopped"]
                x["page_views"] += c["status"].get("2xx", 0)
                x["s5xx"] += c["status"].get("5xx", 0)
        for x in per.values():
            x["error_rate"] = x["s5xx"] / x["requests"] if x["requests"] else None
        return per

    cur, prev = period(mid, to), period(frm, mid)
    rows = []
    for site in sorted(set(cur) | set(prev)):
        k = site.split(".")[0]
        kp = load(rd, f"dash-kpis-{k}")
        if not kp or "current" not in kp:
            rows.append({"site": site, "kpis": kp})
            continue
        r = {"site": site}
        for name, tr, got in (("current", cur.get(site, {}), kp["current"]), ("previous", prev.get(site, {}), kp["previous"])):
            for f in ("requests", "stopped", "page_views", "error_rate"):
                g = got[f]["value"]
                t = tr.get(f)
                ok = (g == t) if f != "error_rate" else (g is not None and t is not None and abs(g - t) < 1e-9)
                r[f"{name}.{f}"] = {"truth": t, "schild": g, "ok": ok}
            r[f"{name}.visitors"] = {"schild": got["visitors"]["value"], "exact": got["visitors"]["exact"]}
            r[f"{name}.latency_p95_ms"] = got["latency_p95_ms"]["value"]
        det = load(rd, f"dash-website-{k}")
        if det:
            r["traffic_24h.requests"] = (det.get("traffic_24h") or {}).get("requests")
            r["incidents_24h"] = det.get("incidents_24h")
        ser = load(rd, f"dash-series-site-{k}")
        if ser and "series" in ser:
            vals = ser["series"][0]["values"]
            r["series10m.requests"] = vals
        ser1 = load(rd, f"dash-series1m-site-{k}")
        if ser1 and "series" in ser1:
            vals = [v for v in ser1["series"][0]["values"]]
            tm = []
            for m in truth["minutes"]:
                t = parse(m["start"])
                if frm <= t < to:
                    tm.append(sum(c["requests"] for h, c in m["sites"].items() if h not in ignore and hostmap.get(h, h) == site))
            r["series1m_vs_truth_mismatch_minutes"] = sum(1 for a, b in zip(vals, tm) if a != b)
            r["series1m_points"] = len(vals)
        bd = load(rd, f"dash-breakdown-country-{k}")
        if bd and "total" in bd:
            r["breakdown_country.total.requests"] = bd["total"]["requests"]
            r["breakdown_truth_requests"] = cur.get(site, {}).get("requests", 0) + prev.get(site, {}).get("requests", 0)
        rows.append(r)
    bad = [(r["site"], k) for r in rows for k, v in r.items() if isinstance(v, dict) and v.get("ok") is False]
    json.dump({"current_truth": cur, "previous_truth": prev, "rows": rows, "mismatches": bad}, open(out, "w"), indent=1)
    print("KPI mismatches:", bad)
    for r in rows:
        print(r["site"], {k: (v["schild"] if isinstance(v, dict) and "schild" in v else v) for k, v in r.items() if k.startswith("current.") or k.startswith("previous.") or k.startswith("traffic") or k.startswith("breakdown") or k.startswith("series1m_vs")})


if __name__ == "__main__":
    main()
