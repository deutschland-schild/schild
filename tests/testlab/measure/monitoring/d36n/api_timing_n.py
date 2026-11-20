#!/usr/bin/env python3
"""D36 re-measurement (TEST ONLY): latency of the website reads on a store
with ~1M events (bulk_d36.sql), REPS calls each (default 20), p50/p95/max,
machine load (uptime) before every set. Every listAlerts filter the API
offers (path, country, net_class, asn, rule, bot_category), each with a
frequent and a rare/no-match value, two filters (400), plus
listAnnotations, listIncidents (site, status), listEvents (site with every
filter), getWebsite, listWebsites, getWebsiteKpis, agent incidents/events.

usage: api_timing_n.py <dashboard base> <cookie jar> <agent base> <token file> <values.json> <out.json> [reps]
  values.json: {"site": "shop.test", "rare_site": "down.test", "country": "DE", "asn": "64500",
                "path": "/search", "rule": "942100", "net_class": "hosting"}  (frequent values)
"""
import json
import subprocess
import sys
import urllib.parse
from datetime import datetime, timedelta, timezone

D, jar, A, tokfile, vfile, outfile = sys.argv[1] + "/api/v0", sys.argv[2], sys.argv[3] + "/agent/v0", sys.argv[4], sys.argv[5], sys.argv[6]
reps = int(sys.argv[7]) if len(sys.argv) > 7 else 20
tok = open(tokfile).read().strip()
v = json.load(open(vfile))
now = datetime.now(timezone.utc)
f = lambda d: (now - timedelta(days=d)).strftime("%Y-%m-%dT%H:%M:%SZ")
q = lambda p: urllib.parse.urlencode(p, doseq=True)
S, R = v["site"], v["rare_site"]


def alerts(site, days, flt=None):
    p = {"from": f(days), "to": f(0)}
    if flt:
        p["filter"] = flt
    return D + f"/websites/{site}/alerts?" + q(p)


sets = {
    "listAlerts": [
        ("listAlerts %s 24h" % S, alerts(S, 1)),
        ("listAlerts %s 7d" % S, alerts(S, 7)),
        ("listAlerts %s 30d" % S, alerts(S, 30)),
        ("listAlerts %s 7d" % R, alerts(R, 7)),
    ],
    "listAnnotations": [
        ("listAnnotations %s 24h" % S, D + f"/websites/{S}/annotations?" + q({"from": f(1), "to": f(0)})),
        ("listAnnotations %s 7d" % S, D + f"/websites/{S}/annotations?" + q({"from": f(7), "to": f(0)})),
        ("listAnnotations %s 7d" % R, D + f"/websites/{R}/annotations?" + q({"from": f(7), "to": f(0)})),
        ("listAnnotations blog.test 30d", D + "/websites/blog.test/annotations?" + q({"from": f(30), "to": f(0)})),
    ],
    "listIncidents": [
        ("listIncidents 7d (no site)", D + "/incidents?" + q({"from": f(7), "to": f(0)})),
        ("listIncidents site=blog.test 7d", D + "/incidents?" + q({"site": "blog.test", "from": f(7), "to": f(0)})),
        ("listIncidents site=shop.test 7d status=unblocked", D + "/incidents?" + q({"site": "shop.test", "status": "unblocked", "from": f(7), "to": f(0)})),
        ("listIncidents site=legacy.test 30d (no incidents)", D + "/incidents?" + q({"site": "legacy.test", "from": f(30), "to": f(0)})),
        ("agent listAgentIncidents site=blog.test 7d", A + "/incidents?" + q({"site": "blog.test", "from": f(7), "to": f(0)})),
    ],
    "listEvents": [
        ("listEvents site=%s" % R, D + "/events?" + q({"site": R, "limit": 100})),
        ("listEvents site=%s outcome=blocked" % R, D + "/events?" + q({"site": R, "outcome": "blocked", "limit": 100})),
        ("listEvents site=%s country=ZZ" % S, D + "/events?" + q({"site": S, "country": "ZZ", "limit": 100})),
        ("listEvents site=%s path=/nothing" % S, D + "/events?" + q({"site": S, "path": "/nothing", "limit": 100})),
        ("listEvents site=%s rule=999999" % S, D + "/events?" + q({"site": S, "rule": "999999", "limit": 100})),
        ("listEvents site=%s net_class=tor" % S, D + "/events?" + q({"site": S, "net_class": "tor", "limit": 100})),
        ("listEvents site=%s method=TRACE" % S, D + "/events?" + q({"site": S, "method": "TRACE", "limit": 100})),
        ("listEvents site=%s ua_class=none" % S, D + "/events?" + q({"site": S, "ua_class": "none", "limit": 100})),
        ("listEvents site=%s q=nothing-matches" % S, D + "/events?" + q({"site": S, "q": "nothing-matches", "limit": 100})),
        ("listEvents site=legacy.test (unprotected)", D + "/events?" + q({"site": "legacy.test", "limit": 100})),
        ("agent listAgentEvents site=%s 24h" % R, A + "/events?" + q({"site": R, "from": f(1), "to": f(0)})),
        ("agent listAgentEvents site=legacy.test 24h", A + "/events?" + q({"site": "legacy.test", "from": f(1), "to": f(0)})),
    ],
    "websites": [
        ("listWebsites", D + "/websites"),
        ("getWebsite %s" % S, D + f"/websites/{S}"),
        ("getWebsiteKpis %s 7d" % S, D + f"/websites/{S}/kpis?" + q({"from": f(7), "to": f(0)})),
    ],
}
for site in (S, R):
    for dim in ("country", "asn", "path", "rule", "net_class"):
        sets["listAlerts"].append((f"listAlerts {site} 7d filter {dim}:{v[dim]} (frequent)", alerts(site, 7, f"{dim}:{v[dim]}")))
    for flt in ("country:ZZ", "asn:4294967000", "path:/nothing", "rule:999999", "net_class:tor", "bot_category:security_scanner"):
        sets["listAlerts"].append((f"listAlerts {site} 7d filter {flt} (rare)", alerts(site, 7, flt)))
    sets["listAlerts"].append((f"listAlerts {site} 30d filter rule:999999 (rare)", alerts(site, 30, "rule:999999")))
sets["listAlerts"].append((f"listAlerts {S} 7d two filters (expect 400)", alerts(S, 7, [f"country:{v['country']}", "rule:999999"])))


def call(url):
    h = ["-H", "Authorization: Bearer " + tok] if url.startswith(A) else ["-b", jar]
    out = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{time_total} %{size_download}"] + h + [url], capture_output=True, text=True).stdout.split()
    return out[0], float(out[1]), int(out[2])


def pct(xs, p):
    xs = sorted(xs)
    import math
    return xs[min(len(xs) - 1, max(0, math.ceil(p * len(xs)) - 1))]


res = {"started": now.isoformat(), "reps": reps, "values": v, "sets": {}}
for name, cases in sets.items():
    up = subprocess.run(["uptime"], capture_output=True, text=True).stdout.strip()
    print(f"== {name}   [{up}]")
    rows = []
    for label, url in cases:
        call(url)  # warm-up, not counted
        ts, code, size = [], None, 0
        for _ in range(reps):
            code, t, size = call(url)
            ts.append(t * 1000)
        r = {"case": label, "status": code, "bytes": size, "p50_ms": round(pct(ts, .5), 1), "p95_ms": round(pct(ts, .95), 1), "max_ms": round(max(ts), 1),
             "url": url.split("?")[0], "query": urllib.parse.unquote(url.split("?", 1)[1]) if "?" in url else ""}
        rows.append(r)
        print(f"  {label:<70} {code} {size:>7} B  p50 {r['p50_ms']:>7} ms  p95 {r['p95_ms']:>7} ms  max {r['max_ms']:>7} ms")
    res["sets"][name] = {"uptime_before": up, "uptime_after": subprocess.run(["uptime"], capture_output=True, text=True).stdout.strip(), "cases": rows}
json.dump(res, open(outfile, "w"), indent=1)
