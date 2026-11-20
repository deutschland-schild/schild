#!/usr/bin/env python3
"""Evening measurement 2026-10-29, item C (TEST ONLY; adapted from
testlab/measure/monitoring/d36n/metrics_api_latency.py, adds the website KPI case over 7 days).
HTTP latency of queryMetricSeries and
getTrafficBreakdown on a worst-case metrics.db (copied from the in-process
fill, zz_abend_size_test.go in this directory), served by the real binary.

usage: metrics_api_latency.py <dashboard base> <cookie jar> <end ISO> <site or -> <out.json> [reps] [website id for KPIs]
  end: the end of the simulated data (the fill ends at the clock of its start).
Cases: 16 series x 1000 points at 1 min (gateway; with site the traffic
series only), 16 series over 14 days auto, breakdown over 14 days for every
dimension, with and without site. Spec targets: series < 100 ms, breakdown
< 300 ms (p95). uptime is recorded before and after.
"""
import json
import math
import subprocess
import sys
import urllib.parse
from datetime import datetime, timedelta, timezone

base, jar, end_s, site, out = sys.argv[1] + "/api/v0", sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
reps = int(sys.argv[6]) if len(sys.argv) > 6 else 20
end = datetime.strptime(end_s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
ts = lambda d: d.strftime("%Y-%m-%dT%H:%M:%SZ")
GW = ["traffic.requests:rate", "traffic.forwarded:rate", "traffic.stopped:rate", "traffic.fail_closed:rate", "traffic.would_block:rate",
      "traffic.latency_total:p50", "traffic.latency_total:p95", "traffic.latency_total:p99", "traffic.latency_overhead:p95", "traffic.latency_upstream:p95",
      "traffic.bytes_in:rate", "traffic.bytes_out:rate", "traffic.clients_unique", "server.cpu_usage:avg", "server.memory_used:max", "server.disk_used_ratio:max"]
ST = GW[:13] + ["traffic.upstream_errors:rate", "traffic.status_5xx:rate", "traffic.detections:rate"]
DIMS = ["path", "country", "asn", "net_class", "ua_class", "method", "status_class", "site", "referrer", "browser", "os", "device", "bot_category", "rule"]


def url(path, params):
    return base + path + "?" + urllib.parse.urlencode(params, doseq=True)


cases = []
for s in ([""] + ([site] if site != "-" else [])):
    lab = "gateway" if not s else "site=" + s
    extra = {"site": s} if s else {}
    cases.append((f"series 16x1000 1m {lab}", url("/monitoring/series", {"metric": ST if s else GW, "from": ts(end - timedelta(minutes=1000)), "to": ts(end), "resolution": "1m", **extra})))
    cases.append((f"series 16 metrics 14d auto {lab}", url("/monitoring/series", {"metric": ST if s else GW, "from": ts(end - timedelta(days=14)), "to": ts(end), "resolution": "auto", **extra})))
    for d in DIMS:
        cases.append((f"breakdown 14d by={d} {lab}", url("/monitoring/traffic/breakdown", {"by": d, "from": ts(end - timedelta(days=14)), "to": ts(end), "top": 20, **extra})))
if len(sys.argv) > 7:
    # KPIs of one website over 7 days (the handler also computes the previous 7 days)
    cases.append((f"kpis 7d (+previous 7d) website={sys.argv[7]}", url(f"/websites/{urllib.parse.quote(sys.argv[7], safe='')}/kpis", {"from": ts(end - timedelta(days=7)), "to": ts(end)})))


def call(u):
    o = subprocess.run(["curl", "-s", "-o", "/dev/null", "-b", jar, "-w", "%{http_code} %{time_total} %{size_download}", u], capture_output=True, text=True).stdout.split()
    return o[0], float(o[1]) * 1000, int(o[2])


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, max(0, math.ceil(p * len(xs)) - 1))]


res = {"uptime_before": subprocess.run(["uptime"], capture_output=True, text=True).stdout.strip(), "reps": reps, "cases": []}
print(res["uptime_before"])
for name, u in cases:
    call(u)
    xs, code, size = [], None, 0
    for _ in range(reps):
        code, t, size = call(u)
        xs.append(t)
    r = {"case": name, "status": code, "bytes": size, "p50_ms": round(pct(xs, .5), 1), "p95_ms": round(pct(xs, .95), 1), "max_ms": round(max(xs), 1)}
    res["cases"].append(r)
    print(f"{name:<45} {code} {size:>8} B p50 {r['p50_ms']:>7} p95 {r['p95_ms']:>7} max {r['max_ms']:>7} ms")
res["uptime_after"] = subprocess.run(["uptime"], capture_output=True, text=True).stdout.strip()
print(res["uptime_after"])
json.dump(res, open(out, "w"), indent=1)
