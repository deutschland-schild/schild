#!/usr/bin/env python3
"""D36 measurement (TEST ONLY): latency of the website reads on a store with
1M events (bulk_d36.sql). 10 calls each, p50 and max.

usage: api_timing.py <dashboard base> <cookie jar> <agent base> <token file>
"""
import statistics
import subprocess
import sys
import urllib.parse
from datetime import datetime, timedelta, timezone

D, jar, A, tokfile = sys.argv[1] + "/api/v0", sys.argv[2], sys.argv[3] + "/agent/v0", sys.argv[4]
tok = open(tokfile).read().strip()
now = datetime.now(timezone.utc)
f = lambda d: (now - timedelta(days=d)).strftime("%Y-%m-%dT%H:%M:%SZ")
q = urllib.parse.urlencode
cases = [
    ("listAlerts shop 7d", D + "/websites/shop.test/alerts?" + q({"from": f(7), "to": f(0)}), "d"),
    ("listAlerts shop 7d filter country:ZZ", D + "/websites/shop.test/alerts?" + q({"from": f(7), "to": f(0), "filter": "country:ZZ"}), "d"),
    ("listAlerts shop 7d filter rule:999999", D + "/websites/shop.test/alerts?" + q({"from": f(7), "to": f(0), "filter": "rule:999999"}), "d"),
    ("listAlerts shop 7d filter path:/nothing", D + "/websites/shop.test/alerts?" + q({"from": f(7), "to": f(0), "filter": "path:/nothing"}), "d"),
    ("listAnnotations shop 7d", D + "/websites/shop.test/annotations?" + q({"from": f(7), "to": f(0)}), "d"),
    ("listAnnotations down 7d", D + "/websites/down.test/annotations?" + q({"from": f(7), "to": f(0)}), "d"),
    ("listIncidents site=blog 7d", D + "/incidents?" + q({"site": "blog.test"}), "d"),
    ("listIncidents site=legacy 30d", D + "/incidents?" + q({"site": "legacy.test", "from": f(30), "to": f(0)}), "d"),
    ("listEvents site=down", D + "/events?" + q({"site": "down.test", "limit": 100}), "d"),
    ("listEvents site=down outcome=blocked", D + "/events?" + q({"site": "down.test", "outcome": "blocked", "limit": 100}), "d"),
    ("getWebsite shop", D + "/websites/shop.test", "d"),
    ("listWebsites", D + "/websites", "d"),
    ("agent listAgentIncidents site=blog 7d", A + "/incidents?" + q({"site": "blog.test", "from": f(7), "to": f(0)}), "a"),
    ("agent listAgentEvents site=down 24h", A + "/events?" + q({"site": "down.test", "from": f(1), "to": f(0)}), "a"),
    ("agent listAgentEvents site=legacy 24h", A + "/events?" + q({"site": "legacy.test", "from": f(1), "to": f(0)}), "a"),
]
for name, url, kind in cases:
    ts, code, size = [], None, 0
    for i in range(10):
        h = ["-b", jar] if kind == "d" else ["-H", "Authorization: Bearer " + tok]
        out = subprocess.run(["curl", "-s", "-o", "/dev/null", "-w", "%{http_code} %{time_total} %{size_download}"] + h + [url], capture_output=True, text=True).stdout.split()
        code, size = out[0], out[2]
        ts.append(float(out[1]) * 1000)
    print(f"{name:42s} status {code} bytes {size:>7} p50 {statistics.median(ts):7.1f} ms  max {max(ts):7.1f} ms")
