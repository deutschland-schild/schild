#!/usr/bin/env python3
"""D36 measurement (TEST ONLY): fetch the website operations of a running
schild (dashboard with a session cookie, agent API with a bearer token read
from a file, MCP tools) and store every response with its status code.

usage: collect_api.py <dashboard base> <cookie jar> <agent base> <token file> <out dir> <from> <mid> <to>
  [from, mid) is the previous period, [mid, to) the current period of getWebsiteKpis.
"""
import json
import os
import subprocess
import sys
import urllib.parse

SITES = ["shop.test", "blog.test", "app.test", "slow.test", "down.test", "legacy.test"]


def fetch(url, headers, out, name, method="GET", body=None):
    cmd = ["curl", "-s", "-o", os.path.join(out, name + ".json"), "-w", "%{http_code} %{time_total}", "-X", method, url]
    for h in headers:
        cmd += ["-H", h]
    if body is not None:
        cmd += ["-H", "Content-Type: application/json", "--data", json.dumps(body)]
    code, t = subprocess.run(cmd, capture_output=True, text=True).stdout.split()
    return {"name": name, "url": url.split("?")[0], "query": urllib.parse.urlparse(url).query, "status": int(code), "time_s": float(t)}


def main():
    dash, jar, agent, tokfile, out, frm, mid, to = sys.argv[1:9]
    os.makedirs(out, exist_ok=True)
    tok = open(tokfile).read().strip()
    dh = ["Cookie: " + "; ".join(l.split("\t")[5] + "=" + l.split("\t")[6].strip() for l in open(jar) if l.count("\t") >= 6 and not l.startswith("# "))]
    ah = ["Authorization: Bearer " + tok]
    idx = []
    q = urllib.parse.urlencode

    def d(name, path, params=None):
        idx.append(fetch(dash + "/api/v0" + path + ("?" + q(params, doseq=True) if params else ""), dh, out, name))

    def a(name, path, params=None):
        idx.append(fetch(agent + "/agent/v0" + path + ("?" + q(params, doseq=True) if params else ""), ah, out, name))

    d("dash-websites", "/websites")
    for s in SITES:
        k = s.split(".")[0]
        d(f"dash-website-{k}", f"/websites/{s}")
        d(f"dash-kpis-{k}", f"/websites/{s}/kpis", {"from": mid, "to": to})
        d(f"dash-realtime-{k}", f"/websites/{s}/realtime")
        d(f"dash-annotations-{k}", f"/websites/{s}/annotations", {"from": frm, "to": to})
        d(f"dash-alerts-{k}", f"/websites/{s}/alerts", {"from": frm, "to": to})
        d(f"dash-incidents-site-{k}", "/incidents", {"site": s})
        d(f"dash-events-site-{k}", "/events", {"site": s, "limit": 100})
        d(f"dash-behaviour-site-{k}", "/behaviour/hits", {"site": s})
        d(f"dash-waves-site-{k}", "/distributed/waves", {"site": s})
        d(f"dash-now-site-{k}", "/monitoring/now", {"site": s})
        d(f"dash-series-site-{k}", "/monitoring/series", {"site": s, "metric": ["traffic.requests:sum", "traffic.stopped:sum", "traffic.status_5xx:sum"], "from": frm, "to": to, "resolution": "10m"})
        d(f"dash-series1m-site-{k}", "/monitoring/series", {"site": s, "metric": ["traffic.requests:sum"], "from": frm, "to": to, "resolution": "1m"})
        d(f"dash-breakdown-path-{k}", "/monitoring/traffic/breakdown", {"by": "path", "site": s, "from": frm, "to": to})
        d(f"dash-breakdown-country-{k}", "/monitoring/traffic/breakdown", {"by": "country", "site": s, "from": frm, "to": to})
        a(f"agent-website-{k}", f"/websites/{s}")
        a(f"agent-events-site-{k}", "/events", {"site": s, "limit": 100, "from": frm, "to": to})
        a(f"agent-incidents-site-{k}", "/incidents", {"site": s, "from": frm, "to": to})
    d("dash-incidents", "/incidents")
    d("dash-events", "/events", {"limit": 100})
    d("dash-breakdown-site", "/monitoring/traffic/breakdown", {"by": "site", "from": frm, "to": to})
    d("dash-kpis-shop-prev", "/websites/shop.test/kpis", {"from": frm, "to": mid})
    # one filter: answered; two filters / breakdown under a filter: 409 filter_unavailable
    d("dash-kpis-shop-filter1", "/websites/shop.test/kpis", {"from": mid, "to": to, "filter": "status_class:4xx"})
    d("dash-kpis-shop-filter1-path", "/websites/shop.test/kpis", {"from": mid, "to": to, "filter": "path:/search"})
    d("dash-kpis-shop-filter2", "/websites/shop.test/kpis", {"from": mid, "to": to, "filter": ["status_class:4xx", "country:DE"]})
    d("dash-series-shop-filter1", "/monitoring/series", {"site": "shop.test", "metric": "traffic.requests:sum", "from": frm, "to": to, "resolution": "10m", "filter": "status_class:4xx"})
    d("dash-series-shop-filter2", "/monitoring/series", {"site": "shop.test", "metric": "traffic.requests:sum", "from": frm, "to": to, "resolution": "10m", "filter": ["status_class:4xx", "country:DE"]})
    d("dash-breakdown-shop-filter1", "/monitoring/traffic/breakdown", {"by": "path", "site": "shop.test", "from": frm, "to": to, "filter": "country:DE"})
    d("dash-alerts-shop-filter-path", "/websites/shop.test/alerts", {"from": frm, "to": to, "filter": "path:/search"})
    d("dash-alerts-shop-filter2", "/websites/shop.test/alerts", {"from": frm, "to": to, "filter": ["path:/search", "country:DE"]})
    d("dash-website-unknown", "/websites/nope.test")
    d("dash-events-site-unknown", "/events", {"site": "nope.test"})
    a("agent-websites", "/websites")
    a("agent-events", "/events", {"limit": 100, "from": frm, "to": to})
    a("agent-incidents", "/incidents", {"from": frm, "to": to})
    for tool, args in (("schild_websites", {}), ("schild_website", {"website": "shop.test"}), ("schild_events", {"site": "app.test", "from": frm, "to": to}), ("schild_incidents", {"site": "blog.test", "from": frm, "to": to})):
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": tool, "arguments": args}}
        idx.append(fetch(agent + "/mcp", ah, out, "mcp-" + tool + ("-" + str(list(args.values())[0]) if args else ""), "POST", body))
    idx.append(fetch(agent + "/mcp", ah, out, "mcp-tools-list", "POST", {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}))
    json.dump(idx, open(os.path.join(out, "_index.json"), "w"), indent=1)
    for i in idx:
        print(i["status"], round(i["time_s"] * 1000, 1), "ms", i["name"])


if __name__ == "__main__":
    main()
