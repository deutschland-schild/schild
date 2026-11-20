#!/usr/bin/env python3
"""D36 re-measurement (TEST ONLY; copy of testlab/measure/monitoring/d36, 10 min buckets
compared whenever they are closed and hold plan minutes, so a shorter run
than 10 aligned minutes still checks the 10 min ring): per-website counters of a running schild
against the ground truth of d36drive.

usage: compare_sites.py <truth.json> <dashboard base URL> <cookie jar> <out.json> [hostmap JSON]

Reads listMetricBuckets (1 min and 10 min), queryMetricSeries with site,
getTrafficBreakdown with site, getWebsite and getWebsiteKpis, and compares
every exact counter per website and minute (1 min ring) and per 10 min bucket
with the truth. Also checks that the websites of a bucket sum to its gateway
totals. Latency p95 per website and minute against the client-side p95
(+25 % / -5 % bound, loopback).
"""
import json
import subprocess
import sys
import urllib.parse
from datetime import datetime, timedelta, timezone

EXACT = ["requests", "forwarded", "stopped", "blocked_waf", "rate_limited", "rejected_limit", "fail_closed",
         "upstream_errors", "upstream_timeouts", "detections", "bytes_in", "bytes_out"]
STATUS = ["1xx", "2xx", "3xx", "4xx", "5xx"]


def get(base, jar, path, params=None):
    url = base + path
    if params:
        url += "?" + urllib.parse.urlencode(params, doseq=True)
    out = subprocess.run(["curl", "-s", "-b", jar, "-w", "\n%{http_code}", url], capture_output=True, text=True).stdout
    body, code = out.rsplit("\n", 1)
    try:
        return int(code), json.loads(body)
    except ValueError:
        return int(code), body


def ts(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def q_hist(counts, q):
    tot = sum(counts.values())
    if tot == 0:
        return None
    need = q * tot
    acc = 0
    for i in sorted(int(k) for k in counts):
        acc += counts[str(i)]
        if acc >= need:
            return 0.05 * 1.25 ** i
    return None


def flat(tc):
    d = {k: tc.get(k, 0) for k in EXACT}
    for s in STATUS:
        d["s" + s] = tc["status"]["s" + s]
    return d


def tflat(c):
    d = {k: c.get(k, 0) for k in EXACT}
    for s in STATUS:
        d["s" + s] = c["status"].get(s, 0)
    return d


def add(a, b):
    for k, v in b.items():
        a[k] = a.get(k, 0) + v


def main():
    truth_path, base, jar, out_path = sys.argv[1:5]
    hostmap = json.loads(sys.argv[5]) if len(sys.argv) > 5 else {}
    ignore = set(hostmap.get("_ignore", []))
    truth = json.load(open(truth_path))
    # truth per site and minute
    tmin = {}
    for m in truth["minutes"]:
        per = {}
        for host, c in m["sites"].items():
            if host in ignore:
                continue
            site = hostmap.get(host, host)
            add(per.setdefault(site, {}), tflat(c))
            per[site].setdefault("_lat95", []).append((c["requests"], c["lat_p95_ms"]))
        tmin[m["start"]] = per
    starts = sorted(tmin)
    first, last = parse(starts[0]), parse(starts[-1]) + timedelta(minutes=1)
    report = {"minutes": [], "mismatches_1m": 0, "compared_1m": 0, "sum_check_1m": [], "tenmin": [], "latency": []}
    # 1 min ring
    _, b1 = get(base, jar, "/api/v0/monitoring/buckets", {"resolution": "1m", "from": ts(first), "limit": 500})
    by_t = {b["t"]: b for b in b1["items"]}
    for st in starts:
        b = by_t.get(st)
        row = {"t": st, "diff": {}}
        if b is None:
            row["missing_bucket"] = True
            report["minutes"].append(row)
            continue
        sites = {s["site"]: s for s in (b.get("sites") or [])}
        ssum = {}
        for s in sites.values():
            add(ssum, flat(s["traffic"]))
        gw = flat(b["traffic"])
        report["sum_check_1m"].append({"t": st, "diff_sites_minus_gateway": {k: ssum.get(k, 0) - gw[k] for k in gw if ssum.get(k, 0) != gw[k]}})
        for site, tc in tmin[st].items():
            got = flat(sites[site]["traffic"]) if site in sites else None
            for k, v in tc.items():
                if k.startswith("_"):
                    continue
                report["compared_1m"] += 1
                g = got[k] if got else 0
                if g != v:
                    report["mismatches_1m"] += 1
                    row["diff"].setdefault(site, {})[k] = {"truth": v, "schild": g}
            if site in sites and sites[site].get("latency"):
                p = q_hist(sites[site]["latency"]["total"]["counts"], 0.95)
                lat = max(x[1] for x in tc["_lat95"]) if tc["_lat95"] else None
                if p and lat:
                    report["latency"].append({"t": st, "site": site, "schild_p95_ms": round(p, 2), "client_p95_ms": lat, "ratio": round(p / lat, 3)})
        extra = sorted(set(sites) - set(tmin[st]))
        if extra:
            row["sites_without_truth"] = {x: sites[x]["traffic"]["requests"] for x in extra}
        report["minutes"].append(row)
    # 10 min ring
    _, b10 = get(base, jar, "/api/v0/monitoring/buckets", {"resolution": "10m", "from": ts(first - timedelta(minutes=10)), "limit": 50})
    for b in b10["items"]:
        t0 = parse(b["t"])
        mins = [s for s in starts if t0 <= parse(s) < t0 + timedelta(minutes=10)]
        if not mins or t0 + timedelta(minutes=10) > datetime.now(timezone.utc):
            continue  # d36n: every closed bucket with plan minutes (the instance gets no other traffic)
        tt = {}
        for s in mins:
            for site, tc in tmin[s].items():
                add(tt.setdefault(site, {}), {k: v for k, v in tc.items() if not k.startswith("_")})
        sites = {s["site"]: s for s in (b.get("sites") or [])}
        row = {"t": b["t"], "diff": {}, "top_bytes": {}}
        for site, tc in tt.items():
            got = flat(sites[site]["traffic"]) if site in sites else {}
            d = {k: {"truth": v, "schild": got.get(k, 0)} for k, v in tc.items() if got.get(k, 0) != v}
            if d:
                row["diff"][site] = d
            if site in sites and sites[site].get("top") is not None:
                row["top_bytes"][site] = len(json.dumps(sites[site]["top"], separators=(",", ":")))
        ssum = {}
        for s in sites.values():
            add(ssum, flat(s["traffic"]))
        gw = flat(b["traffic"])
        row["diff_sites_minus_gateway"] = {k: ssum.get(k, 0) - gw[k] for k in gw if ssum.get(k, 0) != gw[k]}
        row["truth"] = tt
        report["tenmin"].append(row)
    json.dump(report, open(out_path, "w"), indent=1)
    print("1m: compared", report["compared_1m"], "mismatches", report["mismatches_1m"],
          "| sum!=gateway minutes:", sum(1 for x in report["sum_check_1m"] if x["diff_sites_minus_gateway"]))
    for r in report["tenmin"]:
        print("10m", r["t"], "diff sites:", list(r["diff"]), "sum diff:", r["diff_sites_minus_gateway"], "top bytes:", r["top_bytes"])
    if report["latency"]:
        rs = [x["ratio"] for x in report["latency"]]
        print("latency p95 ratio schild/client: min", min(rs), "max", max(rs), "n", len(rs))


if __name__ == "__main__":
    main()
