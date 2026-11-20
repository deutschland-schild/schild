#!/usr/bin/env python3
"""TEST ONLY (MVP-21 re-measurement): query latency on a filled metrics.db
through the agent API. Series 16 metrics x 1000 points (10 s and 1 min),
14-day series (auto), 14-day breakdowns per dimension, with and without site.

  python3 -I querylat.py --api http://127.0.0.1:18289 --token-file token --end 2026-10-29T12:10:00Z --site shop.example --out q.json
"""
import argparse
import json
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone

METRICS = ["traffic.requests:rate", "traffic.forwarded:rate", "traffic.stopped:rate", "traffic.blocked_waf:rate", "traffic.would_block:rate",
           "traffic.status_4xx:rate", "traffic.status_5xx:rate", "traffic.bytes_out:rate", "traffic.latency_total:p95", "traffic.latency_upstream:p95",
           "traffic.clients_unique", "server.cpu_usage", "server.memory_used", "server.disk_used_ratio", "server.tcp_established", "process.cpu_usage"]


def iso(t):
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", required=True)
    ap.add_argument("--token-file", required=True)
    ap.add_argument("--end", required=True)
    ap.add_argument("--site", default="")
    ap.add_argument("--reps", type=int, default=20)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    tok = open(a.token_file).read().strip()
    end = datetime.strptime(a.end, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)

    def get(path, q):
        url = a.api.rstrip("/") + path + "?" + urllib.parse.urlencode(q, doseq=True)
        req = urllib.request.Request(url, headers={"Authorization": "Bearer " + tok})
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                body = r.read()
                st = r.status
        except urllib.error.HTTPError as e:
            body, st = e.read(), e.code
        return st, (time.perf_counter() - t0) * 1000, body

    cases = {
        "series_16x1000_10s": ("/agent/v0/monitoring/series", {"metric": METRICS, "from": iso(end - timedelta(seconds=10000)), "to": iso(end), "resolution": "10s"}),
        "series_16x1000_1m": ("/agent/v0/monitoring/series", {"metric": METRICS, "from": iso(end - timedelta(minutes=1000)), "to": iso(end), "resolution": "1m"}),
        "series_16_14d_auto": ("/agent/v0/monitoring/series", {"metric": METRICS, "from": iso(end - timedelta(days=14)), "to": iso(end)}),
    }
    for d in ["path", "asn", "rule", "country", "referrer", "browser", "status_class"]:
        cases["breakdown_14d_" + d] = ("/agent/v0/monitoring/traffic/breakdown", {"by": d, "from": iso(end - timedelta(days=14)), "to": iso(end), "top": 100})
    if a.site:
        cases["series_16_14d_auto_site"] = ("/agent/v0/monitoring/series", {"metric": METRICS[:10], "from": iso(end - timedelta(days=14)), "to": iso(end), "site": a.site})
        cases["series_16x1000_1m_site"] = ("/agent/v0/monitoring/series", {"metric": METRICS[:10], "from": iso(end - timedelta(minutes=1000)), "to": iso(end), "resolution": "1m", "site": a.site})
        for d in ["path", "country", "rule"]:
            cases["breakdown_14d_site_" + d] = ("/agent/v0/monitoring/traffic/breakdown", {"by": d, "from": iso(end - timedelta(days=14)), "to": iso(end), "top": 100, "site": a.site})
    res = {}
    for name, (path, q) in cases.items():
        times, codes, size, extra = [], set(), 0, {}
        for i in range(a.reps):
            st, ms, body = get(path, q)
            codes.add(st)
            if i > 0:  # first call warms caches
                times.append(ms)
            size = len(body)
            if i == 0:
                try:
                    j = json.loads(body)
                    if "series" in j:
                        extra = {"points": [len(s.get("points", [])) for s in j["series"]][:3], "resolution": j.get("resolution"),
                                 "buckets_per_point": j.get("buckets_per_point")}
                    elif "items" in j:
                        extra = {"items": len(j["items"]), "total": j.get("total"), "resolution": j.get("resolution"), "exact": j.get("exact")}
                    else:
                        extra = {"body": j}
                except Exception:
                    extra = {"raw": body[:200].decode(errors="replace")}
            time.sleep(0.12)  # stay under the per-token rate limit
        times.sort()
        res[name] = {"codes": sorted(codes), "p50_ms": round(times[len(times) // 2], 1), "p95_ms": round(times[int(len(times) * 0.95) - 1], 1),
                     "max_ms": round(times[-1], 1), "bytes": size, **extra}
        print(name, res[name], flush=True)
    json.dump(res, open(a.out, "w"), indent=1)


if __name__ == "__main__":
    main()
