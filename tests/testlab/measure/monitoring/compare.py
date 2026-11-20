#!/usr/bin/env python3
"""MVP-21 measurement: compare the replay ground truth (spec21 replay) with
what schild stored (listMetricBuckets 1m, getTrafficBreakdown, queryMetricSeries)
through the agent API. TEST ONLY.

  python3 -I compare.py --truth truth.json --api http://127.0.0.1:18789 --token-file token --out report.json
"""
import argparse
import json
import math
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone

EXACT_DIMS = ["country", "net_class", "ua_class", "method", "browser", "os", "device", "bot_category"]
EST_DIMS = ["path", "asn", "referrer"]
COUNTERS = ["requests", "forwarded", "stopped", "blocked_waf", "blocked_behaviour", "rate_limited", "rejected_limit", "challenged",
            "fail_closed", "waiting_page_shown", "would_block", "page_views", "detections", "upstream_errors", "upstream_timeouts", "bytes_in", "bytes_out"]


def iso(t):
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class API:
    def __init__(self, base, token):
        self.base, self.token = base.rstrip("/"), token
        self.host = urllib.parse.urlparse(base).netloc

    def get(self, path, **q):
        url = self.base + path + ("?" + urllib.parse.urlencode(q, doseq=True) if q else "")
        req = urllib.request.Request(url, headers={"Authorization": "Bearer " + self.token, "Host": self.host})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")


def bound(i):
    return math.inf if i >= 57 else 0.05 * 1.25 ** i


def hquant(counts, q):
    c = {int(k): v for k, v in counts.items()}
    tot = sum(c.values())
    if tot == 0:
        return None
    target = math.ceil(q * tot)
    cum = 0
    for i in range(58):
        cum += c.get(i, 0)
        if cum >= target:
            return bound(min(i, 56))
    return bound(56)


def traffic_value(tr, k):
    if k == "fail_closed":
        return tr["fail_closed"]
    return tr.get(k, 0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--truth", required=True)
    ap.add_argument("--api", required=True)
    ap.add_argument("--token-file", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    truth = json.load(open(a.truth))
    api = API(a.api, open(a.token_file).read().strip())
    first, last = truth[0]["minute"], truth[-1]["minute"]
    st, page = api.get("/agent/v0/monitoring/buckets", resolution="1m", **{"from": iso(first)}, limit=50)
    assert st == 200, (st, page)
    buckets = {int(datetime.strptime(b["t"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()): b for b in page["items"]}
    report = {"minutes": [], "summary": {}}
    diffs_total = 0
    tsum = {}
    for t in truth:
        m = t["minute"]
        b = buckets.get(m)
        row = {"minute": iso(m), "unknown_answers": t["unknown"], "counter_diffs": {}, "dim_diffs": {}, "estimates": {}}
        if b is None:
            row["missing_bucket"] = True
            report["minutes"].append(row)
            continue
        tr = b["traffic"]
        tc = t["counters"]
        for k in COUNTERS:
            exp, got = tc.get(k, 0), traffic_value(tr, k)
            tsum[k] = tsum.get(k, 0) + exp
            if exp != got:
                row["counter_diffs"][k] = {"truth": exp, "schild": got}
        for i, k in enumerate(["1xx", "2xx", "3xx", "4xx", "5xx"]):
            exp, got = tc.get("status_" + k, 0), tr["status"]["s" + k] if ("s" + k) in tr["status"] else tr["status"].get(k, 0)
            if exp != got:
                row["counter_diffs"]["status_" + k] = {"truth": exp, "schild": got}
        row["fail_closed_by"] = tr.get("fail_closed_by")
        row["partial"] = b.get("partial")
        top = b.get("top") or {}
        for d in EXACT_DIMS:
            got = {e["key"]: [e["requests"], e["stopped"], e["would_block"]] for e in top.get(d, [])}
            exp = {k: v for k, v in t["dims"].get(d, {}).items()}
            dd = {}
            for k in set(got) | set(exp):
                if got.get(k, [0, 0, 0]) != exp.get(k, [0, 0, 0]):
                    dd[k] = {"truth": exp.get(k, [0, 0, 0]), "schild": got.get(k, [0, 0, 0])}
            if dd:
                row["dim_diffs"][d] = dd
        for d in EST_DIMS:
            lst = top.get(d, [])
            got = {e["key"]: e for e in lst}
            exp = t["dims"].get(d, {})
            viol = []
            for k, v in exp.items():
                e = got.get(k)
                if e is None:
                    continue
                if not (e["requests"] - e["error"] <= v[0] <= e["requests"]):
                    viol.append({"key": k, "truth": v[0], "requests": e["requests"], "error": e["error"]})
            listed_unknown = [k for k in got if k not in exp]
            true_top10 = [k for k, _ in sorted(exp.items(), key=lambda kv: (-kv[1][0], kv[0]))[:10]]
            got_top10 = [e["key"] for e in lst[:10]]
            row["estimates"][d] = {"distinct_truth": len(exp), "listed": len(lst), "top10_overlap": len(set(true_top10) & set(got_top10)),
                                   "bound_violations": viol[:20], "n_violations": len(viol), "listed_keys_not_in_truth": listed_unknown[:10],
                                   "missing_truth_keys_with_more_than_min": [k for k, v in exp.items() if k not in got and lst and v[0] > min(x["requests"] for x in lst)][:10]}
        cl = b.get("clients") or {}
        row["clients"] = {"unique_truth": t["unique"], "unique_schild": cl.get("unique"), "new_truth": t["new"], "new_schild": cl.get("new")}
        for k in ["unique", "new"]:
            tv, sv = t[k], cl.get(k)
            row["clients"][k + "_rel_err"] = None if not tv or sv is None else (sv - tv) / tv
        if "visitors" in t:  # D36 amendment: clients.unique/new count visitors, clients.bots bot clients
            for tk, sk in [("visitors", "unique"), ("visitors_new", "new"), ("bot_clients", "bots")]:
                tv, sv = t[tk], cl.get(sk)
                row["clients"][tk + "_truth"] = tv
                row["clients"][tk + "_schild"] = sv
                row["clients"][tk + "_rel_err"] = None if not tv or sv is None else (sv - tv) / tv
        lat = {}
        for q, qq in [("p50", .5), ("p95", .95), ("p99", .99)]:
            s = hquant(b["latency"]["total"]["counts"], qq)
            c = t["latency_ms"][q]
            lat[q] = {"client_ms": c, "schild_bound_ms": s, "rel": None if not c or s is None else (s - c) / c}
            u = hquant(b["latency"]["upstream"]["counts"], qq)
            lat["upstream_" + q] = {"backend_delay_ms": t["upstream_delay_ms"][q], "schild_bound_ms": u}
        row["latency"] = lat
        # path detections
        pd = t.get("extra", {}).get("path_detections", {})
        pdd = {}
        for e in top.get("path", []):
            if pd.get(e["key"], 0) != e.get("detections", 0):
                pdd[e["key"]] = {"truth": pd.get(e["key"], 0), "schild": e.get("detections", 0)}
        if pdd:
            row["dim_diffs"]["path_detections"] = pdd
        diffs_total += len(row["counter_diffs"]) + sum(len(v) for v in row["dim_diffs"].values())
        report["minutes"].append(row)
    # whole-run breakdowns through getTrafficBreakdown
    bd = {}
    frm, to = iso(first), iso(last + 60)
    for d in EXACT_DIMS + EST_DIMS + ["status_class", "site", "rule"]:
        st, res = api.get("/agent/v0/monitoring/traffic/breakdown", by=d, **{"from": frm, "to": to}, top=100)
        if st != 200:
            bd[d] = {"status": st, "body": res}
            continue
        exp = {}
        for t in truth:
            for k, v in t["dims"].get(d, {}).items():
                e = exp.setdefault(k, [0, 0, 0])
                for i in range(3):
                    e[i] += v[i]
        got = {e["key"]: e for e in res["items"]}
        entry = {"exact_flag": res["exact"], "resolution": res["resolution"], "total": res["total"], "other": res["other"], "n_items": len(res["items"])}
        if d in EXACT_DIMS or d == "status_class":
            dd = {}
            for k in set(got) | set(exp):
                g = got.get(k)
                gv = [g["requests"], g["stopped"], g["would_block"]] if g else [0, 0, 0]
                ev = exp.get(k, [0, 0, 0])
                if d == "status_class":
                    gv, ev = gv[:1], ev[:1]
                if gv != ev:
                    dd[k] = {"truth": ev, "schild": gv}
            entry["diffs"] = dd
        elif d in EST_DIMS:
            viol = []
            for k, v in exp.items():
                g = got.get(k)
                if g and not (g["requests"] - g["error"] <= v[0] <= g["requests"]):
                    viol.append({"key": k, "truth": v[0], "requests": g["requests"], "error": g["error"]})
            t10 = [k for k, _ in sorted(exp.items(), key=lambda kv: (-kv[1][0], kv[0]))[:10]]
            entry["top10_overlap"] = len(set(t10) & set([e["key"] for e in res["items"][:10]]))
            entry["violations"] = viol[:20]
            entry["n_violations"] = len(viol)
            entry["truth_top10"] = t10
            entry["schild_top10"] = [(e["key"], e["requests"], e["error"]) for e in res["items"][:10]]
        else:
            entry["items"] = [(e["key"], e["requests"], e["stopped"], e["would_block"]) for e in res["items"][:40]]
        bd[d] = entry
    report["breakdowns"] = bd
    report["summary"] = {"minutes": len(truth), "buckets_found": sum(1 for t in truth if t["minute"] in buckets), "exact_diffs": diffs_total, "truth_totals": tsum}
    json.dump(report, open(a.out, "w"), indent=1)
    print(json.dumps(report["summary"], indent=1))


if __name__ == "__main__":
    sys.exit(main())
