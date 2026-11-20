#!/usr/bin/env python3
"""D36 measurement (TEST ONLY): website status from listWebsites polls
against the status rules (contract/websites.Status thresholds) applied to the
ground truth of d36drive over the same 5-minute window.

usage: status_check.py <truth.json> <status-poll.jsonl> <out.json> [hostmap JSON]

The truth counts each minute's requests as sent evenly between second 3 and
50 of the minute; a minute counts with the share of that interval inside the
window [t - 300 s, t). Expected hard reasons (disrupted): fail_closed >= 5 %
of requests, upstream errors + timeouts >= 20 % of forwarded, 5xx >= 20 % of
requests, each with at least 10 affected requests. A poll is "clear" when
every expected ratio is at least 25 % (relative) away from its threshold, so
step alignment cannot flip it; only clear polls count as hit or miss.
"""
import json
import sys
from datetime import datetime, timezone

MIN_COUNT = 10
RULES = [("fail_closed", lambda c: (c["fail_closed"], c["requests"]), 50),
         ("upstream_unreachable", lambda c: (c["upstream_errors"] + c["upstream_timeouts"], c["forwarded"]), 200),
         ("errors_5xx", lambda c: (c["status"].get("5xx", 0), c["requests"]), 200)]
FIELDS = ["requests", "forwarded", "fail_closed", "upstream_errors", "upstream_timeouts"]


def parse(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()


def main():
    truth = json.load(open(sys.argv[1]))
    polls = [json.loads(l) for l in open(sys.argv[2]) if l.strip()]
    hostmap = json.loads(sys.argv[4]) if len(sys.argv) > 4 else {}
    ignore = set(hostmap.get("_ignore", []))
    mins = []
    for m in truth["minutes"]:
        per = {}
        for h, c in m["sites"].items():
            if h in ignore:
                continue
            s = hostmap.get(h, h)
            d = per.setdefault(s, {k: 0 for k in FIELDS} | {"status": {"5xx": 0}})
            for k in FIELDS:
                d[k] += c[k]
            d["status"]["5xx"] += c["status"].get("5xx", 0)
        mins.append((parse(m["start"]), per))
    first, last = mins[0][0], mins[-1][0] + 60
    rows, hits, misses, unclear = [], 0, 0, 0
    for p in polls:
        t = parse(p["t"])
        if t - 300 < first or t > last + 1:
            continue
        win = {}
        for st, per in mins:
            a, b = st + 3, st + 50
            ov = max(0.0, min(b, t) - max(a, t - 300)) / (b - a)
            if ov <= 0:
                continue
            for s, c in per.items():
                w = win.setdefault(s, {k: 0.0 for k in FIELDS} | {"status": {"5xx": 0.0}})
                for k in FIELDS:
                    w[k] += c[k] * ov
                w["status"]["5xx"] += c["status"]["5xx"] * ov
        for site in p["sites"]:
            sid = site["id"]
            if sid not in win:
                continue
            c = win[sid]
            exp, clear = [], True
            for code, f, per_mil in RULES:
                n, tot = f(c)
                ratio = n * 1000 / tot if tot else 0
                hit = n >= MIN_COUNT and ratio >= per_mil
                if tot and (abs(ratio - per_mil) < 0.25 * per_mil or abs(n - MIN_COUNT) < 3):
                    clear = False
                if hit:
                    exp.append(code)
            got = [r["code"] for r in site["reasons"] if r["code"] in ("fail_closed", "upstream_unreachable", "errors_5xx")]
            soft = [r for r in site["reasons"] if r["code"] in ("site_hint", "server_hint", "baseline_degraded")]
            exp_status = "disrupted" if exp else ("attention" if soft else "ok")
            ok = sorted(got) == sorted(exp) and site["status"] == exp_status
            if not clear:
                unclear += 1
            elif ok:
                hits += 1
            else:
                misses += 1
            rows.append({"t": p["t"], "site": sid, "status": site["status"], "expected_status": exp_status, "hard_got": got, "hard_expected": exp,
                         "clear": clear, "ok": ok, "window": {k: round(v, 1) for k, v in c.items() if k != "status"} | {"s5xx": round(c["status"]["5xx"], 1)},
                         "soft": [r["code"] + (":" + r["hint"] if r.get("hint") else "") for r in soft]})
    json.dump({"hits": hits, "misses": misses, "unclear": unclear, "rows": rows}, open(sys.argv[3], "w"), indent=1)
    print("clear polls: hit", hits, "miss", misses, "| near a threshold (not judged):", unclear)
    for r in rows:
        if r["clear"] and not r["ok"]:
            print("MISS", r["t"], r["site"], r["status"], r["hard_got"], "expected", r["expected_status"], r["hard_expected"], r["window"])


if __name__ == "__main__":
    main()
