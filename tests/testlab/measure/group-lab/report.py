#!/usr/bin/env python3
"""Raw results of the lab scenarios (raw-s*.json) to tests/results/MVP-27-lab.json (contracts/results.schema.json).

usage: report.py RAW_DIR RESULTS_FILE

Every check becomes one metric `check` (1 pass, 0 fail) with its id; every number of a check a metric `value`
with the id of the check and the name of the number. The kill criteria of the spec are filled from the checks
named in KILL below; a criterion no check of this harness covers says NOT MEASURED. Humans decide what a hit
kill criterion means.
"""
import datetime
import json
import os
import re
import sys

SPEC = "MVP-27"

# kill criterion of tests/specs/MVP-27-ha-group.yaml -> the checks that speak to it (prefixes of check ids), and
# what is outside this harness
KILL = [
    ("any request waits for a peer or fails because of one (ACME challenge lookups aside)",
     ["2.12", "2.22", "2.32", "2.42", "2.52", "2.62", "2.72", "2.82", "5.11"],
     "direct load on every node while peers were delayed, lossy, cut off, hanging or killed"),
    ("a lost, empty or returning member deletes or weakens access state on another",
     ["1.24", "1.26", "1.28", "2.54", "2.64", "5.10", "5.14"],
     "kill and return, partition and one-way cut with writes on both sides, five of sixteen lost, rolling restart"),
    ("a record that fails signature, schema or caps is applied", [],
     "NOT MEASURED here: see the loopback harness (tests/results/MVP-27.json)"),
    ("an edge or a removed member reads events, requests, settings, logins or keys", ["4.13", "4.14"],
     "edge on the balancer VM: its files and its mesh calls; a removed member was NOT MEASURED here"),
    ("an erased address returns", ["4.12"],
     "only the firewall of the edge was looked at; returning nodes NOT MEASURED here"),
    ("an address outside the proxy allow list can get another address blocked", ["1.15", "1.16", "1.17", "1.18", "1.20"],
     "PROXY header and X-Forwarded-For of senders outside the allow list; start without an allow list"),
    ("a partial answer is shown as complete", [], "NOT MEASURABLE: group queries with partial answers are not built"),
    ("a copy outlives its origin's retention", [], "NOT MEASURED: needs days of retention"),
    ("certificates are lost or issued again by the move into the group", ["7.06", "7.07"],
     "ACME test server pebble: no certificate was lost and the CA issued none twice. But a node that enters a group "
     "which holds the certificate asks the CA for an order of its own at once (7.04), and two nodes started together "
     "both ask (7.10); no second certificate was issued in these runs only because the CA's checks failed (7.08)"),
]


def unit_of(key):
    k = key.lower()
    if re.search(r"(^|_)ms($|_)|latency", k):
        return "ms"
    if "percent" in k:
        return "percent"
    if re.search(r"(_s$|_s_|seconds|^s$)", k):
        return "s"
    return "count"


def leaves(obj, path=""):
    if isinstance(obj, bool):
        yield path, 1.0 if obj else 0.0
    elif isinstance(obj, (int, float)):
        yield path, float(obj)
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from leaves(v, (path + "." if path else "") + str(k))


def stamp(t):
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def read(path, default=""):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return default


def main():
    raw_dir, out_file = sys.argv[1], sys.argv[2]
    rows, started, finished = [], [], []
    for name in sorted(os.listdir(raw_dir)):
        if re.fullmatch(r"raw-s\d+\.json", name):
            d = json.load(open(os.path.join(raw_dir, name)))
            rows += d["rows"]
            started.append(d["started"])
            finished.append(d["saved"])
    by = {"PASS": 0, "FAIL": 0, "INFO": 0}
    metrics = []
    for r in rows:
        by[r["result"]] += 1
    for verdict, n in by.items():
        metrics.append({"name": "checks", "value": float(n), "unit": "count", "labels": {"verdict": verdict.lower()}})
    for sc in sorted(set(r["scenario"] for r in rows)):
        for verdict in ("PASS", "FAIL", "INFO"):
            n = sum(1 for r in rows if r["scenario"] == sc and r["result"] == verdict)
            metrics.append({"name": "checks", "value": float(n), "unit": "count", "labels": {"scenario": sc, "verdict": verdict.lower()}})
    for r in rows:
        if r["result"] != "INFO":
            metrics.append({"name": "check", "value": 1.0 if r["result"] == "PASS" else 0.0, "unit": "bool",
                            "labels": {"id": r["id"], "scenario": r["scenario"], "title": r["title"][:128]}})
    values = []
    for r in rows:
        for key, val in leaves(r["numbers"]):
            if len(key) <= 128:
                values.append({"name": "value", "value": val, "unit": unit_of(key.split(".")[-1] if unit_of(key.split(".")[-1]) != "count" else key),
                               "labels": {"id": r["id"], "number": key}})
    # the schema takes 1024 metrics: the numbers of failed checks first, then the others by id
    failed = set(r["id"] for r in rows if r["result"] == "FAIL")
    values.sort(key=lambda m: (m["labels"]["id"] not in failed,))
    metrics += values[: 1024 - len(metrics)]

    kill = []
    result = {r["id"]: r["result"] for r in rows}
    for expr, ids, what in KILL:
        have = [i for i in ids if i in result]
        bad = [i for i in have if result[i] == "FAIL"]
        if not ids or not have:
            observed = what if not ids else "NOT MEASURED in this run (checks %s did not run)" % ", ".join(ids)
        elif bad:
            observed = "failed checks %s; %s" % (", ".join(bad), what)
        else:
            observed = "checks %s passed; %s" % (", ".join(have), what)
        kill.append({"expr": expr, "hit": bool(bad), "observed": observed[:512]})

    fails = [r for r in rows if r["result"] == "FAIL"]
    image = read(os.path.join(raw_dir, "image-id"))
    rev = read(os.path.join(raw_dir, "git-rev"))
    out = {
        "results_version": 0,
        "spec": SPEC,
        "run_id": "lab-" + datetime.datetime.fromtimestamp(min(started), datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ"),
        "started_at": stamp(min(started)),
        "finished_at": stamp(max(finished)),
        "seed": 27,
        "profile": "unit",
        "host": {"os": ("macOS " + read(os.path.join(raw_dir, "host-os"), "?") + ", Linux VMs")[:64], "arch": "arm64",
                 "cpus": int(read(os.path.join(raw_dir, "host-cpus"), "1")),
                 "mem_mb": max(1, int(read(os.path.join(raw_dir, "host-mem"), "1048576")) // 1048576)},
        "images": [{"name": "sg27-node:dev", "digest": image if re.fullmatch(r"sha256:[0-9a-f]{64}", image) else "sha256:" + "0" * 64}],
        "metrics": metrics,
        "kill_criteria": kill,
        # never 'pass': this is one part of `measure`; a failed check makes it 'fail'
        "verdict": "fail" if fails else "inconclusive",
        "notes": ("Black-box measurement of the group of gateways on real Linux VMs of one lab host (Apple container, one VM per node, "
                  "HAProxy on a balancer VM, nftables for the edge and for faults, a TUN based delay in place of netem). "
                  "Development build of schild, never a release. Not the testlab profiles pair and fleet of the spec. "
                  "Report: tests/results/MVP-27-lab.md. FAIL checks: %s" % (", ".join(r["id"] for r in fails) or "none"))[:8192],
        "artifacts": ["tests/results/MVP-27-lab.md", "tests/testlab/measure/group-lab/run.py"],
    }
    if re.fullmatch(r"[0-9a-f]{7,40}", rev):
        out["git_rev"] = rev
    with open(out_file, "w") as f:
        json.dump(out, f, indent=1)
        f.write("\n")
    print("%s: %d checks, %d PASS, %d FAIL, %d numbers without a pass mark; %d metrics" % (out_file, len(rows), by["PASS"], by["FAIL"], by["INFO"], len(metrics)))
    for r in fails:
        print("FAIL %s %s" % (r["id"], r["title"]))


if __name__ == "__main__":
    main()
