#!/usr/bin/env python3
"""Raw results of the lab scenarios (raw-s*.json) to a results file (contracts/results.schema.json), by default
tests/results/MVP-27-lab-run3.json; the earlier runs are tests/results/MVP-27-lab.json and MVP-27-lab-run2.json.

usage: report.py RAW_DIR RESULTS_FILE [TABLES.md]

With a third argument the checks are also written as Markdown tables, one per scenario, for the report.

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
     ["2.12", "2.22", "2.32", "2.42", "2.52", "2.62", "2.72", "2.82", "5.11", "20.03", "23.02"],
     "direct load on every node while peers were delayed, lossy, cut off, hanging or killed; a rolling upgrade under load"),
    ("a lost, empty or returning member deletes or weakens access state on another",
     ["1.24", "1.26", "1.28", "2.54", "2.64", "5.10", "5.14", "9.05", "9.06", "9.07", "9.08", "12.11", "12.13", "23.03"],
     "kill and return, partition and one-way cut with writes on both sides, five of sixteen lost, rolling restart, "
     "a new group secret server by server, a node restarted in the middle of a count (scenario 12), a rolling upgrade. Not counted here, for people to place: scenario 11, where a block lifted on "
     "another node within a second stays listed on every node and is dropped by an edge (no member was lost or returned)"),
    ("a record that fails signature, schema or caps is applied", [],
     "NOT MEASURED here: see the loopback harness (tests/results/MVP-27.json)"),
    ("an edge or a removed member reads events, requests, settings, logins or keys", ["4.13", "4.14"],
     "edge on the balancer VM: its files and its mesh calls; a removed member was NOT MEASURED here"),
    ("an erased address returns", ["4.12", "9.09"],
     "the firewall of the edge; two erased addresses across a change of the group secret (one erased before, one "
     "erased on a node of the old group after another node had carried its block into the new group)"),
    ("an address outside the proxy allow list can get another address blocked", ["1.15", "1.16", "1.17", "1.18", "1.20"],
     "PROXY header and X-Forwarded-For of senders outside the allow list; start without an allow list"),
    ("a partial answer is shown as complete", ["10.20", "10.20b", "10.20c", "20.02"],
     "counters across nodes with one node killed: whether the answer for the group names it under partial_nodes"),
    ("a copy outlives its origin's retention", [], "NOT MEASURED: needs days of retention"),
    ("certificates are lost or issued again by the move into the group", ["7.04", "7.06", "7.07", "7.10b", "9.10", "21.10", "21.11"],
     "ACME test server pebble: a node that enters a group which holds the certificate, two nodes started together, "
     "a restart with no member reachable, a change of the group secret on three nodes. The count of orders at the CA "
     "(7.10: the one node that orders may place two, its first fails on TLS-ALPN-01) is not part of this criterion"),
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
    report_md = re.sub(r"\.json$", ".md", "tests/results/" + os.path.basename(out_file))
    rows, started, finished = [], [], []
    for name in sorted(os.listdir(raw_dir), key=lambda n: int(re.sub(r"\D", "", n) or 0)):
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
        "host": {"os": "Linux VMs on one host", "arch": "arm64",
                 "cpus": int(read(os.path.join(raw_dir, "host-cpus"), "1")),
                 "mem_mb": max(1, int(read(os.path.join(raw_dir, "host-mem"), "1048576")) // 1048576)},
        "images": [{"name": "sg27-node:dev", "digest": image if re.fullmatch(r"sha256:[0-9a-f]{64}", image) else "sha256:" + "0" * 64}],
        "metrics": metrics,
        "kill_criteria": kill,
        # never 'pass': this is one part of `measure`; a failed check makes it 'fail'
        "verdict": "fail" if fails else "inconclusive",
        "notes": ("Black-box measurement of the group of gateways on real Linux VMs of one lab host (one VM per node, "
                  "HAProxy on a balancer VM, nftables for the edge and for faults, a TUN based delay in place of netem). "
                  "Development build of schild, never a release. Not the testlab profiles pair and fleet of the spec. "
                  "Report: %s. FAIL checks: %s" % (report_md, ", ".join(r["id"] for r in fails) or "none"))[:8192],
        "artifacts": [report_md, "tests/testlab/measure/group-lab/run.py", "tests/testlab/measure/group-lab/run_more.py",
                      "tests/testlab/measure/group-lab/run3.py"],
    }
    if re.fullmatch(r"[0-9a-f]{7,40}", rev):
        out["git_rev"] = rev
    with open(out_file, "w") as f:
        json.dump(out, f, indent=1)
        f.write("\n")
    print("%s: %d checks, %d PASS, %d FAIL, %d numbers without a pass mark; %d metrics" % (out_file, len(rows), by["PASS"], by["FAIL"], by["INFO"], len(metrics)))
    for r in fails:
        print("FAIL %s %s" % (r["id"], r["title"]))
    if len(sys.argv) > 3:
        tables(rows, sys.argv[3])


def flat(v):
    """Numbers of a check as one line of text, as the tables of the report show them."""
    if isinstance(v, dict):
        return ", ".join("%s %s" % (k.replace("_", " "), flat(x) if not isinstance(x, dict) else "(" + flat(x) + ")") for k, v2 in v.items() for x in [v2])
    if isinstance(v, list):
        return "[" + ", ".join(flat(x) if not isinstance(x, dict) else "(" + flat(x) + ")" for x in v) + "]"
    if v is None:
        return "none"
    if isinstance(v, bool):
        return "yes" if v else "no"
    return str(v)


TITLES = {"s1": "a pair behind HAProxy, set up as the guide says", "s2": "network faults between the node VMs (three nodes)",
          "s3": "clocks (three nodes, n3 shifted)", "s4": "the edge on the balancer VM, real nftables", "s5": "sixteen gateways",
          "s7": "certificates with an ACME test server", "s8": "readiness of a node that reaches no member",
          "s9": "a new group secret, server by server (three nodes, a TLS site, an edge)",
          "s10": "the page data of the group and the counters across nodes (three nodes)",
          "s11": "a block set on one node and lifted on another a moment later (three nodes)",
          "s12": "the running counts at a node's start (three nodes behind the balancer)",
          "s13": "the clock rule: the node with the odd clock leaves traffic",
          "s14": "everything set at runtime is shared: every write operation of the dashboard API, the agent API and the command line",
          "s15": "the state comparison (`shared_state`) on three and on sixteen nodes",
          "s16": "the cheaper exchange: idle CPU, events and requests on the other nodes, packet loss",
          "s17": "tasks once per cluster: the keys of the browser check",
          "s18": "throughput on three nodes",
          "s19": "N1 again: a block lifted on another node within a second, eight rounds, an edge running and an edge that joins",
          "s20": "N2 again: a killed node as partial in every answer over several nodes",
          "s21": "N3 again: readiness answers 503, and certificates with the guide's TLS example as it is now",
          "s23": "a rolling upgrade from the earlier build (e54c040) to the current one under load (three nodes behind the balancer)",
          "s24": "the state comparison under changes, by how often something changes",
          "s25": "a difference in settings right after the birth of a group",
          "s22": "N4 again: a node 30 s behind after another was 90 s ahead, as the documents now describe it"}


def tables(rows, path):
    out = []
    for sc in sorted(set(r["scenario"] for r in rows), key=lambda k: int(k[1:])):
        mine = [r for r in rows if r["scenario"] == sc]
        n = {v: sum(1 for r in mine if r["result"] == v) for v in ("PASS", "FAIL", "INFO")}
        out += ["### Scenario %s: %s" % (sc[1:], TITLES.get(sc, "")), "", "%d checks: %d PASS, %d FAIL, %d numbers without a pass mark." % (len(mine), n["PASS"], n["FAIL"], n["INFO"]), "",
                "| # | Check | Result | Numbers |", "| --- | --- | --- | --- |"]
        for r in mine:
            num = "; ".join("%s %s" % (k.replace("_", " "), flat(v) if not isinstance(v, dict) else flat(v)) for k, v in r["numbers"].items())
            if len(num) > 700:
                num = num[:700] + "..."
            res = {"PASS": "PASS", "FAIL": "**FAIL**", "INFO": "number"}[r["result"]]
            out.append("| %s | %s | %s | %s |" % (r["id"], r["title"].replace("|", "/"), res, num.replace("|", "/")))
        out.append("")
    with open(path, "w") as f:
        f.write("\n".join(out))


if __name__ == "__main__":
    main()
