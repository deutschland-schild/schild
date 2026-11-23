#!/usr/bin/env python3
"""MVP-27 hardening measurement: faults between nodes, crashes, load, 16 gateways, long absence, clocks, versions.

Every scenario is a file of its own (s1_faults.py ... s7_versions.py) with a function run(lab); this runner gives
each a fresh directory, a backend and its processes, writes OUT/<scenario>.json and, from every scenario file found
in OUT, the results file (tests/results/MVP-27-hardening.json). See README.md.
"""
import argparse
import datetime
import hashlib
import importlib
import json
import os
import platform
import subprocess

import hard

SCENARIOS = [("s1", "s1_faults"), ("s2", "s2_crashes"), ("s3", "s3_load"), ("s4", "s4_sizes"), ("s5", "s5_absence"),
             ("s6", "s6_clocks"), ("s7", "s7_versions"), ("s8", "s8_changes")]


def results_json(out_dir, path, repo):
    raws = []
    for key, mod in SCENARIOS:
        f = os.path.join(out_dir, mod + ".json")
        if os.path.exists(f):
            raws.append(json.load(open(f)))
    if not raws:
        return
    metrics = []

    def add(name, value, unit, samples=None, **labels):
        if value is None or isinstance(value, (str, dict, list)):
            return
        e = {"name": name, "value": float(value), "unit": unit}
        if labels:
            e["labels"] = {k: str(v)[:128] for k, v in labels.items()}
        if samples is not None:
            e["samples"] = int(samples)
        metrics.append(e)
    checks = [dict(c, scenario=r["scenario"]) for r in raws for c in r["checks"]]
    for r in raws:
        for v in ("PASS", "FAIL", "INFO"):
            add("checks", sum(1 for c in r["checks"] if c["verdict"] == v), "count", scenario=r["scenario"], verdict=v.lower())
        for m in r.get("metrics", []):
            add(m["name"], m["value"], m["unit"], m.get("samples"), scenario=r["scenario"], **m.get("labels", {}))
    fails = [c for c in checks if c["verdict"] == "FAIL"]
    kcs = []
    for key, expr in hard.KILL.items():
        mine = [c for c in checks if c.get("kill") == key]
        hit = [c for c in mine if c["verdict"] == "FAIL"]
        if hit:
            obs = "; ".join("%s %s: %s" % (c["scenario"], c["id"], c["name"]) for c in hit)
        elif mine:
            obs = "not hit in %d checks of %s" % (len(mine), sorted(set(c["scenario"] for c in mine)))
        else:
            obs = "NOT MEASURED in this run"
        kcs.append({"expr": expr, "hit": bool(hit), "observed": obs[:512]})
    harness = any(c["name"] == "harness" for c in fails)
    doc = {
        "results_version": 0, "spec": "MVP-27",
        "run_id": "hardening-%s" % min(r["started"] for r in raws).replace("-", "").replace(":", ""),
        "started_at": min(r["started"] for r in raws), "finished_at": max(r["finished"] for r in raws),
        "seed": hard.SEED, "profile": "unit", "git_rev": raws[-1]["git_rev"],
        "host": {"os": platform.system().lower(), "arch": platform.machine(), "cpus": os.cpu_count() or 1},
        "images": [{"name": "schild-dev-build", "digest": "sha256:" + raws[-1]["bin_sha256"]}],
        "metrics": metrics[:1024], "kill_criteria": kcs,
        "verdict": "error" if harness else ("fail" if fails else "inconclusive"),
        "notes": ("Hardening measurement of the group of gateways on one machine (127.0.0.1): faults between nodes through a userspace "
                  "TCP proxy, hard crashes, load, 2 and 16 gateways, long absence, clocks, mixed versions. Scenarios in this file: %s. "
                  "Never 'pass': one machine, no balancer, no real network; see tests/results/MVP-27-hardening.md. FAIL checks: %s" % (
                      ", ".join("%s (git %s)" % (r["scenario"], r["git_rev"]) for r in raws),
                      "; ".join("%s %s %s" % (c["scenario"], c["id"], c["name"]) for c in fails) or "none"))[:8000],
        "artifacts": ["tests/results/MVP-27-hardening.md", "tests/results/MVP-27-hardening-checks.json", "tests/testlab/measure/group/hardening/harden.py"],
    }
    with open(path, "w") as f:
        json.dump(doc, f, indent=1)
        f.write("\n")
    # every check with its evidence, next to the results file (the schema of the results file has no place for them)
    with open(path.replace(".json", "-checks.json"), "w") as f:
        json.dump({"spec": "MVP-27", "run_id": doc["run_id"], "seed": hard.SEED,
                   "scenarios": [{"scenario": r["scenario"], "started": r["started"], "finished": r["finished"], "git_rev": r["git_rev"],
                                  "checks": r["checks"], "numbers": r["data"]} for r in raws]}, f, indent=1, default=str)
        f.write("\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True, help="schild development build")
    ap.add_argument("--tool", required=True, help="built helper (tool/main.go)")
    ap.add_argument("--out", required=True, help="directory of the per-scenario files")
    ap.add_argument("--results", default="", help="results file to write from every scenario file in --out")
    ap.add_argument("--port0", type=int, default=19200)
    ap.add_argument("--only", default="", help="comma list of scenarios: s1,s2,...")
    ap.add_argument("--keep", action="store_true", help="keep the data directories")
    ap.add_argument("--old-bin", default="", help="s7: schild built from the older commit")
    ap.add_argument("--old-rev", default="", help="s7: that commit")
    ap.add_argument("--clock-shim", default="", help="s6, s8: built clockshim dylib")
    ap.add_argument("--hostile", default="", help="s8: built adversary of the first measurement (../hostile)")
    ap.add_argument("--quick", action="store_true", help="shorter load and fewer rounds, for work on the harness")
    a = ap.parse_args()
    repo = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", "..", ".."))
    rev = subprocess.run(["git", "-C", repo, "rev-parse", "--short=12", "HEAD"], capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(["git", "-C", repo, "status", "--porcelain", "--untracked-files=no", "--", "gateway", "contract"],
                           capture_output=True, text=True).stdout.strip()
    digest = hashlib.sha256(open(a.bin, "rb").read()).hexdigest()
    version = subprocess.run([a.bin, "version"], capture_output=True, text=True).stdout.splitlines()[0]
    only = [x for x in a.only.split(",") if x]
    os.makedirs(a.out, exist_ok=True)
    for key, mod in SCENARIOS:
        if only and key not in only:
            continue
        print("=== %s" % mod, flush=True)
        started = datetime.datetime.now(datetime.timezone.utc)
        lab = hard.Lab(mod, os.path.abspath(a.bin), os.path.abspath(a.tool), a.port0, keep=a.keep,
                       extra_bins={"old": a.old_bin, "old_rev": a.old_rev, "clock_shim": a.clock_shim, "hostile": a.hostile})
        lab.quick, lab.repo = a.quick, repo
        try:
            hard.scenario(lab, importlib.import_module(mod).run)
        finally:
            lab.close()
        finished = datetime.datetime.now(datetime.timezone.utc)
        n = {v: sum(1 for c in lab.checks if c["verdict"] == v) for v in ("PASS", "FAIL", "INFO")}
        print("=== %s: %s in %.0f s" % (mod, n, (finished - started).total_seconds()), flush=True)
        with open(os.path.join(a.out, mod + ".json"), "w") as f:
            json.dump({"scenario": mod, "started": started.strftime("%Y-%m-%dT%H:%M:%SZ"), "finished": finished.strftime("%Y-%m-%dT%H:%M:%SZ"),
                       "seed": hard.SEED, "git_rev": rev + ("-dirty" if dirty else ""), "bin_sha256": digest, "version": version,
                       "quick": a.quick, "checks": lab.checks, "metrics": lab.data.pop("metrics", []), "data": lab.data}, f, indent=1, default=str)
    if a.results:
        results_json(a.out, a.results, repo)
        print("results:", a.results)


if __name__ == "__main__":
    main()
