#!/usr/bin/env python3
"""Writes random inputs of the audit decisions (contracts/audit.md) as vectors.

contracts-check (Go) and crosscheck.py (Python) then have to agree on them:
addresses in every spelling, next to each other and inside texts, states of
every action, and calls over several minutes. Part of `make contracts-fuzz`.
"""

import argparse
import glob
import json
import os
import random
import shutil

ADDR = ["203.0.113.7", "203.0.113.77", "203.0.113.0/24", "203.0.113.7/32", "203.0.113.7/24", "203.0.113.7/024", "203.0.113.07",
        "203.0.113.7/255.255.255.0", "192.0.2.4/33", "0.0.0.0/0", "2001:db8::1", "2001:db8:0:0::1", "2001:DB8::1", "2001:db8::/64",
        "2001:db8::1/128", "2001:db8::1:0:0:1", "::ffff:203.0.113.7", "::ffff:203.0.113.7/120", "64:ff9b::203.0.113.7", "fe80::1%eth0",
        "::", "::/0"]
BITS = ["a", ".", ":", "/", " ", "32", "24", "7", "f", ",", "(", ")", "ä", "\n", "‮", "~", "-", "\U0001f4a1"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--contracts", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--n", type=int, default=6000)
    a = ap.parse_args()
    r = random.Random(a.seed)
    shutil.rmtree(a.out, ignore_errors=True)
    vdir = os.path.join(a.out, "vectors", "audit", "valid")
    os.makedirs(vdir)
    os.makedirs(os.path.join(a.out, "config"))
    shutil.copytree(os.path.join(a.contracts, "testkeys"), os.path.join(a.out, "testkeys"))
    for f in glob.glob(os.path.join(a.contracts, "*.schema.json")):
        shutil.copy(f, a.out)
    for f in glob.glob(os.path.join(a.contracts, "config", "*.schema.json")):
        shutil.copy(f, os.path.join(a.out, "config"))
    shutil.copy(os.path.join(a.contracts, "audit-actions.json"), a.out)
    with open(os.path.join(a.contracts, "audit-actions.json"), encoding="utf-8") as f:
        actions = json.load(f)["actions"]
    entries = []
    for f in sorted(glob.glob(os.path.join(a.contracts, "vectors", "audit", "valid", "*.json"))):
        with open(f, encoding="utf-8") as h:
            doc = json.loads(json.load(h)["input_raw"])
        if "entry" in doc:
            entries.append(doc["entry"])

    def text():
        return "".join(r.choice(ADDR) if r.random() < .5 else r.choice(BITS) for _ in range(r.randint(1, 7)))[:120]

    def value():
        return r.choice([lambda: r.choice(ADDR), text, lambda: r.randint(-5, 5), lambda: r.random() * 10, lambda: r.random() < .5, lambda: 1.0,
                         lambda: None, lambda: [r.choice(ADDR + ["x", text()]) for _ in range(r.randint(0, 5))]])()

    def entry():
        e = json.loads(json.dumps(r.choice(entries)))
        if r.random() < .6:
            e["address"] = r.choice(ADDR)
            e.pop("address_cut", None)
        if r.random() < .6:
            e["reason"] = text()
        if r.random() < .3:
            e["subject"]["id"] = r.choice([text(), "x1", r.choice(ADDR)])
        if "label" in e["actor"]:
            e["actor"]["label"] = text()[:40]
        for f in e.get("change", {}).get("fields", []):
            for k in ("before", "after"):
                if k in f and r.random() < .7:
                    f[k] = r.choice([r.choice(ADDR), text()])
            for k in ("added", "removed"):
                if k in f:
                    f[k] = [r.choice([r.choice(ADDR), text()]) for _ in range(r.randint(1, 5))]
        return e

    def state(act):
        m = {}
        for f in act["fields"] + ["/x_key", "/not_listed"]:
            if r.random() < .3:
                continue
            seg, d = f[1:].split("/"), m
            for s in seg[:-1]:
                d = d.setdefault(s.replace("*", r.choice(["a", "b", "b/c", "k~"])), {})
                if not isinstance(d, dict):
                    d = {}
            d[seg[-1].replace("*", r.choice(["a", "b", "my-Token"]))] = value()
        return m

    for i in range(a.n):
        k = r.randint(0, 5)
        if k <= 1:
            doc = {"op": "cut", "now": "2026-11-%02dT12:00:00Z" % r.randint(1, 28), "raw_ip_days": r.randint(1, 30),
                   "erased": [r.choice(ADDR) for _ in range(r.randint(0, 3))], "entry": entry()}
        elif k == 2:
            act = r.choice(actions)
            doc = {"op": "diff", "action": act["action"], "before": r.choice([None, state(act)]), "after": state(act)}
        elif k == 3:
            doc = {"op": "view", "viewer": r.choice([{"kind": "dashboard"}, {"kind": "agent"}, {"kind": "website", "website": "shop.example"}]), "entry": entry()}
        elif k == 4:
            doc = {"op": "entry", "from": r.choice(["local", "member"]), "entry": entry()}
        else:
            doc = {"op": "refused", "max_open": r.randint(0, 3),
                   "calls": [{"t": r.randint(0, 200000), "action": "session.start", "operation": "dashboard:login", "address": r.choice(ADDR)} for _ in range(r.randint(1, 25))]}
        v = {"contract": "audit", "description": "fuzz", "context": {"now": "2026-10-26T12:00:00Z"}, "input_raw": json.dumps(doc, ensure_ascii=False), "expect": {"valid": True}}
        with open(os.path.join(vdir, "%06d.json" % i), "w", encoding="utf-8") as f:
            json.dump(v, f)
    print("audit_fuzz: %d inputs, seed %d" % (a.n, a.seed))


if __name__ == "__main__":
    main()
