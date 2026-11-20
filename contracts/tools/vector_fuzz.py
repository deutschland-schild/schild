#!/usr/bin/env python3
"""Differential fuzz of the whole verification pipeline (Go vs Python).

Takes the signed golden vectors, mutates their payloads structurally
(changed values, removed fields, forbidden or unknown fields), re-signs them
with the original TEST ONLY keys and writes them as a vector set into
--out. `make contracts-fuzz` then runs the Go checker and crosscheck.py on
that set and fails on any disagreement (expectations are ignored there).

    python3 -I vector_fuzz.py --contracts .. --seed 42 --n 2000 --out ../.check/fuzz
"""

import argparse
import base64
import glob
import hashlib
import importlib.util
import json
import os
import random
import shutil

SIGNED = {"envelope", "signal", "feedback", "ack", "checkpoint", "rule-bundle", "withdrawal", "agent-report", "agent-enrolment"}
VALUES = [None, True, 0, -1, 1.5, 1e300, 2 ** 64, "", "x" * 300, "203.0.113.9", "2001:db8::1",
          "2026-02-30T10:00:00Z", "2026-10-26T12:05:00Z", "2026-10-26T11:55:00Z", "2026-10-26T11:00:00Z",
          "2026-11-01T00:00:00Z", [], {}, "sha256:" + "a" * 64, "tip", "NL", "ZZ", "ip", "hosting", 7700001,
          "SecRule ARGS \"@rx a\" \"id:7700001,phase:2,pass,severity:NOTICE,msg:'x'\"",
          "SecRule ARGS \"@rx ^$\" \"id:7700002,phase:2,pass,severity:NOTICE,msg:'x'\"",
          "schild-2026-0412", "schild-main", "lab-b", "all", "rules", 41, 42, 43, 0.34, 0.35, 2, 3, 1.0, 10.0]
EXTRA_KEYS = ["ip", "extra", "host", "x_forwarded_for", "Url", "note", "log", "seq", "version", "scope",
              "rule_ids", "max_action_until", "ja4", "User-Agent"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--contracts", default=os.path.join(os.path.dirname(__file__), ".."))
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--n", type=int, default=2000)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    root = os.path.abspath(a.contracts)
    spec = importlib.util.spec_from_file_location("crosscheck", os.path.join(root, "tools", "crosscheck.py"))
    cc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cc)
    with open(os.path.join(root, "testkeys", "keys.json"), encoding="utf-8") as f:
        seeds = {k["keyid"]: bytes.fromhex(k["seed_hex"]) for k in json.load(f)["keys"]}

    def sign(seed, msg):  # RFC 8032 signing with the arithmetic of crosscheck.py
        h = hashlib.sha512(seed).digest()
        s = int.from_bytes(h[:32], "little")
        s &= (1 << 254) - 8
        s |= 1 << 254
        A = cc._compress(cc._mul(s, cc.G))
        r = int.from_bytes(hashlib.sha512(h[32:] + msg).digest(), "little") % cc.L
        R = cc._compress(cc._mul(r, cc.G))
        k = int.from_bytes(hashlib.sha512(R + A + msg).digest(), "little") % cc.L
        return R + ((r + k * s) % cc.L).to_bytes(32, "little")

    rnd = random.Random(a.seed)

    def pick(o):
        if isinstance(o, dict) and o and rnd.random() < 0.75:
            k = rnd.choice(sorted(o))
            if isinstance(o[k], (dict, list)) and rnd.random() < 0.6:
                return pick(o[k])
            return o, k
        if isinstance(o, list) and o and rnd.random() < 0.75:
            i = rnd.randrange(len(o))
            if isinstance(o[i], (dict, list)) and rnd.random() < 0.6:
                return pick(o[i])
            return o, i
        return o, None

    def mutate(obj):
        for _ in range(rnd.randint(1, 2)):
            o, k = pick(obj)
            if k is None:
                continue
            r = rnd.random()
            if r < 0.55:
                o[k] = rnd.choice(VALUES)
            elif r < 0.75 and isinstance(o, dict):
                del o[k]
            elif isinstance(o, dict):
                o[rnd.choice(EXTRA_KEYS)] = rnd.choice(VALUES)
            else:
                o.append(rnd.choice(VALUES))
        return obj

    vecs = []
    for f in sorted(glob.glob(os.path.join(root, "vectors", "*", "*", "*.json"))):
        with open(f, encoding="utf-8") as fh:
            v = json.load(fh)
        if v["contract"] in SIGNED:
            vecs.append(v)
    shutil.rmtree(a.out, ignore_errors=True)
    for rel in glob.glob(os.path.join(root, "*.schema.json")) + glob.glob(os.path.join(root, "config", "*.schema.json")):
        dst = os.path.join(a.out, os.path.relpath(rel, root))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copy(rel, dst)
    os.makedirs(os.path.join(a.out, "testkeys"), exist_ok=True)
    shutil.copy(os.path.join(root, "testkeys", "keys.json"), os.path.join(a.out, "testkeys", "keys.json"))
    n = 0
    for i in range(a.n):
        v = json.loads(json.dumps(rnd.choice(vecs)))
        try:
            env = json.loads(v["input_raw"])
            payload = json.loads(base64.b64decode(env["payload"]).decode("utf-8"))
        except Exception:
            continue
        pb = json.dumps(mutate(payload), separators=(",", ":")).encode("utf-8")
        env["payload"] = base64.b64encode(pb).decode("ascii")
        env["signatures"] = [
            {"keyid": s["keyid"], "sig": base64.b64encode(sign(seeds[s["keyid"]], cc.pae(env["payloadType"], pb))).decode()}
            if s.get("keyid") in seeds else s
            for s in env.get("signatures", [])
        ]
        v["input_raw"] = json.dumps(env, separators=(",", ":"))
        v.pop("input_decoded", None)
        v["expect"] = {"valid": True}
        d = os.path.join(a.out, "vectors", v["contract"].replace("/", "-"), "valid")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, "%05d.json" % i), "w", encoding="utf-8") as f:
            json.dump(v, f)
        n += 1
    print("vector_fuzz: %d mutated signed vectors (seed %d)" % (n, a.seed))


if __name__ == "__main__":
    main()
