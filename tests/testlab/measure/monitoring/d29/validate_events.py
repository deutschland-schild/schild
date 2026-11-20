#!/usr/bin/env python3
"""TEST ONLY: validate events (JSON lines on stdin) against
contracts/events.schema.json with python jsonschema (independent of the
Go validator) and print the D29 fields of behaviour events.
Usage: validate_events.py CONTRACTS_DIR < events.jsonl"""
import json, sys, pathlib
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

d = pathlib.Path(sys.argv[1])
reg = Registry()
schemas = {}
for p in d.glob("*.schema.json"):
    s = json.loads(p.read_text())
    schemas[p.name] = s
    r = Resource.from_contents(s)
    reg = reg.with_resource(p.name, r)
    if "$id" in s:
        reg = reg.with_resource(s["$id"], r)
ev = schemas["events.schema.json"]
v = Draft202012Validator(ev, registry=reg)
ok = bad = 0
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    e = json.loads(line)
    errs = sorted(v.iter_errors(e), key=lambda x: list(x.path))
    d_ = e.get("data", {})
    geo = (d_.get("client") or {}).get("geo", {})
    print(json.dumps({"valid": not errs, "type": e["type"], "ip": (d_.get("client") or {}).get("ip"), "net_class": geo.get("net_class"),
                      "scenario": d_.get("scenario"), "action": d_.get("action"), "would_action": d_.get("would_action"), "reason": d_.get("reason"),
                      "level": d_.get("level"), "duration_s": d_.get("duration_s"), "until": d_.get("until"), "time": e.get("time")}))
    for x in errs[:3]:
        print("  ERROR", list(x.path), x.message[:200])
    ok += not errs
    bad += bool(errs)
print(f"python-jsonschema valid {ok} invalid {bad}")
