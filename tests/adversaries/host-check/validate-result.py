#!/usr/bin/env python3
# Validate a results/<spec>.json against contracts/results.schema.json.
# Usage: python3 -I validate-result.py <contracts_dir> <result.json>
import json, sys
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

contracts, target = sys.argv[1], sys.argv[2]
reg = Registry()
for name in ("results.schema.json", "common.schema.json"):
    with open(f"{contracts}/{name}") as f:
        doc = json.load(f)
    reg = reg.with_resource(name, Resource.from_contents(doc))
    if "$id" in doc:
        reg = reg.with_resource(doc["$id"], Resource.from_contents(doc))
with open(f"{contracts}/results.schema.json") as f:
    schema = json.load(f)
with open(target) as f:
    data = json.load(f)
v = Draft202012Validator(schema, registry=reg)
errs = sorted(v.iter_errors(data), key=lambda e: e.path)
if errs:
    for e in errs:
        print("INVALID:", list(e.path), e.message)
    sys.exit(1)
print("VALID:", target)
