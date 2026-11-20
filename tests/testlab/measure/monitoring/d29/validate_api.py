#!/usr/bin/env python3
"""TEST ONLY: validate a dashboard API response (JSON file) against a schema
of contracts/api/client-dashboard.openapi.yaml with python jsonschema.
Usage: validate_api.py CONTRACTS_DIR SCHEMA_NAME FILE.json"""
import json, sys, pathlib, yaml
from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

d = pathlib.Path(sys.argv[1]).resolve()
base = "file:///contracts/"
reg = Registry()
for p in d.glob("*.schema.json"):
    s = json.loads(p.read_text())
    reg = reg.with_resource(base + p.name, Resource.from_contents(s, default_specification=DRAFT202012))
    if "$id" in s:
        reg = reg.with_resource(s["$id"], Resource.from_contents(s, default_specification=DRAFT202012))
class L(yaml.SafeLoader):
    pass
# YAML 1.2 booleans only (pyyaml would read off/on/yes/no as booleans).
L.yaml_implicit_resolvers = {k: [r for r in v if r[0] != "tag:yaml.org,2002:bool"] for k, v in yaml.SafeLoader.yaml_implicit_resolvers.items()}
import re
L.add_implicit_resolver("tag:yaml.org,2002:bool", re.compile(r"^(?:true|false)$"), list("tf"))
api = yaml.load((d / "api" / "client-dashboard.openapi.yaml").read_text(), Loader=L)
reg = reg.with_resource(base + "api/client-dashboard.openapi.yaml", Resource.from_contents(api, default_specification=DRAFT202012))
schema = {"$id": base + "api/check.json", "$ref": "client-dashboard.openapi.yaml#/components/schemas/" + sys.argv[2]}
v = Draft202012Validator(schema, registry=reg)
doc = json.loads(pathlib.Path(sys.argv[3]).read_text())
errs = list(v.iter_errors(doc))
for e in errs[:5]:
    print("ERROR", list(e.path), e.message[:300])
print(f"{sys.argv[3]}: {sys.argv[2]} {'valid' if not errs else 'INVALID (%d errors)' % len(errs)}")
sys.exit(1 if errs else 0)
