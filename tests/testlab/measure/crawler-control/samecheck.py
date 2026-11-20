#!/usr/bin/env python3
# TEST ONLY: MVP-29 measurement. Compares two replay runs request by request: status, body hash, response headers
# (without Date; header values that carry a per-request id are reduced to their names). The body of a block page
# (X-Schild-Incident) carries a per-request id and time, so only its length is compared.
#   samecheck.py a.jsonl b.jsonl
import json
import re
import sys

VOLATILE = re.compile(r"^(x-schild-incident|x-request-id|x-schild-event|set-cookie|etag|last-modified|x-backend-[a-z-]*):", re.I)


def norm(h):
    out = []
    for line in h.splitlines():
        out.append(line.split(":")[0] + ": *" if VOLATILE.match(line) else line)
    return "\n".join(out)


a = {json.loads(l)["n"]: json.loads(l) for l in open(sys.argv[1])}
b = {json.loads(l)["n"]: json.loads(l) for l in open(sys.argv[2])}
diff = []
for n in sorted(a):
    x, y = a[n], b.get(n)
    page = "X-Schild-Incident:" in x["headers"]
    if y is None or x["status"] != y["status"] or (not page and x["body_sha"] != y["body_sha"]) or norm(x["headers"]) != norm(y["headers"]):
        diff.append((n, x["class"], x["status"], y and y["status"], x["ua"][:60]))
print(f"{len(a)} requests compared, {len(diff)} differ")
for d in diff[:20]:
    print("  ", d)
