#!/usr/bin/env python3
# TEST ONLY: MVP-26 measurement. Writes the hub items of one .index.json as local files for a CrowdSec container.
# The container gets no hub access and no CAPI: everything it needs comes from this tree.
#   prepare.py <index.json> <outdir>
import base64, json, os, sys

idx, out = sys.argv[1], sys.argv[2]
d = json.load(open(idx))
coll = d['collections']['crowdsecurity/appsec-virtual-patching']['appsec-rules']
rules = os.path.join(out, 'appsec-rules')
cfgs = os.path.join(out, 'appsec-configs')
acq = os.path.join(out, 'acquis.d')
for p in (rules, cfgs, acq):
    os.makedirs(p, exist_ok=True)
n = 0
for name in coll:
    it = d['appsec-rules'][name]
    body = base64.b64decode(it['content'])
    with open(os.path.join(rules, name.split('/')[1] + '.yaml'), 'wb') as f:
        f.write(body)
    n += 1
with open(os.path.join(cfgs, 'virtual-patching.yaml'), 'wb') as f:
    f.write(base64.b64decode(d['appsec-configs']['crowdsecurity/virtual-patching']['content']))
with open(os.path.join(acq, 'appsec.yaml'), 'w') as f:
    f.write('# TEST ONLY\nappsec_configs:\n  - crowdsecurity/virtual-patching\nlabels:\n  type: appsec\nlisten_addr: 0.0.0.0:7422\nsource: appsec\n')
print('rules written', n)
