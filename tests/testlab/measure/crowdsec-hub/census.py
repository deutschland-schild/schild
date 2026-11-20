#!/usr/bin/env python3
# TEST ONLY: MVP-26 measurement. Shape census of the selected hub rules (zones, transforms, match types, and/or use).
#   census.py <snapshot.json>
import base64, collections, json, sys
import yaml

d = json.load(open(sys.argv[1]))
zones, trans, mt, varz, other = [collections.Counter() for _ in range(5)]
groups = collections.Counter()


def walk(n, f):
    if 'and' in n:
        for x in n['and']:
            walk(x, f)
    elif 'or' in n:
        for x in n['or']:
            walk(x, f)
    else:
        f(n)


for r in d['rules']:
    y = yaml.safe_load(base64.b64decode(r['content']))
    for k in y:
        other[k] += 1
    groups[len(y.get('rules', []) or [])] += 1

    def leaf(n):
        for z in n.get('zones', []):
            zones[z] += 1
            if n.get('variables'):
                varz[z] += 1
        for t in n.get('transform', []) or []:
            trans[t] += 1
        m = n.get('match', {})
        mt[(m.get('type'), bool(m.get('not')))] += 1
    for n in y.get('rules', []) or []:
        walk(n, leaf)
print('top keys', other)
print('entries', sorted(groups.items()))
print('zones', zones.most_common())
print('zones with variables', varz.most_common())
print('transforms', trans.most_common())
print('match', mt.most_common())
