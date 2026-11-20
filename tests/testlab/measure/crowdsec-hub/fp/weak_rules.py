#!/usr/bin/env python3
# TEST ONLY: MVP-26 measurement. Static view on false positive risk: which hub rules have no URI condition, which
# match on a URI alone, which mention Laravel, Livewire or WordPress. Works on the snapshot.
#   weak_rules.py <snapshot.json>
import base64, json, re, sys
import yaml

d = json.load(open(sys.argv[1]))


def flatten(node):
    if 'and' in node:
        out = [[]]
        for c in node['and']:
            sub = flatten(c)
            out = [a + b for a in out for b in sub]
        return out
    if 'or' in node:
        out = []
        for c in node['or']:
            out += flatten(c)
        return out
    return [[node]]


def s(l):
    m = l.get('match', {})
    return f"{'/'.join(l['zones'])}{':' + ','.join(l['variables']) if l.get('variables') else ''} {m.get('type')} {str(m.get('value'))[:70]!r}"


nouri, urionly, stack = [], [], []
for r in d['rules']:
    raw = base64.b64decode(r['content']).decode()
    y = yaml.safe_load(raw)
    gs = []
    for e in y.get('rules') or []:
        gs += flatten(e)
    for g in gs:
        zs = {z for l in g for z in l['zones']}
        if not zs & {'URI', 'URI_FULL'}:
            nouri.append((r['name'].split('vpatch-')[1], [s(l) for l in g]))
        elif all(set(l['zones']) <= {'URI', 'URI_FULL', 'METHOD'} for l in g):
            urionly.append((r['name'].split('vpatch-')[1], [s(l) for l in g]))
    if re.search(r'(?i)laravel|livewire|wordpress|wp-|woocommerce|ignition', raw):
        stack.append(r['name'].split('vpatch-')[1])
print('no URI condition:', len(nouri))
for x in nouri:
    print('  ', x)
print('URI and method only:', len(urionly))
for x in urionly:
    print('  ', x)
print('stack related:', len(stack), stack)
