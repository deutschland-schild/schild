#!/usr/bin/env python3
# TEST ONLY: MVP-26 measurement. Compares the verdicts of run_diff.py.
#   analyse.py <cases.json> <res.json> [--show kind]
import collections, json, sys

cases = json.load(open(sys.argv[1]))['cases']
res = json.load(open(sys.argv[2]))
show = sys.argv[4] if len(sys.argv) > 4 else None
tab = collections.defaultdict(collections.Counter)
diffs = []
st = collections.Counter()
for c in cases:
    r = res[str(c['id'])]
    s = c['rule'] in r['schild_hub']
    k = c['rule'] in r['cs_hub']
    anyS, anyK = bool(r['schild_hub']), bool(r['cs_hub'])
    cls = 'both' if s and k else 'schild_only' if s else 'crowdsec_only' if k else 'neither'
    tab[c['kind']][cls] += 1
    if not anyK and r['cs_status'] not in (200,):
        tab[c['kind']]['cs_status_%s' % r['cs_status']] += 1
    st[(r['schild_status'])] += 1
    if cls in ('schild_only', 'crowdsec_only'):
        diffs.append((c, r, cls))
    elif set(r['schild_hub']) != set(r['cs_hub']):
        tab[c['kind']]['other_rules_differ'] += 1
        diffs.append((c, r, 'other'))
print('schild status', st.most_common())
for k, v in sorted(tab.items()):
    print(f'{k:20}', dict(v))
print('rules hit by both:', len({c['rule'] for c in cases if c['kind'] == 'hit' and c['rule'] in res[str(c['id'])]['schild_hub'] and c['rule'] in res[str(c['id'])]['cs_hub']}), 'of', len({c['rule'] for c in cases}))
kinds = collections.Counter((d[0]['kind'], d[2]) for d in diffs)
print(kinds.most_common())
if show:
    for c, r, cls in diffs:
        if show == 'all' or c['kind'] == show or cls == show:
            print(cls, c['id'], c['kind'], c['rule'], c['method'], c['target'][:120], {k: str(v)[:60] for k, v in c['headers'].items()}, 'st', r['schild_status'], 'S', r['schild_hub'], 'C', r['cs_hub'], c['note'])
