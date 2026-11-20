#!/usr/bin/env python3
# TEST ONLY: MVP-26 cost summary from cost.sh output.
#   summ.py <outdir> [schild.db ...]
import collections, csv, json, sqlite3, statistics, sys

O = sys.argv[1]
rows = list(csv.DictReader(open(f'{O}/cost.tsv'), delimiter='\t'))
out = {}
for mix in ('replay', 'body'):
    pairs = []
    for r in sorted({x['round'] for x in rows if x['mix'] == mix}):
        d = {x['state']: x for x in rows if x['mix'] == mix and x['round'] == r}
        off, det = d['off'], d['detect']
        n = int(det['waf_n'])
        pairs.append({'round': r, 'n': n, 'cpu_off': float(off['cpu_s']), 'cpu_detect': float(det['cpu_s']), 'cpu_delta_us': (float(det['cpu_s']) - float(off['cpu_s'])) / n * 1e6,
                      'cpu_pct': (float(det['cpu_s']) / float(off['cpu_s']) - 1) * 100, 'waf_delta_us': (float(det['waf_s']) - float(off['waf_s'])) / n * 1e6, 'waf_off_ms': float(off['waf_s']) / n * 1e3})
    ds = [p['cpu_delta_us'] for p in pairs]
    out[mix] = {'pairs': pairs, 'cpu_delta_us_mean': statistics.mean(ds), 'cpu_delta_us_sd': statistics.pstdev(ds), 'cpu_off_ms_per_req': statistics.mean(p['cpu_off'] / p['n'] * 1e3 for p in pairs),
                'cpu_pct_mean': statistics.mean(p['cpu_pct'] for p in pairs)}
    print(mix, {k: round(v, 2) for k, v in out[mix].items() if k != 'pairs'}, [round(d) for d in ds])
# latency, body mix
lat = collections.defaultdict(lambda: collections.defaultdict(list))
for r in sorted({x['round'] for x in rows}):
    st = {x['inst']: x['state'] for x in rows if x['round'] == r}
    for inst, tag in (('ca', 'a'), ('cb', 'b')):
        d = json.load(open(f'{O}/body-{r}-{tag}.json'))
        for c, v in d['classes'].items():
            lat[st[inst]][c].append((v['P50'], v['P99'], v['N'], v['Status']))
for c in sorted(lat['off']):
    f = lambda s, i: statistics.mean(x[i] for x in lat[s][c])
    print(f'{c:16} off p50 {f("off", 0):8.2f} p99 {f("off", 1):8.2f} | detect p50 {f("detect", 0):8.2f} p99 {f("detect", 1):8.2f}', lat['detect'][c][0][3], lat['off'][c][0][3])
out['latency'] = {s: {c: [(x[0], x[1]) for x in v] for c, v in d.items()} for s, d in lat.items()}
# replay latency and classes from the truth files
tr = collections.defaultdict(collections.Counter)
tl = collections.defaultdict(list)
for r in sorted({x['round'] for x in rows}):
    st = {x['inst']: x['state'] for x in rows if x['round'] == r}
    for inst, tag in (('ca', 'a'), ('cb', 'b')):
        for m in json.load(open(f'{O}/truth-{r}-{tag}.json')):
            tr[st[inst]].update(m.get('counters', {}))
            tl[st[inst]].append(m.get('latency_ms', {}))
print({k: dict(v.most_common(14)) for k, v in tr.items()})
print({s: {k: round(statistics.mean(x.get(k, 0) for x in v), 2) for k in v[0]} for s, v in tl.items()})
out['replay_counters'] = {k: dict(v) for k, v in tr.items()}
for db in sys.argv[2:]:
    con = sqlite3.connect(db)
    c = collections.Counter()
    n = 0
    for (b,) in con.execute("select body from events where type='schild.request.evaluated.v1' and rules like '%,6%' or rules like '%,7%' or rules like '%,8%' or rules like '%,9%'"):
        d = json.loads(b)['data']
        n += 1
        for x in d.get('rules', []):
            if x.get('source') == 'crowdsec_hub':
                c[(x['hub']['name'], d.get('path', '')[:50])] += 1
    print(db, 'events scanned', n, c.most_common(10))
json.dump(out, open(f'{O}/summary.json', 'w'), indent=1)
