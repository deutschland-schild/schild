import sys, json
for l in open(sys.argv[1]):
    l = l.strip()
    if not l: continue
    d = json.loads(l)
    lat = {k: (round(v['p50'],1), round(v['p99'],1)) for k, v in d['latency_ms_by_status'].items()}
    sh = d['ok_share_within']
    print(f"  {d['label']:<28} n={d['n']:<6} status={d['status']} errors={sum(d['errors'].values())} hangs={d['hangs']} "
          f"ok<=1s={sh['1s']*100:.1f}% ok<=5s={sh['5s']*100:.1f}% ok<=30s={sh['30s']*100:.1f}% p50/p99 by status={lat}")
st = open(sys.argv[2]).read().split('\n')
print("  stats:", "; ".join(x for x in st if x))
