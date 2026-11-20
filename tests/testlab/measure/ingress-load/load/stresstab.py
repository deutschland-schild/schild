# One line per stress run: normal GETs (ok within 1 s, 503s, p50/p99), checked share per attack part, memory, Go limit.
import json, re, sys
D = sys.argv[1]
for tag in sys.argv[2:]:
    parts = {}
    for l in open(f'{D}/{tag}.jsonl'):
        l = l.strip()
        if l: d = json.loads(l); parts[d['label'].replace(tag + '-', '')] = d
    s = open(f'{D}/{tag}.stats').read()
    mem = [float(m.group(3)) * (1024 if m.group(4) == 'GiB' else 1) for m in re.finditer(r'(\d+)s ([\d.]+)% ([\d.]+)(GiB|MiB)', s)]
    oom = 'oom=true' in s
    lim = ''
    try:
        for l in open(f'{D}/{tag}.startlog.txt'):
            m = re.search(r'"limit_mib":(\d+)', l)
            if m: lim = m.group(1)
    except FileNotFoundError: pass
    n = parts['normal']; lat = n['latency_ms_by_status'].get('200', {})
    chk = {k: f"{v['status'].get('200', 0) / v['n'] * 100:.1f}%" for k, v in parts.items() if k != 'normal'}
    print(f"{tag:<40} normal ok<=1s {n['ok_share_within']['1s']*100:5.1f}%  503={n['status'].get('503', 0):<4} hangs={n['hangs']:<4} p50/p99 {lat.get('p50', 0):7.1f}/{lat.get('p99', 0):8.1f} ms | checked {chk} | peak {max(mem) if mem else 0:5.0f} MiB last {mem[-1] if mem else 0:5.0f} | golimit {lim} | oom={oom}")
