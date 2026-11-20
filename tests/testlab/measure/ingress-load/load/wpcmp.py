# Compare waiting page on/off load runs: normal GETs, navigation flood answers, CPU, memory, counters.
import json, re, sys, os
D = sys.argv[1]
for tag in sys.argv[2:]:
    parts = {}
    for l in open(f'{D}/{tag}.jsonl'):
        l = l.strip()
        if l: d = json.loads(l); parts[d['label'].replace(tag + '-', '')] = d
    s = open(f'{D}/{tag}.stats').read()
    rows = [(int(m.group(1)), float(m.group(2)), float(m.group(3)) * (1024 if m.group(4) == 'GiB' else 1)) for m in re.finditer(r'(\d+)s ([\d.]+)% ([\d.]+)(GiB|MiB)', s)]
    load = [c for t, c, _ in rows if 3 <= t <= 70]
    met = {}
    for f in ('metrics-before', 'metrics-after'):
        for l in open(f'{D}/{tag}.{f}.txt'):
            k, v = l.rsplit(' ', 1); met.setdefault(k, {})[f] = float(v)
    dm = lambda k: met.get(k, {}).get('metrics-after', 0) - met.get(k, {}).get('metrics-before', 0)
    n = parts['normal']; lat = n['latency_ms_by_status'].get('200', {})
    out = {'tag': tag, 'normal_n': n['n'], 'normal_status': n['status'], 'normal_ok1s': round(n['ok_share_within']['1s'] * 100, 1),
           'normal_p50': round(lat.get('p50', 0), 1), 'normal_p99': round(lat.get('p99', 0), 1),
           'flood_status': {k: v['status'] for k, v in parts.items() if k != 'normal'},
           'flood_503_p50': {k: round(v['latency_ms_by_status'].get('503', {}).get('p50', 0), 1) for k, v in parts.items() if k != 'normal'},
           'cpu_mean_pct_load_phase': round(sum(load) / len(load), 1) if load else None, 'cpu_samples': len(load),
           'mem_peak_mib': round(max(r[2] for r in rows)),
           'process_cpu_s': round(dm('process_cpu_seconds_total'), 1),
           'waiting_page_shown': dm('schild_http_waiting_page_shown_total'),
           'fc_busy': dm('schild_http_requests_total{class="fail_closed_waf_busy"}'),
           'fc_timeout': dm('schild_http_requests_total{class="fail_closed_waf_timeout"}'),
           'forwarded': dm('schild_http_requests_total{class="forwarded"}'),
           'bytes_out': dm('schild_http_bytes_total{direction="out"}')}
    print(json.dumps(out))
