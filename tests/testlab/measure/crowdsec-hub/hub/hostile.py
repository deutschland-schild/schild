#!/usr/bin/env python3
# TEST ONLY: MVP-26 update safety under load. The check is triggered through the switch (off -> detect wakes it), which
# also costs two rebuilds; a control run shows what those alone do. Sets: ok, hostile sets within every bound.
#   hostile.py <out dir>
import json, os, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
INST = os.path.join(HERE, '..', 'inst.sh')
B = '/tmp/m26/bin'
OUT = sys.argv[1]
os.makedirs(OUT, exist_ok=True)
P = 343
D = '/tmp/m26/i/hv'
PORT = f'{P}90'
e = dict(os.environ, MODE='observe', STATE='detect', SETTLING='86400', HUBURL='http://127.0.0.1:29700/cur', EXTRA='')


def cur(n):
    open('/tmp/m26/hub/idx/cur.txt', 'w').write(n)


def api(method, path, body=None):
    csrf = open(f'{D}/csrf').read().strip()
    c = ['curl', '-s', '-m', '30', '-b', f'{D}/cj', '-H', f'X-CSRF-Token: {csrf}', '-H', 'Content-Type: application/json', '-X', method]
    if body is not None:
        c += ['-d', json.dumps(body)]
    r = subprocess.run(c + [f'http://127.0.0.1:{P}88/api/v0{path}'], capture_output=True, text=True).stdout
    try:
        return json.loads(r)
    except Exception:
        return r


def status():
    s = api('GET', '/rules/crowdsec-hub')
    return {k: s.get(k) for k in ('set_source', 'update_state', 'rules_loaded', 'rules_skipped', 'last_refusal', 'last_change', 'last_check_at')}


def rss():
    return int(subprocess.run(['ps', '-o', 'rss=', '-p', open(f'{D}/schild.pid').read().strip()], capture_output=True, text=True).stdout or 0)


def trigger(wait=70):
    before = status().get('last_check_at')
    t0 = time.time()
    api('PATCH', '/rules/crowdsec-hub', {'state': 'off'})
    t1 = time.time()
    time.sleep(0.5)
    api('PATCH', '/rules/crowdsec-hub', {'state': 'detect'})
    t2 = time.time()
    while time.time() - t0 < wait:
        s = status()
        if s.get('last_check_at') != before:
            break
        time.sleep(0.3)
    return {'off_ms': round((t1 - t0) * 1000), 'on_ms': round((t2 - t1 - 0.5) * 1000), 'check_s': round(time.time() - t2, 1), 'status': s, 'rss_kb': rss()}


cur('ok')
subprocess.run(['bash', INST, 'start', 'hv', str(P)], env=e, check=True, capture_output=True)
time.sleep(1)
res = {}


def run(label, set_name, mix='light', rps=200, dur=45):
    """load, trigger at second 15, load goes on"""
    cur(set_name)
    p = subprocess.Popen([f'{B}/load', '-target', f'http://127.0.0.1:{PORT}', '-mix', mix, '-rps', str(rps), '-duration', f'{dur}s', '-seed', '28', '-out', f'{OUT}/{label}.json'], stdout=subprocess.PIPE, text=True)
    time.sleep(15)
    r = trigger()
    r['load'] = p.communicate()[0].strip()
    d = json.load(open(f'{OUT}/{label}.json'))
    tl = d['timeline']
    r['bad_seconds'] = [x for x in tl if x['err'] or x['non2xx']][:12]
    r['max_ms_by_phase'] = {'before': max(x['max_ms'] for x in tl if x['s'] < 15), 'after_30s': max(x['max_ms'] for x in tl if x['s'] >= 30)}
    r['p50_before'] = None
    r['classes'] = {k: {a: v[a] for a in ('N', 'P50', 'P99', 'Max', 'Status')} for k, v in d['classes'].items()}
    res[label] = r
    print(label, json.dumps({k: v for k, v in r.items() if k not in ('classes',)})[:700], flush=True)


run('control-ok', 'ok')
run('refused-notjson', 'notjson')
run('refused-huge', 'huge')
run('hang', 'hang', dur=95)
run('newrule', 'newrule')
run('exprx2', 'exprx2')
run('heavy_uri', 'heavy_uri')
s = api('GET', '/rules/crowdsec-hub')
res['heavy_uri_skipped_codes'] = sorted({x['code'] for x in s.get('skipped', [])})
run('heavy_uri_again_body', 'heavy_uri', mix='body', rps=40)
run('heavy_args', 'heavy_args', mix='body', rps=40)
run('back_to_ok', 'ok')
json.dump(res, open(f'{OUT}/hostile.json', 'w'), indent=1)
subprocess.run(['bash', INST, 'stop', 'hv'], env=e, capture_output=True)
