#!/usr/bin/env python3
# TEST ONLY: MVP-26 switch and agent API. Writes through dashboard and agent API while load runs, checks scope, Host and
# Origin rules, the other routes, history, call log, state_source, differs, reset_state.
#   switch.py <out dir>
import http.client, json, os, re, sqlite3, subprocess, sys, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
INST = os.path.join(HERE, '..', 'inst.sh')
B = '/tmp/m26/bin'
OUT = sys.argv[1]
os.makedirs(OUT, exist_ok=True)
P = 340
D = f'/tmp/m26/i/sw'
e = dict(os.environ, MODE='autoblock', STATE='detect', SETTLING='0', HUBURL='http://127.0.0.1:9/none', HUBAUTO='false')
subprocess.run(['bash', INST, 'start', 'sw', str(P)], env=e, check=True, capture_output=True)
csrf = open(f'{D}/csrf').read().strip()
A = f'{P}89'
AG = int(A)
CFG = f'{D}/schild.yaml'


def tok(*a):
    r = subprocess.run([f'{B}/schild', 'token', 'add', '-config', CFG, '--expires', '90d', *a], capture_output=True, text=True)
    ok = r.returncode == 0 and r.stdout.strip()
    t = r.stdout.splitlines()[0].strip() if ok else None
    return t, (r.stdout + r.stderr).replace(t or '\0', '<token>')


def dash(method, path, body=None, h=()):
    c = ['curl', '-s', '-m', '30', '-w', '\n%{http_code}', '-b', f'{D}/cj', '-H', f'X-CSRF-Token: {csrf}', '-H', 'Content-Type: application/json', '-X', method]
    for x in h:
        c += ['-H', x]
    if body is not None:
        c += ['-d', json.dumps(body)]
    r = subprocess.run(c + [f'http://127.0.0.1:{P}88/api/v0{path}'], capture_output=True, text=True).stdout
    b, _, st = r.rpartition('\n')
    try:
        b = json.loads(b)
    except Exception:
        pass
    return int(st or 0), b


def ag(method, path, token=None, body=None, hdr=None, raw=None):
    c = http.client.HTTPConnection('127.0.0.1', AG, timeout=20)
    h = {'Content-Type': 'application/json'} if method != 'GET' else {}
    if token:
        h['Authorization'] = 'Bearer ' + token
    h.update(hdr or {})
    data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
    c.request(method, path, body=data, headers=h)
    r = c.getresponse()
    b = r.read()
    try:
        b = json.loads(b)
    except Exception:
        b = b[:200].decode('latin-1')
    return r.status, b


def probe(path='/password.htm', ip='203.0.113.77'):
    c = http.client.HTTPConnection('127.0.0.1', int(f'{P}90'), timeout=10)
    c.request('GET', path, headers={'Host': 'shop.test', 'X-Forwarded-For': ip, 'User-Agent': 'Mozilla/5.0 m26'})
    r = c.getresponse()
    r.read()
    return r.status


def wait_probe(want, t=30):
    t0 = time.time()
    n = 0
    while time.time() - t0 < t:
        n += 1
        if probe() == want:
            return round((time.time() - t0) * 1000, 1), n
        time.sleep(0.005)
    return None, n


res = {}
wt, out1 = tok('--scope', 'crowdsec:write', '--label', 'Local agent TESTONLY')
rt, out2 = tok('--scope', 'agent:read', '--label', 'Reader')
xt, out3 = tok('--scope', 'export:read', '--label', 'Export')
res['tokens'] = {'write': bool(wt), 'read': bool(rt), 'export': bool(xt), 'sample_output': out1[:300]}
res['no_label_refused'] = tok('--scope', 'crowdsec:write')[1][:200]

U = '/agent/v0/crowdsec-hub'
res['refuse'] = {
    'no token': ag('PATCH', U, None, {'state': 'off'}),
    'read token': ag('PATCH', U, rt, {'state': 'off'}),
    'export token': ag('PATCH', U, xt, {'state': 'off'}),
    'garbage token': ag('PATCH', U, 'schild_garbage', {'state': 'off'}),
    'write token, Origin set': ag('PATCH', U, wt, {'state': 'off'}, {'Origin': 'https://evil.example'}),
    'write token, foreign Host': ag('PATCH', U, wt, {'state': 'off'}, {'Host': 'evil.example'}),
    'write token, text/plain': ag('PATCH', U, wt, {'state': 'off'}, {'Content-Type': 'text/plain'}),
    'write token, no content type': ag('PATCH', U, wt, None, {}, b'{"state":"off"}'),
    'write token, 2 KiB body': ag('PATCH', U, wt, None, None, b'{"state":"off","x":"' + b'a' * 2048 + b'"}'),
    'write token, bad state': ag('PATCH', U, wt, {'state': 'sperren'}),
    'write token, both fields': ag('PATCH', U, wt, {'state': 'off', 'reset_state': True}),
    'write token, reset false': ag('PATCH', U, wt, {'reset_state': False}),
    'write token, extra field': ag('PATCH', U, wt, {'state': 'off', 'mode': 'observe'}),
    'write token, POST': ag('POST', U, wt, {'state': 'off'}),
    'write token, PUT': ag('PUT', U, wt, {'state': 'off'}),
}
res['state_after_refusals'] = ag('GET', U, rt)[1].get('state')
others = {}
for m, p in (('POST', '/agent/v0/status'), ('PATCH', '/agent/v0/status'), ('DELETE', '/agent/v0/incidents/x'), ('POST', '/agent/v0/incidents'), ('PATCH', '/agent/v0/rules/1'), ('POST', '/agent/v0/rules/1/suspend'),
             ('PATCH', '/agent/v0/settings'), ('PATCH', '/agent/v0/crowdsec-hub/rules/1'), ('PATCH', '/agent/v0/crowdsec-hub/')):
    others[f'{m} {p}'] = ag(m, p, wt, {})[0]
res['other_routes_write_token'] = others
res['read_routes'] = {'read token GET': ag('GET', U, rt)[0], 'write token GET': ag('GET', U, wt)[0], 'write token status': ag('GET', '/agent/v0/status', wt)[0], 'export GET hub': ag('GET', U, xt)[0]}

# MCP
init = {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2025-03-26', 'capabilities': {}, 'clientInfo': {'name': 'm26', 'version': '0'}}}
res['mcp_init'] = ag('POST', '/mcp', wt, init)[0]
tl = ag('POST', '/mcp', wt, {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'})[1]
names = [t['name'] for t in tl['result']['tools']] if isinstance(tl, dict) and 'result' in tl else tl
res['mcp_tools_write_token'] = names
tl2 = ag('POST', '/mcp', rt, {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'})[1]
res['mcp_tools_read_token_has_set'] = 'schild_crowdsec_hub_set' in ([t['name'] for t in tl2['result']['tools']] if isinstance(tl2, dict) and 'result' in tl2 else [])
res['mcp_set_read_token'] = ag('POST', '/mcp', rt, {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call', 'params': {'name': 'schild_crowdsec_hub_set', 'arguments': {'state': 'off'}}})
res['mcp_set_write_token'] = str(ag('POST', '/mcp', wt, {'jsonrpc': '2.0', 'id': 4, 'method': 'tools/call', 'params': {'name': 'schild_crowdsec_hub_set', 'arguments': {'state': 'block'}}}))[:300]
time.sleep(0.5)
res['after_mcp'] = {k: ag('GET', U, rt)[1].get(k) for k in ('state', 'state_source', 'state_set_by', 'config_state', 'differs', 'gateway_effect', 'state_set_at')}
res['dash_reset'] = dash('PATCH', '/rules/crowdsec-hub', {'reset_state': True})[1].get('state_source')

# under load: toggles
load = subprocess.Popen([f'{B}/load', '-target', f'http://127.0.0.1:{P}90', '-mix', 'light', '-rps', '200', '-duration', '75s', '-seed', '27', '-out', f'{OUT}/load-switch.json'], stdout=subprocess.PIPE, text=True)
time.sleep(5)
log = []


def step(label, fn, want):
    t0 = time.time()
    st = fn()
    t1 = time.time()
    w, n = wait_probe(want)
    log.append({'step': label, 'http': st, 'write_ms': round((t1 - t0) * 1000, 1), 'effect_ms_after_write': w, 'probes': n, 't': round(t0 - T0, 2)})
    time.sleep(3)


T0 = time.time()
step('dash detect->block', lambda: dash('PATCH', '/rules/crowdsec-hub', {'state': 'block'})[0], 403)
step('agent block->detect', lambda: ag('PATCH', U, wt, {'state': 'detect'})[0], 200)
step('agent detect->off', lambda: ag('PATCH', U, wt, {'state': 'off'})[0], 200)
step('dash off->block', lambda: dash('PATCH', '/rules/crowdsec-hub', {'state': 'block'})[0], 403)
step('agent block->off', lambda: ag('PATCH', U, wt, {'state': 'off'})[0], 200)
step('agent off->block', lambda: ag('PATCH', U, wt, {'state': 'block'})[0], 403)
# rapid changes coalesce, last one wins
t0 = time.time()
sts = []
for s in ('off', 'detect', 'off', 'block', 'off', 'detect', 'block'):
    sts.append(ag('PATCH', U, wt, {'state': s})[0])
log.append({'step': 'rapid 7 writes', 'http': sts, 'write_ms': round((time.time() - t0) * 1000, 1)})
time.sleep(4)
log.append({'step': 'after rapid', 'state': ag('GET', U, rt)[1].get('state'), 'loaded': ag('GET', U, rt)[1].get('rules_loaded'), 'probe': probe()})
# dashboard and agent at once
errs = []


def w1():
    for i in range(10):
        errs.append(dash('PATCH', '/rules/crowdsec-hub', {'state': 'off' if i % 2 else 'block'})[0])


def w2():
    for i in range(10):
        errs.append(ag('PATCH', U, wt, {'state': 'detect'})[0])


a, b = threading.Thread(target=w1), threading.Thread(target=w2)
a.start(); b.start(); a.join(); b.join()
time.sleep(4)
s = ag('GET', U, rt)[1]
log.append({'step': 'concurrent writers', 'codes': sorted(set(errs)), 'state': s.get('state'), 'source': s.get('state_source'), 'loaded': s.get('rules_loaded'), 'probe': probe()})
res['switch_log'] = log
print(load.communicate()[0])

# history, call log
res['final_write'] = ag('PATCH', U, wt, {'state': 'block'})[0]
time.sleep(1)
s = ag('GET', U, rt)[1]
res['agent_state'] = {k: s.get(k) for k in ('state', 'state_source', 'state_set_by', 'config_state', 'differs', 'gateway_effect', 'limited_by', 'state_set_at')}
subprocess.run(['bash', INST, 'restart', 'sw'], env=e, capture_output=True)
csrf = open(f'{D}/csrf').read().strip()
s = ag('GET', U, rt)[1]
res['after_restart'] = {k: s.get(k) for k in ('state', 'state_source', 'state_set_by', 'differs', 'rules_loaded')}
res['probe_after_restart'] = probe()
tid = s.get('state_set_by', {}).get('token_id') if isinstance(s.get('state_set_by'), dict) else None
r = subprocess.run([f'{B}/schild', 'token', 'log', '-config', CFG, '-n', '200'], capture_output=True, text=True)
open(f'{OUT}/token-log.txt', 'w').write(r.stdout + r.stderr)
res['token_log_lines'] = len(r.stdout.splitlines())
res['token_log_refused_patch'] = sum(1 for l in r.stdout.splitlines() if 'crowdsec' in l.lower() and ('403' in l or '401' in l or 'scope' in l))
res['call_log_api'] = str(ag('GET', '/agent/v0/calls?limit=5', rt))[:300]
if tid:
    res['revoke'] = subprocess.run([f'{B}/schild', 'token', 'revoke', tid, '-config', CFG], capture_output=True, text=True).stdout[:200]
    res['revoked_write'] = ag('PATCH', U, wt, {'state': 'off'})
    s = ag('GET', U, rt)[1]
    res['after_revoke'] = {k: s.get(k) for k in ('state', 'state_source', 'state_set_by')}
con = sqlite3.connect(f'{D}/data/schild.db')
evs = [json.loads(b)['data'] for (b,) in con.execute("select body from events where type='schild.rule.hub_switched.v1' order by seq")]
res['history_events'] = len(evs)
res['history_sample'] = evs[:3] + evs[-3:]
res['history_token_labels'] = sorted({e.get('token_label') or '' for e in evs})
st, b = dash('GET', '/websites')
sites = b.get('items', []) if isinstance(b, dict) else []
res['websites'] = [x.get('id') or x.get('host') for x in sites][:5]
if sites:
    wid = sites[0].get('id') or sites[0].get('host')
    st, a = dash('GET', f'/websites/{wid}/annotations?from=2026-10-30T00:00:00Z&to=2026-10-31T00:00:00Z')
    items = a.get('items', a) if isinstance(a, dict) else a
    res['annotations'] = [x for x in items if isinstance(x, dict) and 'crowdsec' in json.dumps(x)][:3] if isinstance(items, list) else str(a)[:300]
    res['annotations_status'] = st
    res['annotations_total'] = len(items) if isinstance(items, list) else None
res['config_change_events'] = list(con.execute("select type,count(*) from events where type like '%config%' or type like '%setting%' group by 1"))
json.dump(res, open(f'{OUT}/switch.json', 'w'), indent=1, default=str)
print(json.dumps(res, indent=1, default=str)[:7000])
subprocess.run(['bash', INST, 'stop', 'sw'], env=e, capture_output=True)
