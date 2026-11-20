#!/usr/bin/env python3
# TEST ONLY: MVP-26 / D40 third pass on the network-on instance of func2.py: approve and addAllow with a valid body,
# annotation of the switch, CRS score with the source off and on for every generated case.
#   func3.py <out.json>
import base64, json, os, socket, sqlite3, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
INST = os.path.join(HERE, '..', 'inst.sh')
B = '/tmp/m26/bin'
PW = 'schild-m26-TESTONLY-pw'
D = '/tmp/m26/i/pw'
res = {}


def sh(*a, **k):
    return subprocess.run(a, capture_output=True, text=True, **k)


env = dict(os.environ, SCHILD_ALLOW_TEST_KEYS='1', SCHILD_CROWDSEC_HUB_URL='http://127.0.0.1:9/none')
p = subprocess.Popen([f'{B}/schild', 'run', '-config', f'{D}/schild.yaml'], env=env, stdout=open(f'{D}/run-3.log', 'w'), stderr=subprocess.STDOUT)
for _ in range(150):
    if sh('curl', '-sf', '-m', '1', 'http://127.0.0.1:36288/readyz').returncode == 0:
        break
    time.sleep(0.1)
time.sleep(0.4)
sh('curl', '-s', '-c', f'{D}/cj', '-H', 'Content-Type: application/json', '-X', 'POST', '-d', json.dumps({'user': 'admin', 'password': PW}), 'http://127.0.0.1:36288/api/v0/auth/login')
csrf = json.loads(sh('curl', '-s', '-b', f'{D}/cj', 'http://127.0.0.1:36288/api/v0/auth/session').stdout).get('csrf_token', '')


def api(method, path, body=None):
    c = ['curl', '-s', '-m', '30', '-w', '\n%{http_code}', '-b', f'{D}/cj', '-H', f'X-CSRF-Token: {csrf}', '-H', 'Content-Type: application/json', '-X', method]
    if body is not None:
        c += ['-d', json.dumps(body)]
    r = sh(*c, f'http://127.0.0.1:36288/api/v0{path}').stdout
    b, _, st = r.rpartition('\n')
    try:
        b = json.loads(b)
    except Exception:
        pass
    return int(st or 0), b


def short(x):
    return x[0], (x[1].get('code') if isinstance(x[1], dict) else str(x[1])[:60]), (x[1].get('errors') if isinstance(x[1], dict) else None)


r = {}
for label, b in (('none', {}), ('wrong', {'confirm': {'password': 'wrong-password-TESTONLY'}}), ('right', {'confirm': {'password': PW}})):
    r['approve ' + label] = short(api('POST', '/review/rec-1/approve', dict(b, action='block')))
r['addAllow bypass, no password, no confirm flag'] = short(api('POST', '/allowlist', {'cidr': '198.51.100.9/32', 'label': 'TEST ONLY', 'level': 'bypass_waf', 'ttl': '24h'}))
r['addAllow bypass, no password, confirm flag'] = short(api('POST', '/allowlist', {'cidr': '198.51.100.9/32', 'label': 'TEST ONLY', 'level': 'bypass_waf', 'ttl': '24h', 'confirm_bypass': True}))
r['addAllow no_block, no password'] = short(api('POST', '/allowlist', {'cidr': '198.51.100.10/32', 'label': 'TEST ONLY', 'level': 'no_block', 'ttl': '24h'}))
st, w = api('GET', '/websites')
res['websites_raw'] = json.dumps(w)[:300]
items = w if isinstance(w, list) else (w.get('websites') or w.get('items') or [])
api('PATCH', '/rules/crowdsec-hub', {'state': 'detect'})
api('PATCH', '/rules/crowdsec-hub', {'state': 'block'})
time.sleep(1)
ann = []
for s in items[:3]:
    wid = s.get('id') or s.get('website') or s.get('host')
    st, a = api('GET', f'/websites/{wid}/annotations?from=2026-10-30T00:00:00Z&to=2026-10-31T00:00:00Z')
    ann.append((wid, st, json.dumps(a)[:700]))
res['annotations'] = ann
res['3.2b'] = r
p.terminate()
p.wait(10)
json.dump(res, open(sys.argv[1], 'w'), indent=1, default=str)
print(json.dumps(res, indent=0, default=str)[:2500])
