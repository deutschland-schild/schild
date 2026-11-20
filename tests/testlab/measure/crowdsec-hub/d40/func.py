#!/usr/bin/env python3
# TEST ONLY: MVP-26 / D40 measurement. Review items 1.2 (too broad trusted_proxies), 1.3 (setup code), 2.2 (no h2c),
# 3.2 (password on heikle actions). Own instances, own ports, documentation addresses.
#   func.py <out.json>
import http.client, json, os, re, socket, sqlite3, subprocess, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
INST = os.path.join(HERE, '..', 'inst.sh')
B = '/tmp/m26/bin'
res = {}
PW = 'schild-m26-TESTONLY-pw'


def sh(*a, **k):
    return subprocess.run(a, capture_output=True, text=True, **k)


def api(D, port, method, path, body=None, cookies=True, hdr=()):
    csrf = open(f'{D}/csrf').read().strip() if os.path.exists(f'{D}/csrf') else ''
    c = ['curl', '-s', '-m', '30', '-w', '\n%{http_code}', '-H', f'X-CSRF-Token: {csrf}', '-H', 'Content-Type: application/json', '-X', method]
    if cookies:
        c += ['-b', f'{D}/cj']
    for h in hdr:
        c += ['-H', h]
    if body is not None:
        c += ['-d', json.dumps(body)]
    r = sh(*c, f'http://127.0.0.1:{port}88/api/v0{path}').stdout
    b, _, st = r.rpartition('\n')
    try:
        b = json.loads(b)
    except Exception:
        pass
    return int(st or 0), b


ECHO = []


class Echo(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def _a(self):
        n = int(self.headers.get('Content-Length') or 0)
        if n:
            self.rfile.read(n)
        ECHO.append(dict(self.headers.items()))
        self.send_response(200)
        self.send_header('Content-Length', '3')
        self.end_headers()
        self.wfile.write(b'ok\n')

    do_GET = do_POST = _a

    def log_message(self, *a):
        pass


# ---- 1.2
def tp_case(i, lst):
    name, P = f'tp{i}', 350 + i
    e = dict(os.environ, MODE='autoblock', STATE='off', TRUSTED=json.dumps(lst), HUBURL='http://127.0.0.1:9/none', HUBAUTO='false',
             EXTRA='/tmp/m26/d40/wr.yaml')
    p = sh('bash', INST, 'start', name, str(P), env=e)
    D = f'/tmp/m26/i/{name}'
    out = {'list': lst, 'started': 'up' in p.stdout, 'start_out': p.stdout[-200:]}
    if 'up' not in p.stdout:
        return out
    SPOOF = '203.0.113.50'
    for k in range(6):
        c = http.client.HTTPConnection('127.0.0.1', int(f'{P}90'), timeout=8)
        c.request('GET', '/?q=%3Cscript%3Ealert(1)%3C/script%3E&a=1%27%20OR%201=1--', headers={'Host': 'shop.test', 'X-Forwarded-For': SPOOF, 'User-Agent': 'Mozilla/5.0 m26'})
        r = c.getresponse()
        r.read()
        out['attack_status'] = r.status
    time.sleep(1.5)
    con = sqlite3.connect(D + '/data/schild.db')
    out['event_ips'] = [list(x) for x in con.execute("select ip, count(*) from events where type like 'schild.request.%' group by 1")]
    out['incident_ips'] = [list(x) for x in con.execute("select ip, count(*) from incidents group by 1")]
    d = json.loads(next(con.execute("select body from events where type like 'schild.request.%' limit 1"))[0])['data']
    out['attribution'] = d.get('client', {}).get('attribution')
    st, ov = api(D, P, 'GET', '/overview')
    out['overview_has_reason'] = 'trusted_proxies_too_broad' in json.dumps(ov)
    out['log_error'] = [l[:220] for l in open(f'{D}/schild-1.log') if 'trusted' in l.lower()][:2]
    # another client, spoofing the address the first one got blocked under, and a clean request
    c = http.client.HTTPConnection('127.0.0.1', int(f'{P}90'), timeout=8)
    c.request('GET', '/about', headers={'Host': 'shop.test', 'X-Forwarded-For': SPOOF, 'User-Agent': 'Mozilla/5.0 m26'})
    r = c.getresponse()
    r.read()
    out['clean_after'] = r.status
    sh('bash', INST, 'stop', name, env=e)
    return out


open('/tmp/m26/d40/wr.yaml', 'w').write('behaviour:\n  presets: [generic]\n  preset_limits: "off"\n  scenarios:\n    waf_repeat: { mode: block }\n')
res['1.2'] = [tp_case(i, l) for i, l in enumerate((['0.0.0.0/0'], ['::/0'], ['10.0.0.0/7'], ['0.0.0.0/1', '128.0.0.0/1'], ['::ffff:0:0/96'], ['127.0.0.1/32', '0.0.0.0/0'], ['127.0.0.1/32'], ['127.0.0.0/8']))]

# backend view with a too broad list: echo backend on the instance's backend port
e = dict(os.environ, MODE='observe', STATE='off', TRUSTED='["0.0.0.0/0"]', HUBURL='http://127.0.0.1:9/none', HUBAUTO='false')
sh('bash', INST, 'start', 'tpb', '359', env=e)
sh('bash', INST, 'stop', 'tpb', env=e)
D = '/tmp/m26/i/tpb'
srv = ThreadingHTTPServer(('127.0.0.1', 35999), Echo)
threading.Thread(target=srv.serve_forever, daemon=True).start()
pid = subprocess.Popen([f'{B}/schild', 'run', '-config', f'{D}/schild.yaml'], env=dict(e, SCHILD_ALLOW_TEST_KEYS='1'), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
for _ in range(100):
    try:
        socket.create_connection(('127.0.0.1', 35990), 0.2).close()
        break
    except OSError:
        time.sleep(0.1)
time.sleep(0.5)
c = http.client.HTTPConnection('127.0.0.1', 35990, timeout=8)
c.request('GET', '/about', headers={'Host': 'shop.test', 'X-Forwarded-For': '203.0.113.50', 'X-Real-IP': '203.0.113.51', 'User-Agent': 'Mozilla/5.0 m26'})
r = c.getresponse()
r.read()
res['1.2_backend_headers'] = {k: v for k, v in (ECHO[-1] if ECHO else {}).items() if k.lower() in ('x-forwarded-for', 'x-real-ip', 'forwarded')}
pid.terminate()
pid.wait(10)


# ---- 1.3
e = dict(os.environ, MODE='observe', STATE='off', HUBURL='http://127.0.0.1:9/none', HUBAUTO='false')
sh('bash', INST, 'start', 'su', '360', env=e)
D = '/tmp/m26/i/su'
sh('bash', INST, 'stop', 'su', env=e)
con = sqlite3.connect(D + '/data/schild.db')
tabs = [t[0] for t in con.execute("select name from sqlite_master where type='table'")]
u = [t for t in tabs if 'user' in t][0]
con.execute(f'delete from {u}')
con.commit()
con.close()
subprocess.run(['bash', '-c', f'rm -f {D}/cj {D}/csrf'])
env2 = dict(e, SCHILD_ALLOW_TEST_KEYS='1')
L = f'{D}/run-su.log'
p = subprocess.Popen([f'{B}/schild', 'run', '-config', f'{D}/schild.yaml'], env=env2, stdout=open(L, 'w'), stderr=subprocess.STDOUT)
for _ in range(100):
    if sh('curl', '-sf', '-m', '1', 'http://127.0.0.1:36088/readyz').returncode == 0:
        break
    time.sleep(0.1)
time.sleep(0.5)
m = re.search(r'"setup_code":"([^"]+)"', open(L).read())
code = m.group(1) if m else None


def setup(body, hdr=(), port=36088):
    c = ['curl', '-s', '-m', '10', '-w', '\n%{http_code}', '-H', 'Content-Type: application/json', '-X', 'POST', '-d', json.dumps(body)]
    for h in hdr:
        c += ['-H', h]
    r = sh(*c, f'http://127.0.0.1:{port}/api/v0/auth/setup').stdout
    b, _, st = r.rpartition('\n')
    return int(st or 0), b[:160]


# tunnel-like: a plain TCP forwarder on loopback, as ssh -L would be


def forward(lp, tp):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', lp))
    s.listen(16)

    def pump(a, b):
        try:
            while True:
                d = a.recv(65536)
                if not d:
                    break
                b.sendall(d)
        except OSError:
            pass
        for x in (a, b):
            try:
                x.close()
            except OSError:
                pass

    def loop():
        while True:
            c, _ = s.accept()
            t = socket.create_connection(('127.0.0.1', tp))
            threading.Thread(target=pump, args=(c, t), daemon=True).start()
            threading.Thread(target=pump, args=(t, c), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()


forward(36077, 36088)
r13 = {'code_in_log': bool(code)}
r13['no code, loopback'] = setup({'password': PW})
r13['empty code'] = setup({'password': PW, 'setup_code': ''})
r13['wrong code'] = setup({'password': PW, 'setup_code': '000000'})
r13['no code, through tunnel'] = setup({'password': PW}, port=36077)
r13['no code, X-Forwarded-For 127.0.0.1'] = setup({'password': PW}, ['X-Forwarded-For: 127.0.0.1'])
r13['no code, Host localhost'] = setup({'password': PW}, ['Host: localhost'])
r13['foreign Origin with code'] = setup({'password': PW, 'setup_code': code}, ['Origin: https://evil.example'])
r13['session first_run'] = sh('curl', '-s', 'http://127.0.0.1:36088/api/v0/auth/session').stdout[:120]
wrong = [setup({'password': PW, 'setup_code': '11111%d' % i})[0] for i in range(12)]
r13['12 wrong codes'] = wrong
r13['right code after the wrong ones'] = setup({'password': PW, 'setup_code': code})
time.sleep(0.2)
# the rate limit may hold the right code back: wait it out once if so
r13['after'] = sh('curl', '-s', 'http://127.0.0.1:36088/api/v0/auth/session').stdout[:120]
p.terminate()
p.wait(10)
r = sh(f'{B}/schild', 'dashboard', 'reset-password', '-config', f'{D}/schild.yaml')
r13['reset_password_out'] = (r.stdout + r.stderr)[:200]
p = subprocess.Popen([f'{B}/schild', 'run', '-config', f'{D}/schild.yaml'], env=env2, stdout=open(L, 'w'), stderr=subprocess.STDOUT)
for _ in range(100):
    if sh('curl', '-sf', '-m', '1', 'http://127.0.0.1:36088/readyz').returncode == 0:
        break
    time.sleep(0.1)
time.sleep(0.5)
m = re.search(r'"setup_code":"([^"]+)"', open(L).read())
code2 = m.group(1) if m else None
r13['after reset: no code'] = setup({'password': PW})
r13['after reset: right code'] = setup({'password': PW + 'x', 'setup_code': code2})
p.terminate()
p.wait(10)
res['1.3'] = r13


# ---- 2.2
def raw(port, data, wait=1.0):
    s = socket.create_connection(('127.0.0.1', port), timeout=3)
    s.sendall(data)
    s.settimeout(wait)
    b = b''
    try:
        while True:
            x = s.recv(4096)
            if not x:
                break
            b += x
    except OSError:
        pass
    s.close()
    return b[:80].decode('latin-1')


PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00'
UPG = b'GET / HTTP/1.1\r\nHost: shop.test\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAoAAAAAIAAAAA\r\n\r\n'
PLAIN = b'GET / HTTP/1.1\r\nHost: shop.test\r\nConnection: close\r\n\r\n'
D = '/tmp/m26/i/px'
os.makedirs(D, exist_ok=True)
open(f'{D}/schild.yaml', 'w').write(f'''# TEST ONLY
config_version: 0
profile: production
mode: observe
node_name: m26-px
network:
  enabled: false
listen:
  proxy: "127.0.0.1:36180"
  dashboard: "127.0.0.1:36188"
  metrics: "127.0.0.1:36111"
upstream:
  url: "http://127.0.0.1:35999"
storage:
  path: {D}/data
''')
p = subprocess.Popen([f'{B}/schild', 'run', '-config', f'{D}/schild.yaml'], env=env2, stdout=open(f'{D}/run.log', 'w'), stderr=subprocess.STDOUT)
for _ in range(100):
    if sh('curl', '-sf', '-m', '1', 'http://127.0.0.1:36188/readyz').returncode == 0:
        break
    time.sleep(0.1)
ECHO.clear()
res['2.2'] = {'proxy preface': raw(36180, PREFACE), 'proxy Upgrade h2c': raw(36180, UPG), 'echo saw upgrade header': [h.get('Upgrade') for h in ECHO], 'proxy plain': raw(36180, PLAIN),
              'curl --http2-prior-knowledge': sh('curl', '-s', '-m', '5', '-o', '/dev/null', '-w', '%{http_code} %{http_version}', '--http2-prior-knowledge', '-H', 'Host: shop.test', 'http://127.0.0.1:36180/').stdout,
              'curl --http2 upgrade': sh('curl', '-s', '-m', '5', '-o', '/dev/null', '-w', '%{http_code} %{http_version}', '--http2', '-H', 'Host: shop.test', 'http://127.0.0.1:36180/').stdout}
p.terminate()
p.wait(10)
e = dict(os.environ, MODE='observe', STATE='off', HUBURL='http://127.0.0.1:9/none', HUBAUTO='false')
sh('bash', INST, 'start', 'in', '361', env=e)
res['2.2']['ingress preface'] = raw(36190, PREFACE)
res['2.2']['ingress Upgrade h2c'] = raw(36190, UPG)
res['2.2']['ingress curl prior knowledge'] = sh('curl', '-s', '-m', '5', '-o', '/dev/null', '-w', '%{http_code} %{http_version}', '--http2-prior-knowledge', '-H', 'Host: shop.test', 'http://127.0.0.1:36190/').stdout
sh('bash', INST, 'stop', 'in', env=e)

# ---- 3.2 password, network on (test keys, unreachable labs and relays)
sh('bash', INST, 'start', 'pw', '362', env=dict(e, STATE='detect', SETTLING='0'))
D = '/tmp/m26/i/pw'
sh('bash', INST, 'stop', 'pw', env=e)
key = subprocess.run(['go', 'run', './cmd/testkeyfile', '-name', 'site-a'], cwd=os.path.join(HERE, '..', '..', '..', 'contract'), capture_output=True, text=True).stdout
open(f'{D}/site.key', 'w').write(key)
os.chmod(f'{D}/site.key', 0o600)
y = open(f'{D}/schild.yaml').read().replace('network:\n  enabled: false\n', f'''channel: schild-main
labs:
  - id: lab-a
    endpoint: "https://lab-a.schild.test:7443"
    operator: op-test-a
    keys:
      - keyid: test-lab-a
        public_key: "ed25519:WG0+tbI28cOvxV+5uFexZByjeJWnjcOIUhGi1gy6EBs="
        purposes: [ack, rules, checkpoint]
  - id: lab-a2
    endpoint: "https://lab-a2.schild.test:7443"
    operator: op-test-a
    keys:
      - keyid: test-lab-a2
        public_key: "ed25519:zfX9dEVVklgBy85lV0UT3CEbHwtb6u4lBouDmk5OZOs="
        purposes: [rules, checkpoint]
min_independent_operators: 1
relays:
  - url: "http://127.0.0.1:9"
site_key:
  keyid: test-site-a
  private_key_file: {D}/site.key
''')
open(f'{D}/schild.yaml', 'w').write(y)
p = subprocess.Popen([f'{B}/schild', 'run', '-config', f'{D}/schild.yaml'], env=dict(e, SCHILD_ALLOW_TEST_KEYS='1', SCHILD_CROWDSEC_HUB_URL='http://127.0.0.1:9/none'), stdout=open(f'{D}/run-net.log', 'w'), stderr=subprocess.STDOUT)
ready = False
for _ in range(100):
    if sh('curl', '-sf', '-m', '1', 'http://127.0.0.1:36288/readyz').returncode == 0:
        ready = True
        break
    time.sleep(0.1)
r32 = {'ready': ready}
if not ready:
    r32['log'] = open(f'{D}/run-net.log').read()[-400:]
else:
    # session may be gone across the restart: log in
    sh('curl', '-s', '-c', f'{D}/cj', '-H', 'Content-Type: application/json', '-X', 'POST', '-d', json.dumps({'user': 'admin', 'password': PW}), 'http://127.0.0.1:36288/api/v0/auth/login')
    s = sh('curl', '-s', '-b', f'{D}/cj', 'http://127.0.0.1:36288/api/v0/auth/session').stdout
    r32['session'] = s[:100]
    open(f'{D}/csrf', 'w').write(json.loads(s).get('csrf_token', ''))
    P = 362
    C = {'confirm': {'password': PW}}
    W = {'confirm': {'password': 'wrong'}}
    NR = 'schild-2026-0001'
    for label, method, path, base in (('suspend', 'POST', f'/rules/{NR}/suspend', {'send_feedback': False}), ('resume', 'POST', f'/rules/{NR}/resume', {}), ('approve', 'POST', '/review/none/approve', {}),
                                      ('privacy delete', 'POST', '/privacy/delete', {'ip': '203.0.113.200', 'keep_incidents': False})):
        r32[label] = {'none': api(D, P, method, path, base)[0:2], 'wrong': api(D, P, method, path, dict(base, **W))[0:2], 'right': api(D, P, method, path, dict(base, **C))[0:2]}
    r32['reject'] = api(D, P, 'POST', '/review/none/reject', {})
    st, b = api(D, P, 'GET', '/rules?source=crowdsec_hub&limit=2')
    hid = b['items'][0]['id']
    r32['hub suspend no password'] = api(D, P, 'POST', f'/rules/{hid}/suspend', {'send_feedback': False})[0]
    r32['hub resume no password'] = api(D, P, 'POST', f'/rules/{hid}/resume', {})[0]
    r32['addAllow no password'] = api(D, P, 'POST', '/allowlist', {'cidr': '198.51.100.9/32', 'label': 'TEST ONLY', 'level': 'bypass_waf', 'expires': 'never'})
    r32['switch to block no password'] = api(D, P, 'PATCH', '/rules/crowdsec-hub', {'state': 'block'})[0]
    r32['switch without csrf'] = sh('curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', '-b', f'{D}/cj', '-H', 'Content-Type: application/json', '-X', 'PATCH', '-d', '{"state":"off"}', 'http://127.0.0.1:36288/api/v0/rules/crowdsec-hub').stdout
    r32['switch without session'] = sh('curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', '-H', 'Content-Type: application/json', '-X', 'PATCH', '-d', '{"state":"off"}', 'http://127.0.0.1:36288/api/v0/rules/crowdsec-hub').stdout
    r32['mode change without password'] = api(D, P, 'PATCH', '/settings', {'mode': 'review'})[0:2]
p.terminate()
p.wait(10)
sh('bash', INST, 'stop', 'pw', env=e)
res['3.2'] = r32
json.dump(res, open(sys.argv[1], 'w'), indent=1, default=str)
print(json.dumps(res, indent=1, default=str)[:9000])
