#!/usr/bin/env python3
# TEST ONLY: MVP-26 / D40 second pass. 1.3 with the right code, an upgrading backend behind the proxy listener (2.2),
# hub rules over cleartext HTTP/2 on the ingress listener, 3.2 with the network on, schild run on a refused Caddyfile.
#   func2.py <out.json>
import json, os, re, socket, sqlite3, subprocess, sys, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
INST = os.path.join(HERE, '..', 'inst.sh')
B = '/tmp/m26/bin'
PW = 'schild-m26-TESTONLY-pw'
res = {}
base = dict(os.environ, MODE='observe', STATE='off', HUBURL='http://127.0.0.1:9/none', HUBAUTO='false')


def sh(*a, **k):
    return subprocess.run(a, capture_output=True, text=True, **k)


def wait(port):
    for _ in range(150):
        if sh('curl', '-sf', '-m', '1', f'http://127.0.0.1:{port}/readyz').returncode == 0:
            return True
        time.sleep(0.1)
    return False


def setup(body, port):
    r = sh('curl', '-s', '-m', '10', '-w', '\n%{http_code}', '-H', 'Content-Type: application/json', '-X', 'POST', '-d', json.dumps(body), f'http://127.0.0.1:{port}/api/v0/auth/setup').stdout
    b, _, st = r.rpartition('\n')
    return int(st or 0), b[:120]


# ---- 1.3 right code, then reset-password with the code the CLI prints
sh('bash', INST, 'start', 'su2', '363', env=base)
sh('bash', INST, 'stop', 'su2', env=base)
D = '/tmp/m26/i/su2'
r = sh(f'{B}/schild', 'dashboard', 'reset-password', '-config', f'{D}/schild.yaml')
m = re.search(r'setup code: (\S+)', r.stdout + r.stderr)
code = m.group(1) if m else None
env = dict(base, SCHILD_ALLOW_TEST_KEYS='1')
p = subprocess.Popen([f'{B}/schild', 'run', '-config', f'{D}/schild.yaml'], env=env, stdout=open(f'{D}/run2.log', 'w'), stderr=subprocess.STDOUT)
wait(36388)
time.sleep(0.3)
r13 = {'no code': setup({'password': PW}, 36388)[0], 'wrong': setup({'password': PW, 'setup_code': 'AAAA-BBBB-CCCC'}, 36388)[0], 'right, 2 fails before': setup({'password': PW, 'setup_code': code}, 36388)}
r13['again, password set'] = setup({'password': PW, 'setup_code': code}, 36388)[0]
p.terminate()
p.wait(10)
p = subprocess.Popen([f'{B}/schild', 'run', '-config', f'{D}/schild.yaml'], env=env, stdout=open(f'{D}/run3.log', 'w'), stderr=subprocess.STDOUT)
wait(36388)
time.sleep(0.3)
r13['after restart, first run gone'] = sh('curl', '-s', 'http://127.0.0.1:36388/api/v0/auth/session').stdout[:80]
p.terminate()
p.wait(10)
res['1.3'] = r13

# ---- 2.2 a backend that says yes to Upgrade: h2c, behind the proxy listener
SEEN = []


def up_backend(port):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(('127.0.0.1', port))
    s.listen(16)

    def one(c):
        d = b''
        while b'\r\n\r\n' not in d:
            x = c.recv(4096)
            if not x:
                return
            d += x
        SEEN.append(d[:300].decode('latin-1'))
        if b'pgrade: h2c' in d:
            c.sendall(b'HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: h2c\r\n\r\n')
            c.settimeout(2)
            try:
                while True:
                    x = c.recv(4096)
                    if not x:
                        break
                    SEEN.append('TUNNEL ' + x[:120].decode('latin-1'))
                    c.sendall(b'TUNNEL-ECHO ' + x)
            except OSError:
                pass
        else:
            c.sendall(b'HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n')
        c.close()

    def loop():
        while True:
            c, _ = s.accept()
            threading.Thread(target=one, args=(c,), daemon=True).start()
    threading.Thread(target=loop, daemon=True).start()


up_backend(36499)


def tunnel(port, host='shop.test', extra=b''):
    SEEN.clear()
    s = socket.create_connection(('127.0.0.1', port), timeout=4)
    s.sendall(b'GET / HTTP/1.1\r\nHost: ' + host.encode() + b'\r\nConnection: Upgrade, HTTP2-Settings\r\nUpgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAoAAAAAIAAAAA\r\n' + extra + b'\r\n')
    s.settimeout(2)
    try:
        a = s.recv(300)
    except OSError:
        a = b''
    out = {'answer': a[:70].decode('latin-1')}
    if a.startswith(b'HTTP/1.1 101'):
        s.sendall(b'GET /?q=<script>alert(1)</script> TEST-ONLY-BYTES-AFTER-UPGRADE')
        try:
            out['through_tunnel'] = s.recv(200)[:90].decode('latin-1')
        except OSError:
            out['through_tunnel'] = None
    s.close()
    out['backend_saw'] = [x[:90] for x in SEEN][:3]
    return out


D = '/tmp/m26/i/px2'
os.makedirs(D, exist_ok=True)
open(f'{D}/schild.yaml', 'w').write(f'''# TEST ONLY
config_version: 0
profile: production
mode: autoblock
node_name: m26-px2
network:
  enabled: false
listen:
  proxy: "127.0.0.1:36480"
  dashboard: "127.0.0.1:36488"
  metrics: "127.0.0.1:36411"
upstream:
  url: "http://127.0.0.1:36499"
storage:
  path: {D}/data
''')
p = subprocess.Popen([f'{B}/schild', 'run', '-config', f'{D}/schild.yaml'], env=env, stdout=open(f'{D}/run.log', 'w'), stderr=subprocess.STDOUT)
wait(36488)
time.sleep(0.3)
res['2.2_upgrade_proxy_listener'] = tunnel(36480)
p.terminate()
p.wait(10)
e = dict(base, MODE='autoblock', STATE='detect', SETTLING='0')
sh('bash', INST, 'start', 'in2', '365', env=e)
D = '/tmp/m26/i/in2'
sh('bash', INST, 'stop', 'in2', env=e)
y = open(f'{D}/Caddyfile').read().replace('reverse_proxy 127.0.0.1:36599', 'reverse_proxy 127.0.0.1:36499')
open(f'{D}/Caddyfile', 'w').write(y)
p = subprocess.Popen([f'{B}/schild', 'run', '-config', f'{D}/schild.yaml'], env=env, stdout=open(f'{D}/run.log', 'w'), stderr=subprocess.STDOUT)
wait(36588)
time.sleep(0.3)
res['2.2_upgrade_ingress'] = tunnel(36590)
res['2.2_attack_over_h2c_ingress'] = sh('curl', '-s', '-m', '5', '-o', '/dev/null', '-w', '%{http_code} %{http_version}', '--http2-prior-knowledge', '-H', 'Host: shop.test', 'http://127.0.0.1:36590/?q=%3Cscript%3Ealert(1)%3C/script%3E').stdout
p.terminate()
p.wait(10)

# ---- schild run on a refused Caddyfile
r = sh('timeout', '10', f'{B}/schild', 'run', '-config', '/tmp/m26/d40/iv/r01-v01/schild.yaml', env=env) if False else None
p = subprocess.Popen([f'{B}/schild', 'run', '-config', '/tmp/m26/d40/iv/r01-v01/schild.yaml'], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
try:
    o, _ = p.communicate(timeout=8)
    res['run_refused_shape'] = {'exit': p.returncode, 'out': o[-200:]}
except subprocess.TimeoutExpired:
    p.terminate()
    res['run_refused_shape'] = 'kept running'

# ---- 3.2 network on
e = dict(base, STATE='detect', SETTLING='0')
sh('bash', INST, 'start', 'pw', '362', env=e)
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
    operator: op-test-a2
    keys:
      - keyid: test-lab-a2
        public_key: "ed25519:zfX9dEVVklgBy85lV0UT3CEbHwtb6u4lBouDmk5OZOs="
        purposes: [rules, checkpoint]
min_independent_operators: 2
relays:
  - url: "http://127.0.0.1:9"
  - url: "http://127.0.0.1:10"
site_key:
  keyid: test-site-a
  private_key_file: {D}/site.key
''')
open(f'{D}/schild.yaml', 'w').write(y)
p = subprocess.Popen([f'{B}/schild', 'run', '-config', f'{D}/schild.yaml'], env=dict(env, SCHILD_CROWDSEC_HUB_URL='http://127.0.0.1:9/none'), stdout=open(f'{D}/run-net.log', 'w'), stderr=subprocess.STDOUT)
ready = wait(36288)
r32 = {'ready': ready}
if not ready:
    r32['log'] = open(f'{D}/run-net.log').read()[-500:]
else:
    time.sleep(0.5)
    sh('curl', '-s', '-c', f'{D}/cj', '-H', 'Content-Type: application/json', '-X', 'POST', '-d', json.dumps({'user': 'admin', 'password': PW}), 'http://127.0.0.1:36288/api/v0/auth/login')
    s = sh('curl', '-s', '-b', f'{D}/cj', 'http://127.0.0.1:36288/api/v0/auth/session').stdout
    r32['session'] = s[:90]
    csrf = json.loads(s).get('csrf_token', '')

    def api(method, path, body=None):
        c = ['curl', '-s', '-m', '30', '-w', '\n%{http_code}', '-b', f'{D}/cj', '-H', f'X-CSRF-Token: {csrf}', '-H', 'Content-Type: application/json', '-X', method]
        if body is not None:
            c += ['-d', json.dumps(body)]
        r = sh(*c, f'http://127.0.0.1:36288/api/v0{path}').stdout
        b, _, st = r.rpartition('\n')
        try:
            d = json.loads(b)
            b = {k: d.get(k) for k in ('code', 'errors', 'detail') if k in d} or str(d)[:100]
        except Exception:
            pass
        return int(st or 0), b
    C = {'confirm': {'password': PW}}
    W = {'confirm': {'password': 'wrong-password-TESTONLY'}}
    NR = 'schild-2026-0001'
    for label, path, base_b in (('suspend', f'/rules/{NR}/suspend', {'send_feedback': False}), ('resume', f'/rules/{NR}/resume', {}), ('approve', '/review/rec-1/approve', {}),
                                ('privacy delete', '/privacy/delete', {'ip': '203.0.113.200', 'keep_incidents': False})):
        r32[label] = {'none': api('POST', path, base_b), 'wrong': api('POST', path, dict(base_b, **W)), 'right': api('POST', path, dict(base_b, **C))}
    r32['reject'] = api('POST', '/review/rec-1/reject', {})
    st, b = sh('curl', '-s', '-b', f'{D}/cj', 'http://127.0.0.1:36288/api/v0/rules?source=crowdsec_hub&limit=2').stdout, None
    hid = json.loads(st)['items'][0]['id']
    r32['hub suspend no password'] = api('POST', f'/rules/{hid}/suspend', {'send_feedback': False})[0]
    r32['hub resume no password'] = api('POST', f'/rules/{hid}/resume', {})[0]
    r32['addAllow bypass no password'] = api('POST', '/allowlist', {'cidr': '198.51.100.9/32', 'label': 'TEST ONLY', 'level': 'bypass_waf', 'expires': 'never'})
    r32['switch to block no password'] = api('PATCH', '/rules/crowdsec-hub', {'state': 'block'})[0]
    r32['switch without csrf'] = sh('curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', '-b', f'{D}/cj', '-H', 'Content-Type: application/json', '-X', 'PATCH', '-d', '{"state":"off"}', 'http://127.0.0.1:36288/api/v0/rules/crowdsec-hub').stdout
    r32['switch without session'] = sh('curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', '-H', 'Content-Type: application/json', '-X', 'PATCH', '-d', '{"state":"off"}', 'http://127.0.0.1:36288/api/v0/rules/crowdsec-hub').stdout
    r32['mode change without password'] = api('PATCH', '/settings', {'mode': 'review'})
    # signals: a hub-only request, a CRS request, a hub plus CRS request
    time.sleep(0.2)
    for path, ip in (('/password.htm', '198.51.100.31'), ('/?q=%3Cscript%3Ealert(1)%3C/script%3E', '198.51.100.32'), ('/.env', '198.51.100.33')):
        sh('curl', '-s', '-o', '/dev/null', '-H', 'Host: shop.test', '-H', f'X-Forwarded-For: {ip}', '-A', 'Mozilla/5.0 m26', f'http://127.0.0.1:36290{path}')
    time.sleep(2)
    m = sh('curl', '-s', 'http://127.0.0.1:36211/metrics').stdout
    r32['signal_metrics'] = [l for l in m.splitlines() if l.startswith('schild_signals_')]
    con = sqlite3.connect(f'{D}/data/schild.db')
    tabs = [t[0] for t in con.execute("select name from sqlite_master where type='table'")]
    r32['tables'] = [t for t in tabs if 'sig' in t or 'outbox' in t or 'queue' in t]
    dump = []
    for t in r32['tables']:
        cols = [c[1] for c in con.execute(f'pragma table_info({t})')]
        for row in con.execute(f'select * from {t} limit 6'):
            dump.append(str(row)[:700])
    r32['signal_rows'] = dump
    r32['events_by_ip'] = list(con.execute("select ip, rules, signal_id, outcome from events where ip like '198.51.100.3%'"))
p.terminate()
p.wait(10)
res['3.2'] = r32
json.dump(res, open(sys.argv[1], 'w'), indent=1, default=str)
print(json.dumps(res, indent=1, default=str)[:7500])
