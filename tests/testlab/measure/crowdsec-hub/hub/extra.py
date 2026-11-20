#!/usr/bin/env python3
# TEST ONLY: MVP-26 last update checks. regex_cost code, third-party text in the read fields, pin against shrink,
# whether the switch or a restart gets out of a grown set.
#   extra.py <index dir> <out.json>
import base64, hashlib, json, os, sqlite3, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
INST = os.path.join(HERE, '..', 'inst.sh')
IDX, OUT = sys.argv[1], sys.argv[2]
C = 'crowdsecurity/appsec-virtual-patching'
P = 349
D = '/tmp/m26/i/ex'
PIN = 'b' * 40
res = {}


def cur(n):
    open(f'{IDX}/cur.txt', 'w').write(n)


def st(full=False):
    r = subprocess.run(['curl', '-s', '-m', '10', '-b', f'{D}/cj', f'http://127.0.0.1:{P}88/api/v0/rules/crowdsec-hub'], capture_output=True, text=True).stdout
    d = json.loads(r)
    return d if full else {k: d.get(k) for k in ('set_source', 'update_state', 'rules_loaded', 'hub_commit', 'last_check_at', 'last_refusal')}


def wait(before=None, t=90):
    t0 = time.time()
    while time.time() - t0 < t:
        s = st()
        if s['last_check_at'] and s['last_check_at'] != before:
            return s
        time.sleep(0.5)
    return dict(s, timeout=True)


d = json.load(open(f'{IDX}/exprx2.json'))
name = 'crowdsecurity/vpatch-M26-text'
y = ("name: crowdsecurity/vpatch-M26-text\ndescription: \"<img src=x onerror=alert(1)> \\x07\\x1b[31m long " + 'x' * 900 + "\"\nrules:\n  - zones: [URI]\n    match:\n      type: contains\n      value: /m26-text-probe\n"
     "labels:\n  label: \"<script>alert(1)</script>\\x07 " + 'y' * 300 + "\"\n  classification:\n    - cve.CVE-2099-0002\n").encode()
d['appsec-rules'][name] = {'path': f'appsec-rules/{name}.yaml', 'version': '0.1', 'content': base64.b64encode(y).decode(), 'description': 'TEST ONLY <b>x</b>',
                           'versions': {'0.1': {'deprecated': False, 'digest': hashlib.sha256(y).hexdigest()}}}
d['collections'][C]['appsec-rules'].append(name)
json.dump(d, open(f'{IDX}/textrule.json', 'w'))

cur('textrule')
e = dict(os.environ, MODE='observe', STATE='detect', HUBURL='http://127.0.0.1:29700/cur', MON='false')
subprocess.run(['bash', INST, 'start', 'ex', str(P)], env=e, check=True, capture_output=True)
res['update'] = wait()
f = st(True)
res['skipped'] = [(x['name'].split('/')[1], x['code']) for x in f['skipped']]
b = json.loads(subprocess.run(['curl', '-s', '-b', f'{D}/cj', f'http://127.0.0.1:{P}88/api/v0/rules?source=crowdsec_hub&limit=500'], capture_output=True, text=True).stdout)
r = [x for x in b['items'] if x['hub']['name'].endswith('M26-text')][0]
res['text_rule'] = {'label': r['hub'].get('label'), 'label_len': len(r['hub'].get('label') or ''), 'description_len': len(r['hub'].get('description') or ''), 'description_head': (r['hub'].get('description') or '')[:60]}
subprocess.run(['bash', INST, 'stop', 'ex'], env=e, capture_output=True)

# grown set: what gets the gateway back?
cur('big450')
subprocess.run(['bash', INST, 'start', 'ex', str(P)], env=e, check=True, capture_output=True)
res['grown'] = wait()
cur('ok')
subprocess.run(['bash', INST, 'stop', 'ex'], env=e, capture_output=True)
y = open(f'{D}/schild.yaml').read().replace('crowdsec_hub:\n', f'crowdsec_hub:\n  pin: {PIN}\n')
open(f'{D}/schild.yaml', 'w').write(y)
before = None
con = sqlite3.connect(f'{D}/data/schild.db')
before = json.loads(con.execute("select v from kv where k='crowdsec_hub_status_v1'").fetchone()[0]).get('last_check')
con.close()
subprocess.run(['bash', INST, 'restart', 'ex'], env=e, capture_output=True)
res['pin_ok_index_against_grown_set'] = wait(before)
subprocess.run(['bash', INST, 'stop', 'ex'], env=e, capture_output=True)
y = open(f'{D}/schild.yaml').read().replace(f'  pin: {PIN}\n', '  auto_update: false\n')
open(f'{D}/schild.yaml', 'w').write(y)
subprocess.run(['bash', INST, 'restart', 'ex'], env=e, capture_output=True)
res['auto_update_false'] = st()
subprocess.run(['bash', INST, 'stop', 'ex'], env=e, capture_output=True)
json.dump(res, open(OUT, 'w'), indent=1)
print(json.dumps(res, indent=0)[:2600])
