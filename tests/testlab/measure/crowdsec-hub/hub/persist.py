#!/usr/bin/env python3
# TEST ONLY: MVP-26. Stored set, restart, newer-set precedence, pin, ETag, recovery after a set that grew.
#   persist.py <index dir> <out.json>
import base64, copy, hashlib, json, os, sqlite3, subprocess, sys, time

HERE = os.path.dirname(os.path.abspath(__file__))
INST = os.path.join(HERE, '..', 'inst.sh')
IDX, OUT = sys.argv[1], sys.argv[2]
C = 'crowdsecurity/appsec-virtual-patching'
PIN = 'a' * 40
res = {}
P = 344
D = '/tmp/m26/i/ps'
SRV = 'http://127.0.0.1:29700'


def cur(n):
    open(f'{IDX}/cur.txt', 'w').write(n)


def mk_big():
    d = json.load(open(f'{IDX}/ok.json'))
    for i in range(450):
        name = f'crowdsecurity/vpatch-M26-grow-{i}'
        y = f"name: {name}\ndescription: TEST ONLY\nrules:\n  - zones: [URI]\n    match:\n      type: contains\n      value: /m26-grow-{i}\nlabels:\n  label: TEST\n".encode()
        d['appsec-rules'][name] = {'path': f'appsec-rules/{name}.yaml', 'version': '0.1', 'content': base64.b64encode(y).decode(), 'description': 'TEST ONLY',
                                   'versions': {'0.1': {'deprecated': False, 'digest': hashlib.sha256(y).hexdigest()}}}
        d['collections'][C]['appsec-rules'].append(name)
    json.dump(d, open(f'{IDX}/big450.json', 'w'))


def start(url, **kw):
    e = dict(os.environ, MODE='observe', STATE='detect', HUBURL=url, MON='false', **kw)
    subprocess.run(['bash', INST, 'start', 'ps', str(P)], env=e, check=True, capture_output=True)
    return e


def st():
    r = subprocess.run(['curl', '-s', '-m', '10', '-b', f'{D}/cj', f'http://127.0.0.1:{P}88/api/v0/rules/crowdsec-hub'], capture_output=True, text=True).stdout
    d = json.loads(r)
    return {k: d.get(k) for k in ('set_source', 'update_state', 'rules_loaded', 'hub_commit', 'pin', 'last_check_at', 'last_refusal', 'last_change', 'auto_update')}


def waitcheck(before=None, t=75):
    t0 = time.time()
    s = st()
    while time.time() - t0 < t:
        s = st()
        if s['last_check_at'] and s['last_check_at'] != before:
            return s
        time.sleep(0.5)
    s['timeout'] = True
    return s


def restart(e, url=None):
    if url:
        open(f'{D}/hub-url', 'w').write(url)
    subprocess.run(['bash', INST, 'restart', 'ps'], env=e, capture_output=True)
    time.sleep(0.4)


def patch(state):
    csrf = open(f'{D}/csrf').read().strip()
    return subprocess.run(['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', '-b', f'{D}/cj', '-H', f'X-CSRF-Token: {csrf}', '-H', 'Content-Type: application/json', '-X', 'PATCH', '-d', json.dumps({'state': state}), f'http://127.0.0.1:{P}88/api/v0/rules/crowdsec-hub'], capture_output=True, text=True).stdout


def row(fn):
    con = sqlite3.connect(f'{D}/data/schild.db', timeout=10)
    r = con.execute("select v from kv where k='crowdsec_hub_set_v1'").fetchone()
    d = json.loads(r[0])
    fn(d)
    con.execute("update kv set v=? where k='crowdsec_hub_set_v1'", (json.dumps(d),))
    con.commit()
    con.close()


def log_hits(n=3):
    return [(json.loads(l)['path'], json.loads(l)['headers'].get('If-None-Match')) for l in open('/tmp/m26/hub/access.log').read().splitlines()[-n:]]


mk_big()
# a. stored set survives a restart, ETag on the next check
cur('newrule')
e = start(SRV + '/cur', HUBAUTO='true')
res['a_first_update'] = waitcheck()
restart(e, 'http://127.0.0.1:9/none')
res['a_restart_offline'] = st()
res['a_probe_rule_present'] = subprocess.run(['sqlite3', f'{D}/data/schild.db', "select length(v) from kv where k='crowdsec_hub_set_v1'"], capture_output=True, text=True).stdout.strip()
before = st()['last_check_at']
restart(e, SRV + '/cur')
res['a_second_check'] = waitcheck(before)
res['a_if_none_match'] = log_hits(1)
ev = subprocess.run(['sqlite3', f'{D}/data/schild.db', "select count(*) from events where type='schild.rule.hub_updated.v1'"], capture_output=True, text=True).stdout.strip()
res['a_hub_updated_events'] = ev

# b. precedence


def stop_edit_start(fn, label):
    subprocess.run(['bash', INST, 'stop', 'ps'], env=e, capture_output=True)
    subprocess.run(['true'])
    if fn:
        row(fn)
    open(f'{D}/hub-url', 'w').write('http://127.0.0.1:9/none')
    subprocess.run(['bash', INST, 'restart', 'ps'], env=e, capture_output=True)
    time.sleep(0.4)
    s = st()
    res[label] = {k: s[k] for k in ('set_source', 'rules_loaded')}


def old(d):
    d['set'] = json.loads(json.dumps(d['set']))
    d['set']['fetched_at'] = '2026-01-01T00:00:00Z'
    d['set'].pop('hub_commit_at', None)
    d['set'].pop('hub_commit', None)


stop_edit_start(old, 'b_stored_older_than_image')
res['b_stored_row_kept'] = subprocess.run(['sqlite3', f'{D}/data/schild.db', "select length(v) from kv where k='crowdsec_hub_set_v1'"], capture_output=True, text=True).stdout.strip()


def future(d):
    d['set']['fetched_at'] = '2027-01-01T00:00:00Z'


stop_edit_start(future, 'b_stored_future_date')


def nodate(d):
    d['set']['hub_commit'] = PIN
    d['set'].pop('hub_commit_at', None)
    d['set']['fetched_at'] = '2026-10-30T23:00:00Z'


stop_edit_start(nodate, 'b_commit_without_date_vs_image')


def fresh(d):
    d['set'].pop('hub_commit', None)
    d['set']['fetched_at'] = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())


stop_edit_start(fresh, 'b_stored_newer')


def tamper(d):
    it = d['set']['rules'][0]
    it['content'] = base64.b64encode(b'name: x\nrules:\n  - zones: [URI]\n    match: {type: contains, value: /x}\n').decode()


stop_edit_start(tamper, 'b_tampered_content')


def broken(d):
    d['set'] = {'schema': 'nonsense'}


stop_edit_start(broken, 'b_broken_row')
subprocess.run(['bash', INST, 'stop', 'ps'], env=e, capture_output=True)

# c. auto_update false and pin
cur('newrule')
e = start(SRV + '/cur', HUBAUTO='false')
time.sleep(5)
res['c_auto_off'] = st()
subprocess.run(['bash', INST, 'stop', 'ps'], env=e, capture_output=True)
n0 = len(open('/tmp/m26/hub/access.log').read().splitlines())
e = start(SRV + '/cur', HUBPIN=PIN)
res['c_pin_first'] = waitcheck()
time.sleep(1)
res['c_pin_state'] = st()
restart(e)
res['c_pin_restart'] = st()
time.sleep(65)
res['c_pin_fetches_after_restart'] = len(open('/tmp/m26/hub/access.log').read().splitlines()) - n0
subprocess.run(['bash', INST, 'stop', 'ps'], env=e, capture_output=True)
cur('notjson')
e = start(SRV + '/cur', HUBPIN=PIN)
res['c_pin_broken'] = waitcheck()
subprocess.run(['bash', INST, 'stop', 'ps'], env=e, capture_output=True)

# d. a set that grew, then the normal hub comes back
cur('big450')
e = start(SRV + '/cur', HUBAUTO='true')
res['d_grown'] = waitcheck()
cur('ok')
b = st()['last_check_at']
patch('off')
time.sleep(0.5)
patch('detect')
res['d_back_to_normal'] = waitcheck(b)
restart(e)
b = st()['last_check_at']
res['d_after_restart'] = waitcheck(b)
# ways out an operator has
subprocess.run(['bash', INST, 'stop', 'ps'], env=e, capture_output=True)
y = open(f'{D}/schild.yaml').read() + f'  pin: {PIN}\n' if False else open(f'{D}/schild.yaml').read().replace('crowdsec_hub:\n', f'crowdsec_hub:\n  pin: {PIN}\n')
open(f'{D}/schild.yaml', 'w').write(y)
subprocess.run(['bash', INST, 'restart', 'ps'], env=e, capture_output=True)
res['d_with_pin'] = waitcheck(None)
res['d_with_pin_state'] = st()
subprocess.run(['bash', INST, 'stop', 'ps'], env=e, capture_output=True)
json.dump(res, open(OUT, 'w'), indent=1)
print(json.dumps(res, indent=0)[:6000])
