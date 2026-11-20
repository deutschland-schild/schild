#!/usr/bin/env python3
# TEST ONLY: MVP-26 effect matrix. For every gateway mode one fresh instance; state changes through the dashboard
# switch. Probes: a hub-only request, a hub plus CRS request, a clean request. Reads the event of each probe.
# Second part: settling, disabled rule, allowlist levels, exception after unblock, waf_repeat counting, score equality.
#   matrix.py <out.json>
import json, os, sqlite3, subprocess, sys, time, urllib.error, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
INST = os.path.join(HERE, '..', 'inst.sh')
EXTRA = '/tmp/m26/effect-extra.yaml'
open(EXTRA, 'w').write('''allowlist:
  - cidr: 192.0.2.0/25
    label: TEST ONLY no block
    level: no_block
    expires: never
  - cidr: 192.0.2.128/25
    label: TEST ONLY bypass
    level: bypass_waf
    expires: never
behaviour:
  presets: [generic]
  preset_limits: "off"
  scenarios:
    waf_repeat: { mode: block }
    path_probing: { mode: observe }
    aggressive_crawl: { mode: observe }
    login_bruteforce: { mode: observe }
''')
HUBONLY = '/password.htm'
HUBONLY2 = '/util/php/eval-stdin.php'
HUBCRS = '/.env'
ipn = [0]


def nextip():
    ipn[0] += 1
    return '2001:db8:26:%x::1' % (0xe000 + ipn[0])


class I:
    def __init__(self, name, port, mode, state='detect', settling=0, env=None):
        e = dict(os.environ, MODE=mode, STATE=state, SETTLING=str(settling), EXTRA=EXTRA, HUBURL='http://127.0.0.1:9/none', HUBAUTO='false')
        e.update(env or {})
        subprocess.run(['bash', INST, 'start', name, str(port)], env=e, capture_output=True, check=True)
        self.name, self.port = name, port
        self.d = f'/tmp/m26/i/{name}'
        self.csrf = open(f'{self.d}/csrf').read().strip()

    def api(self, method, path, body=None):
        c = ['curl', '-s', '-m', '30', '-w', '\n%{http_code}', '-b', f'{self.d}/cj', '-H', f'X-CSRF-Token: {self.csrf}', '-H', 'Content-Type: application/json', '-X', method]
        if body is not None:
            c += ['-d', json.dumps(body)]
        r = subprocess.run(c + [f'http://127.0.0.1:{self.port}88/api/v0{path}'], capture_output=True, text=True).stdout
        b, _, st = r.rpartition('\n')
        try:
            b = json.loads(b)
        except Exception:
            pass
        return int(st or 0), b

    def get(self, path, ip):
        req = urllib.request.Request(f'http://127.0.0.1:{self.port}90{path}', headers={'Host': 'shop.test', 'X-Forwarded-For': ip, 'User-Agent': 'Mozilla/5.0 m26'})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, r.headers.get('X-Backend')
        except urllib.error.HTTPError as e:
            return e.code, e.headers.get('X-Backend')

    def ev(self, ip):
        time.sleep(0.8)
        con = sqlite3.connect(self.d + '/data/schild.db')
        out = []
        for body, outcome, score, inc in con.execute("select body,outcome,score,incident from events where ip=? and type like 'schild.request.%'", (ip,)):
            d = json.loads(body)['data']
            out.append({'outcome': outcome, 'score': score, 'incident': inc, 'reason': d.get('would_block_reason'), 'rules': [(r.get('source'), r.get('hub', {}).get('name', r['id'])) for r in d.get('rules', [])]})
        return out

    def stop(self):
        subprocess.run(['bash', INST, 'stop', self.name], capture_output=True)


def probe(i, path, ip=None):
    ip = ip or nextip()
    st, be = i.get(path, ip)
    e = i.ev(ip)
    return {'status': st, 'backend': be == '1', 'event': e[-1] if e else None}


res = {'matrix': [], 'other': {}}
for n, mode in enumerate(('observe', 'review', 'autoblock')):
    i = I('m-' + mode, 320 + n, mode)
    for state in ('off', 'detect', 'block'):
        st, s = i.api('PATCH', '/rules/crowdsec-hub', {'state': state})
        time.sleep(3)
        row = {'mode': mode, 'state': state, 'patch': st, 'gateway_effect': s.get('gateway_effect'), 'limited_by': s.get('limited_by'), 'rules_loaded': s.get('rules_loaded')}
        row['hub_only'] = probe(i, HUBONLY)
        row['hub_crs'] = probe(i, HUBCRS)
        row['clean'] = probe(i, '/about')
        res['matrix'].append(row)
        print(mode, state, row['gateway_effect'], row['limited_by'], row['hub_only']['status'], row['hub_only']['backend'], (row['hub_only']['event'] or {}).get('outcome'), (row['hub_only']['event'] or {}).get('reason'),
              '| crs', row['hub_crs']['status'], (row['hub_crs']['event'] or {}).get('outcome'), (row['hub_crs']['event'] or {}).get('score'), flush=True)
    i.stop()

# block + autoblock, rule settled, then the details
i = I('m-det', 323, 'autoblock', 'block', 0)
o = res['other']
o['settled_block'] = probe(i, HUBONLY)
inc = (o['settled_block']['event'] or {}).get('incident')
st, b = i.api('GET', f'/incidents/{inc}')
o['incident'] = {'status': st, 'body': (json.dumps(b)[:900] if st == 200 else b)}
# disabled in the dashboard, by base id
st, b = i.api('GET', '/rules?source=crowdsec_hub&limit=500')
rid = {r['hub']['name']: r['id'] for r in b['items']}
target = rid['crowdsecurity/vpatch-CVE-2018-13317']
o['suspend_no_password'] = i.api('POST', f'/rules/{target}/suspend', {'send_feedback': False})[0]
o['after_disable'] = probe(i, HUBONLY)
o['resume_no_password'] = i.api('POST', f'/rules/{target}/resume', {})[0]
o['after_resume'] = probe(i, HUBONLY)
# allowlist
o['no_block_client'] = probe(i, HUBONLY, '192.0.2.10')
o['bypass_client'] = probe(i, HUBONLY, '192.0.2.200')
# exception after unblock
ip = nextip()
a = probe(i, HUBONLY, ip)
inc = a['event']['incident']
o['unblock'] = i.api('POST', f'/incidents/{inc}/unblock', {'false_positive': True})
o['after_unblock_same_ip'] = probe(i, HUBONLY, ip)
o['after_unblock_other_rule_same_ip'] = probe(i, HUBONLY2, ip)
i.stop()

# rule disabled in the file
i = I('m-cfg', 324, 'autoblock', 'block', 0, {'HUBDIS': 'crowdsecurity/vpatch-CVE-2018-13317'})
o['config_disabled'] = probe(i, HUBONLY)
st, b = i.api('GET', '/rules?source=crowdsec_hub&limit=500')
r = [x for x in b['items'] if x['hub']['name'].endswith('2018-13317')][0]
o['config_disabled_view'] = {k: r.get(k) for k in ('id', 'status', 'effective_action')}, r['hub'].get('disabled_by')
o['config_disabled_resume'] = i.api('POST', f"/rules/{r['id']}/resume", {})
i.stop()

# settling: image rule of the first set is older than a small settling, a large one holds it back
i = I('m-set', 325, 'autoblock', 'block', 2592000)
o['settling_large'] = probe(i, HUBONLY)
st, b = i.api('GET', '/rules/crowdsec-hub')
o['settling_status'] = {k: b.get(k) for k in ('state', 'gateway_effect', 'rules_settling', 'settling_s')}
i.stop()

# waf_repeat: two different hub-only rules in a row from one client, 20 rounds
for mode, state, name, sett in (('autoblock', 'detect', 'wr-detect', 0), ('observe', 'block', 'wr-observe', 0), ('review', 'block', 'wr-review', 0), ('autoblock', 'block', 'wr-settling', 2592000), ('autoblock', 'block', 'wr-block', 0)):
    i = I(name, 330 + len(o) % 40, mode, state, sett)
    ip = nextip()
    st = []
    for k in range(20):
        st.append(i.get(HUBONLY, ip)[0])
        st.append(i.get(HUBONLY2, ip)[0])
    time.sleep(1)
    after = i.get('/about', ip)[0]
    m = subprocess.run(['curl', '-s', f'http://127.0.0.1:{i.port}11/metrics'], capture_output=True, text=True).stdout
    con = sqlite3.connect(i.d + '/data/schild.db')
    beh = list(con.execute("select count(*) from events where type like 'schild.behaviour%'"))
    types = list(con.execute("select type,outcome,count(*) from events group by 1,2"))
    o[name] = {'statuses': st, 'clean_after': after, 'behaviour_events': beh[0][0], 'types': types, 'metric': [l for l in m.splitlines() if l.startswith('schild_behaviour') or l.startswith('schild_requests_total')][:12]}
    print(name, sorted(set(st)), after, beh, flush=True)
    i.stop()
json.dump(res, open(sys.argv[1], 'w'), indent=1)
print(json.dumps(res['other'], indent=1)[:6000])
