#!/usr/bin/env python3
# TEST ONLY: MVP-26 update safety. One fresh instance per scenario, pointed at the local hub server through the
# test-only variable. Waits for the first check (0 to 60 s after the start, plus up to 60 s of fetch), then records the
# status, whether the running rules still work, and what the check did.
#   scen.py <out.json> <parallel> [scenario ...]
import concurrent.futures, json, os, subprocess, sys, time, urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
INST = os.path.join(HERE, '..', 'inst.sh')
SCEN = ['ok', 'newrule', 'changed', 'removed30', 'shrink', 'digest1', 'digestall', 'nocoll', 'norules', 'badb64', 'noversion', 'toomany', 'exprx',
        'badrules', 'broad', 'notjson', 'emptyobj', 'truncated', 'truncated200', 'closeearly', 'huge', 'bomb', 'status404', 'status500', 'status304',
        'redirect', 'redirectsame', 'loop', 'slow', 'slowok', 'hang', 'unreach-refused', 'unreach-blackhole']


def http(url, cookie=None):
    req = urllib.request.Request(url)
    if cookie:
        req.add_header('Cookie', cookie)
    with urllib.request.urlopen(req, timeout=5) as r:
        return r.status, r.read()


def probe(port, path, ip):
    req = urllib.request.Request(f'http://127.0.0.1:{port}90{path}', headers={'Host': 'shop.test', 'X-Forwarded-For': ip, 'User-Agent': 'Mozilla/5.0 m26'})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def run(a):
    i, s = a
    port = 310 + i
    name = 'u-' + s
    url = f'http://127.0.0.1:29700/{s}'
    if s == 'unreach-refused':
        url = 'http://127.0.0.1:9/none'
    if s == 'unreach-blackhole':
        url = 'http://192.0.2.1:9/none'
    env = dict(os.environ, MODE='observe', STATE='detect', HUBURL=url, MON='false')
    p = subprocess.run(['bash', INST, 'start', name, str(port)], env=env, capture_output=True, text=True)
    D = f'/tmp/m26/i/{name}'
    t0 = time.time()
    st = None
    cookie = '; '.join(f'{l.split()[5]}={l.split()[6]}' for l in open(f'{D}/cj') if len(l.split()) >= 7 and 'schild' in l.lower() or l.startswith('#HttpOnly_'))
    # cookie jar lines: use curl for simplicity
    while time.time() - t0 < 135:
        r = subprocess.run(['curl', '-s', '-m', '5', '-b', f'{D}/cj', f'http://127.0.0.1:{port}88/api/v0/rules/crowdsec-hub'], capture_output=True, text=True)
        try:
            st = json.loads(r.stdout)
        except Exception:
            st = None
        if st and st.get('last_check_at'):
            break
        time.sleep(1)
    took = round(time.time() - t0, 1)
    res = {'scenario': s, 'seconds_to_check': took}
    if st:
        res.update({k: st.get(k) for k in ('set_source', 'update_state', 'rules_loaded', 'rules_skipped', 'last_refusal', 'last_change', 'index_sha256')})
        res['skipped'] = [(x['name'].split('/')[1], x['code']) for x in st.get('skipped', []) if 'M26' in x['name'] or x['code'] in ('digest_mismatch', 'regex_cost')]
    res['env_probe_status'] = probe(port, '/.env', '2001:db8:26:aa::1')
    res['plain_status'] = probe(port, '/about', '2001:db8:26:aa::2')
    res['new_probe_status'] = probe(port, '/m26-new-rule-probe', '2001:db8:26:aa::3')
    time.sleep(2)
    q = subprocess.run(['sqlite3', f'{D}/data/schild.db', "select type, summary from events where type like 'schild.rule.hub%'"], capture_output=True, text=True)
    res['hub_events'] = q.stdout.strip().splitlines()[:6]
    q = subprocess.run(['sqlite3', f'{D}/data/schild.db', "select rules from events where ip like '2001:db8:26:aa:%'"], capture_output=True, text=True)
    res['probe_rules'] = q.stdout.strip().splitlines()
    res['log_warn'] = subprocess.run(['grep', '-h', 'crowdsec hub', f'{D}/schild-1.log'], capture_output=True, text=True).stdout.strip().splitlines()[-3:]
    subprocess.run(['bash', INST, 'stop', name], capture_output=True)
    print(json.dumps(res)[:400], flush=True)
    return res


def main():
    out, par = sys.argv[1], int(sys.argv[2])
    sc = sys.argv[3:] or SCEN
    with concurrent.futures.ThreadPoolExecutor(par) as ex:
        res = list(ex.map(run, enumerate(sc)))
    json.dump(res, open(out, 'w'), indent=1)


main()
