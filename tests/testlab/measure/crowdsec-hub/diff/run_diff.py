#!/usr/bin/env python3
# TEST ONLY: MVP-26 measurement. Sends every case to the real CrowdSec engine and to schild, collects which hub rules
# each one reports. Client address per case: 2001:db8:26:<hi>:<lo>::1 (documentation range).
#   run_diff.py <cases.json> <schild ingress port> <schild.db> <out.json> [start_at_case]
import base64, json, re, socket, sqlite3, subprocess, sys, time

CS_PORT = 29722
KEY = 'm26-testonly-appsec-key-0123456789'


def ip_of(i):
    return '2001:db8:26:%x:%x::1' % (i >> 16, i & 0xffff)


def send(port, head_lines, body, chunked=False):
    s = socket.create_connection(('127.0.0.1', port), timeout=20)
    data = '\r\n'.join(head_lines).encode('latin-1', 'replace') + b'\r\n'
    if chunked:
        data += b'Transfer-Encoding: chunked\r\n\r\n'
        s.sendall(data)
        for i in range(0, len(body), 7):
            c = body[i:i + 7]
            s.sendall(b'%x\r\n' % len(c) + c + b'\r\n')
        s.sendall(b'0\r\n\r\n')
    else:
        data += b'Content-Length: %d\r\n\r\n' % len(body) if body else b'\r\n'
        s.sendall(data + body)
    buf = b''
    while b'\r\n\r\n' not in buf:
        x = s.recv(65536)
        if not x:
            break
        buf += x
    m = re.match(rb'HTTP/1\.[01] (\d+)', buf)
    hdr, _, rest = buf.partition(b'\r\n\r\n')
    cl = re.search(rb'(?i)content-length: (\d+)', hdr)
    if cl:
        while len(rest) < int(cl.group(1)):
            x = s.recv(65536)
            if not x:
                break
            rest += x
    s.close()
    return int(m.group(1)) if m else 0, rest[:200]


def main():
    cases = json.load(open(sys.argv[1]))['cases']
    port, db, out = int(sys.argv[2]), sys.argv[3], sys.argv[4]
    res = {}
    t0 = time.time()
    since = subprocess.run(['date', '-u', '+%Y-%m-%dT%H:%M:%SZ'], capture_output=True, text=True).stdout.strip()
    for c in cases:
        i = c['id']
        ip = ip_of(i)
        body = base64.b64decode(c['body'])
        extra = [f'{k}: {v}' for k, v in c['headers'].items()]
        # schild
        lines = [f"{c['method']} {c['target']} HTTP/1.1", 'Host: shop.test', f'X-Forwarded-For: {ip}', 'User-Agent: Mozilla/5.0 m26', 'Connection: close'] + extra
        try:
            st, _ = send(port, lines, body, c['chunked'])
        except Exception as e:
            st = -1
        # real engine (chunked is the bouncer's business: it reads the body and forwards it)
        lines = ['POST / HTTP/1.1', f'Host: 127.0.0.1:{CS_PORT}', f'X-Crowdsec-Appsec-Ip: {ip}', f"X-Crowdsec-Appsec-Uri: {c['target']}",
                 'X-Crowdsec-Appsec-Host: shop.test', f"X-Crowdsec-Appsec-Verb: {c['method']}", f'X-Crowdsec-Appsec-Api-Key: {KEY}',
                 'User-Agent: Mozilla/5.0 m26', 'Connection: close'] + extra
        try:
            cst, cb = send(CS_PORT, lines, body)
        except Exception as e:
            cst, cb = -1, b''
        res[i] = {'schild_status': st, 'cs_status': cst, 'cs_body': cb.decode('latin-1')[:80]}
        if i % 200 == 0:
            print(i, round(time.time() - t0), flush=True)
    time.sleep(3)
    con = sqlite3.connect(db)
    ev = {}
    for ip, body, outcome in con.execute("select ip, body, outcome from events where type='schild.request.evaluated.v1'"):
        d = json.loads(body)['data']
        names = sorted({r['hub']['name'] for r in d.get('rules', []) if r.get('source') == 'crowdsec_hub'})
        ev.setdefault(ip, []).append({'hub': names, 'crs': [r['id'] for r in d.get('rules', []) if r.get('source') == 'crs'], 'outcome': outcome, 'limit': d.get('limit')})
    logs = subprocess.run(['docker', 'logs', '--since', since, 'm26-crowdsec'], capture_output=True, text=True)
    cs = {}
    for line in (logs.stdout + logs.stderr).splitlines():
        m = re.search(r'WAF block: (\S+) from (\S+) ', line)
        if m:
            cs.setdefault(m.group(2), set()).add(m.group(1))
    for c in cases:
        i = c['id']
        ip = ip_of(i)
        r = res[i]
        r['schild_hub'] = sorted({n for e in ev.get(ip, []) for n in e['hub']})
        r['schild_event'] = bool(ev.get(ip))
        r['schild_crs'] = sorted({n for e in ev.get(ip, []) for n in e['crs']})
        r['cs_hub'] = sorted(cs.get(ip, []))
    json.dump(res, open(out, 'w'), indent=0)
    print('done', len(res), round(time.time() - t0))


main()
