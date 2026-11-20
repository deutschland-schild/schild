#!/usr/bin/env python3
# TEST ONLY: MVP-26. Same generated requests against an instance with the hub rules off and one with detect, in mode
# observe. Score, CRS rule list and outcome class must not depend on the source.
#   score_eq.py <cases.json> <out.json>
import base64, json, os, re, socket, sqlite3, subprocess, sys, time, ipaddress

HERE = os.path.dirname(os.path.abspath(__file__))
INST = os.path.join(HERE, '..', 'inst.sh')
cases = json.load(open(sys.argv[1]))['cases']


def run(name, P, state):
    e = dict(os.environ, MODE='observe', STATE=state, HUBURL='http://127.0.0.1:9/none', HUBAUTO='false')
    subprocess.run(['bash', INST, 'start', name, str(P)], env=e, check=True, capture_output=True)
    for c in cases:
        ip = '2001:db8:26:%x:%x::1' % (c['id'] >> 16, c['id'] & 0xffff)
        body = base64.b64decode(c['body'])
        lines = [f"{c['method']} {c['target']} HTTP/1.1", 'Host: shop.test', f'X-Forwarded-For: {ip}', 'User-Agent: Mozilla/5.0 m26', 'Connection: close'] + [f'{k}: {v}' for k, v in c['headers'].items()]
        s = socket.create_connection(('127.0.0.1', int(f'{P}90')), timeout=20)
        s.sendall('\r\n'.join(lines).encode('latin-1', 'replace') + b'\r\n' + (b'Content-Length: %d\r\n\r\n' % len(body) + body if body else b'\r\n'))
        while s.recv(65536):
            pass
        s.close()
    time.sleep(3)
    con = sqlite3.connect(f'/tmp/m26/i/{name}/data/schild.db')
    out = {}
    for ip, score, body in con.execute("select ip, score, body from events where type like 'schild.request.%'"):
        d = json.loads(body)['data']
        out[ip] = (score, sorted(r['id'] for r in d.get('rules', []) if r.get('source') == 'crs'), d.get('outcome'), d.get('signal_id'))
    subprocess.run(['bash', INST, 'stop', name], env=e, capture_output=True)
    return out


a = run('eq-off', 347, 'off')
b = run('eq-det', 348, 'detect')
ips = set(a) | set(b)
same = diff = only_detect = 0
ex = []
for ip in ips:
    x, y = a.get(ip), b.get(ip)
    if x is None:
        only_detect += 1
        if y[0] != 0 or y[1]:
            diff += 1
            ex.append((ip, x, y))
    elif y is None and x[0] == 0 and not x[1]:
        same += 1  # a clean request, sampled in one run and not in the other
    elif y is None or x[:2] != y[:2]:
        diff += 1
        ex.append((ip, x, y))
    else:
        same += 1
r = {'cases': len(cases), 'with_event_off': len(a), 'with_event_detect': len(b), 'same_score_and_crs': same, 'only_in_detect_no_crs': only_detect, 'different': diff, 'examples': ex[:5]}
json.dump(r, open(sys.argv[2], 'w'), indent=1)
print(r)
