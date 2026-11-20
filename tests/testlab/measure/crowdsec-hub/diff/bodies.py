#!/usr/bin/env python3
# TEST ONLY: MVP-26 measurement. Where in a body does a hub rule still see the marker? Uses two published rules
# (a JSON BODY_ARGS rule and a urlencoded one) with benign filler in front. Sends to schild only and reads the events.
#   bodies.py <ingress port> <schild.db> <out.json>
import json, socket, sqlite3, sys, time

port, db, out = int(sys.argv[1]), sys.argv[2], sys.argv[3]
# vpatch-CVE-2024-51378: POST /dns/getresetstatus with json.statusfile holding a character outside [a-zA-Z0-9/]
# vpatch-CVE-2024-9465: POST .../checkpoint.php with signatureid holding a character outside [a-zA-Z0-9]
PJ = '/dns/getresetstatus'
PU = '/bin/configurations/parsers/checkpoint/checkpoint.php'
B = 'm26boundaryTESTONLY'


def j(n):
    return json.dumps({'filler': 'a' * n, 'statusfile': 'x;y'}).encode()


def j_arr(n):
    return json.dumps({'items': [{'k': i} for i in range(n)], 'statusfile': 'x;y'}).encode()


def u(n):
    return ('filler=' + 'a' * n + '&signatureid=x;y').encode()


def m(n):
    return (f'--{B}\r\nContent-Disposition: form-data; name="filler"; filename="a.bin"\r\nContent-Type: application/octet-stream\r\n\r\n'.encode() + b'a' * n +
            f'\r\n--{B}\r\nContent-Disposition: form-data; name="signatureid"\r\n\r\nx;y\r\n--{B}--\r\n'.encode())


C = [
    ('json 1 KiB', PJ, 'application/json', j(1 << 10), False),
    ('json 200 KiB', PJ, 'application/json', j(200 << 10), False),
    ('json 1 MiB', PJ, 'application/json', j(1 << 20), False),
    ('json 5 MiB', PJ, 'application/json', j(5 << 20), False),
    ('json 12 MiB', PJ, 'application/json', j(12 << 20), False),
    ('json 1 MiB chunked', PJ, 'application/json', j(1 << 20), True),
    ('json 900 array items', PJ, 'application/json', j_arr(300), False),
    ('urlencoded 1 KiB', PU, 'application/x-www-form-urlencoded', u(1 << 10), False),
    ('urlencoded 200 KiB', PU, 'application/x-www-form-urlencoded', u(200 << 10), False),
    ('urlencoded 1 MiB', PU, 'application/x-www-form-urlencoded', u(1 << 20), False),
    ('urlencoded 5 MiB', PU, 'application/x-www-form-urlencoded', u(5 << 20), False),
    ('urlencoded 1 MiB chunked', PU, 'application/x-www-form-urlencoded', u(1 << 20), True),
    ('multipart 1 KiB', PU, f'multipart/form-data; boundary={B}', m(1 << 10), False),
    ('multipart 200 KiB', PU, f'multipart/form-data; boundary={B}', m(200 << 10), False),
    ('multipart 5 MiB', PU, f'multipart/form-data; boundary={B}', m(5 << 20), False),
    ('multipart 5 MiB chunked', PU, f'multipart/form-data; boundary={B}', m(5 << 20), True),
]
res = []
for i, (label, path, ct, body, chunked) in enumerate(C):
    ip = f'2001:db8:26:ff:{i:x}::1'
    s = socket.create_connection(('127.0.0.1', port), timeout=60)
    h = f'POST {path} HTTP/1.1\r\nHost: shop.test\r\nX-Forwarded-For: {ip}\r\nUser-Agent: Mozilla/5.0 m26\r\nConnection: close\r\nContent-Type: {ct}\r\n'.encode()
    if chunked:
        s.sendall(h + b'Transfer-Encoding: chunked\r\n\r\n')
        for k in range(0, len(body), 65536):
            c = body[k:k + 65536]
            s.sendall(b'%x\r\n' % len(c) + c + b'\r\n')
        s.sendall(b'0\r\n\r\n')
    else:
        s.sendall(h + b'Content-Length: %d\r\n\r\n' % len(body) + body)
    buf = s.recv(4096)
    s.close()
    res.append({'label': label, 'ip': ip, 'bytes': len(body), 'status': int(buf[9:12] or 0)})
time.sleep(3)
con = sqlite3.connect(db)
for r in res:
    rows = list(con.execute("select body, outcome from events where ip=? and type='schild.request.evaluated.v1'", (r['ip'],)))
    names = set()
    for b, o in rows:
        d = json.loads(b)['data']
        names |= {x['hub']['name'].split('/')[1] for x in d.get('rules', []) if x.get('source') == 'crowdsec_hub'}
        r['outcome'] = o
        r['waf_ms'] = d.get('waf_ms')
    r['hub'] = sorted(names)
    print(r)
json.dump(res, open(out, 'w'), indent=1)
