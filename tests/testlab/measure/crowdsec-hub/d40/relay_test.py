#!/usr/bin/env python3
# TEST ONLY: MVP-26 / D40 measurement, review items 2.5 and 2.6. A lying upstream in Python in front of a real
# schild-relay. All bytes are made up; nothing here is signed, a client would refuse every one of these bundles.
#   relay_test.py <schild-relay binary> <out.json>
import base64, hashlib, http.client, json, os, socket, subprocess, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BIN, OUT = sys.argv[1], sys.argv[2]
UP, RL, RM = 26282, 26280, 26281
CH = 'm26-channel'


def env(bid, ver, note=''):
    p = json.dumps({'schema': 'schild.rule_bundle/0.1', 'bundle_id': bid, 'version': ver, 'issued_at': '2026-10-30T00:00:00Z', 'expires': '2026-11-20T00:00:00Z' if note != 'lie' else '2026-11-21T00:00:00Z', 'rules': []}).encode()
    return json.dumps({'payloadType': 'application/vnd.schild.bundle+json', 'payload': base64.b64encode(p).decode(), 'signatures': []}).encode()


GOOD = env('rb1', 1, 'good')
LIE = env('rb1', 1, 'lie')
state = {'stream': [], 'answers': {}, 'log': []}


class U(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *a):
        pass

    def do_GET(self):
        state['log'].append(self.path)
        if self.path.startswith('/v0/stream'):
            self.send_response(200)
            self.send_header('Content-Type', 'text/event-stream')
            self.send_header('Cache-Control', 'no-cache')
            self.send_header('Transfer-Encoding', 'chunked')
            self.end_headers()
            sent = 0
            try:
                while True:
                    while sent < len(state['stream']):
                        ev = state['stream'][sent]
                        sent += 1
                        d = f"id: {ev['id']}\nevent: {ev['type']}\ndata: {json.dumps(ev, separators=(',', ':'))}\n\n".encode()
                        self.wfile.write(b'%x\r\n' % len(d) + d + b'\r\n')
                        self.wfile.flush()
                    d = b': keep-alive\n\n'
                    self.wfile.write(b'%x\r\n' % len(d) + d + b'\r\n')
                    self.wfile.flush()
                    time.sleep(0.3)
            except OSError:
                return
        a = state['answers'].get(self.path)
        if a is None:
            self.send_response(404)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        self.send_response(200)
        self.send_header('Content-Length', str(len(a)))
        self.end_headers()
        self.wfile.write(a)


class TS(ThreadingHTTPServer):
    daemon_threads = True


s = TS(('127.0.0.1', UP), U)
threading.Thread(target=s.serve_forever, daemon=True).start()


def start(extra=None, name='a'):
    e = dict(os.environ, SCHILD_RELAY_LISTEN=f'127.0.0.1:{RL}', SCHILD_RELAY_METRICS=f'127.0.0.1:{RM}', SCHILD_RELAY_UPSTREAMS=f'http://127.0.0.1:{UP}', SCHILD_ALLOW_TEST_KEYS='1', SCHILD_RELAY_MAX_PER_IP='4')
    if extra:
        e.update(extra)
    p = subprocess.Popen([BIN], env=e, stdout=open(f'/tmp/m26/d40/relay-{name}.log', 'w'), stderr=subprocess.STDOUT)
    for _ in range(50):
        try:
            socket.create_connection(('127.0.0.1', RL), 0.2).close()
            return p
        except OSError:
            time.sleep(0.1)
            if p.poll() is not None:
                return p
    return p


def get(path):
    c = http.client.HTTPConnection('127.0.0.1', RL, timeout=15)
    c.request('GET', path)
    r = c.getresponse()
    b = r.read()
    return {'status': r.status, 'cache_control': r.getheader('Cache-Control'), 'sha': hashlib.sha256(b).hexdigest()[:12], 'len': len(b), 'body_is': 'good' if b == GOOD else 'lie' if b == LIE else ('other' if b else 'empty')}


res = {}
p = start()
time.sleep(1.2)
# no reference, upstream gives a matching envelope that differs between two calls
P = '/v0/bundles/rb1/1.json'
state['answers'][P] = LIE
a = get(P)
state['answers'][P] = GOOD
b = get(P)
res['noref: lying envelope, then the other one'] = [a, b]
state['answers'][P] = b'not json at all'
res['noref: junk'] = get(P)
state['answers'][P] = env('other', 9)
res['noref: envelope of another bundle'] = get(P)
del state['answers'][P]

# with a reference on the stream: the bytes at the path do not fit its hash
ref = {'bundle_id': 'rb2', 'version': 2, 'url_path': '/v0/bundles/rb2/2.json', 'sha256': 'sha256:' + hashlib.sha256(env('rb2', 2, 'good')).hexdigest(), 'size': len(env('rb2', 2, 'good'))}
state['answers'][ref['url_path']] = env('rb2', 2, 'lie')
state['stream'].append({'type': 'schild.dist.bundle.v1', 'id': 'u1-1', 'ref': ref})
time.sleep(1.5)
res['ref: subscribe path, wrong bytes, then client asks'] = get(ref['url_path'])
res['ref: wrong size longer'] = None
state['answers'][ref['url_path']] = env('rb2', 2, 'good')
res['ref: upstream now honest, no ref kept, on demand'] = get(ref['url_path'])
ref3 = dict(ref, bundle_id='rb3', url_path='/v0/bundles/rb3/3.json', version=3, sha256='sha256:' + hashlib.sha256(env('rb3', 3, 'good')).hexdigest(), size=len(env('rb3', 3, 'good')))
state['answers'][ref3['url_path']] = env('rb3', 3, 'good')
state['stream'].append({'type': 'schild.dist.bundle.v1', 'id': 'u1-2', 'ref': ref3})
time.sleep(1.5)
res['ref honest on subscribe path'] = get(ref3['url_path'])
state['answers'][ref3['url_path']] = env('rb3', 3, 'lie')
res['ref honest cached, upstream lies later'] = get(ref3['url_path'])
state['answers'][ref['url_path']] = env('rb2', 2, 'lie')
res['ref: honest copy cached, upstream lies again'] = get(ref['url_path'])
res['log'] = state['log'][:40]
res['bad path'] = get('/v0/bundles/rb1/0.json')
p.terminate()
p.wait(5)

# per-IP limit: 4 streams allowed


def stream(hdrs):
    c = socket.create_connection(('127.0.0.1', RL), timeout=3)
    h = ''.join(f'{k}: {v}\r\n' for k, v in hdrs.items())
    c.sendall(f'GET /v0/stream HTTP/1.1\r\nHost: r.example\r\n{h}\r\n'.encode())
    d = c.recv(200)
    return c, int(d[9:12] or 0)


def many(n, hf):
    conns, st = [], []
    for i in range(n):
        c, s_ = stream(hf(i))
        conns.append(c)
        st.append(s_)
    for c in conns:
        c.close()
    time.sleep(0.3)
    return st


p = start(name='b')
time.sleep(0.5)
res['limit: no proxy configured, rotating X-Forwarded-For, 8 streams'] = many(8, lambda i: {'X-Forwarded-For': f'198.51.100.{i + 1}'})
p.terminate()
p.wait(5)
p = start({'SCHILD_RELAY_TRUSTED_PROXIES': '127.0.0.1/32'}, name='c')
time.sleep(0.5)
res['limit: proxy trusted, 8 different clients behind it'] = many(8, lambda i: {'X-Forwarded-For': f'198.51.100.{i + 1}'})
res['limit: proxy trusted, one client, spoofed left part rotates'] = many(8, lambda i: {'X-Forwarded-For': f'203.0.113.{i + 1}, 198.51.100.77'})
res['limit: proxy trusted, junk header'] = many(6, lambda i: {'X-Forwarded-For': f'junk{i}'})
res['limit: proxy trusted, no header'] = many(6, lambda i: {})
p.terminate()
p.wait(5)
p = start({'SCHILD_RELAY_TRUSTED_PROXIES': '127.0.0.1/32', 'SCHILD_RELAY_CLIENT_IP_HEADER': 'CF-Connecting-IP'}, name='d')
time.sleep(0.5)
res['limit: other header set, X-Forwarded-For rotates'] = many(6, lambda i: {'X-Forwarded-For': f'198.51.100.{i + 1}'})
res['limit: other header set, it names different clients'] = many(6, lambda i: {'CF-Connecting-IP': f'198.51.100.{i + 1}'})
p.terminate()
p.wait(5)
for bad in ('0.0.0.0/0', '10.0.0.0/7', '::/0', '2001::/31', 'notacidr'):
    p = start({'SCHILD_RELAY_TRUSTED_PROXIES': bad}, name='e')
    time.sleep(0.6)
    rc = p.poll()
    res[f'start with {bad}'] = 'refused' if rc not in (None, 0) else 'runs'
    if rc is None:
        p.terminate()
        p.wait(5)
print(json.dumps(res, indent=1))
json.dump(res, open(OUT, 'w'), indent=1)
