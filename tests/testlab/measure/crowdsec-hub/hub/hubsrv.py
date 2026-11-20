#!/usr/bin/env python3
# TEST ONLY: MVP-26 update safety. Local stand-in for the hub file. The first path segment picks the behaviour.
# Every request is written to the access log with all its headers, so the report can say what a gateway sends.
#   hubsrv.py <port> <index dir> <access log>
import gzip, hashlib, json, os, socket, socketserver, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT, IDX, LOG = int(sys.argv[1]), sys.argv[2], sys.argv[3]
lock = threading.Lock()
cache = {}


def body(n):
    with lock:
        if n not in cache:
            cache[n] = open(f'{IDX}/{n}.json', 'rb').read()
        return cache[n]


class H(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *a):
        pass

    def do_GET(self):
        with open(LOG, 'a') as f:
            f.write(json.dumps({'t': time.time(), 'peer': self.client_address[0], 'cmd': self.command, 'path': self.path, 'headers': dict(self.headers.items())}) + '\n')
        s = self.path.strip('/').split('/')[0]
        if s == 'cur':  # whatever the control file names
            s = open(f'{IDX}/cur.txt').read().strip()
        if s == 'seq':  # the next name of the list on every request
            with lock:
                lines = open(f'{IDX}/seq.txt').read().split()
                s = lines[0] if lines else 'ok'
                open(f'{IDX}/seq.txt', 'w').write('\n'.join(lines[1:]))
        if s == 'hang':  # headers never come
            time.sleep(300)
            return
        if s == 'closeearly':
            self.close_connection = True
            return
        if s == 'slow':  # one byte a second, for ever
            self.send_response(200)
            self.send_header('Content-Length', str(10 << 20))
            self.end_headers()
            for _ in range(300):
                self.wfile.write(b'{')
                self.wfile.flush()
                time.sleep(1)
            return
        if s == 'slowok':  # the whole index in 20 s
            b = body('ok')
            self.send_response(200)
            self.send_header('Content-Length', str(len(b)))
            self.end_headers()
            step = len(b) // 20 + 1
            for i in range(0, len(b), step):
                self.wfile.write(b[i:i + step])
                self.wfile.flush()
                time.sleep(1)
            return
        if s == 'truncated':
            b = body('ok')
            self.send_response(200)
            self.send_header('Content-Length', str(len(b)))
            self.end_headers()
            self.wfile.write(b[:len(b) // 2])
            self.wfile.flush()
            self.close_connection = True
            return
        if s == 'truncated200':  # a cut file that looks complete at the HTTP level
            b = body('ok')[:2000000]
            self.send_response(200)
            self.send_header('Content-Length', str(len(b)))
            self.end_headers()
            self.wfile.write(b)
            return
        if s == 'notjson':
            b = b'<html>TEST ONLY: maintenance</html>'
            self.send_response(200)
            self.send_header('Content-Length', str(len(b)))
            self.end_headers()
            self.wfile.write(b)
            return
        if s == 'emptyobj':
            b = b'{}'
            self.send_response(200)
            self.send_header('Content-Length', '2')
            self.end_headers()
            self.wfile.write(b)
            return
        if s == 'huge':  # 40 MiB, no length
            self.send_response(200)
            self.send_header('Connection', 'close')
            self.end_headers()
            chunk = b'a' * (1 << 20)
            try:
                for _ in range(40):
                    self.wfile.write(chunk)
            except OSError:
                pass
            self.close_connection = True
            return
        if s == 'bomb':
            b = open(f'{IDX}/bomb.gz', 'rb').read()
            self.send_response(200)
            self.send_header('Content-Encoding', 'gzip')
            self.send_header('Content-Length', str(len(b)))
            self.end_headers()
            self.wfile.write(b)
            return
        if s.startswith('status'):
            code = int(s[6:])
            self.send_response(code)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        if s == 'redirect':
            self.send_response(302)
            self.send_header('Location', 'http://127.0.0.2:%d/ok' % PORT)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        if s == 'redirectsame':
            self.send_response(302)
            self.send_header('Location', '/ok')
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        if s == 'loop':
            self.send_response(302)
            self.send_header('Location', '/loop')
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        try:
            b = body(s)
        except FileNotFoundError:
            self.send_response(404)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        tag = '"' + hashlib.sha256(b).hexdigest()[:16] + '"'
        if self.headers.get('If-None-Match') == tag:
            self.send_response(304)
            self.send_header('ETag', tag)
            self.send_header('Content-Length', '0')
            self.end_headers()
            return
        self.send_response(200)
        self.send_header('ETag', tag)
        self.send_header('Content-Length', str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    do_HEAD = do_POST = do_PUT = do_GET


class S(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 128


S(('127.0.0.1', PORT), H).serve_forever()
