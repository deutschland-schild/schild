# TEST ONLY: backend for the MVP-19 runtime checks. Logs method, host, URI,
# selected headers and the body (first 300 bytes) of every request as one line.
import sys, http.server
LOG = sys.argv[2]
class H(http.server.BaseHTTPRequestHandler):
    def _any(self):
        n = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(n) if n else b''
        hs = {k: v for k, v in self.headers.items() if k.lower().startswith(('x-', 'host'))}
        with open(LOG, 'a') as f:
            f.write(f"{self.command} {self.path} hdr={hs} body={body[:300]!r}\n")
        self.send_response(200); self.send_header('Content-Length', '3'); self.end_headers(); self.wfile.write(b'ok\n')
    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _any
    def log_message(self, *a): pass
http.server.ThreadingHTTPServer(('127.0.0.1', int(sys.argv[1])), H).serve_forever()
