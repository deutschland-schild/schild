#!/usr/bin/env python3
"""Control agent of one lab VM (MVP-27 lab measurement). TEST ONLY.

Runs as root inside every VM of the test network and lets the driver in the client VM run commands there:
start and kill schild, set packet filters, move the clock, read logs. It is a root shell over plain HTTP and
belongs on the host-only test network and nowhere else.

POST /run    {"cmd": "...", "timeout": 30, "stdin": "..."}  -> {"rc": 0, "out": "..."}
POST /spawn  {"cmd": "..."}                                 -> {"pid": 123}   (detached, own session)
PUT  /file?path=/x&mode=600   body = content
GET  /file?path=/x
"""
import http.server
import json
import os
import socketserver
import subprocess
import sys
import urllib.parse

PORT = 9927


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _answer(self, status, body, ctype="application/json"):
        raw = body if isinstance(body, bytes) else json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _body(self):
        return self.rfile.read(int(self.headers.get("Content-Length") or 0))

    def do_POST(self):
        req = json.loads(self._body() or b"{}")
        if self.path == "/run":
            try:
                p = subprocess.run(req["cmd"], shell=True, capture_output=True, timeout=req.get("timeout", 30),
                                   input=(req.get("stdin") or "").encode() if "stdin" in req else None,
                                   stdin=None if "stdin" in req else subprocess.DEVNULL)
                self._answer(200, {"rc": p.returncode, "out": (p.stdout + p.stderr).decode("utf-8", "replace")})
            except subprocess.TimeoutExpired as e:
                self._answer(200, {"rc": -1, "out": "timeout: %s" % ((e.stdout or b"") + (e.stderr or b"")).decode("utf-8", "replace")})
        elif self.path == "/spawn":
            p = subprocess.Popen(req["cmd"], shell=True, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, start_new_session=True)
            self._answer(200, {"pid": p.pid})
        else:
            self._answer(404, {"error": "unknown"})

    def do_PUT(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        path = q["path"][0]
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(self._body())
        if "mode" in q:
            os.chmod(path, int(q["mode"][0], 8))
        self._answer(200, {"ok": True})

    def do_GET(self):
        q = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        try:
            with open(q["path"][0], "rb") as f:
                self._answer(200, f.read(), "application/octet-stream")
        except OSError as e:
            self._answer(404, {"error": str(e)})

    def log_message(self, *a):
        pass


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    # children that are spawned detached are reaped by init of the VM; ignore SIGCHLD so none stays a zombie here
    import signal
    signal.signal(signal.SIGCHLD, signal.SIG_DFL)
    Server(("0.0.0.0", int(sys.argv[1]) if len(sys.argv) > 1 else PORT), Handler).serve_forever()
