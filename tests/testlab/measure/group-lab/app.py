#!/usr/bin/env python3
"""The application behind the gateways (MVP-27 lab measurement): answers 200 to everything.

/slow?ms=N answers after N milliseconds (a request in flight). The body names the address and the
X-Forwarded-For the application saw, so a check can read which client address the gateway passed on.
"""
import http.server
import socketserver
import sys
import time
import urllib.parse


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    disable_nagle_algorithm = True

    def do_GET(self):
        u = urllib.parse.urlparse(self.path)
        # read the body of a POST: left in the socket it would be taken for the start of the next request on a kept connection
        n = int(self.headers.get("Content-Length") or 0)
        if n:
            self.rfile.read(n)
        if u.path == "/slow":
            time.sleep(int(urllib.parse.parse_qs(u.query).get("ms", ["1000"])[0]) / 1000.0)
        body = ("ok xff=%s\n" % self.headers.get("X-Forwarded-For", "-")).encode()
        # one write for the whole answer: headers and body in two segments would wait for Nagle and the delayed ACK
        head = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n" % len(body)
        self.wfile.write(head.encode() + body)

    do_POST = do_GET
    do_HEAD = do_GET

    def log_message(self, *a):
        pass


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 1024


if __name__ == "__main__":
    Server(("0.0.0.0", int(sys.argv[1]) if len(sys.argv) > 1 else 8080), Handler).serve_forever()
