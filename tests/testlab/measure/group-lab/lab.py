"""Helpers of the MVP-27 lab measurement: VMs, gateway nodes, the dashboard API, the load client, faults.

Runs inside the client VM of the test network (Python 3 standard library only). Every other VM runs the
control agent ctl.py; this module reaches them over the test network. Black box: schild is driven through its
binary, schild.yaml, the Caddyfile, its listeners, its command line and the documented dashboard API.
"""
import http.client
import json
import os
import re
import socket
import threading
import time
import urllib.parse

CTL_PORT = 9927
PASSWORD = "measure-27-lab-pass"
SITE = "app.sg27.test"
MESH_PORT = 8790
DASH_PORT = 8788
WEB_PORT = 80
INVENTORY = "/opt/sg27/inventory.json"


def now():
    return time.monotonic()


def pct(values, p):
    """Percentile by nearest rank; None for an empty list."""
    if not values:
        return None
    s = sorted(values)
    k = max(0, min(len(s) - 1, int(round(p / 100.0 * len(s) + 0.5)) - 1))
    return s[k]


def summary(values, digits=1):
    if not values:
        return {"n": 0}
    return {"n": len(values), "min": round(min(values), digits), "p50": round(pct(values, 50), digits),
            "p95": round(pct(values, 95), digits), "p99": round(pct(values, 99), digits), "max": round(max(values), digits)}


# ---------------------------------------------------------------------------------------------------------------
# VMs


class VM:
    """One VM of the test network, reached through its control agent."""

    def __init__(self, name, ip):
        self.name, self.ip = name, ip

    def _call(self, method, path, body=None, timeout=60):
        c = http.client.HTTPConnection(self.ip, CTL_PORT, timeout=timeout)
        try:
            c.request(method, path, body=body)
            r = c.getresponse()
            return r.status, r.read()
        finally:
            c.close()

    def run(self, cmd, timeout=30, stdin=None):
        """Run a shell command as root in the VM; answers (exit code, output)."""
        req = {"cmd": cmd, "timeout": timeout}
        if stdin is not None:
            req["stdin"] = stdin
        try:
            _, raw = self._call("POST", "/run", json.dumps(req).encode(), timeout + 10)
        except OSError as e:
            return -2, "agent unreachable: %r" % e
        d = json.loads(raw)
        return d["rc"], d["out"].strip()

    def sh(self, cmd, timeout=30):
        """Like run, but raises when the command fails: for steps of the setup that must work."""
        rc, out = self.run(cmd, timeout)
        if rc != 0:
            raise RuntimeError("%s: %s -> %d %s" % (self.name, cmd, rc, out))
        return out

    def spawn(self, cmd):
        self._call("POST", "/spawn", json.dumps({"cmd": cmd}).encode())

    def put(self, path, content, mode=None):
        q = "/file?path=" + urllib.parse.quote(path) + ("&mode=%s" % mode if mode else "")
        self._call("PUT", q, content.encode() if isinstance(content, str) else content)

    def get(self, path):
        st, raw = self._call("GET", "/file?path=" + urllib.parse.quote(path))
        return raw.decode("utf-8", "replace") if st == 200 else ""

    # packet filter of this VM: one table of the harness, never the table "inet schild" of the product
    def nft(self, rules):
        """Replace the harness table by the given rules (list of 'hook: rule' strings, hook input or output)."""
        text = ["table inet sg27fault {", " chain i { type filter hook input priority -10; policy accept;"]
        text += ["  " + r[len("input:"):].strip() for r in rules if r.startswith("input:")]
        text += [" }", " chain o { type filter hook output priority -10; policy accept;"]
        text += ["  " + r[len("output:"):].strip() for r in rules if r.startswith("output:")]
        text += [" }", "}"]
        self.run("nft delete table inet sg27fault 2>/dev/null; true")
        self.put("/tmp/sg27fault.nft", "\n".join(text) + "\n")
        return self.sh("nft -f /tmp/sg27fault.nft")

    def nft_clear(self):
        self.run("nft delete table inet sg27fault 2>/dev/null; true")

    def delay(self, peers, delay_ms, jitter_ms=0, loss=0.0):
        """Hold the packets this VM sends to the peers (netdelay.py). delay_clear() ends it."""
        self.delay_clear()
        self.spawn("python3 /opt/sg27/netdelay.py --src %s --delay-ms %s --jitter-ms %s --loss %s %s"
                   % (self.ip, delay_ms, jitter_ms, loss, " ".join(peers)))
        time.sleep(0.4)

    def delay_clear(self):
        self.run("pkill -TERM -f '[n]etdelay.py'; sleep 0.2; ip link del sgd0 2>/dev/null; true")

    def clock_shift(self, seconds):
        """Put the wall clock of the VM so many seconds off the right time and keep it there (clockhold.py: the
        hypervisor sets the clock of a VM right again about every 30 s). clock_release() ends it."""
        self.clock_release()
        self.spawn("python3 /opt/sg27/clockhold.py %s /tmp/sg27-clockhold.log" % seconds)
        time.sleep(0.4)

    def clock_release(self):
        """Back to the right time. Answers the log of the holder: when it had to put the clock back."""
        self.run("pkill -TERM -f '[c]lockhold.py'; true")
        time.sleep(0.4)
        return self.get("/tmp/sg27-clockhold.log")

    def clock_corrections(self):
        """How often the holder had to put the clock back so far (each time the clock was right for a few ms)."""
        return self.get("/tmp/sg27-clockhold.log").count("corrected")

    def clock(self):
        return float(self.sh("date -u +%s.%N"))


def load_inventory(path=INVENTORY):
    with open(path) as f:
        return json.load(f)


# ---------------------------------------------------------------------------------------------------------------
# HTTP as a visitor


def proxy_v1(src, dst, sport=40000, dport=80):
    return ("PROXY TCP4 %s %s %d %d\r\n" % (src, dst, sport, dport)).encode()


class Conn:
    """One connection to a web port. `claim`: this client speaks the PROXY protocol itself, as a balancer does,
    and names that client address. `bind`: source address of the connection (an address this VM holds).
    get() answers the status, 0 for a request that failed."""

    def __init__(self, ip, port=WEB_PORT, claim=None, bind=None, timeout=5.0, host=SITE):
        self.ip, self.port, self.claim, self.bind, self.timeout, self.host = ip, port, claim, bind, timeout, host
        self.c = None
        self.error = ""
        self.body, self.headers = b"", {}
        self.asked_to_close = 0      # answers that carried `Connection: close` without the client having asked for it

    def _open(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if self.bind:
            s.bind((self.bind, 0))
        s.connect((self.ip, self.port))
        if self.claim:
            s.sendall(proxy_v1(self.claim, self.ip, dport=self.port))
        c = http.client.HTTPConnection(self.ip, self.port, timeout=self.timeout)
        c.sock = s
        self.c = c

    def get(self, path="/", close=False, headers=None):
        h = {"Host": self.host, "User-Agent": "Mozilla/5.0 (measure MVP-27 lab)"}
        if close:
            h["Connection"] = "close"
        h.update(headers or {})
        try:
            if self.c is None:
                self._open()
            self.c.request("GET", path, headers=h)
            r = self.c.getresponse()
            self.body = r.read()
            self.headers = dict(r.getheaders())
            if r.will_close and not close:
                self.asked_to_close += 1
            if r.will_close or close:
                self.close()
            return r.status
        except Exception as e:
            self.error = repr(e)
            self.close()
            return 0

    def close(self):
        try:
            if self.c:
                self.c.close()
        finally:
            self.c = None


class RawConn:
    """A client that keeps its connection whatever the answer says: it does not look at `Connection: close` and
    sends its next request on the same socket. Same interface as Conn. get() answers 0 when the request got no
    answer (the socket was closed or reset)."""

    def __init__(self, ip, port=WEB_PORT, claim=None, bind=None, timeout=5.0, host=SITE):
        self.ip, self.port, self.claim, self.bind, self.timeout, self.host = ip, port, claim, bind, timeout, host
        self.c = None                # the socket; named as in Conn, the load client asks `c.c is None`
        self.buf = b""
        self.error = ""
        self.body, self.headers = b"", {}
        self.asked_to_close = 0

    def _open(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if self.bind:
            s.bind((self.bind, 0))
        s.connect((self.ip, self.port))
        if self.claim:
            s.sendall(proxy_v1(self.claim, self.ip, dport=self.port))
        self.c, self.buf = s, b""

    def _more(self):
        chunk = self.c.recv(65536)
        if not chunk:
            raise EOFError("closed by the server without an answer" if not self.buf else "closed by the server inside an answer")
        self.buf += chunk

    def _take(self, n):
        while len(self.buf) < n:
            self._more()
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def _line(self):
        while b"\r\n" not in self.buf:
            self._more()
        line, self.buf = self.buf.split(b"\r\n", 1)
        return line

    def get(self, path="/", close=False, headers=None):
        h = {"Host": self.host, "User-Agent": "Mozilla/5.0 (measure MVP-27 lab, keeps its connection)"}
        h.update(headers or {})
        req = "GET %s HTTP/1.1\r\n%s\r\n\r\n" % (path, "\r\n".join("%s: %s" % kv for kv in h.items()))
        try:
            if self.c is None:
                self._open()
            self.c.sendall(req.encode())
            status = int(self._line().split()[1])
            hdrs = {}
            while True:
                line = self._line()
                if not line:
                    break
                k, _, v = line.decode("latin-1").partition(":")
                hdrs[k.strip().title()] = v.strip()
            if hdrs.get("Transfer-Encoding", "").lower() == "chunked":
                body = b""
                while True:
                    n = int(self._line().split(b";")[0], 16)
                    if n == 0:
                        while self._line():
                            pass
                        break
                    body += self._take(n)
                    self._take(2)
            else:
                body = self._take(int(hdrs.get("Content-Length", "0")))
            self.body, self.headers = body, hdrs
            if hdrs.get("Connection", "").lower() == "close":
                self.asked_to_close += 1          # and stays on the connection all the same
            if close:
                self.close()
            return status
        except Exception as e:
            self.error = repr(e)
            self.close()
            return 0

    def close(self):
        try:
            if self.c:
                self.c.close()
        except OSError:
            pass
        finally:
            self.c, self.buf = None, b""


def tcp_open(ip, port, bind=None, timeout=0.5):
    """Whether a TCP connection from the source address `bind` is accepted (what a firewall drop ends)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if bind:
            s.bind((bind, 0))
        s.connect((ip, port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def get(ip, path="/", claim=None, bind=None, timeout=5.0, port=WEB_PORT, host=SITE, headers=None):
    """One request on a new connection; answers the status (0: failed)."""
    c = Conn(ip, port, claim, bind, timeout, host)
    try:
        return c.get(path, close=True, headers=headers)
    finally:
        c.close()


def tls_get(ip, path, sni, claim=None, port=443, timeout=5.0, bind=None):
    """One HTTPS request without checking the certificate; answers (status, SHA-256 of the certificate shown, session reused).
    Status 0: no TLS answer."""
    import hashlib
    import ssl
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        raw = socket.create_connection((ip, port), timeout=timeout, source_address=(bind, 0) if bind else None)
        if claim:
            raw.sendall(proxy_v1(claim, ip, dport=port))
        t = ctx.wrap_socket(raw, server_hostname=sni)
        der = t.getpeercert(binary_form=True)
        t.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % (path, sni)).encode())
        data = b""
        while True:
            chunk = t.recv(65536)
            if not chunk:
                break
            data += chunk
        t.close()
        m = re.match(rb"HTTP/1.1 (\d+)", data)
        return (int(m.group(1)) if m else 0), hashlib.sha256(der).hexdigest()[:16]
    except Exception as e:
        return 0, repr(e)[:80]


class Load:
    """Requests at a fixed rate from several workers; every request is recorded as (start, seconds, status, tag).

    mode "new": a new connection per request (what a balancer spreads). mode "keep": one connection per worker,
    kept open; a request that fails on a kept connection is tried once more on a new one and counted as retried,
    as a browser does with a connection the server closed. This client honours `Connection: close`: after such an
    answer it opens a new connection for its next request (counted in `asked_to_close`). mode "deaf": like keep,
    but the client ignores `Connection: close` and stays on its connection until the server ends it.
    """

    def __init__(self, ip, rate, workers=8, mode="new", claim=None, bind=None, path="/", timeout=5.0, port=WEB_PORT):
        self.ip, self.rate, self.workers, self.mode, self.path, self.timeout, self.port = ip, rate, workers, mode, path, timeout, port
        self.claim, self.bind = claim, bind
        self.rows, self.retried, self.stop_flag, self.tag = [], 0, False, ""
        self.asked_to_close = 0
        self.lock = threading.Lock()
        self.threads = [threading.Thread(target=self._run, args=(i,), daemon=True) for i in range(workers)]

    def _run(self, i):
        gap = self.workers / float(self.rate)
        nxt = now() + gap * i / self.workers
        c = (RawConn if self.mode == "deaf" else Conn)(self.ip, self.port, self.claim, self.bind, self.timeout)
        while not self.stop_flag:
            d = nxt - now()
            if d > 0:
                time.sleep(d)
            nxt = max(nxt + gap, now() - 5 * gap)
            t0 = now()
            fresh = c.c is None
            st = c.get(self.path, close=self.mode == "new")
            retried = False
            if st == 0 and self.mode in ("keep", "deaf") and not fresh:
                retried = True
                st = c.get(self.path)
            with self.lock:
                self.rows.append((t0, now() - t0, st, self.tag, c.error if st == 0 else "", retried))
                self.retried += 1 if retried else 0
        with self.lock:
            self.asked_to_close += c.asked_to_close
        c.close()

    def start(self):
        self.t0 = now()
        for t in self.threads:
            t.start()
        return self

    def stop(self):
        self.stop_flag = True
        for t in self.threads:
            t.join(self.timeout + 2)
        return self

    def stats(self, since=None, until=None):
        rows = [r for r in self.rows if (since is None or r[0] >= since) and (until is None or r[0] < until)]
        codes = {}
        for r in rows:
            codes[r[2]] = codes.get(r[2], 0) + 1
        lat = [r[1] * 1000 for r in rows if r[2] != 0]
        return {"requests": len(rows), "codes": {str(k): v for k, v in sorted(codes.items())},
                "failed": codes.get(0, 0), "not_200": len(rows) - codes.get(200, 0),
                "latency_ms": summary(lat, 2), "retried": self.retried, "asked_to_close": self.asked_to_close,
                "errors": sorted(set(r[4] for r in rows if r[4]))[:5]}

    def failures(self):
        """Start (seconds since the start of the load), status, error and duration of every request that was not answered 200."""
        return [(round(r[0] - self.t0, 3), r[2], r[4], round(r[1], 3)) for r in self.rows if r[2] != 200]

    def retries(self):
        """Start (seconds since the start of the load) of every request that had to be sent a second time."""
        return [round(r[0] - self.t0, 3) for r in self.rows if r[5]]


class TlsLoad:
    """A light load over TLS: every request on a new connection (and a new handshake), certificate not checked.
    rows: (start, seconds, status); status 0 is a request without an answer."""

    def __init__(self, ip, sni, rate=5, workers=2, bind=None, port=443):
        self.ip, self.sni, self.rate, self.workers, self.bind, self.port = ip, sni, rate, workers, bind, port
        self.rows, self.stop_flag = [], False
        self.threads = [threading.Thread(target=self._run, args=(i,), daemon=True) for i in range(workers)]

    def _run(self, i):
        gap = self.workers / float(self.rate)
        nxt = now() + gap * i / self.workers
        while not self.stop_flag:
            d = nxt - now()
            if d > 0:
                time.sleep(d)
            nxt = max(nxt + gap, now() - 5 * gap)
            t0 = now()
            st, what = tls_get(self.ip, "/tls", self.sni, port=self.port, bind=self.bind)
            self.rows.append((t0, now() - t0, st, what if st == 0 else ""))

    def start(self):
        self.t0 = now()
        for t in self.threads:
            t.start()
        return self

    def stop(self):
        self.stop_flag = True
        for t in self.threads:
            t.join(8)
        return self

    def stats(self):
        codes = {}
        for r in self.rows:
            codes[r[2]] = codes.get(r[2], 0) + 1
        return {"requests": len(self.rows), "codes": {str(k): v for k, v in sorted(codes.items())},
                "not_200": len(self.rows) - codes.get(200, 0),
                "failed_at_s": [round(r[0] - self.t0, 1) for r in self.rows if r[2] != 200][:20],
                "errors": sorted(set(r[3] for r in self.rows if r[3]))[:4]}


# ---------------------------------------------------------------------------------------------------------------
# dashboard API


def api(ip, port, method, path, body=None, headers=None, timeout=15.0):
    """JSON call; answers (status, decoded body or text, headers). Status 0: no answer."""
    h = {"Accept": "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    h.update(headers or {})
    try:
        c = http.client.HTTPConnection(ip, port, timeout=timeout)
        c.request(method, path, body=data, headers=h)
        r = c.getresponse()
        raw = r.read()
        hdrs = dict(r.getheaders())
        c.close()
    except Exception as e:
        return 0, {"error": repr(e)}, {}
    try:
        return r.status, json.loads(raw) if raw else None, hdrs
    except ValueError:
        return r.status, raw.decode("utf-8", "replace"), hdrs


class Dash:
    """The dashboard API of one node with one session. The session of another node is passed as `other`."""

    def __init__(self, node, other=None):
        self.node = node
        self.cookie = other.cookie if other else None
        self.csrf = other.csrf if other else None

    def call(self, method, path, body=None, timeout=15.0):
        h = {}
        if self.cookie:
            h["Cookie"] = self.cookie
        if self.csrf and method != "GET":
            h["X-CSRF-Token"] = self.csrf
        st, js, hdrs = api(self.node.ip, DASH_PORT, method, "/api/v0" + path, body, h, timeout)
        m = re.search(r"(schild_session=[^;]+)", hdrs.get("Set-Cookie", ""))
        if m and st == 200:
            self.cookie = m.group(1)
        if isinstance(js, dict) and js.get("csrf_token"):
            self.csrf = js["csrf_token"]
        return st, js

    def setup(self):
        return self.call("POST", "/auth/setup", {"setup_code": self.node.setup_code(), "password": PASSWORD})

    def login(self):
        return self.call("POST", "/auth/login", {"user": "admin", "password": PASSWORD})

    def session(self):
        return self.call("GET", "/auth/session")

    def block(self, address, duration=604800):
        return self.call("POST", "/blocks", {"address": address, "duration_s": duration, "reason": "MVP-27 lab measurement"})

    def unblock(self, incident):
        return self.call("POST", "/incidents/%s/unblock" % incident, {"false_positive": False})

    def blocks(self):
        st, js = self.call("GET", "/blocks")
        return sorted(b["client"] for b in js.get("items", [])) if st == 200 and isinstance(js, dict) else None

    def allow(self, address, label="MVP-27 lab"):
        return self.call("POST", "/allowlist", {"ip": address, "label": label, "level": "no_block", "ttl": "never"})

    def erase(self, address):
        return self.call("POST", "/privacy/delete", {"ip": address, "confirm": True})

    def allowlist(self):
        st, js = self.call("GET", "/allowlist?limit=500")
        if st != 200:
            return None
        return sorted((e.get("ip") or e.get("cidr") or e.get("host") or "?") for e in js.get("items", []))

    def group(self):
        st, js = self.call("GET", "/group")
        return js if st == 200 else {"status": st, "body": js}

    def member(self, node_ip):
        """The GroupMember of the node with that mesh address, as this node shows it."""
        for m in self.group().get("members", []):
            if m.get("address", "").startswith(node_ip + ":"):
                return m
        return {}

    def reasons(self):
        """Codes of the reasons the overview (start page) carries."""
        st, js = self.call("GET", "/overview")
        if st != 200 or not isinstance(js, dict):
            return None
        return sorted(r.get("code") for r in (js.get("baseline") or {}).get("reasons", []))


# ---------------------------------------------------------------------------------------------------------------
# gateway nodes


class Node(VM):
    """One gateway VM: schild as the web server (ingress mode) with the files an operator deploys."""

    CFG = "/etc/schild/schild.yaml"
    LOG = "/var/log/schild/log"
    DATA = "/var/lib/schild"

    def __init__(self, name, ip, lab):
        super().__init__(name, ip)
        self.lab = lab
        self.started_at = None
        self.binary = "schild"

    def write_files(self, peers, balancers, node_name=None, cluster=True, drain=None, extra="", caddy_global="", site_extra="",
                    site_addr=None, name_from_host=False):
        """The deployment: schild.yaml, the Caddyfile and the group secret, as docs/gateway/03-cluster.md says.

        Only cluster.listen differs from node to node (and node_name, when one is given). name_from_host: the line
        `name_from_host: true` of the guide, with which one node_name for all nodes still gives every node its own name."""
        y = ["config_version: 0"]
        if node_name:
            y.append("node_name: %s" % node_name)
        y += [
            "ingress:",
            "  caddyfile: /etc/schild/Caddyfile",
            "listen:",
            '  dashboard: "0.0.0.0:%d"' % DASH_PORT,   # test network only; the driver calls the documented API here
            "geo:",
            "  db_path: /opt/geo.mmdb",               # TEST ONLY geo fixture of the documentation ranges
            "storage:",
            "  path: %s" % self.DATA,
            # no call leaves the lab (docs/gateway/02-betrieb.md); the VMs have no route out anyway
            "rules:",
            "  crowdsec: { state: off }",
            "bots:",
            "  ranges_fetch: false",
        ]
        if cluster:
            y += ["cluster:", "  enabled: true", '  listen: "%s:%d"' % (self.ip, MESH_PORT)]
            if peers is not None:
                y += ["  secret_file: /etc/schild/cluster.secret",
                      "  peers: [%s]" % ", ".join('"%s:%d"' % (p, MESH_PORT) for p in peers)]
                if name_from_host:
                    y += ["  name_from_host: true"]
            if drain:
                y += ["  drain:", "    delay_s: %d" % drain[0], "    grace_s: %d" % drain[1]]
        if extra:
            y.append(extra)
        self.put(self.CFG, "\n".join(y) + "\n")
        caddy = [
            "{",
            caddy_global or "\tauto_https off",
            "\tservers {",
            "\t\tlistener_wrappers {",
            "\t\t\tproxy_protocol {",
        ]
        caddy += ["\t\t\t\tallow %s/32" % b for b in balancers]
        caddy += [
            "\t\t\t}",
            "\t\t\ttls",
            "\t\t}",
            "\t\tprotocols h1 h2",
            "\t}",
            "}",
            "",
            "(schild) {",
            "\tschild",
            "}",
            "",
            "%s {" % (site_addr or "http://%s:%d" % (SITE, WEB_PORT)),
            "\timport schild",
            site_extra,
            "\treverse_proxy %s:8080" % self.lab["app"].ip,
            "}",
        ]
        self.put("/etc/schild/Caddyfile", "\n".join(l for l in caddy if l != "") + "\n")
        if cluster and peers is not None:
            self.put("/etc/schild/cluster.secret", self.lab["secret"] + "\n", "600")

    def wipe(self):
        self.kill9()
        self.run("rm -rf %s /var/log/schild/* /etc/schild/*; mkdir -p %s" % (self.DATA, self.DATA))
        self.nft_clear()
        self.delay_clear()

    def start(self):
        self.started_at = now()
        self.spawn("exec %s run -config %s >>%s 2>&1" % (self.binary, self.CFG, self.LOG))
        return self

    def alive(self):
        return self.run("pgrep -x schild >/dev/null")[0] == 0

    def kill9(self):
        self.run("pkill -9 -x schild; true")

    def term(self):
        self.run("pkill -TERM -x schild; true")

    def freeze(self):
        self.run("pkill -STOP -x schild; true")

    def thaw(self):
        self.run("pkill -CONT -x schild; true")

    def wait_exit(self, timeout=90):
        end = now() + timeout
        while now() < end:
            if not self.alive():
                return True
            time.sleep(0.2)
        return False

    def ready(self, timeout=2.0):
        """What the node answers its balancer on /.schild/readyz (asked as a balancer does, with a PROXY header)."""
        return get(self.ip, "/.schild/readyz", claim=self.lab["client"].ip, timeout=timeout)

    def wait_ready(self, timeout=60.0):
        """Seconds from the start of the process until /.schild/readyz answers 200; None when it never did."""
        end = now() + timeout
        while now() < end:
            if self.ready() == 200:
                return now() - self.started_at
            time.sleep(0.05)
        return None

    def cli(self, args, timeout=60, stdin=None):
        """`schild ARGS -config CFG` on the node; answers (exit code, output)."""
        return self.run("%s %s -config %s" % (self.binary, args, self.CFG), timeout, stdin)

    def setup_code(self):
        codes = re.findall(r'"setup_code":"([^"]+)"', self.logtext())
        return codes[-1] if codes else ""

    def logtext(self):
        return self.get(self.LOG)

    def count(self, pattern, path=None):
        """Lines of the log (or of `path`) that match; 0 when the file is not there."""
        rc, out = self.run("grep -c -E %s %s 2>/dev/null" % (json.dumps(pattern), path or self.LOG))
        out = out.strip().splitlines()[-1] if out.strip() else "0"
        return int(out) if out.isdigit() else 0

    def grep(self, pattern, n=5):
        rc, out = self.run("grep -E %s %s | tail -%d" % (json.dumps(pattern), self.LOG, n))
        return out

    def usage(self):
        """Resident memory (MiB) and CPU seconds of the schild process."""
        rc, out = self.run("p=$(pgrep -x schild | head -1); awk '/VmRSS/{print $2}' /proc/$p/status; "
                           "awk '{print $14+$15}' /proc/$p/stat; getconf CLK_TCK")
        try:
            rss, ticks, hz = out.split()
            return {"rss_mib": round(int(rss) / 1024.0, 1), "cpu_s": round(int(ticks) / float(hz), 2)}
        except ValueError:
            return {}

    def status(self):
        return self.cli("cluster status")[1]

    def hostname(self):
        """The first label of the host name of the VM: what `cluster.name_from_host` names the node."""
        return self.run("hostname")[1].strip().split(".")[0].lower()

    def disk(self):
        """KiB below storage.path: all of it, the stores of the other nodes' metrics, the node's own metrics.db."""
        rc, out = self.run("du -sk %s 2>/dev/null | cut -f1; du -sk %s/metrics-nodes 2>/dev/null | cut -f1 || echo 0; "
                           "ls %s/metrics-nodes 2>/dev/null | grep -c '\\.db$'; du -sk %s/metrics.db 2>/dev/null | cut -f1"
                           % (self.DATA, self.DATA, self.DATA, self.DATA))
        v = [int(x) for x in out.split() if x.isdigit()]
        v += [0] * (4 - len(v))
        return {"storage_kib": v[0], "metrics_nodes_kib": v[1], "metrics_nodes_files": v[2], "metrics_db_kib": v[3]}


def wait_until(fn, timeout=10.0, pause=0.05):
    """Seconds until fn() is true; None when it never was."""
    t0 = now()
    while now() - t0 < timeout:
        if fn():
            return now() - t0
        time.sleep(pause)
    return None


class Watch:
    """Polls one client address on several nodes (directly, speaking the PROXY protocol) and notes when each
    first answers the wanted status."""

    def __init__(self, nodes, address, want, pause=0.004):
        self.first, self.stop = {}, False
        self.threads = [threading.Thread(target=self._run, args=(n, address, want, pause), daemon=True) for n in nodes]

    def _run(self, node, address, want, pause):
        c = Conn(node.ip, claim=address, timeout=2.0)
        while not self.stop:
            if c.get("/w") == want:
                self.first[node.name] = now()
                break
            time.sleep(pause)
        c.close()

    def start(self):
        for t in self.threads:
            t.start()
        return self

    def wait(self, timeout=10.0):
        end = now() + timeout
        for t in self.threads:
            t.join(max(0.0, end - now()))
        self.stop = True
        return self.first
