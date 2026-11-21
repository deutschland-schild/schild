"""Small helpers of the MVP-27 group measurement: gateway processes, HTTP, the dashboard API, load.

Python 3 standard library only. Everything runs on 127.0.0.1. Black box: the gateway is driven through its
binary, its config file, its HTTP listeners and its command line, as contracts/cluster.md and
docs/gateway/03-gruppe.md describe them.
"""
import http.client
import json
import os
import re
import signal
import socket
import subprocess
import threading
import time

PASSWORD = "measure-27-pass-x"
OWN_ONLY = "203.0.113.250"


def now():
    return time.monotonic()


def pct(values, p):
    """Percentile by nearest rank; None for an empty list."""
    if not values:
        return None
    s = sorted(values)
    k = max(0, min(len(s) - 1, int(round(p / 100.0 * len(s) + 0.5)) - 1))
    return s[k]


def summary(values, digits=2):
    if not values:
        return {"n": 0}
    return {"n": len(values), "p50": round(pct(values, 50), digits), "p95": round(pct(values, 95), digits),
            "p99": round(pct(values, 99), digits), "max": round(max(values), digits), "min": round(min(values), digits)}


class Conn:
    """One keep-alive connection to a proxy port; get() answers the status, 0 for a failed request."""

    def __init__(self, port, timeout=5.0):
        self.port, self.timeout, self.c = port, timeout, None

    def get(self, path="/", xff=None, retry=False):
        headers = {"Host": "127.0.0.1", "User-Agent": "Mozilla/5.0 (measure MVP-27)"}
        if xff:
            headers["X-Forwarded-For"] = xff
        for attempt in (0, 1):
            try:
                if self.c is None:
                    self.c = http.client.HTTPConnection("127.0.0.1", self.port, timeout=self.timeout)
                self.c.request("GET", path, headers=headers)
                r = self.c.getresponse()
                r.read()
                if r.will_close:
                    self.close()
                return r.status
            except Exception:
                self.close()
                if not retry or attempt:
                    return 0
        return 0

    def close(self):
        try:
            if self.c:
                self.c.close()
        finally:
            self.c = None


def get(port, path="/", xff=None, timeout=5.0):
    """One request on a new connection."""
    c = Conn(port, timeout)
    try:
        return c.get(path, xff)
    finally:
        c.close()


def api(port, method, path, body=None, headers=None, timeout=15.0):
    """JSON call; answers (status, decoded body or text). Status 0: no answer."""
    h = {"Host": "127.0.0.1:%d" % port, "Accept": "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body).encode()
        h["Content-Type"] = "application/json"
    h.update(headers or {})
    try:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
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
    """The dashboard API of one node with one session. A session of another node is passed as `other`."""

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
        st, js, hdrs = api(self.node.dash, method, "/api/v0" + path, body, h, timeout)
        sc = hdrs.get("Set-Cookie", "")
        m = re.search(r"(schild_session=[^;]+)", sc)
        if m and st == 200:
            self.cookie = m.group(1)
        if isinstance(js, dict) and js.get("csrf_token"):
            self.csrf = js["csrf_token"]
        return st, js

    def setup(self):
        code = self.node.setup_code()
        return self.call("POST", "/auth/setup", {"setup_code": code, "password": PASSWORD})

    def login(self):
        return self.call("POST", "/auth/login", {"user": "admin", "password": PASSWORD})

    def session(self):
        return self.call("GET", "/auth/session")

    def block(self, address, duration=604800):
        # 7 days by default: a block by hand of 1 h or 24 h ends at the next full minute of the process, also on a
        # single gateway without a group (item 02b), which would spoil every longer measurement
        return self.call("POST", "/blocks", {"address": address, "duration_s": duration, "reason": "MVP-27 measurement"})

    def unblock(self, incident):
        return self.call("POST", "/incidents/%s/unblock" % incident, {"false_positive": False})

    def blocks(self):
        st, js = self.call("GET", "/blocks")
        return sorted(b["client"] for b in js.get("items", [])) if st == 200 else None

    def allowlist(self):
        """Addresses of the allowlist, without OWN_ONLY: the entry one node has in its schild.yaml (item 02d)."""
        st, js = self.call("GET", "/allowlist?limit=500")
        if st != 200:
            return None
        return sorted(a for a in ((e.get("ip") or e.get("cidr") or e.get("host") or "?") for e in js.get("items", [])) if a != OWN_ONLY)

    def events(self, **q):
        qs = "&".join("%s=%s" % (k, v) for k, v in q.items())
        st, js = self.call("GET", "/events?limit=500&" + qs)
        return js.get("items", []) if st == 200 else None

    def privacy(self, ip):
        st, js = self.call("GET", "/privacy/search?ip=" + ip)
        return js if st == 200 else {"status": st, "body": js}


class Node:
    """One `schild run` process with its own ports, config and data directory."""

    def __init__(self, lab, name, idx, cluster=None, extra=""):
        self.lab, self.name = lab, name
        base = lab.port0 + idx * 10
        self.proxy, self.dash, self.metrics, self.agent, self.mesh = base, base + 1, base + 2, base + 3, base + 4
        self.dir = os.path.join(lab.root, name)
        self.data = os.path.join(self.dir, "data")
        self.cfg = os.path.join(self.dir, "schild.yaml")
        self.log = os.path.join(self.dir, "log")
        self.cluster, self.extra, self.proc = cluster, extra, None
        os.makedirs(self.dir, exist_ok=True)
        self.write_config()

    def write_config(self):
        y = [
            "config_version: 0",
            "node_name: %s" % self.name,
            "upstream:",
            '  url: "http://127.0.0.1:%d"' % self.lab.backend_port,
            "listen:",
            '  proxy: "127.0.0.1:%d"' % self.proxy,
            '  dashboard: "127.0.0.1:%d"' % self.dash,
            '  metrics: "127.0.0.1:%d"' % self.metrics,
            "geo:",
            "  db_path: %s" % self.lab.geo,
            "storage:",
            "  path: %s" % self.data,
            "agent_api:",
            "  enabled: true",
            '  listen: "127.0.0.1:%d"' % self.agent,
            # no call leaves the machine (docs/gateway/02-betrieb.md, "Welche Daten wo bleiben")
            "rules:",
            "  crowdsec: { state: off }",
            "bots:",
            "  ranges_fetch: false",
        ]
        if self.cluster is not None:
            y += ["cluster:", "  enabled: true", '  listen: "127.0.0.1:%d"' % self.mesh]
            if self.cluster.get("secret_file"):
                y += ["  secret_file: %s" % self.cluster["secret_file"],
                      "  peers: [%s]" % ", ".join('"%s"' % p for p in self.cluster["peers"])]
            y += ["  drain:", "    delay_s: %d" % self.cluster.get("delay_s", 4), "    grace_s: %d" % self.cluster.get("grace_s", 5)]
        if self.extra:
            y.append(self.extra)
        with open(self.cfg, "w") as f:
            f.write("\n".join(y) + "\n")

    def start(self):
        self.started_at = now()
        self.proc = subprocess.Popen([self.lab.bin, "run", "-config", self.cfg], stdout=open(self.log, "ab"),
                                     stderr=subprocess.STDOUT, cwd=self.dir)
        self.lab.procs.append(self.proc)
        return self

    def alive(self):
        return self.proc is not None and self.proc.poll() is None

    def kill9(self):
        if self.alive():
            self.proc.kill()
            self.proc.wait()

    def term(self):
        if self.alive():
            self.proc.send_signal(signal.SIGTERM)

    def freeze(self):
        self.proc.send_signal(signal.SIGSTOP)

    def thaw(self):
        self.proc.send_signal(signal.SIGCONT)

    def wait_exit(self, timeout=60):
        try:
            self.proc.wait(timeout)
            return True
        except subprocess.TimeoutExpired:
            return False

    def ready(self):
        return get(self.proxy, "/.schild/readyz", timeout=2.0)

    def wait_ready(self, timeout=40.0):
        """Seconds from the start of the process until /.schild/readyz answers 200; None when it never did."""
        end = now() + timeout
        while now() < end:
            if self.ready() == 200:
                return now() - self.started_at
            if not self.alive():
                return None
            time.sleep(0.05)
        return None

    def cli(self, *args, timeout=60, stdin=None):
        """Run `schild ARGS -config CFG`; answers (exit code, output)."""
        try:
            p = subprocess.run([self.lab.bin, *args, "-config", self.cfg], capture_output=True, text=True,
                               timeout=timeout, input=stdin, cwd=self.dir)
            return p.returncode, (p.stdout + p.stderr).strip()
        except subprocess.TimeoutExpired as e:
            return -1, "timeout: %s" % e

    def setup_code(self):
        codes = re.findall(r'"setup_code":"([^"]+)"', open(self.log).read())
        return codes[-1] if codes else ""

    def logtext(self):
        return open(self.log, errors="replace").read()

    def listeners(self):
        """TCP ports this process listens on, from lsof."""
        out = subprocess.run(["lsof", "-nP", "-a", "-p", str(self.proc.pid), "-iTCP", "-sTCP:LISTEN"],
                             capture_output=True, text=True).stdout
        return sorted(set(int(m) for m in re.findall(r":(\d+) \(LISTEN\)", out)))

    def key_file(self):
        return os.path.join(self.data, "cluster", "node.key")


class Blackhole:
    """A TCP listener that accepts and never answers."""

    def __init__(self, port):
        self.s = socket.socket()
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(("127.0.0.1", port))
        self.s.listen(64)
        self.held, self.stop = [], False
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        self.s.settimeout(0.2)
        while not self.stop:
            try:
                c, _ = self.s.accept()
                self.held.append(c)
            except OSError:
                pass

    def close(self):
        self.stop = True
        for c in self.held:
            c.close()
        self.s.close()


class Watch:
    """Polls one address on several proxy ports and notes when each first answers the wanted status."""

    def __init__(self, nodes, xff, want, pause=0.002):
        self.first, self.polls, self.stop = {}, {}, False
        self.threads = [threading.Thread(target=self._run, args=(n, xff, want, pause), daemon=True) for n in nodes]

    def _run(self, node, xff, want, pause):
        c = Conn(node.proxy, 2.0)
        n = 0
        while not self.stop:
            st = c.get("/w", xff, retry=True)
            n += 1
            if st == want:
                self.first[node.name] = now()
                break
            time.sleep(pause)
        self.polls[node.name] = n
        c.close()

    def start(self):
        for t in self.threads:
            t.start()
        return self

    def wait(self, timeout):
        end = now() + timeout
        for t in self.threads:
            t.join(max(0.0, end - now()))
        self.stop = True
        for t in self.threads:
            t.join(1.0)
        return dict(self.first)


def wait_for(cond, timeout, pause=0.05):
    """Seconds until cond() is true, None when it never was."""
    t0 = now()
    while now() - t0 < timeout:
        try:
            if cond():
                return now() - t0
        except Exception:
            pass
        time.sleep(pause)
    return None


def latency(port, n, xff="198.51.100.250", warm=100):
    """n sequential requests on one keep-alive connection; answers (latencies in ms, failed, not 200)."""
    c = Conn(port, 10.0)
    for _ in range(warm):
        c.get("/l", xff)
    lat, failed, other = [], 0, 0
    for _ in range(n):
        t = time.perf_counter()
        st = c.get("/l", xff)
        d = (time.perf_counter() - t) * 1000.0
        if st == 0:
            failed += 1
        elif st != 200:
            other += 1
        lat.append(d)
    c.close()
    return lat, failed, other


class Load:
    """Background load over several nodes, round robin, each request with its time, node, status and latency.

    With `health` it acts as a balancer does: a thread asks /.schild/readyz of every node every 200 ms and a node
    that does not answer 200 gets no new request until it does again.
    """

    def __init__(self, nodes, rps=150, threads=4, health=False, xff_base="198.51.100."):
        self.nodes, self.rps, self.nthreads, self.health = nodes, rps, threads, health
        self.rows, self.stop, self.lock = [], False, threading.Lock()
        self.up = {n.name: True for n in nodes}
        self.xff_base = xff_base
        self.threads = []

    def _health(self):
        while not self.stop:
            for n in self.nodes:
                self.up[n.name] = get(n.proxy, "/.schild/readyz", timeout=0.5) == 200
            time.sleep(0.2)

    def _run(self, k):
        conns = {n.name: Conn(n.proxy, 5.0) for n in self.nodes}
        gap = self.nthreads / float(self.rps)
        i = k
        nxt = now()
        while not self.stop:
            i += 1
            node = self.nodes[i % len(self.nodes)]
            if self.health and not self.up[node.name]:
                conns[node.name].close()  # as a balancer: no connection is kept to a node that is out
                alive = [n for n in self.nodes if self.up[n.name]]
                if not alive:
                    time.sleep(0.01)
                    continue
                node = alive[i % len(alive)]
            t = now()
            st = conns[node.name].get("/load", "%s%d" % (self.xff_base, 1 + i % 100))
            with self.lock:
                self.rows.append((t, node.name, st, (now() - t) * 1000.0))
            nxt += gap
            d = nxt - now()
            if d > 0:
                time.sleep(d)
            else:
                nxt = now()
        for c in conns.values():
            c.close()

    def start(self):
        if self.health:
            self.threads.append(threading.Thread(target=self._health, daemon=True))
        self.threads += [threading.Thread(target=self._run, args=(k,), daemon=True) for k in range(self.nthreads)]
        for t in self.threads:
            t.start()
        return self

    def finish(self):
        self.stop = True
        for t in self.threads:
            t.join(8.0)
        return self.rows


def hostile(lab, *args, stdin=None, timeout=30):
    p = subprocess.run([lab.hostile, *args], capture_output=True, text=True, input=stdin, timeout=timeout)
    out = p.stdout.strip()
    try:
        return json.loads(out)
    except ValueError:
        return {"raw": out, "stderr": p.stderr.strip(), "rc": p.returncode}
