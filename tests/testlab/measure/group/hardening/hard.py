"""Shared helpers of the MVP-27 hardening measurement (faults, crashes, load, 16 nodes, long absence).

Python 3 standard library only, everything on 127.0.0.1. Black box like the first measurement (../run.py): the
gateway is driven through its binary, schild.yaml, its HTTP listeners, its command line and the dashboard API.
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from lib import Conn, Dash, Load, Node, api, get, now, pct, summary, wait_for  # noqa: E402,F401

SEED = 27
HOST = "shop.example"

# the clauses of kill_if in tests/specs/MVP-27-ha-group.yaml a check can speak to
KILL = {
    "waits": "any request waits for a peer or fails because of one (ACME challenge lookups aside)",
    "weakens": "a lost, empty or returning member deletes or weakens access state on another",
    "applied": "a record that fails signature, schema or caps is applied",
    "reads": "an edge or a removed member reads events, requests, settings, logins or keys",
    "erased": "an erased address returns",
    "spoof": "an address outside the proxy allow list can get another address blocked",
    "partial": "a partial answer is shown as complete",
    "copy": "a copy outlives its origin's retention",
    "certs": "certificates are lost or issued again by the move into the group",
}


def iso(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(t))


class Lab:
    """One scenario's processes, directories and verdicts."""

    def __init__(self, scenario, bin_path, tool, port0, keep=False, extra_bins=None):
        self.scenario, self.bin, self.tool, self.port0, self.keep = scenario, bin_path, tool, port0, keep
        self.extra_bins = extra_bins or {}
        self.procs, self.checks, self.data, self.nodes = [], [], {}, []
        # a short path: the control socket of schild lies below the data directory (104 bytes on macOS)
        self.root = tempfile.mkdtemp(prefix="sg27h-", dir="/tmp")
        self.backend_port, self.ctl_port = port0 - 10, port0 - 9
        self.geo = os.path.join(self.root, "geo.mmdb")
        subprocess.run([self.bin, "geo-fixture", "-out", self.geo], check=True, capture_output=True)
        self.spawn([self.tool, "backend", "-listen", "127.0.0.1:%d" % self.backend_port])
        if wait_for(lambda: get(self.backend_port, "/") == 200, 5) is None:
            raise RuntimeError("backend did not start on %d" % self.backend_port)
        self.net = None
        self.started = time.time()

    def spawn(self, argv, **kw):
        p = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kw)
        self.procs.append(p)
        return p

    def check(self, cid, name, ok, detail="", kill=None):
        """One verdict. ok: True PASS, False FAIL, None INFO (a number without a pass mark)."""
        verdict = "INFO" if ok is None else ("PASS" if ok else "FAIL")
        self.checks.append({"id": cid, "name": name, "verdict": verdict, "detail": str(detail)[:900], "kill": kill})
        print("  [%s] %s %s: %s" % (verdict, cid, name, str(detail)[:420]), flush=True)
        return ok

    def secret(self):
        path = os.path.join(self.root, "cluster.secret")
        if not os.path.exists(path):
            out = subprocess.run([self.bin, "cluster", "secret"], capture_output=True, text=True).stdout
            with open(path, "w") as f:
                f.write(out)
            os.chmod(path, 0o600)
        return path

    def close(self):
        for fn in getattr(self, "cleanups", []):
            try:
                fn()
            except Exception as e:
                print("cleanup:", e)
        for p in self.procs:
            if p.poll() is None:
                try:
                    p.send_signal(18)  # SIGCONT, in case it is still frozen
                except Exception:
                    pass
                p.kill()
        for p in self.procs:
            try:
                p.wait(10)
            except Exception:
                pass
        if self.keep:
            print("data kept in", self.root)
        else:
            subprocess.run(["chmod", "-R", "u+rwx", self.root], capture_output=True)
            shutil.rmtree(self.root, ignore_errors=True)


class HNode(Node):
    """A gateway of the hardening measurement: optional cluster.advertise (the fault proxy) and extra YAML."""

    def __init__(self, lab, name, idx, cluster=None, extra="", binary=None, top=""):
        self.binary, self.top = binary or lab.bin, top
        super().__init__(lab, name, idx, cluster, extra)
        self.via = self.mesh + 1  # the port of the fault proxy in front of this node's mesh listener
        lab.nodes.append(self)

    def write_config(self):
        y = [
            "config_version: 0", "node_name: %s" % self.name,
            "upstream:", '  url: "http://127.0.0.1:%d"' % self.lab.backend_port,
            "listen:", '  proxy: "127.0.0.1:%d"' % self.proxy, '  dashboard: "127.0.0.1:%d"' % self.dash,
            '  metrics: "127.0.0.1:%d"' % self.metrics,
            "geo:", "  db_path: %s" % self.lab.geo,
            "storage:", "  path: %s" % self.data,
            "agent_api:", "  enabled: true", '  listen: "127.0.0.1:%d"' % self.agent,
            # no call leaves the machine
            "rules:", "  crowdsec: { state: off }",
            "bots:", "  ranges_fetch: false",
        ]
        c = self.cluster
        if c is not None:
            y += ["cluster:", "  enabled: true", '  listen: "127.0.0.1:%d"' % self.mesh]
            if c.get("advertise"):
                y += ['  advertise: "%s"' % c["advertise"]]
            if c.get("secret_file"):
                y += ["  secret_file: %s" % c["secret_file"],
                      "  peers: [%s]" % ", ".join('"%s"' % p for p in c["peers"])]
            y += ["  drain:", "    delay_s: %d" % c.get("delay_s", 2), "    grace_s: %d" % c.get("grace_s", 3)]
            y += c.get("lines", [])
        if self.extra:
            y.append(self.extra)
        with open(self.cfg, "w") as f:
            f.write("\n".join(y) + "\n")

    def start(self, env=None):
        self.started_at = now()
        e = dict(os.environ)
        e.update(env or {})
        self.proc = subprocess.Popen([self.binary, "run", "-config", self.cfg], stdout=open(self.log, "ab"),
                                     stderr=subprocess.STDOUT, cwd=self.dir, env=e)
        self.lab.procs.append(self.proc)
        if self.lab.net:
            self.lab.net.pids()
        return self

    def cli(self, *args, timeout=60, stdin=None):
        try:
            p = subprocess.run([self.binary, *args, "-config", self.cfg], capture_output=True, text=True,
                               timeout=timeout, input=stdin, cwd=self.dir)
            return p.returncode, (p.stdout + p.stderr).strip()
        except subprocess.TimeoutExpired as e:
            return -1, "timeout: %s" % e

    def loglines(self, pattern, since=0):
        """Log lines (after byte offset `since`) that match the regular expression."""
        with open(self.log, errors="replace") as f:
            f.seek(since)
            return [l.strip() for l in f if re.search(pattern, l)]

    def logsize(self):
        return os.path.getsize(self.log) if os.path.exists(self.log) else 0


class Net:
    """The fault proxy: one listener per node in front of its mesh listener; rules by pair of nodes.

    A rule {"from": a, "to": b, ...} acts on the bytes that travel from node a to node b, whoever opened the
    connection: block holds them (and lets a new connection wait), refuse closes connections a opens to b,
    delay_ms makes them late. The proxy learns the calling node from the pid that holds the other end (netstat).
    """

    def __init__(self, lab):
        self.lab, self.port = lab, lab.ctl_port
        lab.spawn([lab.tool, "proxy", "-control", "127.0.0.1:%d" % self.port])
        if wait_for(lambda: self.stats() is not None, 5) is None:
            raise RuntimeError("fault proxy did not start")
        lab.net = self

    def _post(self, path, body):
        req = urllib.request.Request("http://127.0.0.1:%d%s" % (self.port, path), data=json.dumps(body).encode(), method="POST")
        return urllib.request.urlopen(req, timeout=5).read()

    def stats(self):
        try:
            return json.loads(urllib.request.urlopen("http://127.0.0.1:%d/stats" % self.port, timeout=5).read())
        except Exception:
            return None

    def links(self, nodes):
        self._post("/links", [{"listen": n.via, "target": n.mesh, "node": n.name} for n in nodes])

    def pids(self):
        self._post("/pids", {str(n.proc.pid): n.name for n in self.lab.nodes if n.proc is not None and n.proc.poll() is None})

    def rules(self, rules):
        self._post("/rules", rules)

    def clear(self):
        self.rules([])

    def partition(self, side_a, side_b):
        r = []
        for a in side_a:
            for b in side_b:
                r += [{"from": a.name, "to": b.name, "block": True}, {"from": b.name, "to": a.name, "block": True}]
        self.rules(r)


def group(lab, names, idx0=1, via_proxy=False, extra="", start=True, delay_s=2, grace_s=3, binary=None, lines=None):
    """Nodes of one group by configuration (cluster.secret_file, cluster.peers), started together."""
    sec = lab.secret()
    idx = list(range(idx0, idx0 + len(names)))
    mesh = [lab.port0 + i * 10 + 4 for i in idx]
    reach = [m + 1 for m in mesh] if via_proxy else mesh
    peers = ["127.0.0.1:%d" % p for p in reach]
    nodes = []
    for k, name in enumerate(names):
        c = {"secret_file": sec, "peers": peers, "delay_s": delay_s, "grace_s": grace_s, "lines": lines or []}
        if via_proxy:
            c["advertise"] = "127.0.0.1:%d" % reach[k]
        nodes.append(HNode(lab, name, idx[k], c, extra=extra, binary=binary))
    if via_proxy:
        if lab.net is None:
            Net(lab)
        lab.net.links(nodes)
    if start:
        for n in nodes:
            n.start()
    return nodes


def status_ok(node):
    """How many members `schild cluster status` of this node lists as ok."""
    rc, out = node.cli("cluster", "status", timeout=20)
    return len(re.findall(r"\sgateway\s+\S+\s+ok\s", out)), out


def wait_group(lab, nodes, timeout=60, cid="setup"):
    """Every node ready and in contact with every other; answers (ready times, seconds until all in contact)."""
    ready = [n.wait_ready(timeout) for n in nodes]
    t0 = now()
    t = wait_for(lambda: all(status_ok(n)[0] == len(nodes) - 1 for n in nodes), timeout, 0.3)
    took = None if t is None else round(now() - t0 + max(r or 0 for r in ready), 2)
    lab.check(cid, "%d gateways start as one group" % len(nodes), all(ready) and t is not None,
              "readyz 200 after %s s; every node lists every other as ok %s" % (
                  [r and round(r, 2) for r in ready], "after %s s from the start" % took if t is not None else "NEVER within %d s" % timeout))
    return ready, took


def first_setup(lab, nodes, cid="setup"):
    """First-run setup on the first node; answers one Dash per node sharing its session."""
    time.sleep(1.5)
    d = Dash(nodes[0])
    st, js = d.setup()
    ds = [d] + [Dash(n, d) for n in nodes[1:]]
    t = wait_for(lambda: all(x.session()[1].get("authenticated") for x in ds), 15, 0.1)
    lab.check(cid, "first-run setup on %s, its session works on every node" % nodes[0].name, st == 200 and t is not None,
              "setup %s; session valid everywhere after %s s" % (st, t and round(t, 2)))
    return ds


def gstatus(d):
    st, js = d.call("GET", "/group")
    return js if st == 200 and isinstance(js, dict) else {"state": "status %s" % st, "members": []}


def member_states(d):
    return {m["name"]: m["state"] for m in gstatus(d).get("members", []) if m.get("role") == "gateway"}


def allow_all(d):
    """Every address of the allowlist of a node (pages of 500); None on an error."""
    out, cursor = [], None
    for _ in range(100):
        q = "/allowlist?limit=500" + ("&cursor=" + urllib.request.quote(cursor) if cursor else "")
        st, js = d.call("GET", q, timeout=30)
        if st != 200:
            return None
        out += [(e.get("ip") or e.get("cidr") or e.get("host") or "?") for e in js.get("items", [])]
        cursor = js.get("next_cursor")
        if not cursor or not js.get("items"):
            break
    return sorted(out)


def snapshot(d, settings=True):
    """What a node holds of the shared state, as its dashboard API shows it."""
    out = {}
    st, js = d.call("GET", "/blocks")
    out["blocks"] = sorted(b["client"] for b in js.get("items", [])) if st == 200 else "status %s" % st
    al = allow_all(d)
    out["allowlist"] = al if al is not None else "error"
    st, js = d.call("GET", "/behaviour/rate-limits?limit=500")
    out["limits"] = sorted(x.get("label", x["id"]) for x in js.get("items", []) if x.get("source") == "dashboard") if st == 200 else "status %s" % st
    if settings:
        st, js = d.call("GET", "/settings")
        out["retention"] = js.get("retention") if st == 200 else "status %s" % st
    return out


def wait_same(ds, timeout=20, settings=True):
    """Seconds until every node shows the same snapshot (None: never); answers (seconds, snapshots)."""
    snaps = []

    def same():
        snaps[:] = [snapshot(d, settings) for d in ds]
        return all(s == snaps[0] for s in snaps)
    t = wait_for(same, timeout, 0.2)
    return t, snaps


def diff_snaps(names, snaps):
    """A short text of where snapshots differ."""
    out = []
    for key in snaps[0]:
        vals = [json.dumps(s.get(key), sort_keys=True) for s in snaps]
        if len(set(vals)) > 1:
            if all(isinstance(s.get(key), list) for s in snaps):
                union = sorted(set(x for s in snaps for x in s[key]))
                out.append("%s: %s" % (key, {n: "lacks %s" % sorted(set(union) - set(s[key])) for n, s in zip(names, snaps) if set(union) - set(s[key])}))
            else:
                out.append("%s: %s" % (key, dict(zip(names, vals))))
    return "; ".join(out) or "equal"


def count_requests(d, t_from, t_to=None):
    """Single requests a node holds: the sum of `scanned` of queryRequests with a filter that matches nothing (the
    read cap is 100 000 per call, the cursor goes on). `scanned` counts whole 10 min segments the span touches,
    not the span itself, so callers compare counts taken with one span (before and after). Answers (count, lowest
    sample rate)."""
    t_to = t_to or time.time() + 60
    total, rate, cursor, calls = 0, 1.0, None, 0
    while True:
        q = "/requests?from=%s&to=%s&limit=1&path=/none-such-path" % (iso(t_from), iso(t_to))
        if cursor:
            q += "&cursor=" + urllib.request.quote(cursor)
        st, js = d.call("GET", q, timeout=60)
        calls += 1
        if st == 429:
            time.sleep(0.3)
            if calls > 400:
                return None, None
            continue
        if st != 200:
            return "status %s %s" % (st, js), None
        total += js.get("scanned", 0)
        rate = min(rate, js.get("sample_rate", 1))
        cursor = js.get("next_cursor")
        if not cursor or calls > 400:
            return total, rate


def requests_of_ip(d, ip, t_from, t_to=None):
    """The records of one client address a node holds, as (path, status) list; None on an error."""
    t_to = t_to or time.time() + 60
    rows, cursor = [], None
    for _ in range(200):
        q = "/requests?from=%s&to=%s&limit=500&ip=%s" % (iso(t_from), iso(t_to), ip)
        if cursor:
            q += "&cursor=" + urllib.request.quote(cursor)
        st, js = d.call("GET", q, timeout=60)
        if st == 429:
            time.sleep(0.3)
            continue
        if st != 200:
            return None
        rows += [(r.get("path"), r.get("status")) for r in js.get("items", [])]
        cursor = js.get("next_cursor")
        if not cursor:
            break
    return rows


def count_events(d, path_prefix=None, ip=None, cap=40, outcome=None):
    """Events a node lists for a path prefix or an address (pages of 500, at most `cap` pages)."""
    n, cursor = 0, None
    for _ in range(cap):
        q = "/events?limit=500"
        if path_prefix:
            q += "&path=" + urllib.request.quote(path_prefix)
        if ip:
            q += "&ip=" + ip
        if outcome:
            q += "&outcome=" + outcome
        if cursor:
            q += "&cursor=" + urllib.request.quote(cursor)
        st, js = d.call("GET", q, timeout=60)
        if st != 200:
            return "status %s" % st
        n += len(js.get("items", []))
        cursor = js.get("next_cursor")
        if not cursor or not js.get("items"):
            break
    return n


def load_start(lab, nodes, rps, duration, name, **kw):
    """Starts the load tool in the background; load_wait() answers its result."""
    out = os.path.join(lab.root, "load-%s.json" % name)
    argv = [lab.tool, "load", "-targets", ",".join(str(n.proxy) for n in nodes), "-rps", str(rps), "-duration", str(duration),
            "-seed", str(SEED), "-host", HOST, "-out", out]
    for k, v in kw.items():
        flag = "-" + k.replace("_", "-")
        if v is True:
            argv.append(flag)
        elif v is not False and v is not None:
            argv += [flag, str(v)]
    p = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    lab.procs.append(p)
    return p, out


def load_wait(handle, timeout=900):
    p, out = handle
    p.wait(timeout)
    try:
        return json.load(open(out))
    except Exception as e:
        return {"error": "%r %s" % (e, p.stderr.read()[:300] if p.stderr else "")}


def run_load(lab, nodes, rps, duration, name, **kw):
    return load_wait(load_start(lab, nodes, rps, duration, name, **kw), duration + 120)


def short_load(r):
    """The numbers of a load result worth keeping."""
    if "error" in r:
        return r
    return {"rps_asked": r["rps_asked"], "rps_achieved": round(r["rps_achieved"], 1), "sent": r["sent"], "status": r["status"],
            "failed": r["failed"], "skipped": r["skipped"], "max_queue_lag_ms": r["max_queue_lag_ms"], "latency_ms": r["latency_ms"],
            "per_target": [{"status": p["status"], "p50": p["latency_ms"].get("p50"), "p99": p["latency_ms"].get("p99"), "max": p["latency_ms"].get("max")} for p in r["per_target"]]}


def resources(nodes):
    """Memory, CPU and TCP connections per node, from ps and netstat (no root needed)."""
    pids = {n.proc.pid: n.name for n in nodes if n.alive()}
    out = {name: {"rss_mb": None, "cpu_percent": None, "tcp_established": 0, "tcp_listen": 0} for name in pids.values()}
    ps = subprocess.run(["ps", "-o", "pid=,rss=,%cpu=", "-p", ",".join(str(p) for p in pids)], capture_output=True, text=True).stdout
    for line in ps.splitlines():
        f = line.split()
        if len(f) == 3 and int(f[0]) in pids:
            out[pids[int(f[0])]].update(rss_mb=round(int(f[1]) / 1024.0, 1), cpu_percent=float(f[2]))
    ns = subprocess.run(["netstat", "-anv", "-p", "tcp"], capture_output=True, text=True).stdout
    for line in ns.splitlines():
        m = re.match(r"^tcp4\s+\d+\s+\d+\s+\S+\s+\S+\s+(\S+)?\s.*?:(\d+)\s+[0-9a-f]{5}\s", line)
        if m and int(m.group(2)) in pids:
            k = "tcp_listen" if m.group(1) == "LISTEN" else "tcp_established"
            out[pids[int(m.group(2))]][k] += 1
    return out


class PConn:
    """One keep-alive connection with a host name in Host (an address there is a WAF finding and an event per
    request); get() answers the status, 0 for a failed request."""

    def __init__(self, port, timeout=5.0):
        self.port, self.timeout, self.c = port, timeout, None

    def get(self, path="/", xff=None):
        import http.client
        headers = {"Host": HOST, "User-Agent": "Mozilla/5.0 (measure MVP-27 hardening)"}
        if xff:
            headers["X-Forwarded-For"] = xff
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
            return 0

    def close(self):
        try:
            if self.c:
                self.c.close()
        finally:
            self.c = None


def hget(port, path="/", xff=None, timeout=3.0):
    c = PConn(port, timeout)
    try:
        return c.get(path, xff)
    finally:
        c.close()


def acts(nodes, addr, want=403, timeout=10.0, pause=0.01):
    """Seconds until each node answers a request of the address with `want`; None per node that never did."""
    t0, seen = now(), {}
    conns = {n.name: PConn(n.proxy, 2.0) for n in nodes}
    while now() - t0 < timeout and len(seen) < len(nodes):
        for n in nodes:
            if n.name not in seen and conns[n.name].get("/a", addr) == want:
                seen[n.name] = round(now() - t0, 3)
        time.sleep(pause)
    for c in conns.values():
        c.close()
    return {n.name: seen.get(n.name) for n in nodes}


def metric(lab, name, value, unit, samples=None, **labels):
    if value is None:
        return
    m = {"name": name, "value": float(value), "unit": unit, "labels": {k: str(v) for k, v in labels.items()}}
    if samples is not None:
        m["samples"] = samples
    lab.data.setdefault("metrics", []).append(m)


class Probe:
    """Requests to every node all the time, each on its own keep-alive connection, with time and latency:
    what a visitor sees while something happens between the nodes."""

    def __init__(self, nodes, gap=0.02, xff="198.51.100.77"):
        self.rows, self.stop, self.lock = [], False, threading.Lock()
        self.threads = [threading.Thread(target=self._run, args=(n, gap, xff), daemon=True) for n in nodes]
        for t in self.threads:
            t.start()

    def _run(self, node, gap, xff):
        c = PConn(node.proxy, 5.0)
        while not self.stop:
            t = now()
            st = c.get("/probe", xff)
            with self.lock:
                self.rows.append((t, node.name, st, (now() - t) * 1000.0))
            time.sleep(gap)
        c.close()

    def mark(self):
        return now()

    def window(self, t0, t1=None, names=None):
        """Summary of the requests sent in [t0, t1) to the named nodes."""
        t1 = t1 or now()
        with self.lock:
            rows = [r for r in self.rows if t0 <= r[0] < t1 and (names is None or r[1] in names)]
        lat = [r[3] for r in rows if r[2] != 0]
        return {"n": len(rows), "failed": sum(1 for r in rows if r[2] == 0), "not_200": sum(1 for r in rows if r[2] not in (0, 200)),
                "p50_ms": round(pct(lat, 50) or 0, 2), "p99_ms": round(pct(lat, 99) or 0, 2), "max_ms": round(max(lat), 2) if lat else None}

    def finish(self):
        self.stop = True
        for t in self.threads:
            t.join(6.0)


def served_clean(lab, cid, name, w, limit_ms=250.0, kill="waits"):
    """The verdict on a probe window: nothing failed and nothing waited."""
    ok = w["n"] > 0 and w["failed"] == 0 and w["not_200"] == 0 and (w["max_ms"] or 0) < limit_ms
    lab.check(cid, name, ok, "%d requests, %d failed, %d not 200, p50 %.2f ms, p99 %.2f ms, slowest %s ms (limit %d ms)" % (
        w["n"], w["failed"], w["not_200"], w["p50_ms"], w["p99_ms"], w["max_ms"], limit_ms), kill=kill)
    return ok


def scenario(lab, fn):
    """Runs one scenario function; a harness error is a FAIL of its own, never silence."""
    t0 = now()
    try:
        fn(lab)
    except Exception as e:
        traceback.print_exc()
        lab.check(lab.scenario, "harness", False, "harness error, scenario incomplete: %r" % e)
    lab.data["took_s"] = round(now() - t0, 1)
