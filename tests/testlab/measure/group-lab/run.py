#!/usr/bin/env python3
"""MVP-27 lab measurement: a group of schild gateways on real Linux VMs with a real network between them.

Runs inside the client VM (see README.md); `run.py --only s1,s2` runs single scenarios. Every check is one row
of the raw results: scenario, id, title, result (PASS, FAIL or INFO for a number without a pass mark), numbers
and the evidence as text.
"""
import argparse
import json
import os
import random
import re
import sys
import threading
import time

from lab import (Conn, Dash, Load, Node, VM, Watch, MESH_PORT, SITE, get, load_inventory, now, pct, summary,
                 wait_until)

OUT = "/opt/sg27/out"
SEED = 27
CLIENT_NET = "203.0.113."          # documentation range: the addresses visitors come from (TEST ONLY geo fixture)


class Results:
    def __init__(self):
        self.rows = []
        self.t0 = time.time()

    def check(self, scenario, cid, title, ok, numbers=None, evidence=""):
        """ok: True PASS, False FAIL, None a number without a pass mark."""
        res = "INFO" if ok is None else ("PASS" if ok else "FAIL")
        row = {"scenario": scenario, "id": cid, "title": title, "result": res, "numbers": numbers or {},
               "evidence": evidence if isinstance(evidence, str) else json.dumps(evidence)}
        self.rows.append(row)
        print("%-4s %-6s %s  %s  %s" % (res, cid, title, json.dumps(numbers or {}), row["evidence"][:600]), flush=True)
        self.save()
        return ok

    def save(self):
        os.makedirs(OUT, exist_ok=True)
        with open(os.path.join(OUT, "raw.json.tmp"), "w") as f:
            json.dump({"started": self.t0, "saved": time.time(), "seed": SEED, "rows": self.rows}, f, indent=1)
        os.replace(os.path.join(OUT, "raw.json.tmp"), os.path.join(OUT, "raw-%s.json" % self.name))


R = Results()


class Lab(dict):
    """The VMs by name, the gateway nodes, the group secret."""

    def __init__(self):
        super().__init__()
        inv = load_inventory()
        for name, ip in inv.items():
            self[name] = Node(name, ip, self) if re.fullmatch(r"n\d+", name) else VM(name, ip)
        self.nodes = [self[k] for k in sorted((k for k in inv if re.fullmatch(r"n\d+", k)), key=lambda s: int(s[1:]))]
        self.client, self.app, self.lb = self["client"], self["app"], self["lb"]
        self["secret"] = ""

    def prepare(self):
        """Application, client addresses and routes back to them."""
        # the helper files of this run, on every VM that uses them
        for vm in [self.app] + self.nodes:
            for f in ("app.py", "netdelay.py", "clockhold.py"):
                vm.put("/opt/sg27/" + f, open("/opt/sg27/" + f).read())
        self.app.run("pkill -f '[a]pp.py'; true")
        self.app.spawn("python3 /opt/sg27/app.py 8080")
        self.client.run("for i in $(seq 1 250); do ip addr add %s$i/32 dev lo 2>/dev/null; done; true" % CLIENT_NET)
        for vm in [self.lb] + self.nodes:
            vm.run("ip route replace %s0/24 via %s" % (CLIENT_NET, self.client.ip))
        rc, out = self.nodes[0].run("schild cluster secret")
        self["secret"] = out.splitlines()[-1]
        return rc == 0 and len(self["secret"]) >= 64

    def balancers(self):
        """Senders the gateways take a PROXY header from: the balancer VM and the client VM, which probes single
        nodes as a second balancer would."""
        return [self.lb.ip, self.client.ip]

    def haproxy(self, nodes, inter="2s", fall=2, rise=2, balance="roundrobin", ports=(80,)):
        """HAProxy in TCP mode on the balancer VM: health check on /.schild/readyz, PROXY protocol v2 to the gateways."""
        cfg = ["global", "  maxconn 20000", "  stats socket /run/sg27-haproxy.sock mode 600 level admin", "",
               "defaults", "  mode tcp", "  timeout connect 2s", "  timeout client 60s", "  timeout server 60s", ""]
        for port in ports:
            cfg += ["frontend web%d" % port, "  bind :%d" % port, "  default_backend gateways%d" % port, "",
                    "backend gateways%d" % port, "  balance %s" % balance]
            if port == 80:
                cfg += ["  option httpchk", "  http-check send meth GET uri /.schild/readyz ver HTTP/1.1 hdr Host %s" % SITE,
                        "  http-check expect status 200"]
                cfg += ["  default-server send-proxy-v2 check inter %s fall %d rise %d" % (inter, fall, rise)]
            else:
                # the readiness answer is asked on port 80; the state of that check decides for this port too
                cfg += ["  default-server send-proxy-v2"]
            for n in nodes:
                extra = "" if port == 80 else " track gateways80/%s" % n.name
                cfg += ["  server %s %s:%d%s" % (n.name, n.ip, port, extra)]
            cfg.append("")
        return self.haproxy_raw(cfg)

    def haproxy_raw(self, cfg):
        self.lb.put("/etc/haproxy/sg27.cfg", "\n".join(cfg) + "\n")
        self.lb.run("pkill -x haproxy; sleep 0.3; true")
        out = self.lb.sh("haproxy -c -f /etc/haproxy/sg27.cfg 2>&1 | tail -2")
        self.lb.spawn("haproxy -f /etc/haproxy/sg27.cfg")
        return out

    def lb_state(self):
        """name -> UP or DOWN as HAProxy sees its servers (operational state of the stats socket)."""
        rc, out = self.lb.run("echo 'show servers state gateways80' | nc -U /run/sg27-haproxy.sock")
        st = {}
        for line in out.splitlines():
            f = line.split()
            if len(f) > 6 and f[0].isdigit():
                st[f[3]] = {"0": "DOWN", "1": "DOWN", "2": "UP", "3": "UP"}.get(f[5], f[5])
        return st

    def wait_lb(self, want, timeout=30):
        return wait_until(lambda: all(self.lb_state().get(k) == v for k, v in want.items()), timeout, 0.1)


def fresh_group(lab, nodes, names=None, drain=None, extra="", start=True, settle=3.0):
    """Wipe the nodes, deploy the same files to each and start them together. Answers seconds to ready per node."""
    for i, n in enumerate(nodes):
        n.wipe()
        n.write_files([m.ip for m in nodes], lab.balancers(), node_name=(names[i] if names else n.name), drain=drain, extra=extra)
    if not start:
        return {}
    for n in nodes:
        n.start()
    ready = {n.name: n.wait_ready(60) for n in nodes}
    time.sleep(settle)
    return ready


def first_login(nodes):
    """Set the first password on the first node (after the group settled) and answer a session for every node."""
    d0 = Dash(nodes[0])
    st, js = d0.setup()
    if st != 200:
        st, js = d0.login()
    time.sleep(1.5)
    return [d0] + [Dash(n, d0) for n in nodes[1:]]


def members_ok(dash, count):
    g = dash.group()
    ms = g.get("members", [])
    return g.get("state") == "active" and len(ms) == count and all(m.get("state") in ("self", "ok") for m in ms)


def blocked_everywhere(nodes, address, want=403):
    return all(get(n.ip, "/b", claim=address, timeout=2) == want for n in nodes)


def propagation(setter, watchers, address, lift=False, timeout=10.0):
    """Block (or lift) on one node and time, per other node, when a request of the address is first refused
    (or served again). The clock starts when the call is sent. Answers ({node: ms}, incident)."""
    want = 200 if lift else 403
    w = Watch(watchers, address, want).start()
    time.sleep(0.05)
    t0 = now()
    if lift:
        st, js = setter.unblock(lift)
    else:
        st, js = setter.block(address)
    first = w.wait(timeout)
    return ({k: round((v - t0) * 1000, 1) for k, v in first.items()}, js.get("incident") if isinstance(js, dict) else None, st)


def incident_of(dash, address, timeout=5.0):
    """The incident number of the running block of an address as this node lists it."""
    end = now() + timeout
    while now() < end:
        st, js = dash.call("GET", "/blocks")
        for b in (js or {}).get("items", []) if st == 200 else []:
            if b["client"] == address:
                return b["incident"]
        time.sleep(0.1)
    return None


def unblock_retry(dash, incident, timeout=5.0):
    """Unblock; a node that has not asked for the incident yet answers 404 for up to a second, so try again."""
    end = now() + timeout
    st = 0
    while now() < end:
        st, js = dash.unblock(incident)
        if st == 200:
            return st
        time.sleep(0.1)
    return st


# ---------------------------------------------------------------------------------------------------------------
# scenario 1: a pair behind a load balancer, set up exactly as docs/gateway/03-cluster.md says


def s1(lab):
    S = "s1"
    n1, n2 = lab.nodes[0], lab.nodes[1]
    pair = [n1, n2]
    # "Nur listen unterscheidet sich von Server zu Server": the same schild.yaml on both, node_name included
    for n in pair:
        n.wipe()
        n.write_files([m.ip for m in pair], lab.balancers(), node_name=None)
    rc, out = n1.cli("ingress validate")
    R.check(S, "1.01", "a schild.yaml with the guide's cluster block and no node_name: what schild says", None, {"exit": rc},
            out.splitlines()[0] if out else "")
    if rc != 0:
        # the guide does not say so, but node_name is required: every node gets the same one, as "only listen differs" says
        for n in pair:
            n.write_files([m.ip for m in pair], lab.balancers(), node_name="web")
        rc, out = n1.cli("ingress validate")
        R.check(S, "1.01b", "the same files with one node_name for both nodes are accepted", rc == 0, {}, out.splitlines()[-1])
    R.check(S, "1.02", "the HAProxy configuration of the balancer is valid (TCP mode, httpchk on /.schild/readyz, send-proxy-v2)",
            True, {}, lab.haproxy(pair))
    for n in pair:
        n.start()
    ready = {n.name: n.wait_ready(60) for n in pair}
    R.check(S, "1.03", "both nodes start from the same files, in any order, and answer ready",
            all(v is not None for v in ready.values()), {k: round(v, 2) if v else None for k, v in ready.items()})
    time.sleep(3)
    st1 = n1.status()
    two = len(re.findall(r"\bgateway\b", st1)) == 2
    names = re.findall(r"^(\S+)\s+gateway", st1, re.M)
    R.check(S, "1.04", "schild cluster status on n1 lists two gateways", two, {}, st1)
    R.check(S, "1.05", "the two members can be told apart by name in schild cluster status (guide: remove NODE by name)",
            len(set(names)) == 2, {"names": names}, "both nodes carry the node_name the one deployed file gives them")
    up = lab.wait_lb({"n1": "UP", "n2": "UP"}, 20)
    R.check(S, "1.06", "HAProxy marks both gateways UP by /.schild/readyz over the PROXY protocol", up is not None,
            {"seconds": round(up, 1) if up else None}, json.dumps(lab.lb_state()))

    # the client address through the balancer
    c = Conn(lab.lb.ip, bind=CLIENT_NET + "11")
    codes = [c.get("/who", close=True) for _ in range(4)]
    R.check(S, "1.07", "through the balancer the application gets the visitor's address (PROXY protocol v2)",
            codes == [200] * 4 and b"xff=" + (CLIENT_NET + "11").encode() in c.body, {"codes": codes}, c.body.decode().strip())

    # login
    d1 = Dash(n1)
    st, js = d1.setup()
    time.sleep(1.5)
    d2 = Dash(n2, d1)
    s2 = d2.session()
    R.check(S, "1.08", "the first password set on n1: its session is valid on the dashboard of n2",
            st == 200 and s2[0] == 200 and s2[1].get("authenticated") is True, {"setup": st}, json.dumps(s2[1])[:200])
    d2b = Dash(n2)
    st, js = d2b.login()
    R.check(S, "1.09", "the password set on n1 signs in on n2", st == 200 and js.get("authenticated") is True, {"status": st})
    time.sleep(1.2)
    s1b = Dash(n1, d2b).session()
    R.check(S, "1.10", "a login on n2 is valid on n1", s1b[0] == 200 and s1b[1].get("authenticated") is True, {})

    # blocks from one node to the other
    rnd = random.Random(SEED)
    set_ms, lift_ms, bad, early_404, window = [], [], [], [], []
    for i in range(30):
        a = CLIENT_NET + str(100 + i)
        setter, other, dset, doth = (n1, n2, d1, d2) if i % 2 == 0 else (n2, n1, d2, d1)
        first, inc, st = propagation(dset, [other], a)
        if other.name in first:
            set_ms.append(first[other.name])
        else:
            bad.append("set %s on %s: status %s, not refused on %s in 10 s" % (a, setter.name, st, other.name))
            continue
        # "Freigeben" on the other node, as soon as that node lists the block
        t_listed = now()
        inc2 = incident_of(doth, a)
        st, _ = doth.unblock(inc2 or inc)
        if st != 200:
            early_404.append(st)
            t_ok = wait_until(lambda: doth.unblock(inc2 or inc)[0] == 200, 10, 0.05)
            window.append(round((now() - t_listed) * 1000, 1) if t_ok is not None else None)
            time.sleep(1.0)
        else:
            time.sleep(1.0)
        # a second block of the same address, lifted after a pause, for the time of a lift
        a2 = CLIENT_NET + str(140 + i)
        dset.block(a2)
        time.sleep(rnd.uniform(1.5, 2.2))
        inc3 = incident_of(doth, a2)
        first, _, st = propagation(doth, [setter], a2, lift=inc3)
        if setter.name in first:
            lift_ms.append(first[setter.name])
        else:
            bad.append("lift %s on %s: status %s, still refused on %s after 10 s" % (a2, other.name, st, setter.name))
    s = summary(set_ms)
    R.check(S, "1.11", "a block set on one node of the pair refuses the address on the other within 1 s at p95 (n = 30)",
            s["n"] == 30 and s["p95"] <= 1000, s, "; ".join(b for b in bad if b.startswith("set")))
    l = summary(lift_ms)
    R.check(S, "1.12", "a lift on the other node serves the address again on the first (\"etwa eine Sekunde\")",
            l["n"] == 30 and l["p95"] <= 1500, l, "; ".join(b for b in bad if b.startswith("lift")))
    R.check(S, "1.12b", "\"Freigeben\" on the other node at the moment that node lists the block is answered 200 (n = 30)",
            not early_404, {"answered_404": len(early_404), "of": 30, "ms_until_200": window},
            "the block is in GET /blocks of the node, POST /incidents/<incident>/unblock there answers 404 until the node holds the incident")

    # through the balancer with the real source address
    a = CLIENT_NET + "20"
    st, js = d1.block(a)
    time.sleep(1.5)
    codes = [get(lab.lb.ip, "/x", bind=a) for _ in range(10)]
    other = [get(lab.lb.ip, "/x", bind=CLIENT_NET + "21") for _ in range(4)]
    R.check(S, "1.13", "a blocked address is refused through the balancer whichever node it lands on, others pass",
            codes == [403] * 10 and other == [200] * 4, {"blocked": codes, "other": other})
    blk = d2.call("GET", "/blocks")[1]["items"]
    row = [b for b in blk if b["client"] == a]
    R.check(S, "1.14", "the block list of n2 names the node that decided", bool(row) and bool(row[0].get("node")) and row[0].get("node_self") is False,
            {}, json.dumps({k: row[0].get(k) for k in ("node", "node_self", "incident")} if row else {}))

    # spoofing (the app VM is no balancer: it is not in the allow list of the Caddyfile)
    victim = CLIENT_NET + "66"
    rc, out = lab.app.run("printf 'PROXY TCP4 %s %s 4000 80\\r\\nGET /spoof HTTP/1.1\\r\\nHost: %s\\r\\nConnection: close\\r\\n\\r\\n' | nc -w 3 %s 80"
                          % (a, n1.ip, SITE, n1.ip))
    status = (re.findall(r"HTTP/1.1 (\d+)", out) or ["0"])[0]
    seen = (re.findall(r"xff=(\S+)", out) or ["-"])[0]
    R.check(S, "1.15", "a PROXY header from a sender outside the allow list is not believed: the claimed (blocked) address is not the client",
            status != "403" and seen != a, {"status": status, "client_seen_by_app": seen},
            "sender %s claims the blocked %s; a believed header would be answered 403" % (lab.app.ip, a))
    R.check(S, "1.15b", "what such a sender gets (spec, measure: 'a PROXY header from a sender outside the allow list is refused')",
            None, {"status": status, "client_seen_by_app": seen},
            "answer: %s" % out[:120].replace("\r\n", " | "))
    rc, out = lab.app.run("curl -s -m 3 -H 'Host: %s' -H 'X-Forwarded-For: %s' http://%s/xff" % (SITE, a, n1.ip))
    R.check(S, "1.16", "an X-Forwarded-For header of a sender that is no trusted proxy is not believed either",
            "ok" in out and a not in out.split("xff=")[-1].split(",")[-1], {}, out)
    rc, out = lab.client.run("curl -s -m 3 --interface %s -H 'Host: %s' -H 'X-Forwarded-For: %s' http://%s/xff" % (victim, SITE, a, lab.lb.ip))
    R.check(S, "1.17", "a visitor behind the balancer who sends X-Forwarded-For with a blocked address is served as itself",
            out.startswith("ok"), {}, out)

    # the start without an allow list
    cfgs = {
        "no allow list": "\t\t\tproxy_protocol\n",
        "allow 0.0.0.0/0": "\t\t\tproxy_protocol {\n\t\t\t\tallow 0.0.0.0/0\n\t\t\t}\n",
        "allow list with fallback_policy use": "\t\t\tproxy_protocol {\n\t\t\t\tallow %s/32\n\t\t\t\tfallback_policy use\n\t\t\t}\n" % lab.lb.ip,
    }
    good = n1.get("/etc/schild/Caddyfile")
    for label, block in cfgs.items():
        bad_cf = re.sub(r"\t\t\tproxy_protocol \{.*?\n\t\t\t\}\n", block, good, flags=re.S)
        n1.put("/etc/schild/Caddyfile.bad", bad_cf)
        n1.put("/etc/schild/bad.yaml", n1.get(Node.CFG).replace("/etc/schild/Caddyfile", "/etc/schild/Caddyfile.bad"))
        rc, out = n1.run("schild run -check -config /etc/schild/bad.yaml 2>&1 | tail -3")
        rc2, out2 = n1.run("schild ingress validate -config /etc/schild/bad.yaml 2>&1 | grep -i -E 'REFUSE|proxy|result' | head -4")
        refused = "REFUSE" in out + out2 or "refuse" in (out + out2).lower()
        cid = {"no allow list": "1.18", "allow 0.0.0.0/0": "1.19", "allow list with fallback_policy use": "1.20"}[label]
        R.check(S, cid, "in a cluster schild refuses to start with a proxy_protocol wrapper: %s" % label,
                refused if label != "allow 0.0.0.0/0" else None, {"refused": refused}, (out2 or out)[:400])

    # failover: a node killed under load
    load = Load(lab.lb.ip, rate=200, workers=16, mode="new", bind=CLIENT_NET + "30").start()
    slow = Load(lab.lb.ip, rate=4, workers=8, mode="new", bind=CLIENT_NET + "31", path="/slow?ms=1500", timeout=6).start()
    time.sleep(5)
    t_kill = now()
    n1.kill9()
    down = lab.wait_lb({"n1": "DOWN"}, 20)
    time.sleep(6)
    load.stop()
    slow.stop()
    fails = [f for f in load.failures()]
    span = (max(f[0] for f in fails) - min(f[0] for f in fails)) if fails else 0.0
    first_fail = (min(f[0] for f in fails) - (t_kill - load.t0)) if fails else None
    last_fail = (max(f[0] for f in fails) - (t_kill - load.t0)) if fails else None
    st = load.stats()
    after = [r[1] * 1000 for r in load.rows if 0 <= r[0] - t_kill <= 4 and r[2] == 200]
    R.check(S, "1.21", "one node of the pair killed (SIGKILL) under 200 new connections a second through the balancer: failed requests",
            None, {"requests": st["requests"], "failed_or_not_200": st["not_200"], "codes": st["codes"],
                   "latency_ms_of_served_requests_4s_after_kill": summary(after),
                   "first_failure_s_after_kill": round(first_fail, 2) if fails else None,
                   "last_failure_s_after_kill": round(last_fail, 2) if fails else None,
                   "haproxy_marks_down_after_s": round(down, 2) if down else None}, "errors: %s" % st["errors"])
    R.check(S, "1.22", "after the balancer marked the node down no request fails any more",
            down is not None and all(f[0] - (t_kill - load.t0) <= down + 0.3 for f in fails),
            {"failures_after_down": sum(1 for f in fails if f[0] - (t_kill - load.t0) > (down or 0) + 0.3)})
    sf = slow.failures()
    sst = slow.stats()
    R.check(S, "1.23", "requests in flight (1.5 s each) at the kill: only those on the killed node fail",
            None, {"requests": sst["requests"], "failed": sst["not_200"],
                   "failed_started_before_kill": sum(1 for f in sf if f[0] <= t_kill - slow.t0),
                   "failed_started_after_kill": sum(1 for f in sf if f[0] > t_kill - slow.t0)}, str(sf[:6]))
    s2 = d2.session()
    codes = [get(lab.lb.ip, "/x", bind=a) for _ in range(4)]
    R.check(S, "1.24", "with n1 gone, n2 still holds the block and the login", codes == [403] * 4 and s2[1].get("authenticated") is True,
            {"blocked": codes})
    g = d2.group()
    R.check(S, "1.25", "the dashboard of n2 says the sync is interrupted and n1 unreachable", g.get("state") == "interrupted",
            {"state": g.get("state"), "member": [m.get("state") for m in g.get("members", [])]})

    # while n1 is down: a block, a lift, an allowlist entry on n2; then n1 returns
    b_new = CLIENT_NET + "40"
    d2.block(b_new)
    inc = incident_of(d2, a)
    d2.unblock(inc)
    st_allow = d2.allow(CLIENT_NET + "41")[0]
    load = Load(lab.lb.ip, rate=200, workers=16, mode="new", bind=CLIENT_NET + "30").start()
    time.sleep(2)
    n1.start()
    codes_503, t_ready = 0, None
    t0 = now()
    at_ready = None
    while now() - t0 < 60:
        r = n1.ready(1.0)
        if r == 503:
            codes_503 += 1
        if r == 200:
            t_ready = now() - t0
            at_ready = (get(n1.ip, "/x", claim=b_new, timeout=2), get(n1.ip, "/x", claim=a, timeout=2))
            break
        time.sleep(0.02)
    up = lab.wait_lb({"n1": "UP"}, 30)
    time.sleep(4)
    load.stop()
    st = load.stats()
    R.check(S, "1.26", "n1 returns: readiness is 503 first and at its first 200 the node holds what it missed (new block refused, lifted block served)",
            at_ready == (403, 200), {"ready_after_s": round(t_ready, 2) if t_ready else None, "polls_503": codes_503,
                                     "new_block_at_ready": at_ready[0] if at_ready else None, "lifted_block_at_ready": at_ready[1] if at_ready else None})
    R.check(S, "1.27", "no request through the balancer fails while n1 returns", st["not_200"] == 0,
            {"requests": st["requests"], "codes": st["codes"], "haproxy_up_after_s": round(up, 1) if up else None}, str(st["errors"]))
    time.sleep(1)
    d1 = Dash(n1, d2)
    al = d1.allowlist()
    R.check(S, "1.28", "n1 holds the allowlist entry set while it was away and the session is valid on it again",
            st_allow == 201 and al is not None and CLIENT_NET + "41" in al, {"allowlist": al, "status_of_the_add_on_n2": st_allow})

    # planned stop
    for how in ("drain", "sigterm"):
        cid = "1.29" if how == "drain" else "1.32"
        lab.wait_lb({"n1": "UP", "n2": "UP"}, 30)
        time.sleep(1)
        load = Load(lab.lb.ip, rate=200, workers=16, mode="new", bind=CLIENT_NET + "30").start()
        keep = Load(lab.lb.ip, rate=50, workers=10, mode="keep", bind=CLIENT_NET + "32").start()
        slow = Load(lab.lb.ip, rate=4, workers=8, mode="new", bind=CLIENT_NET + "31", path="/slow?ms=1500", timeout=6).start()
        time.sleep(4)
        t0 = now()
        if how == "drain":
            threading.Thread(target=lambda: n1.cli("cluster drain", 90), daemon=True).start()
        else:
            n1.term()
        t503 = wait_until(lambda: n1.ready(1.0) == 503, 5, 0.02)
        probe = Conn(n1.ip, claim=CLIENT_NET + "33")
        probe.get("/during-delay")
        conn_hdr = probe.headers.get("Connection", "-")
        probe.close()
        down = lab.wait_lb({"n1": "DOWN"}, 20)
        down = (now() - t0) if down is not None else None
        gone = n1.wait_exit(90)
        t_exit = now() - t0
        time.sleep(3)
        load.stop(); keep.stop(); slow.stop()
        st, kst, sst = load.stats(), keep.stats(), slow.stats()
        label = "schild cluster drain" if how == "drain" else "SIGTERM (systemctl stop)"
        R.check(S, cid, "%s under load: no request on a new connection fails" % label, st["not_200"] == 0 and sst["not_200"] == 0,
                {"requests": st["requests"], "codes": st["codes"], "slow_requests": sst["requests"], "slow_codes": sst["codes"]},
                str(st["errors"] + sst["errors"]))
        R.check(S, "%.2f" % (float(cid) + 0.01), "%s: kept-alive connections through the balancer lose no request" % label,
                kst["not_200"] == 0 and kst["retried"] == 0,
                {"requests": kst["requests"], "codes": kst["codes"], "cut_without_answer_and_sent_again": kst["retried"],
                 "cut_at_s_after_stop_began": [round(x - (t0 - keep.t0), 2) for x in keep.retries()],
                 "connection_header_of_an_answer_during_the_delay": conn_hdr},
                "a request on a kept connection that the node closed without an answer is sent once more on a new connection; %s" % kst["errors"])
        R.check(S, "%.2f" % (float(cid) + 0.02), "%s: readiness 503 at once, the node serves 15 s more, then stops" % label,
                t503 is not None and t503 < 1.0 and gone and 14.5 <= t_exit <= 15 + 30 + 3,
                {"readyz_503_after_s": round(t503, 2) if t503 is not None else None,
                 "haproxy_down_after_s": round(down, 2) if down else None, "process_gone_after_s": round(t_exit, 2)})
        n1.start()
        n1.wait_ready(60)
    lab.wait_lb({"n1": "UP", "n2": "UP"}, 30)

    # the commands of the guide on a pair
    rc, out = n1.cli("cluster remove web")
    R.check(S, "1.35", "schild cluster remove NODE by the name both nodes carry: what the command does", None, {"exit": rc}, out[:400])
    time.sleep(2)
    R.check(S, "1.36", "state of the pair after that command", None, {}, n1.status() + "\n--- n2 ---\n" + n2.status())


# ---------------------------------------------------------------------------------------------------------------
# scenario 2: real network faults between the node VMs


def mesh_rules(peers, loss=None, cut="both"):
    """Packet filter rules of one node toward its peers. loss: share of packets dropped in both directions;
    cut: both (nothing passes), in (the node hears nothing of the peers, its own packets leave)."""
    ips = "{ %s }" % ", ".join(peers)
    if loss is not None:
        n = int(loss * 1000)
        return ["input: ip saddr %s numgen random mod 1000 < %d counter drop" % (ips, n),
                "output: ip daddr %s numgen random mod 1000 < %d counter drop" % (ips, n)]
    rules = ["input: ip saddr %s counter drop" % ips]
    if cut == "both":
        rules.append("output: ip daddr %s counter drop" % ips)
    return rules


def member_state(dash, node_ip):
    for m in dash.group().get("members", []):
        if m.get("address", "").startswith(node_ip + ":"):
            return m.get("state")
    return None


def direct_load(nodes, seconds, rate=100, tag=""):
    """Kept connections to every node at once (the client speaks the PROXY protocol); answers stats per node."""
    loads = [Load(n.ip, rate=rate, workers=4, mode="keep", claim=CLIENT_NET + "50").start() for n in nodes]
    return loads


def load_numbers(loads, nodes):
    out = {}
    for n, l in zip(nodes, loads):
        st = l.stats()
        out[n.name] = {"requests": st["requests"], "not_200": st["not_200"], "retried": st["retried"],
                       "p50": st["latency_ms"].get("p50"), "p99": st["latency_ms"].get("p99"), "max": st["latency_ms"].get("max")}
    return out


def s2(lab):
    S = "s2"
    nodes = lab.nodes[:3]
    n1, n2, n3 = nodes
    ready = fresh_group(lab, nodes)
    d1, d2, d3 = first_login(nodes)
    ok = wait_until(lambda: members_ok(d1, 3) and members_ok(d3, 3), 20)
    R.check(S, "2.01", "three nodes on three VMs form a group from the same files", ok is not None,
            {"ready_s": {k: round(v, 2) if v else None for k, v in ready.items()}})

    # baseline
    loads = direct_load(nodes, 15)
    time.sleep(15)
    [l.stop() for l in loads]
    base = load_numbers(loads, nodes)
    base_p99 = max(v["p99"] for v in base.values())
    R.check(S, "2.02", "baseline without a fault: 100 requests a second on each node for 15 s", all(v["not_200"] == 0 for v in base.values()), base)
    rc, out = n1.run("ping -c 5 -i 0.2 -q %s | tail -1" % n2.ip)
    R.check(S, "2.03", "round trip between two node VMs without a fault", None, {}, out)

    def request_path(cid, title, loads):
        num = load_numbers(loads, nodes)
        worst = max(v["max"] or 0 for v in num.values())
        R.check(S, cid, title + ": no request fails or waits (max under 500 ms)",
                all(v["not_200"] == 0 and v["retried"] == 0 for v in num.values()) and worst < 500,
                dict(num, baseline_p99_ms=base_p99))

    def blocks_during(cid, title, base_octet, count=10, limit=1000):
        times, missing = [], 0
        for i in range(count):
            a = CLIENT_NET + str(base_octet + i)
            first, inc, st = propagation(d1, [n2, n3], a, timeout=8)
            times += list(first.values())
            missing += 2 - len(first)
            time.sleep(0.3)
        sm = summary(times)
        R.check(S, cid, title + ": a block set on n1 refuses the address on n2 and n3 within 1 s at p95",
                missing == 0 and sm.get("p95", 1e9) <= limit, dict(sm, not_within_8s=missing))

    # delay and loss
    octet = 60
    for cid, label, kind, value in (("2.1", "delay 50 ms each way", "delay", 50), ("2.2", "delay 200 ms each way", "delay", 200),
                                    ("2.3", "loss 1 % each way", "loss", 0.01), ("2.4", "loss 10 % each way", "loss", 0.10)):
        loads = direct_load(nodes, 20)
        time.sleep(2)
        for n in nodes:
            peers = [m.ip for m in nodes if m is not n]
            if kind == "delay":
                n.delay(peers, value, jitter_ms=value * 0.1)
            else:
                n.nft(mesh_rules(peers, loss=value))
        time.sleep(1)
        rc, out = n1.run("ping -c 20 -i 0.1 -q %s | tail -2" % n2.ip, 20)
        R.check(S, cid + "0", "%s between the node VMs: the fault is on the wire (ping n1 to n2)" % label, None, {}, out.replace("\n", " | "))
        blocks_during(cid + "1", label, octet)
        octet += 10
        g = d1.group()
        states = sorted(m.get("state") for m in g.get("members", []))
        time.sleep(4)
        [l.stop() for l in loads]
        request_path(cid + "2", label, loads)
        R.check(S, cid + "3", "%s: what the dashboard of n1 says" % label, None, {"state": g.get("state"), "members": states})
        for n in nodes:
            n.delay_clear()
            n.nft_clear()
        time.sleep(3)

    # node n3 behind a cut, in four ways; detection on n1, the request path on all, the state after it heals
    for cid, label, how in (("2.5", "full partition (n3 cut from n1 and n2, packets dropped both ways)", "both"),
                            ("2.6", "one-way cut (n3 hears nothing of n1 and n2, its own packets arrive)", "in"),
                            ("2.7", "n3 hangs (process stopped with SIGSTOP, the kernel still answers)", "freeze"),
                            ("2.8", "n3 killed (SIGKILL, connections refused)", "kill")):
        wait_until(lambda: members_ok(d1, 3) and members_ok(d3, 3), 30)
        before = CLIENT_NET + str(octet); octet += 1
        d1.block(before)
        time.sleep(1.5)
        loads = direct_load(nodes if how not in ("freeze", "kill") else nodes[:2], 25)
        time.sleep(2)
        t0 = now()
        if how in ("both", "in"):
            n3.nft(mesh_rules([n1.ip, n2.ip], cut=how))
        elif how == "freeze":
            n3.freeze()
        else:
            n3.kill9()
        detect = wait_until(lambda: member_state(d1, n3.ip) not in ("ok", None), 30, 0.05)
        detect = round(now() - t0, 2) if detect is not None else None
        g = d1.group()
        limit = 1.5 if how == "kill" else 4.5
        R.check(S, cid + "0", "%s: n1 shows n3 as not reachable (guide: at once for a failure, about three seconds for a hanging server)" % label,
                detect is not None and detect <= limit, {"seconds": detect, "state_of_n1": g.get("state"), "n3": member_state(d1, n3.ip)})
        # both sides stay writable
        a_side, b_side = CLIENT_NET + str(octet), CLIENT_NET + str(octet + 1)
        al_a, al_b = CLIENT_NET + str(octet + 2), CLIENT_NET + str(octet + 3)
        octet += 4
        first, _, st_a = propagation(d1, [n2], a_side, timeout=5)
        res = {"block_on_n1_reaches_n2_ms": first.get("n2"), "status": st_a}
        if how in ("both", "in"):
            st_b = d3.block(b_side)[0]
            st_ala = d1.allow(al_a)[0]
            st_alb = d3.allow(al_b)[0]
            inc = incident_of(d3, before)
            st_lift = d3.unblock(inc)[0] if inc else None
            d3b = Dash(n3)
            st_login = d3b.login()[0]
            res.update({"block_on_n3": st_b, "allow_on_n1": st_ala, "allow_on_n3": st_alb, "lift_on_n3": st_lift, "login_on_n3": st_login,
                        "readyz_n3": n3.ready(), "state_n3": d3.group().get("state"),
                        "n3_serves": get(n3.ip, "/x", claim=CLIENT_NET + "51"), "n3_refuses_own_block": get(n3.ip, "/x", claim=b_side)})
        R.check(S, cid + "1", "%s: the nodes that reach each other keep sharing (block n1 to n2 within 1 s)" % label,
                first.get("n2") is not None and first["n2"] <= 1000, res)
        time.sleep(8)
        [l.stop() for l in loads]
        num = load_numbers(loads, nodes)
        worst = max(v["max"] or 0 for v in num.values())
        R.check(S, cid + "2", "%s: no request on any serving node fails or waits (max under 500 ms), from 2 s before the fault to 10 s into it" % label,
                all(v["not_200"] == 0 and v["retried"] == 0 for v in num.values()) and worst < 500, dict(num, baseline_p99_ms=base_p99))
        # heal
        t0 = now()
        if how in ("both", "in"):
            n3.nft_clear()
        elif how == "freeze":
            n3.thaw()
        else:
            n3.start()
        if how in ("both", "in"):
            def same():
                b = [d.blocks() for d in (d1, d2, d3)]
                al = [d.allowlist() for d in (d1, d2, d3)]
                return b[0] == b[1] == b[2] and al[0] == al[1] == al[2] and a_side in b[0] and b_side in b[0]
            conv = wait_until(same, 40, 0.1)
            b, al = d1.blocks() or [], d1.allowlist() or []
            b3, al3 = d3.blocks() or [], d3.allowlist() or []
            sess = Dash(n1, d3b).session()
            R.check(S, cid + "3", "%s healed: the three nodes hold the same blocks and allowlist" % label, conv is not None,
                    {"seconds": round(conv, 2) if conv is not None else None})
            R.check(S, cid + "4", "%s healed: nothing set on either side is lost (blocks, allowlist entries, the lift, the login of both sides)" % label,
                    a_side in b and b_side in b and al_a in al and al_b in al and al_a in al3 and al_b in al3 and before not in b and before not in b3
                    and sess[1].get("authenticated") is True,
                    {"block_n1_side": a_side in b, "block_n3_side": b_side in b, "allow_n1_side_on_n1": al_a in al, "allow_n3_side_on_n1": al_b in al,
                     "allow_n1_side_on_n3": al_a in al3, "allow_n3_side_on_n3": al_b in al3, "lifted_block_gone_on_n1": before not in b,
                     "lifted_block_gone_on_n3": before not in b3, "login_of_n3_valid_on_n1": sess[1].get("authenticated")})
        else:
            if how == "kill":
                n3.wait_ready(60)
            back = wait_until(lambda: members_ok(d1, 3), 40, 0.1)
            took = wait_until(lambda: get(n3.ip, "/x", claim=a_side, timeout=2) == 403, 20, 0.05)
            R.check(S, cid + "3", "%s, n3 back: n1 shows the group active again and n3 refuses the address blocked meanwhile" % label,
                    back is not None and took is not None, {"active_after_s": round(now() - t0, 2) if back is not None else None,
                                                             "block_on_n3_after_s": round(took, 2) if took is not None else None})
        act = wait_until(lambda: members_ok(d1, 3) and members_ok(d3, 3), 40, 0.1)
        R.check(S, cid + "5", "%s healed: seconds until n1 and n3 both show 'active' with every member reachable" % label, None,
                {"seconds": round(now() - t0, 2) if act is not None else None})


# ---------------------------------------------------------------------------------------------------------------
# scenario 3: clocks


def s3(lab):
    S = "s3"
    nodes = lab.nodes[:3]
    n1, n2, n3 = nodes
    ref = lab.client
    octet = [150]

    def offset(n):
        return round(n.clock() - ref.clock(), 1)

    def reset_clocks():
        for n in nodes:
            n.clock_release()
        wait_until(lambda: all(abs(offset(n)) < 1 for n in nodes), 45, 1.0)   # the hypervisor sets a clock right every 30 s

    def addr():
        octet[0] += 1
        return CLIENT_NET + str(octet[0])

    def counters(d):
        return d.group().get("counters", {})

    def operator_view(n, d):
        g = d.group()
        st = n.status()
        hint = [l for l in st.splitlines() if re.search(r"clock|skew|ahead|Uhr", l, re.I) and not l.startswith("Since the start")]
        count = [l for l in st.splitlines() if l.startswith("Since the start")]
        return {"state": g.get("state"), "members": sorted(m.get("state") for m in g.get("members", [])), "counters": g.get("counters"),
                "status_lines_that_name_a_clock": hint, "status_counter_line": count, "readyz": n.ready()}

    def many(setter, watchers, count=5, timeout=4):
        """Blocks set one after the other; answers (ms of every watcher that refused in time, how many did not)."""
        times, missing, addrs = [], 0, []
        self_set = []
        for _ in range(count):
            a = addr()
            self_set.append(now())
            first, inc, st = propagation(setter, watchers, a, timeout=timeout)
            times += list(first.values())
            missing += len(watchers) - len(first)
            addrs.append(a)
            time.sleep(0.4)
        many.set_at = self_set
        return times, missing, addrs

    def step(cid, label, shift, from_n3, to_n3):
        """A fresh group with right clocks, then n3 moved by `shift` seconds against the others."""
        reset_clocks()
        fresh_group(lab, nodes)
        d1, d2, d3 = first_login(nodes)
        wait_until(lambda: members_ok(d1, 3) and members_ok(d3, 3), 20)
        before = addr()           # a block from before the clock moved, lifted on n3 afterwards
        d1.block(before)
        time.sleep(1.5)
        n3.clock_shift(shift)
        time.sleep(2.5)
        off = offset(n3)
        R.check(S, cid + "0", "n3 %s: the clock of the VM is where the test put it" % label, abs(off - shift) < 2, {"offset_s": off})

        times, missing, addrs = many(d3, [n1, n2])
        sm = summary(times)
        if from_n3:
            R.check(S, cid + "1", "n3 %s: blocks set on n3 act on n1 and n2 within 1 s at p95 (5 blocks)" % label, missing == 0 and sm["p95"] <= 1000,
                    dict(sm, not_within_4s=missing, counters_n1=counters(d1)))
        else:
            R.check(S, cid + "1", "n3 %s: blocks set on n3 are not taken by n1 and n2 while their time is more than 60 s ahead (contract section 4, check 4)" % label,
                    missing == 10, dict(sm, not_within_4s=missing, of=10, counters_n1=counters(d1)))
            # when does n1 take each of the five? Each was set at another moment, so each has its own 60 s line
            set_at, taken = list(many.set_at), {}
            t_end = now() + 75
            while now() < t_end and len(taken) < len(addrs):
                for i, x in enumerate(addrs):
                    if i not in taken and get(n1.ip, "/x", claim=x, timeout=2) == 403:
                        taken[i] = round(now() - set_at[i], 1)
                time.sleep(0.2)
            after = [taken.get(i) for i in range(len(addrs))]
            want = shift - 60
            R.check(S, cid + "1b", "n3 %s: n1 takes each such block when its time is within 60 s of n1's clock, about %d s after it was set, not earlier" % (label, want),
                    all(v is not None and want - 2 <= v <= want + 8 for v in after),
                    {"seconds_after_each_was_set": after, "set_at_s_after_the_first": [round(x - set_at[0], 1) for x in set_at], "counters_n1": counters(d1)},
                    "a block taken earlier than %d s after it was set was taken while its time was more than 60 s ahead of n1's wall clock" % want)

        times, missing, addrs1 = many(d1, [n2, n3])
        sm = summary(times)
        if to_n3:
            R.check(S, cid + "2", "n3 %s: blocks set on n1 act on n2 and n3 within 1 s at p95 (5 blocks)" % label, missing == 0 and sm["p95"] <= 1000,
                    dict(sm, not_within_4s=missing, counters_n3=counters(d3)))
        else:
            on_n3 = [get(n3.ip, "/x", claim=x) for x in addrs1]
            on_n2 = [get(n2.ip, "/x", claim=x) for x in addrs1]
            R.check(S, cid + "2", "n3 %s: blocks set on n1 are not taken by n3, for which their time lies more than 60 s ahead; n2 takes them" % label,
                    on_n3 == [200] * 5 and on_n2 == [403] * 5, {"n3_answers": on_n3, "n2_answers": on_n2, "counters_n3": counters(d3)},
                    n3.grep("clock|ahead", 2)[:500])

        # lifts across the clock difference
        res = {}
        for name, dash, target in (("set on n3, lifted on n1", d1, addrs[0]), ("set on n1, lifted on n3", d3, addrs1[0]),
                                   ("set on n1 before the clock moved, lifted on n3", d3, before)):
            inc = incident_of(dash, target, 2.0)
            if not inc:
                res[name] = "the lifting node does not hold the block"
                continue
            st = unblock_retry(dash, inc)
            gone = wait_until(lambda: blocked_everywhere(nodes, target, 200), 8, 0.1)
            res[name] = {"unblock_status": st, "lifted_everywhere_after_s": round(gone, 2) if gone is not None else None,
                         "still_refused_on": [n.name for n in nodes if get(n.ip, "/x", claim=target) == 403]}
        bad = [k for k, v in res.items() if isinstance(v, dict) and v["lifted_everywhere_after_s"] is None]
        R.check(S, cid + "3", "n3 %s: a lift on one side of the clock difference lifts the block on all three nodes" % label, not bad, res)

        # logins
        dl = Dash(n3)
        stl = dl.login()[0]
        v13 = wait_until(lambda: Dash(n1, dl).session()[1].get("authenticated") is True, 6, 0.1)
        dl1 = Dash(n1)
        dl1.login()
        v31 = wait_until(lambda: Dash(n3, dl1).session()[1].get("authenticated") is True, 6, 0.1)
        R.check(S, cid + "4", "n3 %s: a login on n3 is valid on n1, and one on n1 valid on n3, within 6 s (a balancer without stickiness sends the next click elsewhere)" % label,
                (v13 is not None and v31 is not None) if (from_n3 and to_n3) else None,
                {"login_on_n3_valid_on_n1_after_s": round(v13, 2) if v13 is not None else None,
                 "login_on_n1_valid_on_n3_after_s": round(v31, 2) if v31 is not None else None})

        v1, v3 = operator_view(n1, d1), operator_view(n3, Dash(n3, d3) if to_n3 else dl)
        R.check(S, cid + "5", "n3 %s: what the operator sees on n1 and on n3" % label, None, {"n1": v1, "n3": v3})
        R.check(S, cid + "7", "n3 %s: the clock stayed there to the end of the step" % label, abs(offset(n3) - shift) < 2,
                {"offset_s_at_the_end": offset(n3), "times_the_holder_put_the_clock_back": n3.clock_corrections()},
                "each time the hypervisor set the clock right, it was right for a few milliseconds")
        R.check(S, cid + "6", "n3 %s: schild cluster status names the clock difference (spec, merge: 'schild cluster status reports a skew over 5 s')" % label,
                bool(v1["status_lines_that_name_a_clock"] or v3["status_lines_that_name_a_clock"]),
                {"n1": v1["status_lines_that_name_a_clock"], "n3": v3["status_lines_that_name_a_clock"]},
                "the only line that changes is the counter: n1 '%s', n3 '%s'" % ("".join(v1["status_counter_line"]), "".join(v3["status_counter_line"])))
        return d1, d2, d3

    reset_clocks()
    R.check(S, "3.01", "clocks of the three node VMs against the client VM before the test (seconds)", None, {n.name: offset(n) for n in nodes})
    step("3.1", "30 s ahead", 30, True, True)
    d1, d2, d3 = step("3.2", "90 s ahead", 90, False, True)

    # the clock of the node that was 90 s ahead is corrected (as NTP would step it)
    n3.clock_release()
    t0 = now()
    a = addr()
    d1.block(a)
    w = wait_until(lambda: get(n3.ip, "/x", claim=a) == 403, 120, 0.25)
    R.check(S, "3.60", "the clock of n3 is set right after it was 90 s ahead: seconds until n3 takes a block set on n1 at that moment", None,
            {"seconds": round(now() - t0, 1) if w is not None else None, "n2_took_it": get(n2.ip, "/x", claim=a) == 403, "counters_n3": counters(d3)},
            "while n3 was ahead, n1 and n2 took its records; what they write afterwards carries a time after those")

    # and then falls behind, on the same running group (no fresh start): the order ahead, right, behind
    for cid, back in (("3.61", -30), ("3.62", -90)):
        n3.clock_shift(back)
        time.sleep(2.5)
        times, missing, addrs = many(d1, [n2, n3], count=3, timeout=6)
        on_n3 = [get(n3.ip, "/x", claim=x) for x in addrs]
        dl1 = Dash(n1)
        dl1.login()
        v31 = wait_until(lambda: Dash(n3, dl1).session()[1].get("authenticated") is True, 6, 0.1)
        R.check(S, cid, "n3 was 90 s ahead, was set right and is now %d s behind (same processes): blocks set on n1 act on n3 within 1 s" % -back,
                on_n3 == [403] * 3 and missing == 0 and summary(times)["p95"] <= 1000,
                {"offset_s": offset(n3), "n3_answers_6_s_after_each_block": on_n3, "not_within_6s": missing, "ms": summary(times),
                 "login_on_n1_valid_on_n3_after_s": round(v31, 2) if v31 is not None else None, "counters_n3": counters(d3),
                 "times_the_holder_put_the_clock_back": n3.clock_corrections()}, n3.grep("clock|ahead|put off", 2)[:400])
    n3.clock_release()

    step("3.3", "30 s behind", -30, True, True)
    d1, d2, d3 = step("3.4", "90 s behind", -90, True, False)
    time.sleep(1)

    # a node that starts while its clock is 90 s behind
    a = addr()
    d1.block(a)
    n3.kill9()
    time.sleep(1)
    n3.start()
    t = n3.wait_ready(40)
    at_ready = get(n3.ip, "/x", claim=a) if t is not None else None
    time.sleep(3)
    R.check(S, "3.50", "n3 restarted while its clock is 90 s behind: at its first ready answer it refuses the address the group blocked while it was down",
            t is not None and at_ready == 403, {"ready_after_s": round(t, 2) if t is not None else None, "blocked_address_at_ready": at_ready,
                                                "3_s_later": get(n3.ip, "/x", claim=a), "offset_s": offset(n3)}, json.dumps(operator_view(n3, Dash(n3, d1))))
    n3.clock_release()
    t0 = now()
    conv = wait_until(lambda: d1.blocks() is not None and d1.blocks() == Dash(n3, d1).blocks(), 60, 0.2)
    R.check(S, "3.51", "clock of n3 corrected: n3 takes what it had put off and holds the same blocks as n1", conv is not None,
            {"seconds": round(now() - t0, 2) if conv is not None else None, "counters_n3": counters(d3)})
    reset_clocks()
    R.check(S, "3.52", "clocks at the end (seconds against the client VM)", all(abs(offset(n)) < 2 for n in nodes), {n.name: offset(n) for n in nodes})


# ---------------------------------------------------------------------------------------------------------------
# scenario 4: blocks on the balancer VM (role edge)


def reach(lab, address, port=80, timeout=0.7):
    """What a visitor with this source address gets from the balancer VM: the status, 0 when nothing answers."""
    return get(lab.lb.ip, "/edge", bind=address, timeout=timeout, port=port)


def s4(lab):
    S = "s4"
    nodes = lab.nodes[:3]
    n1, n2, n3 = nodes
    lb = lab.lb
    fresh_group(lab, nodes)
    d1, d2, d3 = first_login(nodes)
    wait_until(lambda: members_ok(d1, 3), 20)
    lab.haproxy(nodes)
    lab.wait_lb({"n1": "UP", "n2": "UP", "n3": "UP"}, 20)
    lb.run("pkill -x schild; nft delete table inet schild 2>/dev/null; rm -rf /var/lib/schild-edge; true")
    EDGE = "/var/lib/schild-edge"

    rc, out = n1.cli("cluster invite -role edge")
    code = re.search(r"\b([a-z2-7]{4,}(?:-[a-z2-7]{4,}){3,})\b", out)
    R.check(S, "4.01", "schild cluster invite -role edge on a gateway prints a code", rc == 0 and code is not None, {"exit": rc},
            re.sub(r"[a-z2-7]{4,}(-[a-z2-7]{4,}){3,}", "<code>", out)[:500])
    code = code.group(1) if code else ""
    rc, out = lb.run("schild cluster join %s:%d %s -edge -name lb-1 -data %s" % (n1.ip, MESH_PORT, code, EDGE), 30)
    R.check(S, "4.02", "schild cluster join ADDRESS CODE -edge -name lb-1 -data DIR on the balancer VM, as the guide writes it", rc == 0, {"exit": rc}, out[:500])
    rc2, out2 = lb.run("schild cluster join %s:%d %s -edge -name lb-2 -data /var/lib/schild-edge2" % (n1.ip, MESH_PORT, code), 30)
    R.check(S, "4.03", "the same code a second time is refused (one use)", rc2 != 0, {"exit": rc2}, out2[:200])
    lb.run("rm -rf /var/lib/schild-edge2")
    lb.spawn("exec schild firewall run -group -data %s >>/var/log/schild/edge.log 2>&1" % EDGE)
    t = wait_until(lambda: lb.run("nft list table inet schild >/dev/null 2>&1")[0] == 0, 15, 0.1)
    R.check(S, "4.04", "schild firewall run -group -data DIR creates the nftables table inet schild on the balancer VM", t is not None,
            {"seconds": round(t, 2) if t is not None else None}, lb.run("nft list table inet schild | head -40")[1][:1500])
    time.sleep(1)
    g = d1.group()
    R.check(S, "4.05", "the dashboard API of a gateway lists the balancer VM as an edge, apart from the gateways",
            [m.get("name") for m in g.get("members", []) if m.get("role") == "edge"] == ["lb-1"]
            and sum(1 for m in g.get("members", []) if m.get("role") == "gateway") == 3,
            {"edges": [{k: m.get(k) for k in ("name", "state", "address", "last_in", "blocks_held")} for m in g.get("members", []) if m.get("role") == "edge"],
             "gateways": sum(1 for m in g.get("members", []) if m.get("role") == "gateway")}, n1.status())

    # blocked there, lifted there
    drop_ms, lift_ms, bad = [], [], []
    for i in range(12):
        a = CLIENT_NET + str(200 + i)
        d = (d1, d2, d3)[i % 3]
        if reach(lab, a) != 200:
            bad.append("%s not served before the block" % a)
            continue
        t0 = now()
        st, js = d.block(a)
        w = wait_until(lambda: reach(lab, a, timeout=0.25) == 0, 6, 0.02)
        if w is None:
            bad.append("%s: status %s, still answered %s after 6 s" % (a, st, reach(lab, a)))
            continue
        # the first probe that got no answer started 0.25 s before it was counted
        drop_ms.append(round((now() - t0) * 1000 - 250, 1))
        time.sleep(0.5)
        inc = incident_of(d, a)
        t0 = now()
        unblock_retry(d, inc)
        w = wait_until(lambda: reach(lab, a, timeout=0.25) == 200, 6, 0.02)
        if w is None:
            bad.append("%s: lifted, still no answer after 6 s" % a)
        else:
            lift_ms.append(round((now() - t0) * 1000, 1))
    sm = summary(drop_ms)
    R.check(S, "4.06", "a block set on any gateway drops the packets of the address on the balancer VM within 2 s at p95 (n = 12)",
            not bad and sm.get("n") == 12 and sm["p95"] <= 2000, sm, "; ".join(bad))
    sm = summary(lift_ms)
    R.check(S, "4.07", "a lift serves the address through the balancer VM again within 2 s at p95 (n = 12)", sm.get("n") == 12 and sm["p95"] <= 2000, sm)

    a = CLIENT_NET + "220"
    d1.block(a)
    wait_until(lambda: reach(lab, a, timeout=0.25) == 0, 6, 0.02)
    rc, out = lb.run("nft list table inet schild")
    el = re.search(re.escape(a) + r"[^,}\n]*", out)
    exp = re.search(r"expires (\d+)d(\d+)h", el.group(0)) if el else None
    R.check(S, "4.08", "the element of a 7 day block carries its end as the kernel timeout", exp is not None and exp.group(1) == "6", {},
            el.group(0) if el else out[:600])
    rc, out2 = lb.run("nft list table inet schild | grep -E 'dport|port' | head -6")
    other_port = get(lb.ip, "/file?path=/etc/hostname", bind=a, port=9927, timeout=2)
    R.check(S, "4.09", "only the ports 80 and 443 are dropped: the blocked address still reaches another port of the VM", other_port == 200,
            {"status_on_another_port": other_port}, out2)
    rc, out = lb.run("schild firewall status -data %s" % EDGE)
    R.check(S, "4.10", "schild firewall status on the balancer VM names the table and the blocked address", a in out, {"exit": rc}, out[:500])

    # own and allowlisted addresses are left out
    b = CLIENT_NET + "221"
    d2.block(b)
    time.sleep(1.5)
    st = d2.allow(b)[0]
    w = wait_until(lambda: reach(lab, b, timeout=0.25) in (200, 403), 6, 0.05)
    in_set = b in lb.run("nft list table inet schild")[1]
    R.check(S, "4.11", "an address put on the allowlist after its block leaves the firewall of the balancer VM", st == 201 and w is not None and not in_set,
            {"allow_status": st, "seconds": round(w, 2) if w is not None else None, "status_through_balancer": reach(lab, b), "still_in_set": in_set})

    # an erased address
    c = CLIENT_NET + "222"
    d3.block(c)
    wait_until(lambda: reach(lab, c, timeout=0.25) == 0, 6, 0.02)
    st, js = d1.erase(c)
    w = wait_until(lambda: reach(lab, c, timeout=0.25) == 200, 30, 0.05)
    R.check(S, "4.12", "an erased address (Art. 17) with a running block leaves the firewall of the balancer VM within 30 s", st == 200 and w is not None,
            {"status": st, "seconds": round(w, 2) if w is not None else None, "nodes": (js or {}).get("nodes") if isinstance(js, dict) else None})

    # what the edge holds and may read
    for i in range(5):
        get(lb.ip, "/only-a-visit-%d" % i, bind=CLIENT_NET + "223")
    time.sleep(2)
    session = (d1.cookie or "=").split("=", 1)[1]
    rc, files = lb.run("find %s -type f -exec ls -la {} \\; | awk '{print $5, $9}'" % EDGE)
    found = {}
    for label, needle in (("session cookie", session), ("csrf token", d1.csrf or "-"), ("allowlisted address", b), ("address of a visitor that is not blocked", CLIENT_NET + "223"),
                          ("the word password", "password"), ("an event type", "schild.block.set"), ("the group secret", lab["secret"])):
        rc, out = lb.run("grep -r -a -l -F -- %s %s /var/log/schild/edge.log 2>/dev/null | head -3" % (json.dumps(needle), EDGE))
        found[label] = out.split()
    R.check(S, "4.13", "the data directory and the log of the edge hold no login, no setting, no visitor that is not blocked, no secret of the group",
            not any(found.values()), {"found_in": found}, files)
    key = lb.run("ls %s/cluster/node.key 2>/dev/null || find %s -name node.key | head -1" % (EDGE, EDGE))[1].strip()
    group = re.search(r"(g-[0-9a-f]{32})", n1.status()).group(1)
    calls = {}
    if lb.run("test -x /opt/sg27/hostile")[0] == 0 and key:
        for name, path, body in (("sync", "/mesh/v0/sync", {"group": group, "vector": {}, "wait_ms": 0}),
                                 ("ask firewall", "/mesh/v0/ask", {"kind": "firewall", "body": {}}),
                                 ("ask events", "/mesh/v0/ask", {"kind": "events", "body": {"after": 0}}),
                                 ("ask incidents", "/mesh/v0/ask", {"kind": "incidents", "body": {"since_ms": 0}}),
                                 ("ask requests", "/mesh/v0/ask", {"kind": "requests", "body": {"after": 0}}),
                                 ("ask hub_index", "/mesh/v0/ask", {"kind": "hub_index", "body": {}}),
                                 ("tell counts", "/mesh/v0/tell", {"kind": "counts", "body": {}}),
                                 ("tell config", "/mesh/v0/tell", {"kind": "config", "body": {}}),
                                 ("lock", "/mesh/v0/lock", {"name": "x"})):
            rc, out = lb.run("/opt/sg27/hostile call -key %s -addr %s:%d -path %s -timeout 25 -body '%s'" % (key, n2.ip, MESH_PORT, path, json.dumps(body)), 40)
            try:
                r = json.loads(out)
            except ValueError:
                r = {"status": -1, "body": out}
            body_text = r.get("body", "") or ""
            classes = sorted(set(re.findall(r'"class":"([a-z]+)"', body_text)))
            calls[name] = {"status": r.get("status"), "bytes": len(body_text), "classes": classes,
                           "names_a_visitor_not_blocked": (CLIENT_NET + "223") in body_text}
        ok = (calls["sync"]["status"] == 200 and calls["sync"]["classes"] in (["members"], []) and calls["ask firewall"]["status"] == 200
              and all(v["status"] == 403 for k, v in calls.items() if k not in ("sync", "ask firewall")))
        R.check(S, "4.14", "with the key of the edge: sync answers member records only, ask answers the firewall list only, every other mesh call 403",
                ok, calls)
        R.check(S, "4.15", "the firewall list the edge gets names blocked clients and their end, not the incident, the source or a visitor that is not blocked",
                None, {}, json.loads(lb.run("/opt/sg27/hostile call -key %s -addr %s:%d -path /mesh/v0/ask -timeout 25 -body '%s'"
                                           % (key, n2.ip, MESH_PORT, json.dumps({"kind": "firewall", "body": {}})), 40)[1]).get("body", "")[:700])
    else:
        R.check(S, "4.14", "mesh calls with the key of the edge", None, {}, "not measured: no key file found below %s or the mesh client is missing" % EDGE)

    # the edge loses every gateway: blocks end by their kernel timeout, nothing new arrives
    lb.nft(["output: tcp dport %d counter drop" % MESH_PORT, "input: tcp sport %d counter drop" % MESH_PORT])
    e = CLIENT_NET + "224"
    d1.block(e)
    time.sleep(6)
    still = reach(lab, a, timeout=0.25)
    new = reach(lab, e)
    g = d1.group()
    R.check(S, "4.16", "the balancer VM reaches no gateway: the blocks it holds stay dropped, a new block is refused by the gateways behind it (block page)",
            still == 0 and new == 403, {"held_block": still, "new_block": new,
             "edge_as_n1_sees_it": [{k: m.get(k) for k in ("name", "state", "last_in", "blocks_held")} for m in g.get("members", []) if m.get("role") == "edge"]},
            lb.run("tail -3 /var/log/schild/edge.log")[1][:500])
    lb.nft_clear()
    w = wait_until(lambda: reach(lab, e, timeout=0.25) == 0, 30, 0.05)
    R.check(S, "4.17", "the balancer VM reaches the gateways again: the new block is dropped there", w is not None, {"seconds": round(w, 2) if w is not None else None})

    # the gateway the edge joined at is killed: it asks another
    n1.kill9()
    f = CLIENT_NET + "225"
    t0 = now()
    d2.block(f)
    w = wait_until(lambda: reach(lab, f, timeout=0.25) == 0, 30, 0.05)
    R.check(S, "4.18", "the gateway the edge joined at is killed: a block set on another gateway is dropped on the balancer VM within 2 s",
            w is not None and w <= 2.25, {"seconds": round(w - 0.25, 2) if w is not None else None})
    n1.start(); n1.wait_ready(60)

    # a clean stop removes the table
    lb.run("pkill -TERM -x schild")
    t = wait_until(lambda: lb.run("nft list table inet schild >/dev/null 2>&1")[0] != 0, 10, 0.1)
    R.check(S, "4.19", "a clean stop (SIGTERM) of schild firewall run removes the table", t is not None, {"seconds": round(t, 2) if t is not None else None},
            "after it the blocked address gets through the balancer VM: %s" % reach(lab, a))
    rc, out = n2.run("cat /etc/schild/cluster.secret >/dev/null && echo present")
    rc, out = lb.run("mkdir -p /etc/schild-e && printf 'config_version: 0\\nnode_name: lb-x\\n' > /dev/null; ls %s/cluster 2>/dev/null" % EDGE)
    R.check(S, "4.20", "files of the edge below its data directory", None, {}, files)


# ---------------------------------------------------------------------------------------------------------------
# scenario 5: sixteen gateways


def s5(lab):
    S = "s5"
    nodes = lab.nodes[:16]
    if len(nodes) < 16:
        R.check(S, "5.00", "sixteen gateway VMs are there", False, {"vms": len(nodes)})
        return
    n1 = nodes[0]
    for n in nodes:
        n.wipe()
        n.write_files([m.ip for m in nodes], lab.balancers(), node_name=n.name, drain=(5, 10))
    lab.haproxy(nodes, inter="1s", fall=2, rise=2)
    t0 = now()
    threads = [threading.Thread(target=n.start) for n in nodes]
    [t.start() for t in threads]
    [t.join() for t in threads]
    spawn_s = now() - t0
    ready = {}

    def wait_one(n):
        ready[n.name] = n.wait_ready(90)
    threads = [threading.Thread(target=wait_one, args=(n,)) for n in nodes]
    [t.start() for t in threads]
    [t.join() for t in threads]
    vals = [v for v in ready.values() if v is not None]
    R.check(S, "5.01", "sixteen gateways started together from the same files: every node answers ready", len(vals) == 16,
            {"seconds_to_ready": summary(vals, 2), "not_ready": [k for k, v in ready.items() if v is None], "start_calls_took_s": round(spawn_s, 2)})
    time.sleep(2)
    d = first_login(nodes)

    def all_see(count, who=None):
        return all(members_ok(x, count) for x in (who or d))
    conv = wait_until(lambda: all_see(16), 90, 0.5)
    R.check(S, "5.02", "every one of the sixteen dashboards shows sixteen gateways, all reachable, state active", conv is not None,
            {"seconds_since_start": round(now() - t0, 1) if conv is not None else None},
            "" if conv is not None else json.dumps({x.node.name: [x.group().get("state"), len(x.group().get("members", []))] for x in d}))
    sess = [x.session()[1].get("authenticated") is True for x in d]
    R.check(S, "5.03", "the login made on n1 is valid on all sixteen", all(sess), {"valid_on": sum(sess)})
    up = lab.wait_lb({n.name: "UP" for n in nodes}, 30)
    R.check(S, "5.04", "HAProxy has all sixteen UP", up is not None, {})
    time.sleep(20)
    idle0 = {n.name: n.usage() for n in nodes}
    time.sleep(60)
    idle1 = {n.name: n.usage() for n in nodes}
    cpu = [round((idle1[k]["cpu_s"] - idle0[k]["cpu_s"]) / 60.0 * 100, 2) for k in idle0 if idle0[k] and idle1[k]]
    rss = [idle1[k]["rss_mib"] for k in idle1 if idle1[k]]
    R.check(S, "5.05", "idle group of sixteen, per node: resident memory (MiB) and CPU (percent of one core, over 60 s)", None,
            {"rss_mib": summary(rss), "cpu_percent_of_one_core": summary(cpu, 2)})

    # blocks to fifteen others
    times, missing = [], 0
    for i in range(20):
        a = CLIENT_NET + str(60 + i)
        k = i % 16
        first, inc, st = propagation(d[k], [n for n in nodes if n is not nodes[k]], a, timeout=8)
        times += list(first.values())
        missing += 15 - len(first)
        time.sleep(0.3)
    sm = summary(times)
    R.check(S, "5.06", "a block set on one of sixteen refuses the address on the fifteen others within 1 s at p95 (20 blocks, 300 pairs)",
            missing == 0 and sm.get("p95", 1e9) <= 1000, dict(sm, not_within_8s=missing))

    # load through the balancer, then five nodes lost at once
    load = Load(lab.lb.ip, rate=300, workers=24, mode="new", bind=CLIENT_NET + "30").start()
    time.sleep(20)
    u0 = {n.name: n.usage() for n in nodes}
    tu0 = now()
    time.sleep(20)
    u1 = {n.name: n.usage() for n in nodes}
    span = now() - tu0
    cpu = [round((u1[k]["cpu_s"] - u0[k]["cpu_s"]) / span * 100, 2) for k in u0 if u0[k] and u1[k]]
    st = load.stats()
    R.check(S, "5.07", "300 requests a second through the balancer over sixteen nodes (about 19 a node): no failure; per node memory and CPU", st["not_200"] == 0,
            {"requests": st["requests"], "codes": st["codes"], "latency_ms": st["latency_ms"], "rss_mib": summary([u1[k]["rss_mib"] for k in u1 if u1[k]]),
             "cpu_percent_of_one_core": summary(cpu, 2)})
    lost = nodes[11:16]
    t_kill = now()
    threads = [threading.Thread(target=n.kill9) for n in lost]
    [t.start() for t in threads]
    [t.join() for t in threads]
    down = lab.wait_lb({n.name: "DOWN" for n in lost}, 20)
    detect = wait_until(lambda: sum(1 for m in d[0].group().get("members", []) if m.get("state") not in ("ok", "self")) == 5, 20, 0.05)
    time.sleep(8)
    g = d[0].group()
    fails = [r for r in load.rows if r[2] != 200 and r[0] >= t_kill - 1]
    last = max((r[0] - t_kill for r in fails), default=None)
    R.check(S, "5.08", "five of sixteen killed at once under load: failed requests, and none after the balancer marked them down",
            down is not None and (last is None or last <= down + 0.5),
            {"failed": len(fails), "last_failure_s_after_kill": round(last, 2) if last is not None else None, "haproxy_all_down_after_s": round(down, 2) if down else None,
             "n1_shows_five_unreachable_after_s": round(detect, 2) if detect is not None else None, "state_n1": g.get("state")})
    alive = nodes[:11]
    times, missing = [], 0
    for i in range(6):
        a = CLIENT_NET + str(90 + i)
        first, inc, st2 = propagation(d[i], [n for n in alive if n is not nodes[i]], a, timeout=8)
        times += list(first.values())
        missing += 10 - len(first)
    sm = summary(times)
    R.check(S, "5.09", "with five gone, a block set on one of the eleven refuses the address on the ten others within 1 s at p95",
            missing == 0 and sm.get("p95", 1e9) <= 1000, dict(sm, not_within_8s=missing))
    t0 = now()
    [n.start() for n in lost]
    back = {}

    def wait_back(n):
        t = n.wait_ready(90)
        back[n.name] = (t, get(n.ip, "/x", claim=CLIENT_NET + "90") if t is not None else None)
    threads = [threading.Thread(target=wait_back, args=(n,)) for n in lost]
    [t.start() for t in threads]
    [t.join() for t in threads]
    conv = wait_until(lambda: all_see(16), 90, 0.5)
    R.check(S, "5.10", "the five return together: each refuses the address blocked meanwhile at its first ready answer; all sixteen dashboards active again",
            all(v[0] is not None and v[1] == 403 for v in back.values()) and conv is not None,
            {"ready_s": {k: round(v[0], 2) if v[0] else None for k, v in back.items()}, "blocked_at_ready": {k: v[1] for k, v in back.items()},
             "all_active_after_s": round(now() - t0, 1) if conv is not None else None})
    lab.wait_lb({n.name: "UP" for n in nodes}, 30)
    time.sleep(3)
    load.stop()
    st = load.stats(since=t_kill + (down or 0) + 1)
    R.check(S, "5.11", "from the moment the balancer had the five down until they were back: no failed request", st["not_200"] == 0,
            {"requests": st["requests"], "codes": st["codes"]}, str(st["errors"]))

    # rolling restart of all sixteen under load
    load = Load(lab.lb.ip, rate=300, workers=24, mode="new", bind=CLIENT_NET + "30").start()
    keep = Load(lab.lb.ip, rate=60, workers=12, mode="keep", bind=CLIENT_NET + "32").start()
    time.sleep(3)
    t0 = now()
    per = []
    for n in nodes:
        t1 = now()
        threading.Thread(target=lambda n=n: n.cli("cluster drain", 60), daemon=True).start()
        gone = n.wait_exit(60)
        t_gone = now() - t1
        n.start()
        r = n.wait_ready(60)
        up = lab.wait_lb({n.name: "UP"}, 30)
        per.append({"node": n.name, "stopped_after_s": round(t_gone, 1), "ready_after_start_s": round(r, 2) if r else None, "exited": gone,
                    "haproxy_up": up is not None})
    total = now() - t0
    time.sleep(3)
    load.stop(); keep.stop()
    st, kst = load.stats(), keep.stats()
    R.check(S, "5.12", "rolling restart of all sixteen (schild cluster drain, start, wait for ready and the balancer; delay_s 5, check every 1 s, fall 2) under load: no request on a new connection fails",
            st["not_200"] == 0 and all(p["exited"] and p["ready_after_start_s"] is not None for p in per),
            {"requests": st["requests"], "codes": st["codes"], "seconds_for_all": round(total, 1),
             "ready_after_start_s": summary([p["ready_after_start_s"] for p in per if p["ready_after_start_s"]], 2)}, str(st["errors"]))
    R.check(S, "5.13", "rolling restart: kept connections through the balancer lose no request", kst["not_200"] == 0 and kst["retried"] == 0,
            {"requests": kst["requests"], "codes": kst["codes"], "cut_without_answer_and_sent_again": kst["retried"]}, str(kst["errors"]))
    conv = wait_until(lambda: all_see(16), 60, 0.5)
    blocks = [x.blocks() for x in d]
    sess = [x.session()[1].get("authenticated") is True for x in d]
    R.check(S, "5.14", "after the rolling restart: all sixteen active, the same blocks on every node, the login still valid everywhere",
            conv is not None and all(b == blocks[0] and b for b in blocks) and all(sess),
            {"blocks_per_node": sorted(set(len(b or []) for b in blocks)), "login_valid_on": sum(sess)})
    R.check(S, "5.15", "after all of it, per node: resident memory (MiB)", None, {"rss_mib": summary([n.usage().get("rss_mib", 0) for n in nodes])})


# ---------------------------------------------------------------------------------------------------------------
# scenario 7: certificates with an ACME test server (pebble) on the application VM


CERT_SITE = "cert.sg27.test"


def s7(lab):
    S = "s7"
    from lab import tls_get
    n1, n2 = lab.nodes[0], lab.nodes[1]
    pair = [n1, n2]
    app = lab.app
    if app.run("test -x /opt/sg27/pebble && test -f /opt/sg27/pebble.minica.pem")[0] != 0:
        R.check(S, "7.00", "the ACME test server (pebble) is on the application VM", None, {}, "not measured: pebble was not copied to the lab")
        return
    ca = app.get("/opt/sg27/pebble.minica.pem")

    def pebble_start():
        app.run("pkill -x pebble; sleep 0.3; rm -f /var/log/pebble.log; grep -q %s /etc/hosts || echo '%s %s' >> /etc/hosts" % (CERT_SITE, lab.lb.ip, CERT_SITE))
        app.put("/opt/sg27/pebble.json", json.dumps({"pebble": {
            "listenAddress": "0.0.0.0:14000", "managementListenAddress": "0.0.0.0:15000",
            "certificate": "/opt/sg27/pebble-cert.pem", "privateKey": "/opt/sg27/pebble-key.pem",
            "httpPort": 80, "tlsPort": 443, "ocspResponderURL": "", "externalAccountBindingRequired": False,
            "retryAfter": {"authz": 3, "order": 5},
            "profiles": {"default": {"description": "default", "validityPeriod": 7776000}}}}))
        app.spawn("PEBBLE_VA_NOSLEEP=1 PEBBLE_WFE_NONCEREJECT=0 exec /opt/sg27/pebble -config /opt/sg27/pebble.json >/var/log/pebble.log 2>&1")
        time.sleep(1.0)

    def issued():
        rc, out = app.run("grep -c 'Issued certificate serial' /var/log/pebble.log")
        return int(out or 0)

    def deploy():
        glob = "\tacme_ca https://pebble:14000/dir\n\tacme_ca_root /etc/schild/pebble.minica.pem"
        for n in pair:
            n.wipe()
            n.run("grep -q pebble /etc/hosts || echo '%s pebble' >> /etc/hosts" % app.ip)
            n.write_files([m.ip for m in pair], lab.balancers(), node_name=n.name, caddy_global=glob, site_addr=CERT_SITE)
            n.put("/etc/schild/pebble.minica.pem", ca)

    def cert_of(n):
        return tls_get(n.ip, "/", CERT_SITE, claim=CLIENT_NET + "70")

    def wait_cert(n, timeout=60):
        """Seconds until the node shows a certificate pebble issued (not a self-made one) and answers 200."""
        t0 = now()
        while now() - t0 < timeout:
            st, fp = cert_of(n)
            if st == 200:
                return now() - t0, fp
            time.sleep(0.25)
        return None, cert_of(n)[1]

    # The balancer for a TLS site. Port 80 of such a node is the redirect listener: it does not speak the PROXY
    # protocol and answers /.schild/readyz with a redirect (check 7.02), so port 80 goes without PROXY and with a
    # TCP check, and port 443 with PROXY v2 and the readiness check over TLS.
    cfg = ["global", "  maxconn 20000", "  stats socket /run/sg27-haproxy.sock mode 600 level admin", "",
           "defaults", "  mode tcp", "  timeout connect 2s", "  timeout client 60s", "  timeout server 60s", "",
           "frontend web80", "  bind :80", "  default_backend gateways80", "",
           "backend gateways80", "  balance roundrobin", "  default-server check inter 1s fall 2 rise 1"]
    cfg += ["  server %s %s:80" % (n.name, n.ip) for n in pair]
    cfg += ["", "frontend web443", "  bind :443", "  default_backend gateways443", "",
            "backend gateways443", "  balance roundrobin", "  option httpchk",
            "  http-check send meth GET uri /.schild/readyz ver HTTP/1.1 hdr Host %s" % CERT_SITE, "  http-check expect status 200",
            "  default-server send-proxy-v2 check check-ssl verify none check-sni %s check-alpn http/1.1 inter 1s fall 2 rise 1" % CERT_SITE]
    cfg += ["  server %s %s:443" % (n.name, n.ip) for n in pair]
    lab.haproxy_raw(cfg + [""])

    def lb443():
        rc, out = lab.lb.run("echo 'show servers state gateways443' | nc -U /run/sg27-haproxy.sock")
        return {f[3]: ("UP" if f[5] in ("2", "3") else "DOWN") for f in (l.split() for l in out.splitlines()) if len(f) > 6 and f[0].isdigit()}

    def placed():
        """Orders the CA was asked for so far."""
        rc, out = app.run("grep -c 'Added order' /var/log/pebble.log")
        return int(out or 0)

    def both_serve(timeout):
        t0 = now()
        while now() - t0 < timeout:
            a, b = cert_of(n1), cert_of(n2)
            if a[0] == 200 and b[0] == 200:
                return round(now() - t0, 1), a[1], b[1]
            time.sleep(0.5)
        return None, cert_of(n1)[1], cert_of(n2)[1]

    # one node first, the second later
    pebble_start()
    deploy()
    rc, out = n1.cli("ingress validate")
    R.check(S, "7.01", "the Caddyfile with a TLS site and the ACME test server is accepted in a cluster", rc == 0, {}, out.splitlines()[-1] if out else "")
    n1.start()
    time.sleep(1.0)
    c = Conn(n1.ip, claim=lab.client.ip, host=CERT_SITE)
    with_proxy = c.get("/.schild/readyz")
    c2 = Conn(n1.ip, host=CERT_SITE)
    without = c2.get("/.schild/readyz")
    R.check(S, "7.02", "a TLS site with the listener_wrappers of the guide: /.schild/readyz on port 80, asked by a balancer that speaks the PROXY protocol, answers 200 or 503 (guide: 'auf den Web-Ports')",
            with_proxy in (200, 503), {"port_80_with_proxy_header": with_proxy, "port_80_without_proxy_header": without, "location": c2.headers.get("Location")},
            "port 80 is the redirect listener there: the PROXY wrapper of the global options is not on it, and the readiness answer is a redirect to HTTPS; "
            + n1.grep("schild_redirects|server running", 2)[:300])
    t1, fp1 = wait_cert(n1, 150)
    up = wait_until(lambda: lb443().get("n1") == "UP", 20, 0.2)
    R.check(S, "7.03", "n1 alone obtains the certificate through the balancer and is then ready on port 443 (readiness asked over TLS and PROXY)",
            t1 is not None and issued() == 1 and up is not None,
            {"seconds_from_start_to_certificate": round(t1 + 1, 1) if t1 else None, "orders_placed": placed(), "issued_by_the_ca": issued(), "haproxy_443": lb443()},
            "before a node has a certificate the readiness check over TLS cannot pass, so the CA reaches it on port 80 only (HTTP-01); "
            + n1.grep("will retry", 1)[:300])

    # n2 starts later with an empty storage: the group holds the certificate
    before = placed()
    n2.start()
    t_first = wait_until(lambda: placed() > before, 20, 0.2)
    t2, fp2 = wait_cert(n2, 150)
    R.check(S, "7.04", "n2 starts later with an empty storage while n1 holds the certificate: n2 asks the CA for no order of its own (guide: 'Eine Bestellung pro Zertifikat')",
            t_first is None, {"orders_placed_before": before, "orders_placed_after": placed(), "first_order_of_n2_s_after_its_start": round(t_first, 2) if t_first is not None else None,
                              "issued_by_the_ca": issued()}, n2.grep("obtaining certificate|lock acquired|took a change", 4)[:700])
    R.check(S, "7.05", "n2 shows the certificate n1 obtained within 10 s of its start", t2 is not None and t2 <= 10 and fp2 == fp1,
            {"seconds": round(t2, 1) if t2 else None, "same_certificate": fp2 == fp1, "issued_by_the_ca": issued(),
             "certificate_files_on_n2": int(n2.run("find /var/lib/schild/caddy/certificates -name '*.crt' | wc -l")[1] or 0)},
            n2.grep("certificate obtained|will retry|loaded", 2)[:500])
    wait_until(lambda: lb443() == {"n1": "UP", "n2": "UP"}, 20, 0.2)
    codes = [tls_get(lab.lb.ip, "/", CERT_SITE)[0] for _ in range(6)]
    fps = sorted(set(tls_get(lab.lb.ip, "/", CERT_SITE)[1] for _ in range(6)))
    R.check(S, "7.06", "through the balancer every TLS connection gets one and the same certificate", codes == [200] * 6 and len(fps) == 1, {"codes": codes, "certificates": fps,
                                                                                                                                       "issued_by_the_ca": issued()})

    # a node restarted with no member reachable serves its certificate
    n1.kill9()
    n2.kill9()
    count = issued()
    n2.start()
    t, fp = wait_cert(n2, 40)
    time.sleep(3)
    R.check(S, "7.07", "n2 restarted with n1 down: it serves a certificate from its own copy at once, no new order", t is not None and t <= 5 and issued() == count,
            {"seconds": round(t, 1) if t else None, "issued_by_the_ca_before": count, "after": issued()})
    n2.kill9()

    # Only n1 asks the CA while both nodes are behind the round-robin balancer and in step: the CA is down at
    # first, n1 starts, n2 starts 20 s later, the CA comes up at 30 s. A node tries again a minute after a
    # failed try, so n1 asks at about 60 s and n2 not before 80 s. The CA's three checks on port 80 land on both.
    runs = []
    last_err = ""
    for i in range(3):
        app.run("pkill -x pebble; rm -f /var/log/pebble.log; true")
        deploy()
        t0 = now()
        n1.start()
        time.sleep(20)
        n2.start()
        time.sleep(10)
        pebble_start()
        # the first try of n1 failed because the CA was down; wait for the end of its second
        w = wait_until(lambda: issued() >= 1 or int(n1.run("grep -c 'will retry' %s" % Node.LOG)[1] or 0) >= 2, 60, 0.5)
        time.sleep(0.5)
        at = round(now() - t0, 1)
        first = {"second_try_of_n1_ended_at_s": at, "issued_by_the_ca_then": issued(), "orders_placed_then": placed(),
                 "challenge_answers_of_n1": int(n1.run("grep -c 'served key authentication' %s" % Node.LOG)[1] or 0),
                 "challenge_answers_of_n2": int(n2.run("grep -c 'served key authentication' %s" % Node.LOG)[1] or 0),
                 "ca_checks_on_port_80": int(app.run("grep -c 'Attempting to validate w/ HTTP' /var/log/pebble.log")[1] or 0)}
        last_err = (n1.grep("challenge failed.*http-01", 1))[:600] or last_err
        t, fa, fb = both_serve(120)
        first.update({"both_serve_s_after_n1_started": round(now() - t0, 1) if t is not None else None, "same_certificate": fa == fb and t is not None,
                      "orders_placed": placed(), "issued_by_the_ca": issued()})
        runs.append(first)
        n1.kill9(); n2.kill9()
    R.check(S, "7.08", "one node asks the CA while both are behind the round-robin balancer and in step, 3 runs: its first try with the CA up gets the certificate (guide: the CA's check works on whichever server it lands)",
            all(r["issued_by_the_ca_then"] == 1 for r in runs), {"runs": runs}, last_err)
    R.check(S, "7.09", "the same 3 runs: one certificate issued per run in the end, and both nodes show it (guide: 'Eine Bestellung pro Zertifikat')",
            all(r["issued_by_the_ca"] == 1 and r["same_certificate"] for r in runs),
            {"issued": [r["issued_by_the_ca"] for r in runs], "orders_placed": [r["orders_placed"] for r in runs],
             "both_serve_s_after_n1_started": [r["both_serve_s_after_n1_started"] for r in runs]})

    # both nodes started fresh at the same moment with the CA up, as a deployment does that starts every node
    pebble_start()
    deploy()
    n1.start(); n2.start()
    time.sleep(8)
    o1 = int(n1.run("grep -c 'obtaining certificate' %s" % Node.LOG)[1] or 0)
    o2 = int(n2.run("grep -c 'obtaining certificate' %s" % Node.LOG)[1] or 0)
    R.check(S, "7.10", "both nodes started fresh at the same moment with the CA reachable: one of them asks the CA, the other waits (first 8 s)",
            placed() <= 1, {"orders_placed_in_8_s": placed(), "n1_started_obtaining": o1, "n2_started_obtaining": o2, "issued_by_the_ca": issued()},
            (n1.grep("lock acquired", 1) + " | " + n2.grep("lock acquired", 1))[:500])
    n1.kill9(); n2.kill9()
    app.run("pkill -x pebble; true")


# ---------------------------------------------------------------------------------------------------------------


SCENARIOS = {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only", default="")
    ap.add_argument("--name", default="")
    a = ap.parse_args()
    random.seed(SEED)
    lab = Lab()
    only = [s for s in a.only.split(",") if s] or sorted(SCENARIOS)
    R.name = a.name or "-".join(only)
    ok = lab.prepare()
    print("lab: %d gateways, secret made: %s" % (len(lab.nodes), ok), flush=True)
    for s in only:
        print("=== %s" % s, flush=True)
        try:
            SCENARIOS[s](lab)
        except Exception as e:  # a scenario that breaks is reported, the others still run
            import traceback
            R.check(s, s + ".err", "the scenario ran to its end", False, {}, traceback.format_exc()[-1500:])
    R.save()


SCENARIOS.update({"s1": s1, "s2": s2, "s3": s3, "s4": s4, "s5": s5, "s7": s7})

if __name__ == "__main__":
    main()
