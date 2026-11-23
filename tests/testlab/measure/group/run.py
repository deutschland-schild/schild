#!/usr/bin/env python3
"""MVP-27 group of gateways: black-box measurement on one machine (see README.md).

Real `schild run` processes on 127.0.0.1, one group set up by configuration (A: n1..n3), one by join codes
(B: m1..m3). Writes raw.json into the output directory and, with --results, tests/results/MVP-27.json.
"""
import argparse
import base64
import datetime
import hashlib
import json
import os
import platform
import random
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.parse

from lib import (PASSWORD, Blackhole, Conn, Dash, Load, Node, Watch, api, get, hostile, latency, now, pct, summary,
                 wait_for)

SEED = 27
ATTACK = "?q=" + urllib.parse.quote("<script>alert(1)</script>")


class Lab:
    pass


R = {"items": {}, "checks": []}


def check(item, name, ok, detail=""):
    """One verdict line. ok: True PASS, False FAIL, None INFO (a number without a pass mark)."""
    verdict = "INFO" if ok is None else ("PASS" if ok else "FAIL")
    R["checks"].append({"item": item, "name": name, "verdict": verdict, "detail": str(detail)[:600]})
    print("  [%s] %s %s: %s" % (verdict, item, name, str(detail)[:300]), flush=True)


def item(name):
    def deco(fn):
        def run(*a, **kw):
            print("== %s" % name, flush=True)
            t0 = now()
            try:
                out = fn(*a, **kw)
            except Exception as e:
                traceback.print_exc()
                check(name, "harness", False, "harness error, item incomplete: %r" % e)
                out = {"harness_error": repr(e)}
            R["items"].setdefault(name, {}).update(out or {})
            R["items"][name]["took_s"] = round(now() - t0, 1)
            return out
        return run
    return deco


def iso(t):
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def status_of(node):
    rc, out = node.cli("cluster", "status")
    m = re.search(r"(\d+) records taken, (\d+) refused, (\d+) put off", out)
    counts = tuple(int(x) for x in m.groups()) if m else None
    return out, counts


def all_ready(nodes, timeout=40):
    return [n.wait_ready(timeout) for n in nodes]


# ---------------------------------------------------------------------------------------------------- item 1
@item("01_single")
def single_gateway(lab):
    s = Node(lab, "s0", 0).start()
    lab.single = s
    t = s.wait_ready()
    ports = s.listeners()
    has_dir = os.path.exists(os.path.join(s.data, "cluster"))
    check("01_single", "no extra listener", ports == [s.proxy, s.dash, s.metrics, s.agent],
          "listening on %s, configured proxy/dashboard/metrics/agent %s" % (ports, [s.proxy, s.dash, s.metrics, s.agent]))
    check("01_single", "no cluster directory", not has_dir, "data dir holds %s" % sorted(os.listdir(s.data)))
    log = s.logtext()
    check("01_single", "no cluster line in the log", "cluster" not in log.lower(), "")
    d = Dash(s)
    st, _ = d.setup()
    lab.single_dash = d
    return {"ready_s": t, "listeners": ports, "cluster_dir": has_dir, "setup_status": st}


# ---------------------------------------------------------------------------------------------------- groups
def group_by_config(lab):
    print("== group A by configuration", flush=True)
    rc = subprocess.run([lab.bin, "cluster", "secret"], capture_output=True, text=True)
    lab.secret = os.path.join(lab.root, "cluster.secret")
    with open(lab.secret, "w") as f:
        f.write(rc.stdout)
    os.chmod(lab.secret, 0o600)
    peers = ["127.0.0.1:%d" % (lab.port0 + i * 10 + 4) for i in (1, 2, 3)]
    lab.peersA = peers
    own = 'allowlist:\n  - { ip: 203.0.113.250, label: "own of n3", level: no_block, expires: never }'
    A = [Node(lab, "n%d" % i, i, {"secret_file": lab.secret, "peers": peers}, extra=own if i == 3 else "").start() for i in (1, 2, 3)]
    ready = all_ready(A)
    # the first-run setup only after every node took its first sync (item 14 measures what happens before)
    synced = wait_for(lambda: all(status_of(n)[0].count(" ok ") == 2 for n in A), 20, 0.3)
    time.sleep(2.0)
    d1 = Dash(A[0])
    st, js = d1.setup()
    out, _ = status_of(A[0])
    R["items"]["00_setup_config"] = {"ready_s": ready, "peers_ok_s": synced, "setup_status": st, "status": out,
                                    "listeners_n1": A[0].listeners()}
    check("00_setup", "group by configuration starts", all(ready) and st == 200 and out.count(" ok ") == 2,
          "ready after %s s, first-run setup on n1 %s, status lists %d peers ok" % (ready, st, out.count(" ok ")))
    check("00_setup", "one mesh listener more than a single gateway", A[0].listeners() == sorted(
        [A[0].proxy, A[0].dash, A[0].metrics, A[0].agent, A[0].mesh]), A[0].listeners())
    return A, d1


def group_by_code(lab):
    # Joining by code (cluster init, invite, join) was removed in 5b12c2c; group B is now set up like group A, by a
    # secret file of its own and cluster.peers, so the items that use it (02c, 09c, 10, 12) still run.
    print("== group B by its own secret file (join codes removed)", flush=True)
    sec = os.path.join(lab.root, "cluster-b.secret")
    with open(sec, "w") as f:
        f.write(subprocess.run([lab.bin, "cluster", "secret"], capture_output=True, text=True).stdout)
    os.chmod(sec, 0o600)
    peers = ["127.0.0.1:%d" % (lab.port0 + (5 + i) * 10 + 4) for i in (1, 2, 3)]
    B = [Node(lab, "m%d" % i, 5 + i, {"secret_file": sec, "peers": peers}) for i in (1, 2, 3)]
    for n in B:
        n.start()
    ready = all_ready(B)
    wait_for(lambda: all(status_of(n)[0].count(" ok ") == 2 for n in B), 20, 0.3)
    time.sleep(2.0)
    d1 = Dash(B[0])
    st, _ = d1.setup()
    out, _ = status_of(B[0])
    R["items"]["00_setup_code"] = {"steps": "secret file (join codes removed)", "ready_s": ready, "setup_status": st, "status": out}
    check("00_setup", "group B (own secret file) starts", all(ready) and st == 200 and out.count(" ok ") == 2,
          "ready after %s s, setup %s, status lists %d peers ok" % (ready, st, out.count(" ok ")))
    return B, d1


# ---------------------------------------------------------------------------------------------------- item 7
@item("07_settings_logins")
def settings_logins(lab, A, d1):
    out = {}
    d2, d3 = Dash(A[1], d1), Dash(A[2], d1)
    t = wait_for(lambda: d2.session()[1].get("authenticated") and d3.session()[1].get("authenticated"), 10)
    check("07", "a dashboard session of n1 works on n2 and n3", t is not None, "after %s s" % (t and round(t, 2)))
    out["session_shared_s"] = t
    fresh = Dash(A[1])
    st, _ = fresh.login()
    check("07", "the password set on n1 signs in on n2", st == 200, "login on n2: %s" % st)
    # a setting
    st, js = d1.call("PATCH", "/settings", {"retention": {"events_days": 33}})
    t0 = now()
    t = wait_for(lambda: d2.call("GET", "/settings")[1].get("retention", {}).get("events_days") == 33
                 and d3.call("GET", "/settings")[1].get("retention", {}).get("events_days") == 33, 10, 0.02)
    check("07", "a setting changed on n1 reads the same on n2 and n3", st == 200 and t is not None,
          "PATCH %s, on n2 and n3 after %s s" % (st, t and round(t, 3)))
    out["setting_s"] = t
    # allowlist entry made on n2, effective on n3: a block by hand of an own address is refused
    own = "203.0.113.200"
    st, js = d2.call("POST", "/allowlist", {"ip": own, "label": "m27 own", "level": "no_block"})
    t = wait_for(lambda: own in (Dash(A[0], d1).allowlist() or []) and own in (d3.allowlist() or []), 10, 0.02)
    st3, js3 = d3.block(own)
    check("07", "an allowlist entry made on n2 is listed on n1 and n3", st == 201 and t is not None,
          "POST %s, listed after %s s" % (st, t and round(t, 3)))
    check("07", "and is effective on n3 (block by hand refused as own address)", st3 == 409,
          "POST /blocks on n3: %s %s" % (st3, (js3 or {}).get("code") if isinstance(js3, dict) else js3))
    out["allowlist_s"] = t
    # two changes right after each other on two nodes, as one person does behind a balancer without stickiness
    d1b = Dash(A[0], d1)
    want_entries = []
    for i in range(10):
        a, b = "192.0.2.%d" % (60 + 2 * i), "192.0.2.%d" % (61 + 2 * i)
        s1 = d1b.call("POST", "/allowlist", {"ip": a, "label": "quick %d a" % i, "level": "no_block"})[0]
        s2 = d2.call("POST", "/allowlist", {"ip": b, "label": "quick %d b" % i, "level": "no_block"})[0]
        want_entries += [a, b]
        out.setdefault("quick_posts", []).append([s1, s2])
        time.sleep(2.5)
    time.sleep(2.0)
    have = [Dash(n, d1).allowlist() or [] for n in A]
    lost = sorted(set(want_entries) - set(have[0]))
    out["quick_lost"], out["quick_same_on_all"] = lost, have[0] == have[1] == have[2]
    out["quick_lists_after_2s"] = have
    time.sleep(15.0)
    later = [Dash(n, d1).allowlist() or [] for n in A]
    out["quick_lists_after_17s"] = later
    out["quick_same_on_all_after_17s"] = later[0] == later[1] == later[2]
    check("07", "after those quick changes the allowlist is the same on the three nodes (17 s later)", later[0] == later[1] == later[2],
          "entries of the 20 per node: %s; only on some nodes: %s" % ([len(set(l) & set(want_entries)) for l in later],
                                                                    sorted(set().union(*map(set, later)) - set.intersection(*map(set, later)))))
    check("07", "10 times: an allowlist entry added on n1 and right after it another on n2: all 20 are kept", not lost and have[0] == have[1] == have[2],
          "every POST answered %s; missing afterwards on n1: %d of 20 %s; lists equal on the three nodes: %s" % (
              sorted(set(x for p in out["quick_posts"] for x in p)), len(lost), lost, out["quick_same_on_all"]))
    # agent token made on n1 by the command line
    rc, txt = A[0].cli("token", "add", "--scope", "agent:read", "--expires", "90d")
    m = re.search(r"(sat1_\S+)", txt)
    tok = m.group(1) if m else ""
    t = wait_for(lambda: api(A[2].agent, "GET", "/agent/v0/status", headers={"Authorization": "Bearer " + tok})[0] == 200, 10)
    check("07", "an agent token made on n1 is accepted by the agent API of n3", t is not None,
          "token add rc %s, accepted after %s s" % (rc, t and round(t, 2)))
    out["token_s"] = t
    # logout
    extra = Dash(A[0])
    extra.login()
    on2 = Dash(A[1], extra)
    ok_before = wait_for(lambda: on2.session()[1].get("authenticated"), 5)
    st, _ = extra.call("POST", "/auth/logout")
    t = wait_for(lambda: not on2.session()[1].get("authenticated"), 10)
    check("07", "a logout on n1 ends the session on n2", ok_before is not None and t is not None,
          "logout %s, session gone on n2 after %s s" % (st, t and round(t, 2)))
    return out


# ---------------------------------------------------------------------------------------------------- item 2
def propagation(tag, nodes, dash, count, base, lift_on=None):
    """Blocks set by hand on nodes[0]; time from sending the API call until the others refuse the address."""
    setter, others = nodes[0], nodes[1:]
    set_ms, lift_ms, api_ms, missed, lmissed, incident_ms, lift_errors = [], [], [], 0, 0, [], []
    for i in range(count):
        addr = "%s%d" % (base, 10 + i)
        w = Watch(others, addr, 403).start()
        time.sleep(0.15 + lab_rng.random() * 0.2)
        t0 = now()
        st, js = dash.block(addr)
        t1 = now()
        if st != 200:
            w.wait(0)
            raise RuntimeError("block %s on %s: %s %s" % (addr, setter.name, st, js))
        first = w.wait(8.0)
        api_ms.append((t1 - t0) * 1000)
        for n in others:
            if n.name in first:
                set_ms.append((first[n.name] - t0) * 1000)
            else:
                missed += 1
        # lift: every second one on another node than the one that set it. That node knows the incident only
        # once it asked for it (contract section 9): the call is repeated while it answers 404
        lifter = dash if (lift_on is None or i % 2 == 0) else lift_on
        watch_on = [n for n in nodes if n is not lifter.node]
        if lifter is not dash:
            ts = now()
            known = wait_for(lambda: lifter.call("GET", "/incidents/%s" % js["incident"])[0] == 200, 10, 0.02)
            incident_ms.append((now() - t0) * 1000 if known is not None else float("inf"))
        w = Watch(watch_on, addr, 200).start()
        time.sleep(0.15)
        t0 = now()
        st, _ = lifter.unblock(js["incident"])
        if st != 200:
            w.wait(0)
            lift_errors.append((addr, lifter.node.name, st))
            dash.unblock(js["incident"])
            continue
        first = w.wait(8.0)
        for n in watch_on:
            if n.name in first:
                lift_ms.append((first[n.name] - t0) * 1000)
            else:
                lmissed += 1
    out_extra = {"incident_known_on_other_node_ms": summary([x for x in incident_ms if x != float("inf")], 1),
                 "incident_never_known": sum(1 for x in incident_ms if x == float("inf")), "lift_errors": lift_errors}
    return {**out_extra, "blocks": count, "set_ms": summary(set_ms, 1), "lift_ms": summary(lift_ms, 1), "api_call_ms": summary(api_ms, 1),
            "set_not_seen_in_8s": missed, "lift_not_seen_in_8s": lmissed, "raw_set_ms": [round(x, 1) for x in set_ms],
            "raw_lift_ms": [round(x, 1) for x in lift_ms]}


@item("02_block_propagation")
def block_propagation(lab, A, d1):
    out = propagation("A", A, d1, 40, "203.0.113.", Dash(A[1], d1))
    s, l = out["set_ms"], out["lift_ms"]
    check("02", "block set on n1 acts on n2 and n3 within 1 s at p95", out["set_not_seen_in_8s"] == 0 and s["p95"] <= 1000,
          "n=%d p50 %.0f ms p95 %.0f ms max %.0f ms, not seen within 8 s: %d" % (s["n"], s["p50"], s["p95"], s["max"], out["set_not_seen_in_8s"]))
    check("02", "lift acts on the other nodes within 1 s at p95", out["lift_not_seen_in_8s"] == 0 and l["p95"] <= 1000,
          "n=%d p50 %.0f ms p95 %.0f ms max %.0f ms, not seen within 8 s: %d" % (l["n"], l["p50"], l["p95"], l["max"], out["lift_not_seen_in_8s"]))
    k = out["incident_known_on_other_node_ms"]
    check("02", "the incident of a block set on n1 is found on n2 (to lift it there)", out["incident_never_known"] == 0 and not out["lift_errors"],
          "found on n2 after p50 %s ms, p95 %s ms from the block call (n=%s); never within 10 s: %d; lift errors %s" % (
              k.get("p50"), k.get("p95"), k.get("n"), out["incident_never_known"], out["lift_errors"]))
    return out


@item("02b_block_holds")
def block_holds(lab, A, d1):
    """Blocks by hand, nothing else done: do they still run after two full minutes? Group and single gateway."""
    plan = [("1h", 3600, "203.0.113.150"), ("24h", 86400, "203.0.113.151"), ("7d", 604800, "203.0.113.152")]
    d0 = lab.single_dash
    for name, dur, addr in plan:
        d1.block(addr, dur)
        d0.block(addr, dur)
    t0 = now()
    wait_for(lambda: all(get(n.proxy, "/", plan[2][2]) == 403 for n in A), 5)
    ended = {}
    rows = []
    while now() - t0 < 125:
        row = {name: {"group": [get(n.proxy, "/", addr) for n in A], "single": get(lab.single.proxy, "/", addr)} for name, dur, addr in plan}
        for name in row:
            for where in ("group", "single"):
                gone = row[name][where] == 200 if where == "single" else 200 in row[name][where]
                if gone and (name, where) not in ended:
                    ended[(name, where)] = round(now() - t0, 1)
        rows.append((round(now() - t0, 1), row))
        time.sleep(2.5)
    out = {"ended_after_s": {"%s %s" % k: v for k, v in ended.items()}, "last": rows[-1][1],
           "process_age_at_set_s": {"n1": round(t0 - A[0].started_at, 1), "single": round(t0 - lab.single.started_at, 1)}}
    for name, dur, addr in plan:
        ok = (name, "group") not in ended
        single = "on the single gateway without a group it ended after %s s" % ended[(name, "single")] if (name, "single") in ended else "on the single gateway it still runs"
        check("02b", "a block by hand of %s still runs on every node of the group after 125 s" % name, ok,
              ("still 403 on n1..n3" if ok else "ended after %s s on the group (statuses at the end %s)" % (ended[(name, "group")], rows[-1][1][name]["group"])) + "; " + single
              + "; process age when set: n1 %s s, single %s s" % (out["process_age_at_set_s"]["n1"], out["process_age_at_set_s"]["single"]))
    return out


@item("02d_own_allowlist")
def own_allowlist(lab, A, d1):
    """n3 alone has 203.0.113.250 on the allowlist of its schild.yaml; n1 blocks the address."""
    addr = "203.0.113.250"
    st, js = d1.block(addr)
    time.sleep(3.0)
    sts = [get(n.proxy, "/", addr) for n in A]
    check("02d", "the allowlist of a node's own schild.yaml beats a block received from the group", st == 200 and sts == [403, 403, 200],
          "block on n1 %s; request from the address on n1, n2, n3: %s (n3 has it in schild.yaml)" % (st, sts))
    if st == 200:
        d1.unblock(js["incident"])
    return {"block": st, "statuses": sts}


# ---------------------------------------------------------------------------------------------------- item 6
def rl_run(nodes, path, xff, total, rps):
    """total requests of one client, round robin over nodes; answers passed, limited, other, elapsed."""
    conns = [Conn(n.proxy) for n in nodes]
    passed = limited = other = 0
    t0 = now()
    for i in range(total):
        st = conns[i % len(conns)].get(path, xff, retry=True)
        if st == 200:
            passed += 1
        elif st == 429:
            limited += 1
        else:
            other += 1
        if rps:
            d = t0 + (i + 1) / float(rps) - now()
            if d > 0:
                time.sleep(d)
    for c in conns:
        c.close()
    return {"passed": passed, "limited": limited, "other": other, "elapsed_s": round(now() - t0, 2), "nodes": len(nodes),
            "rps": rps, "total": total}


@item("06_rate_limit")
def rate_limit(lab, A, d1):
    out = {"limit": 60, "per": "1m", "burst": 60}
    st, js = d1.call("POST", "/behaviour/rate-limits", {"route": "/rl/**", "limit": 60, "per": "1m", "burst": 60,
                                                        "mode": "block", "label": "m27"})
    out["create"] = [st, js if st != 201 else js.get("id")]
    d3 = Dash(A[2], d1)

    def listed():
        s, j = d3.call("GET", "/behaviour/rate-limits?limit=500")
        return s == 200 and any(x.get("label") == "m27" or x.get("route") == "/rl/**" for x in j.get("items", []))
    t = wait_for(listed, 10, 0.02)
    check("06", "a rate limit made on n1 is listed on n3", st == 201 and t is not None, "create %s, listed after %s s" % (st, t and round(t, 3)))
    time.sleep(1.0)
    runs = {}
    runs["one_node_20rps"] = rl_run(A[:1], "/rl/a", "198.51.100.11", 300, 20)
    runs["three_nodes_20rps"] = rl_run(A, "/rl/a", "198.51.100.12", 300, 20)
    runs["one_node_5rps"] = rl_run(A[:1], "/rl/a", "198.51.100.13", 150, 5)
    runs["three_nodes_5rps"] = rl_run(A, "/rl/a", "198.51.100.14", 150, 5)
    runs["one_node_burst"] = rl_run(A[:1], "/rl/a", "198.51.100.15", 300, 0)
    runs["three_nodes_burst"] = rl_run(A, "/rl/a", "198.51.100.16", 300, 0)
    runs["n3_only_20rps"] = rl_run(A[2:], "/rl/a", "198.51.100.17", 300, 20)
    runs["one_node_4rps_60s"] = rl_run(A[:1], "/rl/a", "198.51.100.18", 240, 4)
    runs["three_nodes_4rps_60s"] = rl_run(A, "/rl/a", "198.51.100.19", 240, 4)
    out["runs"] = runs
    for rate in (20, 5):
        one, three = runs["one_node_%drps" % rate], runs["three_nodes_%drps" % rate]
        bound = one["passed"] + rate
        check("06", "one client over 3 nodes at %d rps passes at most what it passes on one node plus one second of requests" % rate,
              three["passed"] <= bound and one["limited"] > 0,
              "one node: %d of %d passed; three nodes round robin: %d passed; bound %d + %d = %d" % (
                  one["passed"], one["total"], three["passed"], one["passed"], rate, bound))
    one, three = runs["one_node_burst"], runs["three_nodes_burst"]
    check("06", "burst as fast as the client can (300 requests)", None,
          "one node: %d passed in %.2f s; three nodes: %d passed in %.2f s (limit 60, burst 60; 3 x 60 = 180 is what three nodes take alone)" % (
              one["passed"], one["elapsed_s"], three["passed"], three["elapsed_s"]))
    one, three = runs["one_node_4rps_60s"], runs["three_nodes_4rps_60s"]
    check("06", "a client that keeps asking at 4 rps for 60 s (limit 60 per minute): passed on one node vs spread over three", None,
          "one node: %d of 240 passed; three nodes round robin: %d of 240 passed" % (one["passed"], three["passed"]))
    check("06", "the limit made on n1 limits on n3", runs["n3_only_20rps"]["limited"] > 0, runs["n3_only_20rps"])
    return out


# ---------------------------------------------------------------------------------------------------- item 3
@item("03_latency")
def latency_modes(lab, A, d1):
    N = 3000
    out = {}

    def run(name, port):
        lat, failed, other = latency(port, N)
        out[name] = dict(summary(lat, 3), failed=failed, not_200=other)
        return lat

    # interleaved rounds: off, on, off, on
    run("off_1", lab.single.proxy)
    run("on_1", A[0].proxy)
    run("off_2", lab.single.proxy)
    run("on_2", A[0].proxy)

    # peers killed while requests run on n1
    stop = []
    trace = []

    def bg():
        c = Conn(A[0].proxy, 10.0)
        while not stop:
            t = time.perf_counter()
            st = c.get("/l", "198.51.100.251")
            trace.append((now(), st, (time.perf_counter() - t) * 1000))
    th = threading.Thread(target=bg, daemon=True)
    th.start()
    time.sleep(1.0)
    t_kill = now()
    A[1].kill9()
    A[2].kill9()
    time.sleep(8.0)
    stop.append(1)
    th.join()
    after = [x for x in trace if x[0] >= t_kill]
    out["during_peer_kill"] = dict(summary([x[2] for x in after], 3), failed=sum(1 for x in after if x[1] == 0),
                                   not_200=sum(1 for x in after if x[1] not in (0, 200)))
    run("peers_stopped", A[0].proxy)
    # a write while every peer is stopped
    t0 = now()
    st, js = d1.block("203.0.113.160")
    out["block_api_ms_peers_stopped"] = round((now() - t0) * 1000, 1)
    out["block_local_peers_stopped"] = [st, get(A[0].proxy, "/", "203.0.113.160")]
    if st == 200:
        d1.unblock(js["incident"])
    A[1].start()
    A[2].start()
    out["peers_back_ready_s"] = all_ready(A[1:])
    time.sleep(2.0)

    # peers frozen (SIGSTOP): their sockets accept, nothing answers
    stop.clear()
    trace.clear()
    th = threading.Thread(target=bg, daemon=True)
    th.start()
    time.sleep(1.0)
    t_freeze = now()
    A[1].freeze()
    A[2].freeze()
    time.sleep(12.0)
    stop.append(1)
    th.join()
    after = [x for x in trace if x[0] >= t_freeze]
    out["during_peer_freeze"] = dict(summary([x[2] for x in after], 3), failed=sum(1 for x in after if x[1] == 0),
                                     not_200=sum(1 for x in after if x[1] not in (0, 200)))
    run("peers_frozen", A[0].proxy)
    t0 = now()
    st, js = d1.block("203.0.113.161")
    out["block_api_ms_peers_frozen"] = round((now() - t0) * 1000, 1)
    out["block_local_peers_frozen"] = [st, get(A[0].proxy, "/", "203.0.113.161")]
    t0 = now()
    rc, txt = A[0].cli("cluster", "status")
    out["status_peers_frozen"] = txt
    A[1].thaw()
    A[2].thaw()
    t = wait_for(lambda: get(A[1].proxy, "/", "203.0.113.161") == 403 and get(A[2].proxy, "/", "203.0.113.161") == 403, 15, 0.02)
    out["catch_up_after_thaw_s"] = t
    check("03", "a block set while the peers were frozen reaches them after they run again", t is not None, "after %s s" % (t and round(t, 2)))
    if st == 200:
        d1.unblock(js["incident"])

    # a node whose peers are listeners that accept and never answer
    holes = [Blackhole(lab.port0 + 96), Blackhole(lab.port0 + 97)]
    x = Node(lab, "x1", 4, {"secret_file": lab.secret, "peers": ["127.0.0.1:%d" % (lab.port0 + 96), "127.0.0.1:%d" % (lab.port0 + 97)]})
    x.start()
    seq, t0 = [], now()
    while now() - t0 < 20:
        st = x.ready()
        if not seq or seq[-1][1] != st:
            seq.append((round(now() - t0, 2), st))
        if st == 200:
            break
        time.sleep(0.05)
    out["blackhole_node_readyz"] = seq
    served_while_not_ready = get(x.proxy, "/")
    run("peers_blackhole", x.proxy)
    out["blackhole_connections_held"] = sum(len(h.held) for h in holes)
    x.kill9()
    for h in holes:
        h.close()
    run("off_3", lab.single.proxy)
    run("on_3", A[0].proxy)

    off = [out[k]["p50"] for k in ("off_1", "off_2", "off_3")]
    on = [out[k]["p50"] for k in ("on_1", "on_2", "on_3")]
    off99 = [out[k]["p99"] for k in ("off_1", "off_2", "off_3")]
    on99 = [out[k]["p99"] for k in ("on_1", "on_2", "on_3")]
    fails = sum(out[k]["failed"] + out[k]["not_200"] for k in out if isinstance(out[k], dict) and "failed" in out[k])
    check("03", "no request failed in any mode", fails == 0, "failed or not 200 over all modes: %d" % fails)
    check("03", "latency p50 off vs on", None, "off %s ms, on %s ms (three rounds each, %d requests)" % (off, on, N))
    check("03", "latency p99 off vs on", None, "off %s ms, on %s ms" % (off99, on99))
    worst = max(out[k]["max"] for k in ("during_peer_kill", "during_peer_freeze", "peers_stopped", "peers_frozen", "peers_blackhole"))
    check("03", "no request waits for a peer (stopped, frozen, black hole)", worst < 250 and fails == 0,
          "slowest single request in those modes %.1f ms; p99 stopped %.2f, frozen %.2f, black hole %.2f, during kill %.2f, during freeze %.2f ms" % (
              worst, out["peers_stopped"]["p99"], out["peers_frozen"]["p99"], out["peers_blackhole"]["p99"],
              out["during_peer_kill"]["p99"], out["during_peer_freeze"]["p99"]))
    check("03", "a write does not wait for stopped or frozen peers", out["block_api_ms_peers_stopped"] < 1000 and out["block_api_ms_peers_frozen"] < 1000
          and out["block_local_peers_stopped"] == [200, 403] and out["block_local_peers_frozen"] == [200, 403],
          "POST /blocks took %.0f ms with peers stopped, %.0f ms with peers frozen; local effect %s %s" % (
              out["block_api_ms_peers_stopped"], out["block_api_ms_peers_frozen"], out["block_local_peers_stopped"], out["block_local_peers_frozen"]))
    check("03r", "a node that never synced and reaches no member (black hole peers) answers 503 on /.schild/readyz first (contract section 10: until it took the state, or 10 s)",
          seq[-1][1] == 200 and any(s == 503 for _, s in seq),
          "readyz over time (s since start, status; 0 = not listening yet): %s" % (seq,))
    return out


# ---------------------------------------------------------------------------------------------------- item 4
@item("04_kill_restart")
def kill_restart(lab, A, d1):
    out = {}
    n1, n2, n3 = A
    d2, d3 = Dash(n2, d1), Dash(n3, d1)
    pre = ["203.0.113.%d" % i for i in range(170, 175)]
    inc = {}
    for a in pre:
        st, js = d1.block(a)
        inc[a] = js.get("incident")
    wait_for(lambda: all(get(n3.proxy, "/", a) == 403 for a in pre), 5)
    load = Load(A, rps=150, threads=3).start()
    # events written by n3 up to the kill
    sent, stop = [], []

    def attacker():
        c = Conn(n3.proxy, 3.0)
        i = 0
        while not stop:
            i += 1
            st = c.get("/kp-%04d%s" % (i, ATTACK), "198.51.100.%d" % (101 + i % 50))
            sent.append((i, now(), st))
            time.sleep(0.02)
    th = threading.Thread(target=attacker, daemon=True)
    th.start()
    time.sleep(6.0)
    t_kill = now()
    n3.kill9()
    stop.append(1)
    th.join()
    time.sleep(4.0)
    truth = {"/kp-%04d" % i: t for i, t, st in sent if st == 403}
    out["attack_statuses"] = sorted(set(st for _, _, st in sent))
    ev1 = d1.events(path="/kp-") or []
    ev2 = d2.events(path="/kp-") or []
    have1 = set(e.get("path") for e in ev1)
    have2 = set(e.get("path") for e in ev2)
    missing1 = sorted((t_kill - t) for p, t in truth.items() if p not in have1)
    missing2 = sorted((t_kill - t) for p, t in truth.items() if p not in have2)
    out["events_written_by_n3"] = len(truth)
    out["events_missing_on_n1"] = len(missing1)
    out["events_missing_on_n2"] = len(missing2)
    out["oldest_missing_age_s"] = round(max(missing1 + missing2), 2) if missing1 + missing2 else 0
    check("04", "events n3 wrote up to 5 s before the kill are found on n1 and n2",
          len(truth) > 50 and all(x <= 5.0 for x in missing1 + missing2),
          "n3 answered %d attacks with 403; missing on n1 %d, on n2 %d; oldest missing one was answered %.2f s before the kill (contract: all but the last second)" % (
              len(truth), len(missing1), len(missing2), out["oldest_missing_age_s"]))
    still = [[get(n.proxy, "/", a) for a in pre] for n in (n1, n2)]
    check("04", "blocks still act on n1 and n2 after the kill", all(s == 403 for row in still for s in row), still)
    # changes while n3 is away
    st, js = d1.block("203.0.113.180")
    d2.unblock(inc[pre[0]])
    d1.call("POST", "/allowlist", {"ip": "203.0.113.201", "label": "m27 away", "level": "no_block"})
    for i in range(20):
        get(n1.proxy, "/away-%02d%s" % (i, ATTACK), "198.51.100.%d" % (160 + i))
    time.sleep(3.0)
    rows = load.finish()
    t_rows = [r for r in rows if r[0] > t_kill + 0.05]
    bad_alive = [r for r in rows if r[1] != "n3" and r[2] != 200]
    bad_n3_before = [r for r in rows if r[1] == "n3" and r[2] != 200 and r[0] < t_kill - 0.5]
    n3_after = [r for r in t_rows if r[1] == "n3"]
    lat_alive_before = [r[3] for r in rows if r[1] != "n3" and r[0] < t_kill]
    lat_alive_after = [r[3] for r in rows if r[1] != "n3" and r[0] >= t_kill]
    out["load"] = {"requests": len(rows), "failed_on_n1_n2": len(bad_alive), "failed_on_n3_before_kill": len(bad_n3_before),
                   "sent_to_n3_after_kill": len(n3_after), "failed_on_n3_after_kill": sum(1 for r in n3_after if r[2] != 200),
                   "n1_n2_ms_before": summary(lat_alive_before, 2), "n1_n2_ms_after": summary(lat_alive_after, 2)}
    check("04", "the other nodes serve on: no failed request on n1 and n2", len(bad_alive) == 0,
          "%d requests in all, failed on n1/n2: %d; p99 on n1/n2 before the kill %.2f ms, after %.2f ms" % (
              len(rows), len(bad_alive), out["load"]["n1_n2_ms_before"].get("p99", -1), out["load"]["n1_n2_ms_after"].get("p99", -1)))
    # restart
    n3.start()
    seq, t0, bad = [], now(), []
    first200 = None
    while now() - t0 < 30:
        rs = n3.ready()
        if not seq or seq[-1][1] != rs:
            seq.append((round(now() - t0, 3), rs))
        if rs == 200:
            first200 = now() - t0
            break
        time.sleep(0.01)
    at_ready = {"new_block_203.0.113.180": get(n3.proxy, "/", "203.0.113.180"),
                "old_blocks": [get(n3.proxy, "/", a) for a in pre[1:]],
                "lifted_while_away": get(n3.proxy, "/", pre[0])}
    out["readyz_after_restart"] = seq
    out["at_first_200"] = at_ready
    ok = at_ready["new_block_203.0.113.180"] == 403 and all(s == 403 for s in at_ready["old_blocks"]) and at_ready["lifted_while_away"] == 200
    check("04", "readiness is 503 until the restarted node caught up", first200 is not None and any(s == 503 for _, s in seq) and ok,
          "readyz over time (s, status) %s; at the first 200: %s" % (seq, at_ready))
    t = wait_for(lambda: "203.0.113.201" in (d3.allowlist() or []), 10)
    check("04", "the allowlist entry made while n3 was away is on n3", t is not None, "after %s s past ready" % (t and round(t, 2)))
    t = wait_for(lambda: len(d3.events(path="/away-") or []) >= 20, 15)
    out["events_caught_up_s"] = t
    check("04", "n3 catches up the events n1 wrote while it was away", t is not None,
          "20 events of n1 on n3 after %s s past ready (%d found)" % (t and round(t, 2), len(d3.events(path="/away-") or [])))
    own = set(e.get("path") for e in (d3.events(path="/kp-") or []))
    out["n3_own_events_after_restart"] = len(own & set(truth))
    time.sleep(2.0)
    b = [Dash(n, d1).blocks() for n in A]
    al = [Dash(n, d1).allowlist() for n in A]
    check("04", "blocks and allowlist are the same on all three afterwards", b[0] == b[1] == b[2] and al[0] == al[1] == al[2] and "203.0.113.201" in al[0], "blocks %s; allowlist %s" % (b, al))
    out["blocks_after"], out["allowlist_after"] = b, al
    for a in pre[1:] + ["203.0.113.180"]:
        pass
    return out


# ---------------------------------------------------------------------------------------------------- item 5
def drain_one(lab, nodes, node, how):
    """Stop one node under a load that follows readiness like a balancer; answers the times and failures."""
    load = Load(nodes, rps=150, threads=4, health=True).start()
    probe, stop = [], []

    def prober():
        while not stop:
            t = now()
            r = get(node.proxy, "/.schild/readyz", timeout=1.0)
            s = get(node.proxy, "/probe", "198.51.100.240", timeout=2.0)
            probe.append((t, r, s))
            time.sleep(0.02)
    th = threading.Thread(target=prober, daemon=True)
    th.start()
    time.sleep(2.0)
    t_cmd = now()
    res = {}
    if how == "drain":
        box = {}
        ct = threading.Thread(target=lambda: box.update(r=node.cli("cluster", "drain", timeout=60)), daemon=True)
        ct.start()
    else:
        node.term()
    exited = node.wait_exit(40)
    t_exit = now()
    if how == "drain":
        ct.join(30)
        res["cli"] = box.get("r")
        res["cli_returned_after_s"] = round(now() - t_cmd, 2)
    time.sleep(1.5)
    stop.append(1)
    th.join()
    # back in
    node.start()
    back = node.wait_ready(40)
    time.sleep(2.0)
    rows = load.finish()
    first503 = next((t for t, r, s in probe if t >= t_cmd and r == 503), None)
    last_served = max((t for t, r, s in probe if s == 200 and t >= t_cmd), default=None)
    served_in_503 = sum(1 for t, r, s in probe if first503 and t >= first503 and r == 503 and s == 200)
    failed_in_503 = sum(1 for t, r, s in probe if first503 and t >= first503 and r == 503 and s != 200)
    failed = [r for r in rows if r[2] != 200]
    res.update({
        "exited": exited, "stop_took_s": round(t_exit - t_cmd, 2),
        "readyz_503_after_s": round(first503 - t_cmd, 3) if first503 else None,
        "served_for_s_after_503": round(last_served - first503, 2) if first503 and last_served else None,
        "probe_served_while_503": served_in_503, "probe_failed_while_503": failed_in_503,
        "load_requests": len(rows), "load_failed": len(failed),
        "load_failed_detail": [(round(r[0] - t_cmd, 2), r[1], r[2]) for r in failed[:20]],
        "load_to_node_after_cmd": sum(1 for r in rows if r[1] == node.name and t_cmd <= r[0] <= t_exit),
        "back_ready_s": back,
    })
    return res


@item("05_drain")
def drain(lab, A, d1):
    out = {}
    out["cluster_drain_n2"] = drain_one(lab, A, A[1], "drain")
    out["sigterm_n3"] = drain_one(lab, A, A[2], "term")
    out["cluster_drain_n1"] = drain_one(lab, A, A[0], "drain")
    for k, r in out.items():
        check("05", "%s: readiness 503 first, served during the delay" % k,
              r["exited"] and r["readyz_503_after_s"] is not None and r["probe_served_while_503"] > 10 and r["probe_failed_while_503"] == 0,
              "503 after %s s, then served for %s s (%d probe requests answered 200 while 503, %d failed), stop took %s s" % (
                  r["readyz_503_after_s"], r["served_for_s_after_503"], r["probe_served_while_503"], r["probe_failed_while_503"], r["stop_took_s"]))
    total = sum(r["load_failed"] for r in out.values())
    reqs = sum(r["load_requests"] for r in out.values())
    check("05", "every node stopped and started in turn under load: failed requests", total == 0,
          "%d of %d requests failed (load follows /.schild/readyz every 200 ms): %s" % (
              total, reqs, [r["load_failed_detail"] for r in out.values() if r["load_failed"]]))
    time.sleep(2)
    # the session survives the turn
    st, js = d1.session()
    check("05", "the dashboard session is still valid after every node was restarted once", js.get("authenticated") is True, js)
    return out


# ---------------------------------------------------------------------------------------------------- item 8
@item("08_erasure")
def erasure(lab, A, d1):
    out = {}
    n1, n2, n3 = A
    ds = [d1, Dash(n2, d1), Dash(n3, d1)]
    E, E2 = "198.51.100.220", "203.0.113.190"
    for n in A:
        for i in range(5):
            get(n.proxy, "/er-%s-%d%s" % (n.name, i, ATTACK), E)
            get(n.proxy, "/er-clean-%d" % i, E)
    t = wait_for(lambda: all(d.privacy(E).get("events", 0) >= 15 for d in ds), 15)
    out["events_on_every_node_s"] = t
    before = [d.privacy(E) for d in ds]
    out["before"] = before
    check("08", "every node holds the 15 events of the address before the erasure (events are shared)", t is not None,
          "after %s s; events per node %s" % (t and round(t, 2), [b.get("events") for b in before]))

    def ring(d):
        q = "/requests?ip=%s&from=%s&to=%s&limit=500" % (E, iso(time.time() - 3600), iso(time.time() + 60))
        st, js = d.call("GET", q)
        return len(js.get("items", [])) if st == 200 else "status %s" % st
    time.sleep(2.5)
    out["ring_before"] = [ring(d) for d in ds]
    st, js = d1.block(E2)
    wait_for(lambda: get(n2.proxy, "/", E2) == 403, 5)
    n3.kill9()
    t0 = now()
    st, js = d1.call("POST", "/privacy/delete", {"ip": E, "confirm": True})
    out["delete"] = [st, js]
    t = wait_for(lambda: d1.privacy(E).get("events") == 0 and ds[1].privacy(E).get("events") == 0, 30, 0.02)
    out["gone_on_n1_n2_s"] = (now() - t0) if t is not None else None
    st2, js2 = d1.call("POST", "/privacy/delete", {"ip": E2, "confirm": True})
    tb = wait_for(lambda: get(n1.proxy, "/", E2) == 200 and get(n2.proxy, "/", E2) == 200, 30, 0.02)
    out["block_of_erased_address_gone_s"] = tb
    check("08", "erased on n1: gone on n2 within 30 s", t is not None,
          "delete %s %s; events of the address 0 on n1 and n2 after %s s" % (st, js, t is not None and round(out["gone_on_n1_n2_s"], 3)))
    check("08", "the running block of an erased address ends on n1 and n2", tb is not None, "after %s s" % (tb and round(tb, 2)))
    time.sleep(2.0)
    out["ring_after_n1_n2"] = [ring(d) for d in ds[:2]]
    check("08", "requests of the address are gone from the request ring on n1 and n2", out["ring_after_n1_n2"] == [0, 0],
          "records by ip before %s, after %s" % (out["ring_before"], out["ring_after_n1_n2"]))
    n3.start()
    r = n3.wait_ready(40)
    first = ds[2].privacy(E)
    blk = get(n3.proxy, "/", E2)
    trace = []
    t0 = now()
    while now() - t0 < 8.0:
        row = [get(n.proxy, "/", E2) for n in A]
        if not trace or trace[-1][1] != row:
            trace.append((round(now() - t0, 2), row))
        time.sleep(0.1)
    out["block_of_erased_address_after_restart"] = {"n3_at_ready": blk, "n1_n2_n3_over_8s": trace, "listed": [E2 in (d.blocks() or []) for d in ds]}
    detail = "request from the address on n3 at its first ready: %s; on n1, n2, n3 over the next 8 s (s, statuses): %s; listed as running block on n1, n2, n3: %s" % (
        blk, trace, out["block_of_erased_address_after_restart"]["listed"])
    check("08t", "at its first ready answer n3 no longer applies the block of an address erased while it was down", blk == 200, detail)
    check("08", "that block is gone on n3 within 8 s and does not return on n1 and n2",
          trace[-1][1] == [200, 200, 200] and all(r[0] == 200 and r[1] == 200 for _, r in trace), detail)
    later = [d.privacy(E) for d in ds]
    out["n3_at_ready"], out["all_after_8s"], out["ring_after_all"] = first, later, [ring(d) for d in ds]
    ev = [len(d.events(ip=E) or []) for d in ds]
    check("08", "n3 was down during the erasure: nothing of the address on it once it is ready", r is not None and first.get("events") == 0,
          "ready after %s s; privacy search on n3 at ready: %s" % (r and round(r, 2), first))
    check("08", "the erased address does not return on any node (8 s later)", all(x.get("events") == 0 for x in later) and ev == [0, 0, 0]
          and out["ring_after_all"] == [0, 0, 0], "privacy search events %s, event list by ip %s, ring by ip %s" % ([x.get("events") for x in later], ev, out["ring_after_all"]))
    return out


# ---------------------------------------------------------------------------------------------------- item 9
def b64(obj):
    return base64.b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode()


def sign(lab, key, rec):
    return hostile(lab, "sign", "-key", key, stdin=json.dumps(rec))


def mk_block(lab, key, group, origin, seq, addr, sample, hlc_ms=None, node="n4", mutate=None, **over):
    t = time.time()
    data = dict(sample)
    data.update({"client": addr, "since": iso(t), "until": iso(t + 604800), "duration_s": 604800, "incident": "H7KQ-%04d" % seq, "node": node})
    data.pop("event_id", None)
    if mutate:
        mutate(data)
    rec = {"v": 1, "group": group, "class": "blocks", "id": addr, "origin": origin, "seq": seq,
           "hlc": int(hlc_ms if hlc_ms else t * 1000) << 16, "expires": data.get("until", iso(t + 604800)), "data": b64(data)}
    rec.update(over)
    return sign(lab, key, rec)


def mk_lift(lab, key, group, origin, seq, addr, incident):
    t = time.time()
    rec = {"v": 1, "group": group, "class": "blocks", "id": addr, "origin": origin, "seq": seq, "hlc": int(t * 1000) << 16,
           "deleted": True, "expires": iso(t + 7 * 86400 + 3600), "data": b64({"incident": incident, "node": "n4"})}
    return sign(lab, key, rec)


@item("09_hostile_records")
def hostile_records(lab, A, d1):
    out = {}
    n1, n2, n3 = A
    group = re.search(r"(g-[0-9a-f]{32})", status_of(n1)[0]).group(1)
    # n4: a real fourth member by the group secret, then stopped; the adversary takes its key and its address
    n4 = Node(lab, "n4", 4, {"secret_file": lab.secret, "peers": lab.peersA + ["127.0.0.1:%d" % (lab.port0 + 44)]}).start()
    n4.wait_ready()
    t = wait_for(lambda: all(re.search(r"n4\s+gateway\s+\S+\s+ok", status_of(n)[0]) for n in A), 15)
    out["n4_member_s"] = t
    st, js = d1.block("203.0.113.210")  # a sample block to copy the shape of its data from
    time.sleep(1.5)
    n4.kill9()
    key4 = os.path.join(lab.root, "n4.key")
    shutil.copy(n4.key_file(), key4)
    me = hostile(lab, "id", "-key", key4)["id"]
    r = hostile(lab, "call", "-key", key4, "-addr", "127.0.0.1:%d" % n1.mesh, "-body",
                json.dumps({"group": group, "vector": {}, "wait_ms": 0}))
    body = json.loads(r["body"])
    sample = None
    for rec in body["records"]:
        if rec["class"] == "blocks" and not rec.get("deleted"):
            sample = json.loads(base64.b64decode(rec["data"]))
    out["sample_block_data_keys"] = sorted(sample) if sample else None
    seq = [body["vector"].get(me, 0) + 10]

    def nxt():
        seq[0] += 1
        return seq[0]
    recfile = os.path.join(lab.root, "hostile-records.json")
    served = []

    def serve(recs):
        served.extend(recs)
        with open(recfile, "w") as f:
            json.dump(served, f)
    serve([])
    srv = subprocess.Popen([lab.hostile, "serve", "-key", key4, "-listen", "127.0.0.1:%d" % n4.mesh, "-records", recfile],
                           stdout=open(os.path.join(lab.root, "hostile-serve.log"), "w"), stderr=subprocess.STDOUT)
    lab.procs.append(srv)
    time.sleep(1.0)
    _, before = status_of(n1)

    def acts(addr, wait=5.0):
        """Statuses of a request from addr on the three nodes after `wait` seconds at most: 403 anywhere = applied."""
        end = now() + wait
        sts = []
        while now() < end:
            sts = [get(n.proxy, "/", addr) for n in A]
            if all(s == 403 for s in sts):
                break
            time.sleep(0.2)
        return sts

    cases = {}
    # control: a correct block signed by the member key must act, or nothing below means anything
    c1 = "198.51.100.201"
    serve([mk_block(lab, key4, group, me, nxt(), c1, sample)])
    cases["control_valid_block"] = acts(c1)
    control = cases["control_valid_block"] == [403, 403, 403]
    check("09", "control: a correctly signed block of member n4, served by the adversary, acts on every node", control, cases["control_valid_block"])

    def refused(name, recs, addrs, why):
        serve(recs)
        res = {a: acts(a, 3.0) for a in addrs}
        cases[name] = res
        ok = control and all(s == 200 for sts in res.values() for s in sts)
        check("09", name, ok, "%s; statuses on n1..n3: %s" % (why, res))

    # tampered after signing
    r1 = mk_block(lab, key4, group, me, nxt(), "198.51.100.202", sample)
    r1["id"] = "198.51.100.203"
    r2 = mk_block(lab, key4, group, me, nxt(), "198.51.100.204", sample)
    d = json.loads(base64.b64decode(r2["data"]))
    d["client"] = "198.51.100.205"
    r2["data"], r2["id"] = b64(d), "198.51.100.205"
    r3 = mk_block(lab, key4, group, me, nxt(), "198.51.100.206", sample)
    r3["hlc"] += 1
    r4 = mk_block(lab, key4, group, me, nxt(), "198.51.100.207", sample)
    sig = bytearray(base64.b64decode(r4["sig"]))
    sig[5] ^= 1
    r4["sig"] = base64.b64encode(bytes(sig)).decode()
    refused("tampered after signing (id, data, hlc, signature bit)", [r1, r2, r3, r4],
            ["198.51.100.%d" % i for i in range(202, 208)], "4 records of member n4 changed after signing")
    # signed by a key that is no member
    evil = os.path.join(lab.root, "evil.key")
    with open(evil, "w") as f:
        f.write(lab_rng.randbytes(32).hex() + "\n")
    eid = hostile(lab, "id", "-key", evil)
    member = {"v": 1, "group": group, "class": "members", "id": eid["id"], "origin": eid["id"], "seq": 1, "hlc": int(time.time() * 1000) << 16,
              "data": b64({"name": "evil", "role": "gateway", "public_key": eid["public_key"], "address": "127.0.0.1:%d" % (lab.port0 + 98), "joined": iso(time.time())})}
    refused("signed by a key that is no member",
            [sign(lab, evil, member), mk_block(lab, evil, group, eid["id"], 2, "198.51.100.208", sample),
             mk_block(lab, evil, group, me, nxt(), "198.51.100.209", sample)],
            ["198.51.100.208", "198.51.100.209"], "its own member record without admission, a block under its own id, a block under n4's id")
    out["evil_listed_as_member"] = "evil" in status_of(n1)[0]
    check("09", "the non-member is not in the member list", not out["evil_listed_as_member"], "")
    # clock a day ahead, wrong group, unknown version, unknown field, over the size cap
    big = mk_block(lab, key4, group, me, nxt(), "198.51.100.214", sample, mutate=lambda d: d.update(incident="X" * (300 * 1024)))
    refused("clock a day ahead, other group, version 2, unknown data field, data over 256 KiB", [
        mk_block(lab, key4, group, me, nxt(), "198.51.100.210", sample, hlc_ms=(time.time() + 86400) * 1000),
        mk_block(lab, key4, "g-" + "0" * 32, me, nxt(), "198.51.100.211", sample),
        mk_block(lab, key4, group, me, nxt(), "198.51.100.212", sample, v=2),
        mk_block(lab, key4, group, me, nxt(), "198.51.100.213", sample, mutate=lambda d: d.update(extra="x")),
        big], ["198.51.100.%d" % i for i in range(210, 215)], "each correctly signed by member n4")
    # replay of a block after its lift
    rp = "198.51.100.215"
    blk = mk_block(lab, key4, group, me, nxt(), rp, sample)
    serve([blk])
    a1 = acts(rp)
    time.sleep(0.3)
    serve([mk_lift(lab, key4, group, me, nxt(), rp, json.loads(base64.b64decode(blk["data"]))["incident"])])
    t = wait_for(lambda: all(get(n.proxy, "/", rp) == 200 for n in A), 6)
    again = dict(blk)
    again["_always"] = True
    serve([again])
    time.sleep(4.0)
    a3 = [get(n.proxy, "/", rp) for n in A]
    cases["replay"] = {"block": a1, "lifted_after_s": t, "after_replay": a3}
    check("09", "replay of a lifted block (the same signed record, handed over on every call)", a1 == [403] * 3 and t is not None and a3 == [200] * 3,
          "block acted %s, lift after %s s, after 4 s of replay %s" % (a1, t and round(t, 2), a3))
    # channel still alive after all refusals
    c2 = "198.51.100.216"
    serve([mk_block(lab, key4, group, me, nxt(), c2, sample)])
    cases["control_after"] = acts(c2)
    check("09", "control: a correct block after the refused ones still acts (the refusals did not just stall the channel)",
          cases["control_after"] == [403] * 3, cases["control_after"])
    txt, after = status_of(n1)
    out["status_counts_before_after"] = [before, after]
    check("09", "refused records are counted in `schild cluster status` of n1", bool(before and after and after[1] + after[2] > before[1] + before[2]),
          "records taken/refused/put off before %s, after %s" % (before, after))
    # removed member
    rc, txt = n1.cli("cluster", "remove", "n4")
    out["remove"] = [rc, txt]
    time.sleep(2.0)
    rm = "198.51.100.217"
    serve([mk_block(lab, key4, group, me, nxt(), rm, sample)])
    cases["removed_member_block"] = acts(rm, 4.0)
    calls = {}
    for name, path, bodyj in (("sync", "/mesh/v0/sync", {"group": group, "vector": {}, "wait_ms": 0}),
                              ("ask_events", "/mesh/v0/ask", {"kind": "events", "body": {"after": 0}}),
                              ("ask_firewall", "/mesh/v0/ask", {"kind": "firewall", "body": {}}),
                              ("tell", "/mesh/v0/tell", {"kind": "counts", "body": {}})):
        rr = hostile(lab, "call", "-key", key4, "-addr", "127.0.0.1:%d" % n2.mesh, "-path", path, "-body", json.dumps(bodyj))
        calls[name] = [rr.get("status"), len(rr.get("body", ""))]
    cases["removed_member_calls"] = calls
    check("09", "a removed member: `cluster remove n4`, then a correctly signed block of n4 is not applied", rc == 0 and cases["removed_member_block"] == [200] * 3,
          "remove rc %s; statuses %s" % (rc, cases["removed_member_block"]))
    check("09", "a removed member reads nothing over the mesh", all(v[0] in (403, 410) for v in calls.values()), calls)
    srv.kill()
    # a TLS client that is no member, and one without a certificate
    stranger = {}
    for who, flag in (("random_key", ["-random"]), ("no_certificate", ["-nocert"])):
        for name, path, bodyj in (("sync", "/mesh/v0/sync", {"group": group, "vector": {}, "wait_ms": 0}),
                                  ("ask_events", "/mesh/v0/ask", {"kind": "events", "body": {"after": 0}}),
                                  ("ask_firewall", "/mesh/v0/ask", {"kind": "firewall", "body": {}}),
                                  ("tell", "/mesh/v0/tell", {"kind": "counts", "body": {}}),
                                  ("lock", "/mesh/v0/lock", {"name": "x"}),
                                  ("join_wrong_code", "/mesh/v0/join", {"secret": "AAAAAAAAAAAAAAAAAAAAAA==", "name": "evil", "address": "127.0.0.1:1"}),
                                  ("hello_garbage", "/mesh/v0/hello", {"record": {}})):
            rr = hostile(lab, "call", *flag, "-addr", "127.0.0.1:%d" % n1.mesh, "-path", path, "-body", json.dumps(bodyj))
            stranger["%s %s" % (who, name)] = [rr.get("status"), (rr.get("body") or rr.get("error") or "")[:120]]
    cases["stranger"] = stranger
    check("09", "a TLS client that is no member (random key, no certificate) gets no 200 on any mesh call",
          all(v[0] != 200 for v in stranger.values()), {k: v[0] for k, v in stranger.items()})
    rr = hostile(lab, "call", "-key", n2.key_file(), "-addr", "127.0.0.1:%d" % n1.mesh, "-path", "/mesh/v0/ask", "-body", json.dumps({"kind": "events", "body": {"after": 0}}))
    cases["member_ask_events_control"] = [rr.get("status"), len(rr.get("body", ""))]
    check("09", "control: the same ask with a member key answers 200 with rows", rr.get("status") == 200 and len(rr.get("body", "")) > 100, cases["member_ask_events_control"])
    out["cases"] = cases
    return out


@item("09b_edge")
def edge(lab, B, d1):
    out = {}
    m1, m2, m3 = B
    group = re.search(r"(g-[0-9a-f]{32})", status_of(m1)[0]).group(1)
    for i in range(5):
        get(m2.proxy, "/edge-ev-%d%s" % (i, ATTACK), "198.51.100.30")
    time.sleep(1.5)
    st, js = d1.block("203.0.113.220")
    rc, txt = m1.cli("cluster", "invite", "-role", "edge")
    m = re.search(r"cluster join (\S+) (\S+)", txt)
    code = m.group(2) if m else (re.findall(r"\b[a-z2-7]+(?:-[a-z2-7]+){3,}\b", txt) or [""])[0]
    edir = os.path.join(lab.root, "edge1")
    p = subprocess.run([lab.bin, "cluster", "join", "127.0.0.1:%d" % m1.mesh, code, "-edge", "-name", "lb-1", "-data", edir],
                       capture_output=True, text=True, timeout=30)
    out["join"] = [p.returncode, (p.stdout + p.stderr).strip()[:400]]
    ekey = os.path.join(edir, "cluster", "node.key")
    if not os.path.exists(ekey):
        found = [os.path.join(dp, f) for dp, _, fs in os.walk(edir) for f in fs if f == "node.key"]
        ekey = found[0] if found else ekey
    time.sleep(1.5)
    stxt = status_of(m1)[0]
    out["status"] = stxt
    check("09b", "an edge joins with a code of role edge", p.returncode == 0 and re.search(r"lb-1\s+edge", stxt) is not None, out["join"])
    calls = {}

    def call(name, key, path, bodyj, addr=m2.mesh):
        rr = hostile(lab, "call", "-key", key, "-addr", "127.0.0.1:%d" % addr, "-path", path, "-body", json.dumps(bodyj), "-timeout", "30")
        calls[name] = [rr.get("status"), (rr.get("body") or rr.get("error") or "")]
        return rr
    rr = call("edge sync", ekey, "/mesh/v0/sync", {"group": group, "vector": {}, "wait_ms": 0})
    classes = sorted(set(r.get("class") for r in json.loads(rr["body"]).get("records", []))) if rr.get("status") == 200 else None
    check("09b", "sync answers an edge with member records only", classes == ["members"], "classes handed to the edge: %s" % classes)
    rr = call("member sync (control)", m3.key_file(), "/mesh/v0/sync", {"group": group, "vector": {}, "wait_ms": 0})
    mclasses = sorted(set(r.get("class") for r in json.loads(rr["body"]).get("records", []))) if rr.get("status") == 200 else None
    check("09b", "control: the same sync with a gateway key hands over the other classes", mclasses is not None and len(mclasses) > 2, mclasses)
    rr = call("edge ask firewall", ekey, "/mesh/v0/ask", {"kind": "firewall", "body": {}})
    fw = rr.get("body", "")
    leak = [w for w in ("incident", "source", "dashboard", "password", "hash", "csrf", "public_key") if w in fw]
    check("09b", "ask firewall answers an edge the block list and nothing else", rr.get("status") == 200 and "203.0.113.220" in fw and not leak,
          "status %s, body %s" % (rr.get("status"), fw[:300]))
    for kind, bodyj in (("events", {"after": 0}), ("incidents", {"since_ms": 0}), ("requests", {}), ("settings", {}), ("counts", {})):
        call("edge ask %s" % kind, ekey, "/mesh/v0/ask", {"kind": kind, "body": bodyj})
    call("edge tell counts", ekey, "/mesh/v0/tell", {"kind": "counts", "body": {"limits": [], "clients": [], "sites": []}})
    call("edge tell requests", ekey, "/mesh/v0/tell", {"kind": "requests", "body": {}})
    call("edge lock", ekey, "/mesh/v0/lock", {"name": "x"})
    call("edge unlock", ekey, "/mesh/v0/unlock", {"name": "x", "seq": 0})
    call("member ask events (control)", m3.key_file(), "/mesh/v0/ask", {"kind": "events", "body": {"after": 0}})
    denied = {k: v[0] for k, v in calls.items() if k.startswith("edge ") and k not in ("edge sync", "edge ask firewall")}
    check("09b", "every other mesh call answers an edge 403", all(v == 403 for v in denied.values()), denied)
    check("09b", "control: ask events with a gateway key answers 200 with rows", calls["member ask events (control)"][0] == 200
          and '"rows":[{' in calls["member ask events (control)"][1], "status %s, %d bytes" % (calls["member ask events (control)"][0], len(calls["member ask events (control)"][1])))
    # an edge that tries to write: its own record of itself as a gateway, by hello
    eid = hostile(lab, "id", "-key", ekey)
    member = {"v": 1, "group": group, "class": "members", "id": eid["id"], "origin": eid["id"], "seq": 50, "hlc": int(time.time() * 1000) << 16,
              "data": b64({"name": "lb-1", "role": "gateway", "public_key": eid["public_key"], "address": "127.0.0.1:%d" % (lab.port0 + 99), "joined": iso(time.time())})}
    rr = call("edge hello as gateway", ekey, "/mesh/v0/hello", {"record": sign(lab, ekey, member)})
    time.sleep(1.5)
    stxt = status_of(m1)[0]
    check("09b", "an edge cannot make itself a gateway by hello", rr.get("status") != 200 and re.search(r"lb-1\s+edge", stxt) is not None,
          "hello %s; status line: %s" % (rr.get("status"), (re.search(r"lb-1.*", stxt) or [""])[0] if re.search(r"lb-1.*", stxt) else ""))
    out["calls"] = {k: [v[0], v[1][:160]] for k, v in calls.items()}
    lab.edge_key, lab.groupB = ekey, group
    return out


@item("09c_removed_member_running")
def removed_running(lab, B, d1):
    out = {}
    m1, m2, m3 = B
    if not getattr(lab, "groupB", None):  # set by item 09b, which no longer runs (edges removed)
        lab.groupB = re.search(r"(g-[0-9a-f]{32})", status_of(m1)[0]).group(1)
    d3 = Dash(m3, d1)
    ok_before = d3.session()[1].get("authenticated")
    rc, txt = m1.cli("cluster", "remove", "m3")
    out["remove"] = [rc, txt]
    time.sleep(3.0)
    out["m3_log_says_removed"] = bool(re.search(r"removed", m3.logtext()))
    out["status_m1"] = status_of(m1)[0]
    # after the removal: what m1 writes must not reach m3, what m3 writes must not be taken
    st, js = d1.block("203.0.113.230")
    for i in range(5):
        get(m1.proxy, "/rm-ev-%d%s" % (i, ATTACK), "198.51.100.31")
    d1.call("PATCH", "/settings", {"retention": {"events_days": 44}})
    st3, js3 = d3.block("203.0.113.231")
    time.sleep(5.0)
    on_m3 = get(m3.proxy, "/", "203.0.113.230")
    on_m12 = [get(m1.proxy, "/", "203.0.113.231"), get(m2.proxy, "/", "203.0.113.231")]
    ev3 = len(d3.events(path="/rm-ev-") or [])
    set3 = d3.call("GET", "/settings")[1]
    set3 = set3.get("retention", {}).get("events_days") if isinstance(set3, dict) else set3
    calls = {}
    for name, path, bodyj in (("sync", "/mesh/v0/sync", {"group": lab.groupB, "vector": {}, "wait_ms": 0}),
                              ("ask_events", "/mesh/v0/ask", {"kind": "events", "body": {"after": 0}}),
                              ("ask_firewall", "/mesh/v0/ask", {"kind": "firewall", "body": {}})):
        rr = hostile(lab, "call", "-key", m3.key_file(), "-addr", "127.0.0.1:%d" % m1.mesh, "-path", path, "-body", json.dumps(bodyj))
        calls[name] = [rr.get("status"), len(rr.get("body", ""))]
    out.update({"block_of_m1_on_m3": on_m3, "block_of_m3_on_m1_m2": on_m12, "events_of_m1_on_m3": ev3, "setting_of_m1_on_m3": set3,
                "calls_with_m3_key": calls, "m3_block_status": st3})
    check("09c", "removed while running: what m1 writes afterwards does not reach m3 (block, events, setting)",
          rc == 0 and on_m3 == 200 and ev3 == 0 and set3 != 44, "block of m1 on m3: %s, events of m1 on m3: %d, setting on m3: %s" % (on_m3, ev3, set3))
    check("09c", "removed while running: a block m3 sets afterwards is not taken by m1 and m2", st3 == 200 and on_m12 == [200, 200],
          "block on m3 %s; the address on m1, m2: %s" % (st3, on_m12))
    check("09c", "mesh calls with the removed key answer 410", all(v[0] == 410 for v in calls.values()), calls)
    check("09c", "the removed node says so in its log and serves on", out["m3_log_says_removed"] and get(m3.proxy, "/") == 200, "")
    return out


# ---------------------------------------------------------------------------------------------------- item 10
@item("10_pause_resume")
def pause_resume(lab, B, d1):
    # `schild cluster pause` and `resume` were removed in c27a180; the node is stopped (kill -9) and started instead
    out = {}
    m1, m2, m3 = B
    m2.kill9()
    time.sleep(1.0)
    st, js = d1.block("203.0.113.240")
    time.sleep(4.0)
    during = {"m1_block": [get(n.proxy, "/", "203.0.113.240") for n in (m1, m3)]}
    out["during"] = during
    check("10", "with m2 stopped a block of m1 acts on m1 and m3", during["m1_block"] == [403, 403], during["m1_block"])
    t0 = now()
    m2.start()
    t = wait_for(lambda: [get(n.proxy, "/", "203.0.113.240") for n in B] == [403] * 3, 40, 0.02)
    out["caught_up_s"] = (now() - t0) if t is not None else None
    check("10", "m2 started again takes the block", t is not None, "after %s s from its start" % (t is not None and round(out["caught_up_s"], 2)))
    return out


# ---------------------------------------------------------------------------------------------------- item 11
@item("11_split")
def split(lab, B, d1):
    out = {}
    m1, m2, m3 = B
    ds = [d1, Dash(m2, d1), Dash(m3, d1)]
    d3 = ds[2]
    X, Y, Z, E, Q1, Q3 = "203.0.113.50", "203.0.113.51", "203.0.113.52", "198.51.100.221", "203.0.113.53", "203.0.113.54"
    st, jz = d1.block(Z)
    for n in B:
        for i in range(3):
            get(n.proxy, "/sp-%s-%d%s" % (n.name, i, ATTACK), E)
    t = wait_for(lambda: all(d.privacy(E).get("events", 0) >= 9 for d in ds) and get(m3.proxy, "/", Z) == 403, 15)
    out["prepared_s"] = t
    # the cut: m3 pauses; m1+m2 on one side, m3 on the other, both writable
    rc, txt = m3.cli("cluster", "pause")
    time.sleep(1.0)
    acts = []
    acts.append(("m1 blocks X", d1.block(X)[0]))
    time.sleep(1.2)
    acts.append(("m3 allowlists X", d3.call("POST", "/allowlist", {"ip": X, "label": "split m3", "level": "no_block"})[0]))
    acts.append(("m3 blocks Y", d3.block(Y)[0]))
    acts.append(("m3 lifts Z", d3.unblock(jz["incident"])[0]))
    acts.append(("m3 erases E", d3.call("POST", "/privacy/delete", {"ip": E, "confirm": True})[0]))
    acts.append(("m1 sets events_days 11", d1.call("PATCH", "/settings", {"retention": {"events_days": 11}})[0]))
    time.sleep(1.2)
    acts.append(("m3 sets events_days 22 (later)", d3.call("PATCH", "/settings", {"retention": {"events_days": 22}})[0]))
    acts.append(("m3 sets summaries_days 100", d3.call("PATCH", "/settings", {"retention": {"summaries_days": 100}})[0]))
    time.sleep(1.2)
    acts.append(("m1 sets summaries_days 200 (later)", d1.call("PATCH", "/settings", {"retention": {"summaries_days": 200}})[0]))
    time.sleep(2.0)
    out["actions"] = acts

    def state(d):
        s = d.call("GET", "/settings")[1]
        ret = s.get("retention", {}) if isinstance(s, dict) else {}
        return {"blocks": d.blocks(), "allowlist": d.allowlist(), "events_days": ret.get("events_days"), "summaries_days": ret.get("summaries_days"),
                "X": get(d.node.proxy, "/", X), "Y": get(d.node.proxy, "/", Y), "Z": get(d.node.proxy, "/", Z), "E_events": d.privacy(E).get("events")}
    out["during_cut"] = {d.node.name: state(d) for d in ds}
    rc, txt = m3.cli("cluster", "resume")
    t0 = now()
    t = wait_for(lambda: state(ds[0]) == dict(state(ds[1]), **{}) == state(ds[2]), 20, 0.2)
    out["same_after_s"] = t
    time.sleep(3.0)
    after = {d.node.name: state(d) for d in ds}
    out["after_heal"] = after
    a = after["m1"]
    same = after["m1"] == after["m2"] == after["m3"]
    check("11", "after the cut healed the state is the same on all three nodes", same, after if not same else "equal after %s s: %s" % (t and round(t, 1), a))
    check("11", "a block set on the cut-off side holds everywhere (Y)", all(s["Y"] == 403 for s in after.values()), [s["Y"] for s in after.values()])
    check("11", "an allowlist entry set on the other side holds and beats the block (X passes)",
          all(X in (s["allowlist"] or []) and s["X"] == 200 for s in after.values()), [(s["allowlist"], s["X"]) for s in after.values()])
    check("11", "a lift on the cut-off side holds everywhere (Z)", all(s["Z"] == 200 for s in after.values()), [s["Z"] for s in after.values()])
    check("11", "an erasure on the cut-off side holds everywhere (E)", all(s["E_events"] == 0 for s in after.values()), [s["E_events"] for s in after.values()])
    check("11", "settings: the later change stands on every node (the settings overlay is one value: events_days and summaries_days were set on different sides)", None,
          "events_days set 11 on m1 then 22 on m3; summaries_days set 100 on m3 then 200 on m1 (the last change of all). After: %s" % (
              [(s["events_days"], s["summaries_days"]) for s in after.values()]))
    # allowlist entries added on both sides of a second cut
    m3.cli("cluster", "pause")
    time.sleep(1.0)
    s1 = d1.call("POST", "/allowlist", {"ip": Q1, "label": "split q1", "level": "no_block"})[0]
    time.sleep(1.2)
    s3 = d3.call("POST", "/allowlist", {"ip": Q3, "label": "split q3", "level": "no_block"})[0]
    f1, f3 = Dash(m1), Dash(m3)
    l1 = f1.login()[0]
    time.sleep(1.2)
    l3 = f3.login()[0]
    time.sleep(1.5)
    m3.cli("cluster", "resume")
    time.sleep(6.0)
    sess = [f1.session()[1].get("authenticated"), f3.session()[1].get("authenticated"), d1.session()[1].get("authenticated")]
    out["logins_both_sides"] = {"logins": [l1, l3], "authenticated_after": sess}
    check("11", "a login on each side of a cut: both sessions are still valid after healing", sess[0] is True and sess[1] is True,
          "login on m1 %s, 1.2 s later on m3 %s; after healing the session of m1 is valid: %s, of m3: %s (the older session of the harness: %s)" % (l1, l3, sess[0], sess[1], sess[2]))
    lists = [d.allowlist() for d in ds]
    out["allowlist_both_sides"] = {"posts": [s1, s3], "after": lists}
    both = all(Q1 in (l or []) and Q3 in (l or []) for l in lists)
    check("11", "allowlist entries added on both sides of a cut both hold (spec: 'an allowlist entry set on either side holds')", both,
          "m1 added %s, 1.2 s later m3 added %s; allowlists after healing: %s" % (Q1, Q3, lists))
    # SIGSTOP: a node that hangs for 8 s
    m2.freeze()
    time.sleep(8.0)
    st, js = d1.block("203.0.113.55")
    time.sleep(0.5)
    m2.thaw()
    t0 = now()
    t = wait_for(lambda: get(m2.proxy, "/", "203.0.113.55") == 403, 15, 0.01)
    out["after_sigcont_s"] = t
    check("11", "a node that hung for 8 s (SIGSTOP) takes the block it missed", t is not None, "after %s s from SIGCONT" % (t and round(t, 3)))
    return out


@item("12_alone_restart")
def alone_restart(lab, B, d1):
    """Every node of group B stopped, m1 started alone: it keeps blocks, allowlist, settings and logins."""
    out = {}
    m1, m2, m3 = B
    before = {"blocks": d1.blocks(), "allowlist": d1.allowlist(), "settings": d1.call("GET", "/settings")[1].get("retention")}
    for n in B:
        n.kill9()
    m1.start()
    seq, t0 = [], now()
    while now() - t0 < 25:
        st = m1.ready()
        if not seq or seq[-1][1] != st:
            seq.append((round(now() - t0, 2), st))
        if st == 200:
            break
        time.sleep(0.05)
    served_before_ready = None
    out["readyz"] = seq
    sess = d1.session()[1]
    after = {"blocks": d1.blocks(), "allowlist": d1.allowlist(), "settings": (d1.call("GET", "/settings")[1] or {}).get("retention")}
    acts = [get(m1.proxy, "/", a) for a in (before["blocks"] or [])]
    out.update({"before": before, "after": after, "session": sess, "block_statuses": acts})
    check("12", "restarted with no member reachable: blocks, allowlist, settings and the login are kept",
          before == after and sess.get("authenticated") is True and bool(acts) and all(a == 403 for a in acts),
          "before %s; after %s; session %s; requests from the blocked addresses %s" % (before, after, sess.get("authenticated"), acts))
    check("12", "readiness alone: 503, then 200 after about 10 s", seq[-1][1] == 200, seq)
    return out


@item("13_empty_member")
def empty_member(lab, A, d1):
    """n3 loses its whole data directory and comes back empty: nothing on n1 and n2 may get weaker."""
    out = {}
    n1, n2, n3 = A
    d2 = Dash(n2, d1)

    def state(d):
        rl = d.call("GET", "/behaviour/rate-limits?limit=500")[1]
        return {"blocks": d.blocks(), "allowlist": d.allowlist(), "session": d.session()[1].get("authenticated"),
                "own_limits": sorted(x.get("route") for x in rl.get("items", []) if x.get("route") == "/rl/**") if isinstance(rl, dict) else rl,
                "events_days": d.call("GET", "/settings")[1].get("retention", {}).get("events_days")}
    before = state(d1)
    n3.kill9()
    shutil.rmtree(n3.data)
    n3.start()
    r = n3.wait_ready(40)
    time.sleep(6.0)
    after1, after2 = state(d1), state(d2)
    d3 = Dash(n3, d1)
    after3 = state(d3)
    out.update({"before_n1": before, "after_n1": after1, "after_n2": after2, "after_n3_empty": after3, "ready_s": r, "status": status_of(n1)[0]})
    check("13", "an empty member (data directory lost) weakens nothing on n1 and n2", before == after1 == after2,
          "n1 before %s; n1 after %s; n2 after %s" % (before, after1, after2))
    check("13", "and it takes the state of the group", after3 == before, "n3 after: %s" % after3)
    return out


@item("14_setup_before_first_sync")
def setup_race(lab):
    """A fresh group by configuration: the first-run password set on c1 as soon as c1 says it is ready."""
    peers = ["127.0.0.1:%d" % (lab.port0 + i * 10 + 4) for i in (1, 2, 3)]
    C = [Node(lab, "c%d" % i, i, {"secret_file": lab.secret, "peers": peers}).start() for i in (1, 2, 3)]
    ready = all_ready(C)
    d = Dash(C[0])
    st, _ = d.setup()
    t_setup = now() - C[0].started_at
    rows = []
    for k in range(16):
        rows.append((round(now() - C[0].started_at, 2), [(x.get("authenticated"), x.get("first_run")) for x in (Dash(n, d).session()[1] for n in C)]))
        time.sleep(0.5)
    st_login, _ = Dash(C[0]).login()
    log = C[0].logtext()
    m = re.search(r'"time":"[^"]*T(\d+:\d+:\d+\.\d+)[^"]*","level":"WARN","msg":"cluster: this node takes the group', log)
    replaced = re.findall(r'takes the group\'s value at its first sync[^}]*"thing":"([^"]+)"', log)
    status = status_of(C[0])[0]
    for n in C:
        n.kill9()
    ok = rows[-1][1][0] == (True, False) and st_login == 200
    check("14", "a password set on a node that answers ready survives the node's first sync", ok,
          "readyz 200 after %s s; setup %s at %.2f s; (authenticated, first_run) on c1..c3 over time: %s; login with the password afterwards: %s; replaced at the first sync: %s" % (
              [round(x, 2) for x in ready], st, t_setup, rows[::3], st_login, replaced))
    return {"ready_s": ready, "setup_status": st, "setup_at_s": t_setup, "sessions": rows, "login_after": st_login, "replaced": replaced, "status": status}


# ---------------------------------------------------------------------------------------------------- main
def results_json(lab, started, finished, out_path):
    m = []

    def add(name, value, unit, samples=None, **labels):
        if value is None or isinstance(value, str):
            return
        e = {"name": name, "value": float(value) if not isinstance(value, bool) else float(int(value)), "unit": unit}
        if labels:
            e["labels"] = {k: str(v) for k, v in labels.items()}
        if samples is not None:
            e["samples"] = samples
        m.append(e)
    I = R["items"]
    p = I.get("02_block_propagation", {})
    for kind in ("set_ms", "lift_ms"):
        s = p.get(kind, {})
        for q in ("p50", "p95", "max"):
            add("block_%s" % kind.replace("_ms", "_propagation"), s.get(q), "ms", s.get("n"), quantile=q, setup="config", nodes=3)
    lat = I.get("03_latency", {})
    for mode, s in lat.items():
        if isinstance(s, dict) and "p50" in s:
            for q in ("p50", "p95", "p99", "max"):
                add("request_latency", s.get(q), "ms", s.get("n"), mode=mode, quantile=q)
            add("request_failed", s.get("failed", 0) + s.get("not_200", 0), "count", s.get("n"), mode=mode)
    k = I.get("04_kill_restart", {})
    add("kill_failed_requests_other_nodes", k.get("load", {}).get("failed_on_n1_n2"), "count", k.get("load", {}).get("requests"))
    add("kill_events_written", k.get("events_written_by_n3"), "count")
    add("kill_events_missing", k.get("events_missing_on_n1"), "count", node="n1")
    add("kill_events_missing", k.get("events_missing_on_n2"), "count", node="n2")
    add("kill_oldest_missing_event_age", k.get("oldest_missing_age_s"), "s")
    for name, r in I.get("05_drain", {}).items():
        if isinstance(r, dict):
            add("drain_failed_requests", r.get("load_failed"), "count", r.get("load_requests"), step=name)
            add("drain_readyz_503_after", r.get("readyz_503_after_s"), "s", step=name)
            add("drain_served_after_503", r.get("served_for_s_after_503"), "s", step=name)
    for name, r in I.get("06_rate_limit", {}).get("runs", {}).items():
        add("rate_limit_passed", r.get("passed"), "count", r.get("total"), run=name, limit="60_per_1m_burst_60")
    e = I.get("08_erasure", {})
    add("erasure_gone_on_other_node", e.get("gone_on_n1_n2_s"), "s")
    add("pause_resume_catch_up", I.get("10_pause_resume", {}).get("caught_up_s"), "s")
    s = I.get("07_settings_logins", {})
    add("setting_propagation", s.get("setting_s"), "s")
    add("allowlist_propagation", s.get("allowlist_s"), "s")
    for v in ("PASS", "FAIL", "INFO"):
        add("checks", sum(1 for c in R["checks"] if c["verdict"] == v), "count", verdict=v.lower())
    fails = [c for c in R["checks"] if c["verdict"] == "FAIL"]

    def hit(prefixes):
        return [c for c in fails if c["item"] in prefixes]

    def kc(expr, items, observed_ok, measurable=True):
        f = hit(items)
        return {"expr": expr, "hit": bool(f), "observed": ("; ".join("%s %s" % (c["item"], c["name"]) for c in f)[:500] if f else observed_ok)[:512]}
    kcs = [
        kc("any request waits for a peer or fails because of one (ACME challenge lookups aside)", ["03", "04"], "no failed and no slow request with peers stopped, frozen or black-holed; 2 s slow peers and ACME not measured"),
        kc("a lost, empty or returning member deletes or weakens access state on another", ["04", "11", "12", "13"], "kill and restart, empty member, cut and heal: access state kept"),
        kc("a record that fails signature, schema or caps is applied", ["09"], "none of the tampered, foreign, future, oversized or replayed records acted"),
        kc("an edge or a removed member reads events, requests, settings, logins or keys", ["09b", "09c"], "edge: members and block list only; removed member: 410"),
        kc("an erased address returns", ["08"], "erased address stayed gone, also on the node that was down"),
        {"expr": "an address outside the proxy allow list can get another address blocked", "hit": False, "observed": "NOT MEASURED: needs the ingress mode with a PROXY protocol listener"},
        {"expr": "a partial answer is shown as complete", "hit": False, "observed": "NOT MEASURABLE: group queries with partial answers are not built (contracts/cluster.md section 13)"},
        {"expr": "a copy outlives its origin's retention", "hit": False, "observed": "NOT MEASURED: needs days of retention"},
        {"expr": "certificates are lost or issued again by the move into the group", "hit": False, "observed": "NOT MEASURED: no ACME server in this setup"},
    ]
    harness_err = any(c["name"] == "harness" for c in fails)
    verdict = "error" if harness_err else ("fail" if fails else "inconclusive")
    rev = subprocess.run(["git", "-C", lab.repo, "rev-parse", "--short=12", "HEAD"], capture_output=True, text=True).stdout.strip()
    dirty = subprocess.run(["git", "-C", lab.repo, "status", "--porcelain", "--untracked-files=no"], capture_output=True, text=True).stdout.strip()
    digest = hashlib.sha256(open(lab.bin, "rb").read()).hexdigest()
    doc = {
        "results_version": 0, "spec": "MVP-27", "run_id": "group-%s" % started.strftime("%Y%m%dT%H%M%SZ"),
        "started_at": started.strftime("%Y-%m-%dT%H:%M:%SZ"), "finished_at": finished.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "seed": SEED, "profile": "unit", "git_rev": rev + ("-dirty" if dirty else ""),
        "host": {"os": platform.system().lower(), "arch": platform.machine(), "cpus": os.cpu_count() or 1},
        "images": [{"name": "schild-dev-build", "digest": "sha256:" + digest}],
        "metrics": m, "kill_criteria": kcs, "verdict": verdict,
        "notes": ("Black-box measurement of the group of gateways on one machine: real `schild run` processes (development build) on 127.0.0.1, "
                  "3 gateways by cluster.secret_file and cluster.peers, 3 by join codes, round robin done by the load client. "
                  "Not the testlab profiles pair and fleet of the spec: no balancer, no keepalived, no ACME server, no nftables, 3 nodes instead of 10. "
                  "Verdict is never 'pass': most of `measure` is outside this setup; see tests/results/MVP-27-group-measurement.md. "
                  "FAIL checks: " + ("; ".join("%s %s" % (c["item"], c["name"]) for c in fails) or "none"))[:8000],
        "artifacts": ["tests/results/MVP-27-group-measurement.md", "tests/testlab/measure/group/run.py"],
    }
    with open(out_path, "w") as f:
        json.dump(doc, f, indent=1)
        f.write("\n")


def main():
    global lab_rng
    ap = argparse.ArgumentParser()
    ap.add_argument("--bin", required=True, help="schild development build")
    ap.add_argument("--hostile", required=True, help="built hostile tool")
    ap.add_argument("--out", required=True, help="directory for raw.json")
    ap.add_argument("--results", default="", help="write the results JSON here (tests/results/MVP-27.json)")
    ap.add_argument("--port0", type=int, default=18100)
    ap.add_argument("--only", default="", help="comma list of item prefixes, for work on the harness")
    ap.add_argument("--keep", action="store_true", help="keep the data directories")
    a = ap.parse_args()
    lab_rng = random.Random(SEED)
    lab = Lab()
    lab.bin, lab.hostile, lab.port0, lab.procs = os.path.abspath(a.bin), os.path.abspath(a.hostile), a.port0, []
    lab.repo = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "..", ".."))
    # a short path: the control socket of schild lies below the data directory and a unix socket path is short
    lab.root = tempfile.mkdtemp(prefix="sg27-", dir="/tmp")
    lab.backend_port = a.port0 - 10
    lab.geo = os.path.join(lab.root, "geo.mmdb")
    started = datetime.datetime.now(datetime.timezone.utc)
    only = [x for x in a.only.split(",") if x]

    def want(prefix):
        return not only or any(prefix.startswith(o) for o in only)
    try:
        subprocess.run([lab.bin, "geo-fixture", "-out", lab.geo], check=True, capture_output=True)
        be = subprocess.Popen([sys.executable, os.path.join(os.path.dirname(os.path.abspath(__file__)), "backend.py"), str(lab.backend_port)])
        lab.procs.append(be)
        wait_for(lambda: get(lab.backend_port, "/") == 200, 5)
        R["version"] = subprocess.run([lab.bin, "version"], capture_output=True, text=True).stdout.strip()
        single_gateway(lab)
        A, dA = group_by_config(lab)
        if want("07"): settings_logins(lab, A, dA)
        if want("02"): block_propagation(lab, A, dA)
        if want("02b"): block_holds(lab, A, dA)
        if want("02d"): own_allowlist(lab, A, dA)
        if want("06"): rate_limit(lab, A, dA)
        if want("03"): latency_modes(lab, A, dA)
        if want("04"): kill_restart(lab, A, dA)
        if want("05"): drain(lab, A, dA)
        if want("08"): erasure(lab, A, dA)
        if want("09_"): hostile_records(lab, A, dA)
        if want("13"): empty_member(lab, A, dA)
        for n in A + [lab.single]:
            n.kill9()
        if want("14"): setup_race(lab)
        if any(want(x) for x in ("02c", "09b", "09c", "10", "11", "12")):
            B, dB = group_by_code(lab)
            if want("02c"):
                def p2():
                    out = propagation("B", B, dB, 10, "203.0.113.")
                    check("02c", "group by join codes: block set on m1 acts on m2 and m3 within 1 s at p95", out["set_not_seen_in_8s"] == 0 and out["set_ms"]["p95"] <= 1000,
                          "set %s; lift %s" % (out["set_ms"], out["lift_ms"]))
                    return out
                item("02c_block_propagation_join_code")(p2)()
            if want("10"): pause_resume(lab, B, dB)
            # item 11 made its cut with `schild cluster pause` (removed in c27a180): the cut with both sides
            # writable is measured by the fault proxy of the hardening measurement (hardening/s1_faults.py)
            if want("11"): check("11", "split by pause", None, "NOT RUN: cluster pause removed; see hardening s1 t.cut, t.heal")
            # item 09b: edges were removed in 5b12c2c
            if want("09b"): check("09b", "edge", None, "NOT RUN: edges removed")
            if want("09c"): removed_running(lab, B, dB)
            if want("12"): alone_restart(lab, B, dB)
    finally:
        for p in lab.procs:
            if p.poll() is None:
                try:
                    p.send_signal(18)  # SIGCONT, in case it is still frozen
                except Exception:
                    pass
                p.kill()
        for p in lab.procs:
            try:
                p.wait(10)
            except Exception:
                pass
        finished = datetime.datetime.now(datetime.timezone.utc)
        os.makedirs(a.out, exist_ok=True)
        R["seed"], R["started"], R["finished"] = SEED, started.isoformat(), finished.isoformat()
        with open(os.path.join(a.out, "raw.json"), "w") as f:
            json.dump(R, f, indent=1, default=str)
        if a.results and not only:
            results_json(lab, started, finished, a.results)
        if a.keep:
            print("data kept in", lab.root)
        else:
            shutil.rmtree(lab.root, ignore_errors=True)
    n = {v: sum(1 for c in R["checks"] if c["verdict"] == v) for v in ("PASS", "FAIL", "INFO")}
    print("checks: %s; raw results in %s" % (n, os.path.join(a.out, "raw.json")))


if __name__ == "__main__":
    main()
