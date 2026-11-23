"""Scenario 8: what changed between 11eced1 and the tree before the release (fourth run). Each check is judged
against a sentence of docs/gateway/03-cluster.md or contracts/cluster.md, quoted in the check's name or detail.

  a  start refused: missing secret file, mode 0644 and 0660, a short secret, the mesh port taken, enabled without
     secret_file; accepted: 0640 and 0440
  b  a brand-new group of three: nobody ready while one named peer never started; all ready once it starts
  c  two fresh nodes added while the one established member is down: not ready with empty state; ready with its
     blocks once it is back
  d  the clock rule by majority: five gateways with one 120 s off, then one more 6 s off; two against two; a pair
  e  `schild cluster remove` of a member whose clock is 30 s ahead and which just wrote, or writes all the time
  f  a stranger at the mesh (hello, sync) and a fake 410 from a non-member: at an extra address of cluster.peers
     and at the address of a stopped member
  g  drain under load: SIGTERM and `schild cluster drain`, with the load tool acting as a balancer
  h  regression: blocks and lifts, settings, logins, a short outage, the state hashes when quiet and under changes
  i  a node away longer than 30 days, by the mark the contract names (cluster.db, in_step_at), set back by hand
"""
import http.client
import json
import os
import random
import re
import shutil
import socket
import sqlite3
import subprocess
import threading
import time

from hard import (SEED, Dash, HNode, acts, first_setup, group, gstatus, hget, load_start, load_wait, member_states, metric, now,
                  short_load, snapshot, wait_for, wait_group, wait_same, diff_snaps)


def ready_of(n):
    return n.ready() if n.alive() else 0


def reasons(d):
    st, js = d.call("GET", "/overview")
    if st != 200 or not isinstance(js, dict):
        return ["overview %s" % st]
    return sorted(r.get("code") for r in (js.get("baseline") or {}).get("reasons", []))


def timeline(nodes, seconds, gap=0.25):
    """readyz of every node every `gap` seconds for `seconds`: {name: [(t, status)]} with only the changes."""
    t0, out, last = now(), {n.name: [] for n in nodes}, {}
    while now() - t0 < seconds:
        for n in nodes:
            st = ready_of(n)
            if last.get(n.name) != st:
                out[n.name].append((round(now() - t0, 2), st))
                last[n.name] = st
        time.sleep(gap)
    return out


def shim_env(lab, ms):
    if not ms:
        return None
    return {"DYLD_INSERT_LIBRARIES": lab.extra_bins["clock_shim"], "SG27H_CLOCK_OFFSET_MS": str(ms)}


def restart(lab, n, ms=0):
    n.kill9()
    n.start(env=shim_env(lab, ms))


def stop_all(nodes):
    for n in nodes:
        n.kill9()


def fresh_secret(lab):
    """Each part is a group of its own: the next lab.secret() makes a new secret file."""
    p = os.path.join(lab.root, "cluster.secret")
    if os.path.exists(p):
        os.rename(p, p + ".%d" % int(time.time() * 1000))


def self_id(d):
    return next((m["id"] for m in gstatus(d).get("members", []) if m.get("state") == "self"), None)


def state_by_id(d, nid):
    return next((m["state"] for m in gstatus(d).get("members", []) if m.get("id") == nid), None)


def idx_peers(lab, idx):
    return ["127.0.0.1:%d" % (lab.port0 + i * 10 + 4) for i in idx]


# ------------------------------------------------------------------------------------------------------------ a
def start_refused(lab):
    out = lab.data.setdefault("a", {})
    sec = open(lab.secret()).read()
    cases = [
        ("missing", "the secret file is missing", None, r"secret"),
        ("0644", "the secret file may be read by others (0644)", 0o644, r"0644|mode|chmod|read"),
        ("0660", "the group may write the secret file (0660)", 0o660, r"0660|mode|chmod|writ"),
        ("short", "the secret is shorter than 32 bytes", 0o600, r"short|32|length"),
        ("port", "the port of cluster.listen is taken", 0o600, r"in use|already|bind|listen"),
        ("nosecretfile", "cluster.enabled without cluster.secret_file", 0o600, r"secret_file"),
        ("0640", "a secret file 0640 (owner and group read) is accepted", 0o640, None),
        ("0440", "a secret file 0440 is accepted", 0o440, None),
    ]
    for k, (key, what, mode, pattern) in enumerate(cases):
        idx = 1 + k
        path = os.path.join(lab.root, "secret-%s" % key)
        if key != "missing":
            with open(path, "w") as f:
                f.write("tooshort\n" if key == "short" else sec)
            os.chmod(path, mode)
        n = HNode(lab, "a%d" % idx, idx, {"secret_file": path, "peers": idx_peers(lab, [idx])})
        if key == "nosecretfile":
            with open(n.cfg) as f:
                y = [l for l in f.read().splitlines() if "secret_file" not in l]
            with open(n.cfg, "w") as f:
                f.write("\n".join(y) + "\n")
        hold = None
        if key == "port":
            hold = socket.socket()
            hold.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            hold.bind(("127.0.0.1", n.mesh))
            hold.listen(1)
        t0 = now()
        n.start()
        r = None
        if pattern is None:
            r = n.wait_ready(30)
            time.sleep(1.0)
        exited = n.wait_exit(1 if pattern is None else 30)
        took = round(now() - t0, 2)
        rc = n.proc.returncode if exited else None
        tail = [l[-300:] for l in n.loglines(r"^schild: |\"level\":\"ERROR\"|[Rr]efus|[Ff]atal")][-3:]
        if hold:
            hold.close()
        row = {"exited": exited, "exit_code": rc, "seconds": took, "log": tail}
        if pattern is None:
            row["ready_s"] = r and round(r, 2)
            lab.check("a." + key, what + " (guide: 'Lesen darf er sie als Besitzer oder über seine Gruppe', chmod 0640)",
                      not exited and r is not None, "process %s, readyz 200 after %s s; error lines %s" % ("runs" if not exited else "exited %s" % rc, row["ready_s"], tail))
        else:
            named = any(re.search(pattern, l, re.I) for l in tail)
            row["names_cause"] = named
            lab.check("a." + key, "start refused: %s (guide: 'bricht der Start ab. Das Log nennt den Grund')" % what,
                      exited and rc not in (0, None) and named,
                      "exit %s after %s s; a log line names the cause (/%s/): %s; %s" % (rc, took, pattern, named, tail))
        out[key] = row
        n.kill9()


# ------------------------------------------------------------------------------------------------------------ b
def brand_new(lab):
    out = lab.data.setdefault("b", {})
    nodes = group(lab, ["b1", "b2", "b3"], idx0=10, start=False)
    b1, b2, b3 = nodes
    b1.start()
    b2.start()
    tl = timeline([b1, b2], 25)
    out["before_b3"] = tl
    never = all(all(st != 200 for _, st in tl[n.name]) for n in (b1, b2))
    lab.check("b.wait", "a brand-new group of three: b1 and b2 answer no 200 while b3, named in cluster.peers, never started (guide: 'Ein ganz neuer Cluster wird erst bereit, wenn jeder Server aus cluster.peers einmal gestartet ist')",
              never, "readyz changes over 25 s: %s" % tl)
    t0 = now()
    b3.start()
    got = {}

    def all_up():
        for n in nodes:
            if n.name not in got and ready_of(n) == 200:
                got[n.name] = round(now() - t0, 2)
        return len(got) == 3
    wait_for(all_up, 60, 0.05)
    out["after_b3_start_s"] = got
    lab.check("b.ready", "all three ready once b3 started", len(got) == 3, "seconds from the start of b3 until readyz 200: %s" % got)
    metric(lab, "brand_new_group_ready_after_last_start", max(got.values()) if len(got) == 3 else None, "s", nodes=3)
    stop_all(nodes)
    # a pair, both started at once
    pair = group(lab, ["b4", "b5"], idx0=13, start=False)
    t0 = now()
    for n in pair:
        n.start()
    r = [n.wait_ready(60) for n in pair]
    out["pair_ready_s"] = [x and round(x, 2) for x in r]
    lab.check("b.pair", "a brand-new pair started together becomes ready", all(r), "readyz 200 after %s s" % out["pair_ready_s"])
    metric(lab, "brand_new_group_ready_after_last_start", max(r) if all(r) else None, "s", nodes=2)
    stop_all(pair)


# ------------------------------------------------------------------------------------------------------------ c
def fresh_while_down(lab):
    out = lab.data.setdefault("c", {})
    sec = lab.secret()
    idx = [16, 17, 18]
    c1 = HNode(lab, "c1", idx[0], {"secret_file": sec, "peers": idx_peers(lab, idx[:1])})
    c1.start()
    r = c1.wait_ready(30)
    ds = first_setup(lab, [c1], cid="c.setup")
    d1 = ds[0]
    X1, X2, AL = "203.0.113.71", "203.0.113.72", "192.0.2.171"
    s = [d1.block(X1)[0], d1.block(X2)[0], d1.call("POST", "/allowlist", {"ip": AL, "label": "c", "level": "no_block"})[0],
         d1.call("PATCH", "/settings", {"retention": {"events_days": 44}})[0]]
    before = snapshot(d1)
    out["c1_alone"] = {"ready_s": r and round(r, 2), "writes": s, "state": before}
    c1.term()
    c1.wait_exit(30)
    c1.cluster["peers"] = idx_peers(lab, idx)
    c1.write_config()
    c2 = HNode(lab, "c2", idx[1], {"secret_file": sec, "peers": idx_peers(lab, idx)})
    c3 = HNode(lab, "c3", idx[2], {"secret_file": sec, "peers": idx_peers(lab, idx)})
    c2.start()
    c3.start()
    tl = timeline([c2, c3], 25)
    out["while_c1_down"] = tl
    lab.check("c.wait", "two fresh nodes started while the only established member is down answer no 200 (contract 10: 'Two nodes neither of which was ever in step do not make each other in step with nothing')",
              all(all(st != 200 for _, st in tl[n.name]) for n in (c2, c3)), "readyz changes over 25 s: %s" % tl, kill="weakens")
    t0 = now()
    c1.start()
    first = {}

    def watch():
        for n in (c2, c3):
            if n.name not in first and ready_of(n) == 200:
                first[n.name] = (round(now() - t0, 2), hget(n.proxy, "/", X1), hget(n.proxy, "/", X2))
        return len(first) == 2
    wait_for(watch, 60, 0.02)
    out["after_c1_back"] = first
    lab.check("c.back", "once c1 is back both become ready, and at their first 200 they hold its blocks (403 for both addresses)",
              len(first) == 2 and all(v[1] == 403 and v[2] == 403 for v in first.values()),
              "seconds from c1's start to readyz 200, answers to the two blocked addresses at that moment: %s" % first, kill="weakens")
    ds3 = [d1, Dash(c2, d1), Dash(c3, d1)]
    t, snaps = wait_same(ds3, 15)
    lab.check("c.back", "and then hold c1's state: blocks, allowlist, settings, the login", t is not None and snaps[0] == before and all(bool(d.session()[1].get("authenticated")) for d in ds3),
              "%s; equal to c1 before: %s" % (diff_snaps(["c1", "c2", "c3"], snaps), snaps[0] == before))
    stop_all([c1, c2, c3])


# ------------------------------------------------------------------------------------------------------------ d
def clock_rule(lab):
    out = lab.data.setdefault("d", {})
    names = ["d1", "d2", "d3", "d4", "d5"]
    nodes = group(lab, names, idx0=20)
    wait_group(lab, nodes, cid="d.setup")
    ds = first_setup(lab, nodes, cid="d.setup")
    d1n, d2n, d3n, d4n, d5n = nodes
    dmap = dict(zip(names, ds))

    def look(sel, seconds, gap=1.0):
        """readyz and the clock reason of every selected node, every `gap` s; answers the rows."""
        rows, t0 = [], now()
        while now() - t0 < seconds:
            row = {"t": round(now() - t0, 1)}
            for n in sel:
                row[n.name] = (ready_of(n), "cluster_clock_out_of_service" in reasons(dmap[n.name]))
            rows.append(row)
            time.sleep(gap)
        return rows

    def summary(rows, sel):
        return {n.name: {"503": sum(1 for r in rows if r[n.name][0] != 200), "clock_reason": sum(1 for r in rows if r[n.name][1]),
                         "last": rows[-1][n.name]} for n in sel}

    # d.1 five gateways, d5 120 s ahead
    t0 = now()
    restart(lab, d5n, 120000)
    first_out = wait_for(lambda: ready_of(d5n) != 200 and "cluster_clock_out_of_service" in reasons(dmap["d5"]) and d5n.alive(), 40, 0.25)
    rows = look(nodes, 12)
    st = d5n.cli("cluster", "status")[1]
    clock_lines = [l[-220:] for l in d5n.loglines(r"(?i)clock")][-2:]
    sm = summary(rows, nodes)
    out["five_one_120"] = {"left_after_s": first_out and round(first_out, 2), "rows": rows, "summary": sm,
                           "status_clock_lines": [l for l in st.splitlines() if re.search(r"(?i)clock|time", l)][:4], "log": clock_lines}
    lab.check("d.five", "five gateways, d5 120 s ahead: d5 leaves traffic (readyz 503) with the reason cluster_clock_out_of_service (contract 8a, guide 'Ein Server mit falscher Uhr nimmt keine Anfragen mehr an')",
              first_out is not None and sm["d5"]["last"] == (503, True) and sm["d5"]["503"] == len(rows),
              "left %s s after its restart; per node over 12 s (polls not 200, polls with the reason, last): %s; status lines %s; log %s" % (
                  first_out and round(first_out, 2), sm, out["five_one_120"]["status_clock_lines"], clock_lines))
    lab.check("d.five", "and the four others stay in traffic", all(sm[n]["503"] == 0 and sm[n]["clock_reason"] == 0 for n in names[:4]), sm)
    # d.2 d4 6 s ahead as well
    restart(lab, d4n, 6000)
    r4 = d4n.wait_ready(40)
    rows = look(nodes, 15)
    sm = summary(rows, nodes)
    out["five_one_120_one_6"] = {"d4_ready_s": r4 and round(r4, 2), "rows": rows, "summary": sm}
    lab.check("d.five6", "with d4 6 s ahead at the same time, d5 (120 s) still stays out (contract 8a: 'with five gateways, three that agree suffice')",
              sm["d5"]["503"] == len(rows) and sm["d5"]["clock_reason"] == len(rows), sm)
    lab.check("d.five6", "and d4 (6 s) and the three others stay in traffic", r4 is not None and all(sm[n]["503"] == 0 and sm[n]["clock_reason"] == 0 for n in names[:4]),
              "d4 ready after %s s; %s" % (r4 and round(r4, 2), sm))
    # back to the right time: d5 returns
    restart(lab, d4n, 0)
    t0 = now()
    restart(lab, d5n, 0)
    r5 = d5n.wait_ready(40)
    d4n.wait_ready(40)
    out["d5_back_s"] = r5 and round(r5, 2)
    lab.check("d.back", "d5 restarted with the right clock answers ready again", r5 is not None, "after %s s" % out["d5_back_s"])
    # d.3 four gateways, two against two: d5 stopped, d3 and d4 120 s ahead
    d5n.kill9()
    restart(lab, d3n, 120000)
    restart(lab, d4n, 120000)
    time.sleep(3.0)
    sel = nodes[:4]
    rows = look(sel, 25)
    sm = summary(rows, sel)
    out["four_two_two"] = {"rows": rows, "summary": sm}
    lab.check("d.twotwo", "four gateways, two 120 s ahead of the other two: nobody leaves by the clock rule (contract 8a: 'two against two ... no node leaves')",
              all(sm[n.name]["clock_reason"] == 0 for n in sel), sm)
    lab.check("d.twotwo", "and all four answer ready", all(sm[n.name]["503"] == 0 for n in sel),
              "polls not 200 per node over 25 s: %s" % {k: v["503"] for k, v in sm.items()})
    # d.4 two gateways: d3, d4 stopped; d2 120 s ahead
    d3n.kill9()
    d4n.kill9()
    restart(lab, d2n, 120000)
    time.sleep(3.0)
    sel = nodes[:2]
    rows = look(sel, 25)
    sm = summary(rows, sel)
    out["two"] = {"rows": rows, "summary": sm}
    lab.check("d.two", "two gateways in view, one 120 s ahead: nobody leaves (guide: 'Bei nur zwei Servern ... bedienen beide weiter')",
              all(sm[n.name]["clock_reason"] == 0 and sm[n.name]["503"] == 0 for n in sel), sm)
    # d.5 three gateways: d3 back on the right clock, d2 still 120 s ahead (the measurement the guide quotes: about 4 s)
    restart(lab, d3n, 0)
    t3 = d3n.wait_ready(40)
    t0 = now()
    left = wait_for(lambda: ready_of(d2n) != 200 and "cluster_clock_out_of_service" in reasons(dmap["d2"]), 40, 0.25)
    sel = nodes[:3]
    rows = look(sel, 10)
    sm = summary(rows, sel)
    out["three"] = {"d3_ready_s": t3 and round(t3, 2), "d2_left_after_s": left and round(left, 2), "rows": rows, "summary": sm}
    lab.check("d.three", "three gateways, d2 120 s ahead: d2 leaves traffic with the clock reason, the two others stay (guide: 'In der Messung mit drei Servern dauerte das etwa vier Sekunden')",
              left is not None and sm["d2"]["503"] == len(rows) and all(sm[n]["503"] == 0 for n in ("d1", "d3")),
              "d2 left %s s after d3 was ready; %s" % (left and round(left, 2), sm))
    stop_all(nodes)


# ------------------------------------------------------------------------------------------------------------ e
def remove_ahead(lab):
    out = lab.data.setdefault("e", {})
    names = ["e1", "e2", "e3"]
    nodes = group(lab, names, idx0=26)
    wait_group(lab, nodes, cid="e.setup")
    ds = first_setup(lab, nodes, cid="e.setup")
    e1, e2, e3 = nodes
    d1, d2, d3 = ds

    def judge(tag, what, rc, txt, extra):
        time.sleep(5.0)
        s1, s2 = state_by_id(d1, extra["e3_id"]), state_by_id(d2, extra["e3_id"])
        removed_log = e3.loglines(r"(?i)removed")[-1:]
        probe = "203.0.113.%d" % (90 + len(out))
        st = d3.block(probe)[0]
        later = acts([e1, e2], probe, 403, 4.0)
        row = {"rc": rc, "output": txt[-300:], "e3_on_e1": s1, "e3_on_e2": s2, "e3_log": [l[-200:] for l in removed_log],
               "block_of_e3_afterwards": {"status": st, "acts_on": later}, **extra}
        out[tag] = row
        is_removed = s1 == "removed" and s2 == "removed" and all(v is None for v in later.values())
        still_member = s1 not in ("removed", None) and s2 not in ("removed", None) and all(v is not None for v in later.values())
        ok = (rc == 0 and is_removed) or (rc != 0 and still_member)
        lab.check(tag, "%s: removed, or the command reports an error and e3 stays a member (guide: 'Meldet der Befehl einen Fehler, ist der Server noch Mitglied')" % what, ok,
                  "remove exit %s (%s); e3 as e1 / e2 list it: %s / %s; a block e3 sets 5 s later acts on e1, e2 after %s s; e3's log: %s" % (
                      rc, txt[-160:].replace("\n", " | "), s1, s2, later, row["e3_log"]), kill="reads" if rc == 0 and not is_removed else None)
        return rc == 0 and is_removed

    restart(lab, e3, 30000)
    r = e3.wait_ready(40)
    out["e3_ready_s"] = r and round(r, 2)
    e3id = self_id(d3)
    st = d3.block("203.0.113.81")[0]
    rc, txt = e1.cli("cluster", "remove", "e3")
    judge("e.once", "`schild cluster remove e3` on e1 right after e3 (clock 30 s ahead) wrote a block", rc, txt, {"write": st, "e3_id": e3id})
    # a removed node back as a new one (guide: delete its cluster directory), then remove while it writes all the time
    e3.kill9()
    shutil.rmtree(os.path.join(e3.data, "cluster"), ignore_errors=True)
    e3.start(env=shim_env(lab, 30000))
    r = e3.wait_ready(40)
    e3id = wait_for(lambda: self_id(d3) not in (None, e3id), 20, 0.3) and self_id(d3)
    t = wait_for(lambda: state_by_id(d1, e3id) == "ok", 20, 0.3)
    lab.check("e.back", "e3 with an empty cluster directory comes back as a new member (guide 'Einen entfernten Server zurückholen')",
              r is not None and t is not None, "ready after %s s; listed ok on e1 after %s s" % (r and round(r, 2), t and round(t, 2)))
    stop = [False]
    writes = []

    def writer():
        k = 0
        while not stop[0]:
            k += 1
            writes.append(d3.block("198.51.100.%d" % (k % 250 + 1))[0])
            time.sleep(0.15)
    th = threading.Thread(target=writer, daemon=True)
    th.start()
    time.sleep(2.0)
    # two members named e3 now (the removed one and the new one): by its id, as the guide says
    rc, txt = e1.cli("cluster", "remove", e3id or "e3")
    time.sleep(1.0)
    stop[0] = True
    th.join(5)
    judge("e.stream", "`schild cluster remove e3` while e3 (clock 30 s ahead) writes a block every 150 ms", rc, txt,
          {"writes": len(writes), "write_statuses": sorted(set(writes)), "e3_id": e3id})
    if rc != 0:
        rc2, txt2 = e1.cli("cluster", "remove", e3id or "e3")
        out["e.stream"]["second_try"] = [rc2, txt2[-200:]]
    stop_all(nodes)


# ------------------------------------------------------------------------------------------------------------ f
def strangers(lab):
    out = lab.data.setdefault("f", {})
    hostile = lab.extra_bins.get("hostile")
    if not hostile or not os.path.exists(hostile):
        lab.check("f", "stranger and fake 410", None, "NOT MEASURED: no hostile tool (--hostile)")
        return
    idx = [30, 31, 32]
    extra_addr = "127.0.0.1:%d" % (lab.port0 + 33 * 10 + 4)
    sec = lab.secret()
    nodes = [HNode(lab, "f%d" % (k + 1), i, {"secret_file": sec, "peers": idx_peers(lab, idx)}) for k, i in enumerate(idx)]
    for n in nodes:
        n.start()
    f1, f2, f3 = nodes
    for n in nodes:
        n.wait_ready(60)
    ds = first_setup(lab, nodes, cid="f.setup")
    # then the deployment names a fourth address no member holds (a new group would wait for it, contract 10)
    for n in nodes:
        n.cluster["peers"] = idx_peers(lab, idx) + [extra_addr]
        n.write_config()
        restart(lab, n)
        n.wait_ready(40)
    d1 = ds[0]
    grp = re.search(r"(g-[0-9a-f]{32})", f1.cli("cluster", "status")[1])
    grp = grp.group(1) if grp else ""

    def call(*args):
        p = subprocess.run([hostile, "call", *args], capture_output=True, text=True, timeout=30)
        try:
            return json.loads(p.stdout)
        except ValueError:
            return {"status": None, "error": (p.stdout + p.stderr)[:200]}

    def counts(d):
        g = gstatus(d)
        return {"members": sorted((m["name"], m["state"]) for m in g.get("members", [])), "shared": g.get("shared"), "state": g.get("state")}

    # f.1 a stranger: hello with a member record of its own, with f2's real member record, sync
    wait_for(lambda: all(gstatus(d).get("state") == "active" for d in ds), 30, 0.5)
    time.sleep(2.0)
    before = [counts(d) for d in ds]
    evil = os.path.join(lab.root, "evil.key")
    with open(evil, "w") as f:
        f.write(random.Random(SEED).randbytes(32).hex() + "\n")
    eid = json.loads(subprocess.run([hostile, "id", "-key", evil], capture_output=True, text=True).stdout)
    import base64
    rec = {"v": 1, "group": grp, "class": "members", "id": eid["id"], "origin": eid["id"], "seq": 1, "hlc": int(time.time() * 1000) << 16,
           "data": base64.b64encode(json.dumps({"name": "evil", "role": "gateway", "public_key": eid["public_key"], "address": "127.0.0.1:1",
                                                "joined": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}).encode()).decode()}
    signed = json.loads(subprocess.run([hostile, "sign", "-key", evil], input=json.dumps(rec), capture_output=True, text=True).stdout)
    calls = {}
    calls["hello own record"] = call("-key", evil, "-addr", "127.0.0.1:%d" % f1.mesh, "-path", "/mesh/v0/hello", "-body", json.dumps({"record": signed}))
    # f2's own member record, as any member hands it over; shown by a key that is not f2's
    sync = call("-key", f2.key_file(), "-addr", "127.0.0.1:%d" % f1.mesh, "-body", json.dumps({"group": grp, "vector": {}, "wait_ms": 0}))
    f2rec = None
    f2id = json.loads(subprocess.run([hostile, "id", "-key", f2.key_file()], capture_output=True, text=True).stdout)["id"]
    try:
        for r in json.loads(sync["body"])["records"]:
            if r["class"] == "members" and r["id"] == f2id:
                f2rec = r
    except Exception:
        pass
    calls["hello f2's record, other key"] = call("-key", evil, "-addr", "127.0.0.1:%d" % f1.mesh, "-path", "/mesh/v0/hello", "-body", json.dumps({"record": f2rec}))
    calls["sync"] = call("-key", evil, "-addr", "127.0.0.1:%d" % f1.mesh, "-body", json.dumps({"group": grp, "vector": {}, "wait_ms": 0}))
    calls["hello no certificate"] = call("-nocert", "-addr", "127.0.0.1:%d" % f1.mesh, "-path", "/mesh/v0/hello", "-body", json.dumps({"record": signed}))
    time.sleep(3.0)
    after = [counts(d) for d in ds]
    short = {k: [v.get("status"), (v.get("body") or v.get("error") or "")[:100]] for k, v in calls.items()}
    out["stranger"] = {"calls": short, "before": before, "after": after, "f2_record_found": f2rec is not None}
    lab.check("f.stranger", "a stranger's hello (its own record, f2's real record under another key, no certificate) and sync: no 200 (contract 7: 'a record that fails is answered 403 ... and leaves nothing behind')",
              all(v.get("status") not in (200, None) for v in calls.values()) and f2rec is not None, short, kill="applied")
    lab.check("f.stranger", "and nothing is stored: the member list and the shared counts are the same before and after on every node",
              before == after and not any("evil" in str(a) for a in after), "before %s; after %s" % (before[0], after[0]), kill="applied")
    # f.2 a fake 410 at an extra address of cluster.peers (no member)
    glog = os.path.join(lab.root, "gone-extra.log")
    gone = subprocess.Popen([hostile, "gone", "-random", "-listen", extra_addr, "-group", grp], stdout=open(glog, "w"), stderr=subprocess.STDOUT)
    lab.procs.append(gone)
    time.sleep(20.0)
    asked = [l for l in open(glog).read().splitlines() if '"answer":410' in l]

    def none_removed(sel, dsel):
        rows = {}
        for n, d in zip(sel, dsel):
            g = gstatus(d)
            rows[n.name] = {"state": g.get("state"), "readyz": ready_of(n), "log_removed": [l[-160:] for l in n.loglines(r"(?i)removed from|was removed|been removed")][-1:]}
        return rows
    rows = none_removed(nodes, ds)
    probe = "203.0.113.97"
    d1.block(probe)
    spread = acts(nodes, probe, 403, 4.0)
    out["fake_410_extra_peer"] = {"answers_410": len(asked), "callers": sorted(set(re.findall(r'"caller":"([^"]*)"', "\n".join(asked)))), "nodes": rows, "block_after": spread}
    lab.check("f.410", "a fake 410 with the group's id from a non-member at an extra address of cluster.peers marks no node removed (contract 7: 'A node believes a 410 ... only from a member')",
              len(asked) > 0 and all(r["state"] != "removed" and r["readyz"] == 200 and not r["log_removed"] for r in rows.values()) and all(v is not None for v in spread.values()),
              "%d calls answered 410 in 20 s; per node %s; a block of f1 afterwards acts on %s" % (len(asked), rows, spread), kill="weakens")
    gone.kill()
    # f.3 the same at the address of a stopped member
    f3.kill9()
    glog2 = os.path.join(lab.root, "gone-member.log")
    gone2 = subprocess.Popen([hostile, "gone", "-random", "-listen", "127.0.0.1:%d" % f3.mesh, "-group", grp], stdout=open(glog2, "w"), stderr=subprocess.STDOUT)
    lab.procs.append(gone2)
    time.sleep(15.0)
    asked2 = [l for l in open(glog2).read().splitlines() if '"answer":410' in l or '"path"' in l]
    rows2 = none_removed([f1, f2], ds[:2])
    gone2.kill()
    gone2.wait(5)
    f3.start()
    r3 = f3.wait_ready(40)
    probe = "203.0.113.98"
    d1.block(probe)
    spread = acts(nodes, probe, 403, 4.0)
    out["fake_410_member_address"] = {"requests": len(asked2), "nodes": rows2, "f3_back_ready_s": r3 and round(r3, 2), "block_after": spread}
    lab.check("f.410", "an impostor (another key) at the address of the stopped member f3 answering 410 marks neither f1 nor f2 removed; f3 returns afterwards",
              all(r["state"] != "removed" and r["readyz"] == 200 and not r["log_removed"] for r in rows2.values()) and r3 is not None and all(v is not None for v in spread.values()),
              "%d requests reached the impostor (TLS may end before HTTP when the key is not the member's); per node %s; f3 ready again after %s s; a block of f1 acts on %s" % (
                  len(asked2), rows2, r3 and round(r3, 2), spread), kill="weakens")
    stop_all(nodes)


# ------------------------------------------------------------------------------------------------------------ g
class HeaderProbe:
    """Keep-alive requests straight to one node; notes (time, status, Connection header) of every answer."""

    def __init__(self, node, gap=0.05):
        self.node, self.gap, self.rows, self.stop = node, gap, [], False
        self.th = threading.Thread(target=self._run, daemon=True)
        self.th.start()

    def _run(self):
        c = None
        while not self.stop:
            t = time.time()
            try:
                if c is None:
                    c = http.client.HTTPConnection("127.0.0.1", self.node.proxy, timeout=3)
                c.request("GET", "/drainprobe", headers={"Host": "shop.example", "X-Forwarded-For": "198.51.100.66"})
                r = c.getresponse()
                r.read()
                self.rows.append((t, r.status, (r.getheader("Connection") or "").lower()))
                if r.will_close:
                    c.close()
                    c = None
            except Exception as e:
                self.rows.append((t, 0, type(e).__name__))
                try:
                    c and c.close()
                except Exception:
                    pass
                c = None
            time.sleep(self.gap)

    def finish(self):
        self.stop = True
        self.th.join(5)


def drain(lab):
    out = lab.data.setdefault("g", {})
    names = ["g1", "g2", "g3"]
    delay, grace = 15, 30
    nodes = group(lab, names, idx0=36, delay_s=delay, grace_s=grace)
    wait_group(lab, nodes, cid="g.setup")
    g1, g2, g3 = nodes

    def one(tag, victim, how):
        h = load_start(lab, nodes, 300, 45, "drain-" + tag, conns=8, ips=200, ipnet="10.66", health=True, path="/drain-" + tag)
        time.sleep(8.0)
        hp = HeaderProbe(victim)
        time.sleep(1.0)
        t_sig = time.time()
        m0 = now()
        if how == "sigterm":
            victim.term()
            cli = None
        else:
            cli = {}
            threading.Thread(target=lambda: cli.update(rc_out=victim.cli("cluster", "drain", timeout=90)), daemon=True).start()
        t503 = wait_for(lambda: ready_of(victim) != 200, 5, 0.02)
        exited = victim.wait_exit(delay + grace + 15)
        took = round(now() - m0, 2)
        time.sleep(0.5)
        hp.finish()
        r = load_wait(h)
        start = t_sig + (t503 or 0) + 0.05
        in_delay = [x for x in hp.rows if start <= x[0] < t_sig + delay - 0.3 and x[1] != 0]
        early = [(round(x[0] - t_sig, 3), x[1], x[2]) for x in hp.rows if t_sig <= x[0] < start]
        closes = sum(1 for x in in_delay if "close" in x[2])
        before = [x for x in hp.rows if x[0] < t_sig]
        failed_direct = [x for x in hp.rows if t_sig <= x[0] < t_sig + delay - 0.3 and x[1] in (0,)]
        row = {"how": how, "cli": cli, "readyz_503_after_s": t503 and round(t503, 3), "exited": exited, "exit_s": took,
               "exit_code": victim.proc.returncode, "probe": {"before": len(before), "before_close": sum(1 for x in before if "close" in x[2]),
                                                               "in_delay": len(in_delay), "in_delay_close": closes, "failed_in_delay": len(failed_direct)},
               "load": short_load(r), "answers_before_503": early}
        out[tag] = row
        lab.check("g." + tag, "%s: readyz 503 at once, every answer in the delay carries Connection: close (contract 10)" % how,
                  t503 is not None and t503 < 1.0 and len(in_delay) > 0 and closes == len(in_delay) and row["probe"]["before_close"] == 0,
                  "503 after %s s; straight to the node: %d answers before (%d with close), %d in the %d s delay, %d of them with close, %d failed" % (
                      t503 and round(t503, 3), len(before), row["probe"]["before_close"], len(in_delay), delay, closes, len(failed_direct)))
        lab.check("g." + tag, "no failed request at the balancer simulation (the load tool following readyz)",
                  "error" not in r and r.get("failed") == 0 and set(r.get("status", {}).keys()) <= {"200"},
                  "load %s" % row["load"], kill="waits")
        lab.check("g." + tag, "the process ends within delay + grace + 15 s (%d s; guide 'Zeit zum Anhalten')" % (delay + grace + 15),
                  exited and took <= delay + grace + 15, "exited %s after %s s, exit code %s" % (exited, took, victim.proc.returncode))
        metric(lab, "drain_exit", took, "s", how=how, delay_s=delay, grace_s=grace)
        victim.start()
        victim.wait_ready(40)

    one("sigterm", g3, "sigterm")
    one("cli", g2, "schild cluster drain")
    stop_all(nodes)


# ------------------------------------------------------------------------------------------------------------ h
def regression(lab):
    out = lab.data.setdefault("h", {})
    names = ["h1", "h2", "h3"]
    nodes = group(lab, names, idx0=40)
    wait_group(lab, nodes, cid="h.setup")
    ds = first_setup(lab, nodes, cid="h.setup")
    h1, h2, h3 = nodes
    d1, d2, d3 = ds
    # blocks and lifts
    times, lifts, incidents = [], [], []
    for k in range(12):
        src = ds[k % 3]
        a = "203.0.113.%d" % (120 + k)
        st, js = src.block(a)
        incidents.append((a, (js or {}).get("incident")))
        seen = acts(nodes, a, 403, 5.0)
        times.append(max(v if v is not None else 99 for v in seen.values()))
    for k, (a, inc) in enumerate(incidents):
        dst = ds[(k + 1) % 3]
        dst.unblock(inc)
        seen = acts(nodes, a, 200, 5.0)
        lifts.append(max(v if v is not None else 99 for v in seen.values()))
    ts, tl = sorted(times), sorted(lifts)
    p95b, p95l = ts[int(0.95 * (len(ts) - 1))], tl[int(0.95 * (len(tl) - 1))]
    out["blocks_s"], out["lifts_s"] = times, lifts
    lab.check("h.blocks", "a block set on one node acts on every node within 1 s at p95 (spec must)", p95b <= 1.0,
              "12 blocks, set in turn on h1..h3; seconds until all three answer 403: p95 %.3f, max %.3f" % (p95b, ts[-1]))
    lab.check("h.blocks", "a lift on another node acts on every node within 1 s at p95 (guide 'Freigeben hebt sie überall auf')", p95l <= 1.0,
              "12 lifts, each on another node than its block; p95 %.3f, max %.3f" % (p95l, tl[-1]))
    metric(lab, "block_all_nodes_p95", p95b, "s", nodes=3)
    metric(lab, "lift_all_nodes_p95", p95l, "s", nodes=3)
    # settings and logins
    d2.call("PATCH", "/settings", {"retention": {"events_days": 37}})
    t = wait_for(lambda: all((d.call("GET", "/settings")[1].get("retention") or {}).get("events_days") == 37 for d in ds), 10, 0.05)
    lab.check("h.settings", "a setting changed on h2 is in force on every node", t is not None, "after %s s" % (t and round(t, 2)))
    f3 = Dash(h3)
    st = f3.login()[0]
    t = wait_for(lambda: all(bool(Dash(n, f3).session()[1].get("authenticated")) for n in (h1, h2)), 10, 0.05)
    lab.check("h.logins", "a login made on h3 is valid on h1 and h2", st == 200 and t is not None, "login %s; valid after %s s" % (st, t and round(t, 2)))
    # a short outage
    h3.kill9()
    time.sleep(3.0)
    Y, Z = "203.0.113.150", "192.0.2.150"
    w = [d1.block(Y)[0], d1.call("POST", "/allowlist", {"ip": Z, "label": "h", "level": "no_block"})[0], d2.call("PATCH", "/settings", {"retention": {"events_days": 38}})[0]]
    time.sleep(10.0)
    h3.start()
    first = None
    end = now() + 40
    while now() < end:
        if ready_of(h3) == 200:
            first = (round(now() - h3.started_at, 2), hget(h3.proxy, "/", Y))
            break
        time.sleep(0.02)
    t, snaps = wait_same(ds, 15)
    out["outage"] = {"writes": w, "first_ready": first, "same_after_s": t}
    lab.check("h.outage", "h3 back after 13 s away: at its first ready answer the block set meanwhile acts", first is not None and first[1] == 403,
              "ready after %s s, the blocked address answered %s" % (first and first[0], first and first[1]), kill="weakens")
    lab.check("h.outage", "and it holds the same state as the others", t is not None, "%s" % diff_snaps(names, snaps))

    def shared(d):
        return {m["name"]: m.get("shared_state") for m in gstatus(d).get("members", []) if m.get("state") not in ("self",)}
    # state hashes when quiet
    t = wait_for(lambda: all(all(s and set(s.values()) == {"same"} for s in shared(d).values()) for d in ds), 40, 1.0)
    out["quiet_same_s"] = t
    lab.check("h.hash", "state hashes after a quiet spell: every node shows 'same' for every other in every class (guide 'Gleicher Stand')", t is not None,
              "after %s s: %s" % (t and round(t, 1), {d.node.name: shared(d) for d in ds}))
    # under a stream of changes
    stop = [False]
    wrote = [0]

    def stream():
        k = 0
        while not stop[0]:
            k += 1
            src = ds[k % 3]
            src.block("198.51.%d.%d" % (100 + (k // 250) % 3, k % 250 + 1), duration=3600)
            if k % 25 == 0:
                src.call("PATCH", "/settings", {"retention": {"events_days": 30 + k % 20}})
            wrote[0] += 1
            time.sleep(0.1)
    th = threading.Thread(target=stream, daemon=True)
    th.start()
    seen = {"same": 0, "differs": 0, "unknown": 0, "missing": 0}
    differs = []
    t0 = now()
    while now() - t0 < 60:
        for d in ds:
            for name, s in shared(d).items():
                if not s:
                    seen["missing"] += 1
                    continue
                for cls, v in s.items():
                    seen[v] = seen.get(v, 0) + 1
                    if v == "differs":
                        differs.append((round(now() - t0, 1), d.node.name, name, cls))
        time.sleep(1.0)
    stop[0] = True
    th.join(5)
    out["stream"] = {"writes": wrote[0], "seen": seen, "differs": differs[:20]}
    lab.check("h.stream", "60 s of changes (10 a second, blocks and settings on all three): no 'differs' (guide: 'Eine Änderung, die gerade unterwegs ist, gilt deshalb nie als Abweichung')",
              not differs, "%d writes; class verdicts seen %s; differs %s" % (wrote[0], seen, differs[:6]))
    t = wait_for(lambda: all(all(s and set(s.values()) == {"same"} for s in shared(d).values()) for d in ds), 60, 1.0)
    out["after_stream_same_s"] = t
    lab.check("h.stream", "after the stream every node shows 'same' again", t is not None, "after %s s" % (t and round(t, 1)))
    return nodes, ds


# ------------------------------------------------------------------------------------------------------------ i
def away_30_days(lab, nodes, ds):
    """Grey box: the 30 days cannot pass here. The mark the contract names (cluster.db, meta in_step_at) is set back
    by 31 days while the node is stopped; everything else is black box."""
    out = lab.data.setdefault("i", {})
    h1, h2, h3 = nodes
    d1, d2, d3 = ds
    E, A, A0 = "192.0.2.230", "192.0.2.231", "192.0.2.229"
    # control: the same outage without the mark set back; what h3 wrote alone reaches the others
    h1.kill9()
    h2.kill9()
    time.sleep(1.0)
    c0 = d3.call("POST", "/allowlist", {"ip": A0, "label": "i-control", "level": "no_block"})[0]
    h3.kill9()
    h1.start()
    h2.start()
    h1.wait_ready(40)
    h2.wait_ready(40)
    h3.start()
    h3.wait_ready(40)
    tc = wait_for(lambda: all(A0 in (snapshot(d, False)["allowlist"] or []) for d in ds), 20, 0.3)
    out["control"] = {"write": c0, "on_every_node_after_s": tc}
    lab.check("i.control", "control: after an outage of minutes, an allowlist entry h3 added while alone reaches h1 and h2", c0 in (200, 201) and tc is not None,
              "added %s; on every node after %s s" % (c0, tc and round(tc, 2)))
    d1.call("POST", "/allowlist", {"ip": E, "label": "i-e", "level": "no_block"})
    t = wait_for(lambda: all(E in (snapshot(d, False)["allowlist"] or []) for d in ds), 10, 0.2)
    # h3 alone: h1 and h2 stopped; it adds A while alone, then stops
    h1.kill9()
    h2.kill9()
    alone = wait_for(lambda: ready_of(h3) == 200, 20, 0.2)
    sa = d3.call("POST", "/allowlist", {"ip": A, "label": "i-a", "level": "no_block"})[0]
    h3.kill9()
    h1.start()
    h2.start()
    r = [h1.wait_ready(40), h2.wait_ready(40)]
    # the group removes E while h3 is away
    items = d1.call("GET", "/allowlist?limit=500")[1].get("items", [])
    eid = next((x.get("id") for x in items if (x.get("ip") or x.get("cidr")) == E), None)
    sd = d1.call("DELETE", "/allowlist/%s" % eid)[0] if eid else None
    time.sleep(2.0)
    db = os.path.join(h3.data, "cluster", "cluster.db")
    con = sqlite3.connect(db)
    old = con.execute("select v from meta where k = 'mark:in_step_at'").fetchone()
    back = int(time.time() * 1000) - 31 * 86400 * 1000
    con.execute("update meta set v = cast(? as blob) where k = 'mark:in_step_at'", (str(back),))
    con.commit()
    con.close()
    size0 = h3.logsize()
    h3.start()
    r3 = h3.wait_ready(40)
    t2, snaps = wait_same(ds, 20, settings=False)
    al = [snapshot(d, False)["allowlist"] for d in ds]
    lines = [l[-240:] for l in h3.loglines(r"(?i)30 days|replaced|gave up|gives up|dropp|away", size0) if "ranges_fetch" not in l][:4]
    g3 = gstatus(d3)
    out.update({"setup_s": t, "alone_ready_s": alone, "write_alone": sa, "h1h2_ready_s": r, "delete_E": sd, "mark_before": old and old[0].decode() if old and isinstance(old[0], bytes) else old,
                "h3_ready_s": r3 and round(r3, 2), "allowlists": al, "log": lines, "replaced": g3.get("replaced")})
    lab.check("i.away", "a node whose in_step_at mark is 31 days old (set back by hand, grey box) does not hand over what it held alone: the entry it added alone is on no node (contract 5 'A node away longer than 30 days')",
              sa in (200, 201) and r3 is not None and all(A not in (x or []) for x in al), "h3 ready after %s s; allowlists %s; log %s; replaced %s" % (r3 and round(r3, 2), al, lines, g3.get("replaced")), kill="erased")
    lab.check("i.away", "and the entry the group removed meanwhile is gone on it too", sd in (200, 204) and all(E not in (x or []) for x in al), "delete %s; allowlists %s" % (sd, al), kill="erased")
    lab.check("i.away", "and its log names what it gave up", bool(lines), lines)


def run(lab):
    only = os.environ.get("SG27H_S8", "abcdefghi")
    shim = lab.extra_bins.get("clock_shim")

    def hi(lab):
        nodes, ds = regression(lab)
        if "i" in only:
            away_30_days(lab, nodes, ds)
        stop_all(nodes)
    parts = [("a", start_refused), ("b", brand_new), ("c", fresh_while_down), ("d", clock_rule), ("e", remove_ahead),
             ("f", strangers), ("g", drain), ("h", hi)]
    for key, fn in parts:
        if key not in only and not (key == "h" and "i" in only):
            continue
        if key in "de" and not shim:
            lab.check(key, fn.__name__, None, "NOT MEASURED: no clock shim")
            continue
        fresh_secret(lab)
        print("--- s8 part %s" % key, flush=True)
        try:
            fn(lab)
        except Exception as e:
            import traceback
            traceback.print_exc()
            lab.check(key, "harness", False, "harness error, part %s incomplete: %r" % (key, e))
        finally:
            stop_all(lab.nodes)
