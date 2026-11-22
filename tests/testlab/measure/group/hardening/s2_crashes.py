"""Scenario 2: hard crashes and restarts of three gateways, a lost cluster directory, a read-only and a full
data directory."""
import os
import random
import re
import shutil
import subprocess
import threading
import time

from hard import (SEED, allow_all, count_requests, Dash, HNode, Probe, acts, diff_snaps, first_setup, group, gstatus, hget, load_start, load_wait, member_states,
                  metric, now, served_clean, short_load, snapshot, wait_for, wait_group, wait_same)

BAD = r"panic:|fatal error|database disk image is malformed|corrupt"


def run(lab):
    rng = random.Random(SEED)
    names = ["c1", "c2", "c3"]
    nodes = group(lab, names)
    wait_group(lab, nodes, cid="c.setup")
    ds = first_setup(lab, nodes, cid="c.setup")
    n1, n2, n3 = nodes
    d1, d2, d3 = ds
    out = lab.data

    # ---- kill -9 while the node takes writes
    rounds = []
    for rnd in range(2 if lab.quick else 4):
        acked, stop = [], threading.Event()

        def writer():
            i = 0
            w = Dash(n3, d1)
            while not stop.is_set():
                ip = "10.%d.%d.%d" % (70 + rnd, i // 250, i % 250 + 1)
                st, _ = w.call("POST", "/allowlist", {"ip": ip, "label": "crash %d" % rnd, "level": "no_block"}, timeout=3)
                if st == 201:
                    acked.append(("allow", ip, now()))
                if i % 5 == 0 and i // 5 < 12:
                    a = "203.0.113.%d" % (10 + rnd * 12 + i // 5)
                    st, _ = w.call("POST", "/blocks", {"address": a, "duration_s": 604800, "reason": "crash"}, timeout=3)
                    if st == 200:
                        acked.append(("block", a, now()))
                i += 1
        probe = Probe([n1, n2])
        t_load = now()
        lh = load_start(lab, nodes, 300, 8, "crash%d" % rnd, path="/crash%d" % rnd)
        th = threading.Thread(target=writer, daemon=True)
        th.start()
        time.sleep(1.5 + rng.random() * 2.0)
        mark = n3.logsize()
        t_kill = now()
        n3.kill9()
        stop.set()
        th.join(5)
        time.sleep(1.0)
        n3.start()
        ready = n3.wait_ready(40)
        w = probe.window(t_kill - 1.0)
        probe.finish()
        ld = load_wait(lh)
        allow = [a for k, a, _ in acked if k == "allow"]
        blocks = [a for k, a, _ in acked if k == "block"]

        def missing():
            m = {}
            for nd, d in zip(nodes, ds):
                al, bl = set(allow_all(d) or []), set(snapshot(d, False)["blocks"])
                m[nd.name] = sorted(set(allow) - al) + sorted(set(blocks) - bl)
            return m
        t = wait_for(lambda: not any(missing().values()), 25, 0.3)
        miss = missing()
        last_ack = max((x[2] for x in acked), default=t_kill)
        bad = n3.loglines(BAD, mark)
        rounds.append({"acked": len(acked), "last_ack_before_kill_ms": round((t_kill - last_ack) * 1000, 1), "ready_s": ready,
                       "missing": {k: v[:8] for k, v in miss.items()}, "missing_n": {k: len(v) for k, v in miss.items()}, "bad_log": bad[:3],
                       "others": w, "load": short_load(ld)})
        lab.check("c.kill9", "round %d: kill -9 of c3 while it takes writes: every write it answered with 2xx is on every node afterwards" % (rnd + 1),
                  t is not None, "%d writes answered (%d allowlist entries, %d blocks), the last %.1f ms before the kill; missing afterwards per node %s%s" % (
                      len(acked), len(allow), len(blocks), (t_kill - last_ack) * 1000, {k: len(v) for k, v in miss.items()},
                      "" if t is not None else "; e.g. %s" % {k: v[:4] for k, v in miss.items() if v}), kill="weakens")
        lab.check("c.kill9", "round %d: c3 starts again and is ready, nothing in its log about a damaged store" % (rnd + 1), ready is not None and not bad,
                  "ready after %s s; log lines matching /%s/: %s" % (ready and round(ready, 2), BAD, bad[:2]))
        served_clean(lab, "c.kill9", "round %d: the two other nodes serve on without a failed or slow request" % (rnd + 1), w)
        metric(lab, "ready_after_kill9", ready, "s", round=rnd + 1)
        # single requests: the 300 a second of this round were spread over the three nodes while c3 died
        cnt = []
        time.sleep(3.0)
        tq = wait_for(lambda: (cnt.clear() or cnt.extend(count_requests(d, lab.started - 60)[0] for d in ds)) or len(set(cnt)) == 1, 25, 1.0)
        rounds[-1]["requests_held"] = list(cnt)
        segs = n3.loglines(r"unreadable segment|corrupt record", mark)
        # how many of its last seconds that is: what c3 answered per second before it died (the load client's count)
        tl = (ld.get("timeline_answered_failed") or [[], [], []])[2]
        answered = [tl[i] for i in range(0, len(tl), 2)]
        died = int(t_kill - t_load)
        rounds[-1]["killed_s_into_load"] = round(t_kill - t_load, 2)
        behind = (max(cnt[:2]) - cnt[2]) if all(isinstance(x, int) for x in cnt) else None
        lacks = None if behind is None else behind - sum(r.get("c3_lacks") or 0 for r in rounds[:-1])
        rounds[-1].update(c3_answered_per_second=answered, c3_lacks=lacks)
        lab.check("c.kill9", "round %d: afterwards the three nodes hold the same number of single requests (25 s)" % (rnd + 1), tq is not None,
                  "requests held by c1, c2, c3: %s; c3 lacks %s more than before this round; c3 was killed %.1f s into the load and had answered per second until then: %s (in all %s); log of c3 about its request store: %s" % (
                      cnt, lacks, t_kill - t_load, answered[:died + 1], sum(answered[:died + 1]), [re.sub(r'^.*?"msg":', "", x)[:200] for x in segs[:2]] or "nothing"))
        metric(lab, "requests_missing_on_killed_node", lacks, "count", round=rnd + 1)
    out["kill9_rounds"] = rounds
    t, snaps = wait_same(ds, 20)
    lab.check("c.kill9", "after the rounds every node shows the same state", t is not None, diff_snaps(names, snaps))

    # ---- every node restarted in turn: planned (SIGTERM, drain) under load that follows readiness like a balancer
    before = snapshot(d1)
    lh = load_start(lab, nodes, 300, 38, "rolling", health=True, path="/roll")
    time.sleep(2.0)
    steps = []
    for nd in nodes:
        t0 = now()
        nd.term()
        gone = nd.wait_exit(30)
        nd.start()
        r = nd.wait_ready(40)
        steps.append({"node": nd.name, "stopped": gone, "down_s": round(now() - t0, 2), "ready_s": r})
        time.sleep(2.5)
    ld = load_wait(lh)
    out["rolling_term"] = {"steps": steps, "load": short_load(ld), "first_failures": (ld.get("first_failures") or [])[:10]}
    lab.check("c.rolling", "every node stopped (SIGTERM, drain) and started in turn under 300 requests a second that follow readyz: no request fails",
              ld.get("failed") == 0 and all(s["ready_s"] for s in steps), "requests %s, failed %s, statuses %s; steps %s" % (ld.get("sent"), ld.get("failed"), ld.get("status"), steps), kill="waits")
    metric(lab, "rolling_restart_failed_requests", ld.get("failed"), "count", ld.get("sent"), nodes=3, how="sigterm")
    t, snaps = wait_same(ds, 20)
    lab.check("c.rolling", "the state is the same on every node and as before", t is not None and snaps[0] == before, diff_snaps(names, snaps) if t is None else "equal to before: %s" % (snaps[0] == before), kill="weakens")

    # ---- every node killed in turn (kill -9), no drain
    steps = []
    for nd in nodes:
        nd.kill9()
        time.sleep(0.5)
        nd.start()
        steps.append({"node": nd.name, "ready_s": nd.wait_ready(40)})
        time.sleep(1.0)
    t, snaps = wait_same(ds, 20)
    lab.check("c.rolling", "every node killed (kill -9) and started in turn: all return ready with the same state as before",
              all(s["ready_s"] for s in steps) and t is not None and snaps[0] == before, "steps %s; %s" % (steps, diff_snaps(names, snaps)), kill="weakens")
    out["rolling_kill"] = steps

    # ---- all at once
    for rnd in range(3):
        for i in range(600):
            hget(nodes[i % 3].proxy, "/all%d/%d" % (rnd, i % 20), "10.97.%d.%d" % (rnd, i % 200 + 1))
        held = []
        wait_for(lambda: (held.clear() or held.extend(count_requests(d, lab.started - 60)[0] for d in ds)) or len(set(held)) == 1, 20, 1.0)
        time.sleep(3.0)  # nothing is in flight when the nodes die
        marks = [nd.logsize() for nd in nodes]
        for nd in nodes:
            nd.proc.kill()
        for nd in nodes:
            nd.proc.wait()
        t0 = now()
        for nd in nodes:
            nd.start()
        ready = [nd.wait_ready(40) for nd in nodes]
        t, snaps = wait_same(ds, 20)
        sess = [bool(d.session()[1].get("authenticated")) for d in ds]
        acting = acts(nodes, before["blocks"][0], 403, 5) if before["blocks"] else {}
        bad = [re.sub(r'^.*?"msg":', "", l)[:220] for nd, mk in zip(nodes, marks) for l in nd.loglines(BAD, mk)]
        lab.check("c.all", "round %d: all three killed at the same moment (kill -9) and started together: ready, same state as before, login valid" % (rnd + 1),
                  all(ready) and t is not None and snaps[0] == before and all(sess) and all(v is not None for v in acting.values()),
                  "ready after %s s; %s; equal to before: %s; sessions %s; a block of before acts %s" % (
                      [r and round(r, 2) for r in ready], diff_snaps(names, snaps), snaps[0] == before, sess, acting), kill="weakens")
        time.sleep(6.0)
        after = [count_requests(d, lab.started - 60)[0] for d in ds]
        lost = [b - a if isinstance(a, int) and isinstance(b, int) else None for b, a in zip(held, after)]
        lab.check("c.all", "round %d: no stored single request is lost by the kill (nothing was in flight for 3 s)" % (rnd + 1),
                  all(x is not None and x <= 0 for x in lost) and not bad,
                  "requests held by c1, c2, c3 before %s, after the restart %s, lost %s; log about a damaged store: %s" % (held, after, lost, bad[:3] or "nothing"))
        out.setdefault("all_at_once_requests", []).append({"before": held, "after": after, "lost": lost, "log": bad[:6]})
        for r in ready:
            metric(lab, "ready_after_all_killed", r, "s", round=rnd + 1)
        out.setdefault("all_at_once", []).append({"ready_s": ready, "same": t is not None, "equal_before": snaps[0] == before})

    # ---- a node that starts with an empty cluster directory (its key and its copy of the records are gone)
    n3.kill9()
    old_id = next((m["id"] for m in gstatus(d1).get("members", []) if m["name"] == "c3"), "?")
    shutil.rmtree(os.path.join(n3.data, "cluster"))
    X1 = "203.0.113.200"
    d1.block(X1)
    n3.start()
    r = n3.wait_ready(40)
    at_ready = hget(n3.proxy, "/", X1)
    t, snaps = wait_same(ds, 25)
    sess = [bool(d.session()[1].get("authenticated")) for d in ds]
    lab.check("c.empty", "c3 returns with an empty cluster directory (new key): ready, and the block set meanwhile acts at its first ready answer",
              r is not None and at_ready == 403, "ready after %s s, request of the blocked address at ready %s" % (r and round(r, 2), at_ready))
    kept = dict(before, blocks=sorted(before["blocks"] + [X1]))
    lab.check("c.empty", "the state of the two others is unchanged and c3 holds it too; the login stays", t is not None and snaps[0] == kept and all(sess),
              "%s; c1 equal to before plus the new block: %s; sessions %s" % (diff_snaps(names, snaps), snaps[0] == kept, sess), kill="weakens")
    time.sleep(12.0)
    g = gstatus(d1)
    mem = [(m["name"], m["id"][:10], m["state"]) for m in g.get("members", [])]
    ghost = [m for m in g.get("members", []) if m["name"] == "c3" and m["id"] == old_id]
    out["empty_cluster_dir"] = {"members_on_c1": mem, "state_on_c1": g.get("state"), "old_id": old_id}
    lab.check("c.empty", "12 s later: the state of the group on c1 and what became of the former identity of c3", None,
              "state %s; members (name, id, state) %s; the former identity of c3 is %s" % (g.get("state"), mem, "still listed as %s" % ghost[0]["state"] if ghost else "not listed"))
    if ghost:
        rc, txt = n1.cli("cluster", "remove", old_id)
        time.sleep(6.0)
        g2 = gstatus(d1)
        mem2 = [(m["name"], m["id"][:10], m["state"]) for m in g2.get("members", [])]
        ok3 = member_states(d1).get("c3")
        lab.check("c.empty", "`schild cluster remove <former id>` clears it and the group is active with the new c3", rc == 0 and g2.get("state") == "active" and hget(n3.proxy, "/.schild/readyz") == 200,
                  "remove rc %s (%s); state %s; members %s" % (rc, txt[:120], g2.get("state"), mem2))
        X2 = "203.0.113.201"
        d1.block(X2)
        r2 = acts(nodes, X2, 403, 8)
        lab.check("c.empty", "after that a block of c1 still reaches the new c3", all(v is not None for v in r2.values()), "seconds %s" % r2, kill="weakens")
        out["empty_cluster_dir"]["after_remove"] = {"members": mem2, "state": g2.get("state")}

    # ---- read-only data directory on a running node
    probe = Probe(nodes)
    time.sleep(0.5)
    t0 = probe.mark()
    subprocess.run(["chmod", "-R", "a-w", n2.data])
    mark = n2.logsize()
    time.sleep(1.0)
    W1 = "203.0.113.210"
    st1, _ = d1.block(W1)
    r = acts(nodes, W1, 403, 8)
    st2, js2 = d2.call("POST", "/allowlist", {"ip": "10.99.0.1", "label": "read-only", "level": "no_block"})
    st3, js3 = d2.call("POST", "/blocks", {"address": "203.0.113.211", "duration_s": 604800, "reason": "read-only"})
    for i in range(200):
        hget(nodes[i % 3].proxy, "/ro/%d" % i, "10.98.0.%d" % (i % 50 + 1))
    time.sleep(4.0)
    w_all = probe.window(t0)
    w_others = probe.window(t0, names=["c1", "c3"])
    rz = hget(n2.proxy, "/.schild/readyz")
    errs = n2.loglines(r'"level":"(ERROR|WARN)"', mark)
    out["read_only"] = {"probe_all": w_all, "probe_others": w_others, "block_of_c1_acts_s": r, "allowlist_on_ro_node": [st2, js2], "block_on_ro_node": [st3, js3 if st3 != 200 else "ok"],
                        "readyz": rz, "log_warn_error_lines": len(errs), "log_examples": [e[:300] for e in errs[:4]]}
    served_clean(lab, "c.readonly", "data directory of c2 made read-only while it runs: the other two serve without a failed or slow request", w_others)
    served_clean(lab, "c.readonly", "c2 itself goes on serving requests", probe.window(t0, names=["c2"]), kill=None)
    lab.check("c.readonly", "a block set on c1 still acts on c2 (it cannot store it)", r["c2"] is not None, "seconds %s" % r)
    lab.check("c.readonly", "what c2 answers to a change made on it, its readiness and its log", None,
              "POST /allowlist %s %s; POST /blocks %s; readyz %s; %d WARN or ERROR lines, e.g. %s" % (
                  st2, (js2 or {}).get("code") if isinstance(js2, dict) else js2, st3, rz, len(errs), [re.sub(r'^.*?"msg":', "", e)[:160] for e in errs[:2]]))
    lab.check("c.readonly", "c2 does not report success for a change it could not store", st2 not in (200, 201) or "10.99.0.1" in (allow_all(d1) or []),
              "POST /allowlist on c2 answered %s; the entry is on c1: %s" % (st2, "10.99.0.1" in (allow_all(d1) or [])))
    subprocess.run(["chmod", "-R", "u+w", n2.data])
    t, snaps = wait_same(ds, 25)
    lab.check("c.readonly", "writable again: every node shows the same state within 25 s", t is not None, "after %s s; %s" % (t and round(t, 2), diff_snaps(names, snaps)))
    n2.kill9()
    n2.start()
    r = n2.wait_ready(40)
    t, snaps = wait_same(ds, 25)
    lab.check("c.readonly", "c2 restarted afterwards: ready, same state", r is not None and t is not None, "ready %s s; %s" % (r and round(r, 2), diff_snaps(names, snaps)))
    probe.finish()
    # a start on a read-only directory
    n2.kill9()
    subprocess.run(["chmod", "-R", "a-w", n2.data])
    n2.start()
    exited = n2.wait_exit(8)
    tail = open(n2.log, errors="replace").read()[-600:]
    rz = None if exited else hget(n2.proxy, "/.schild/readyz")
    lab.check("c.readonly", "a start on a read-only data directory", None, "process %s; readyz %s; last log: %s" % (
        "exited with %s" % n2.proc.returncode if exited else "runs", rz, re.sub(r"\s+", " ", tail[-300:])))
    out["read_only"]["start"] = {"exited": exited, "rc": n2.proc.returncode if exited else None, "readyz": rz}
    n2.kill9()
    subprocess.run(["chmod", "-R", "u+w", n2.data])
    n2.start()
    n2.wait_ready(40)

    # ---- a full disk: a fourth node on a small disk image (hdiutil, no root)
    vol = os.path.join(lab.root, "vol")
    img = os.path.join(lab.root, "small.sparseimage")
    mk = subprocess.run(["hdiutil", "create", "-size", "6g", "-type", "SPARSE", "-fs", "APFS", "-volname", "sg27h", img], capture_output=True, text=True)
    os.makedirs(vol, exist_ok=True)
    at = subprocess.run(["hdiutil", "attach", img, "-mountpoint", vol, "-nobrowse"], capture_output=True, text=True)
    if mk.returncode != 0 or at.returncode != 0:
        lab.check("c.full", "a full data directory", None, "NOT MEASURED: no disk image without root here (%s %s)" % (mk.stderr[:120], at.stderr[:120]))
        return
    lab.cleanups = [lambda: subprocess.run(["hdiutil", "detach", vol, "-force"], capture_output=True)]
    peers = n1.cluster["peers"] + ["127.0.0.1:%d" % (lab.port0 + 4 * 10 + 4)]
    n4 = HNode(lab, "c4", 4, {"secret_file": lab.secret(), "peers": peers})
    # the data directory on the small volume, through a link so the control socket path stays short
    os.rmdir(n4.data) if os.path.isdir(n4.data) else None
    os.makedirs(os.path.join(vol, "d"))
    os.symlink(os.path.join(vol, "d"), n4.data)
    n4.start()
    r = n4.wait_ready(30)
    if r is None:
        tail = re.sub(r"\s+", " ", open(n4.log, errors="replace").read()[-500:])
        lab.check("c.full", "a node on a 6 GB volume", None, "NOT MEASURED further: the node did not become ready (process %s): %s" % ("runs" if n4.alive() else "exited %s" % n4.proc.returncode, tail))
        out["full_disk"] = {"started": False, "log": tail}
        n4.kill9()
        return
    d4 = Dash(n4, d1)
    all4 = nodes + [n4]
    ds4 = ds + [d4]
    wait_for(lambda: snapshot(d4, False) == snapshot(d1, False), 20, 0.3)
    probe = Probe(all4)
    time.sleep(0.5)
    fill = os.path.join(vol, "fill.bin")
    subprocess.run(["dd", "if=/dev/zero", "of=" + fill, "bs=1m"], capture_output=True)
    free = shutil.disk_usage(vol).free
    mark = n4.logsize()
    t0 = probe.mark()
    lh = load_start(lab, all4, 400, 10, "full", path="/full")
    F1 = "203.0.113.220"
    d1.block(F1)
    r = acts(all4, F1, 403, 8)
    st4, js4 = d4.call("POST", "/allowlist", {"ip": "10.99.0.4", "label": "full disk", "level": "no_block"})
    st5, js5 = d4.block("203.0.113.221")
    ld = load_wait(lh)
    time.sleep(2.0)
    w_others, w4 = probe.window(t0, names=names), probe.window(t0, names=["c4"])
    errs = n4.loglines(r'"level":"(ERROR|WARN)"', mark)
    rz = hget(n4.proxy, "/.schild/readyz")
    reach = {"allow 10.99.0.4 on c1": "10.99.0.4" in (allow_all(d1) or []), "block .221 on c1": hget(n1.proxy, "/", "203.0.113.221")}
    out["full_disk"] = {"free_bytes": free, "others": w_others, "c4": w4, "block_of_c1_acts_s": r, "allowlist_on_full": [st4, js4 if st4 != 201 else "ok"],
                        "block_on_full": [st5, js5 if st5 != 200 else "ok"], "readyz": rz, "load": short_load(ld), "log_lines": len(errs), "log_examples": [e[:300] for e in errs[:4]], "reach": reach}
    served_clean(lab, "c.full", "the volume of c4 is full (%d bytes free): the other three serve without a failed or slow request" % free, w_others)
    served_clean(lab, "c.full", "c4 itself goes on serving requests", w4, kill=None)
    lab.check("c.full", "a block set on c1 still acts on c4", r["c4"] is not None, "seconds %s" % r)
    lab.check("c.full", "what c4 answers to changes made on it, its readiness and its log", None,
              "POST /allowlist %s, POST /blocks %s, both then on c1: %s; readyz %s; load over the four nodes: %s failed of %s, statuses on c4 %s; %d WARN or ERROR lines, e.g. %s" % (
                  st4, st5, reach, rz, ld.get("failed"), ld.get("sent"), (ld.get("per_target") or [{}] * 4)[3].get("status"), len(errs), [re.sub(r'^.*?"msg":', "", e)[:160] for e in errs[:2]]))
    lab.check("c.full", "c4 does not report success for a change that is lost", (st4 != 201 or reach["allow 10.99.0.4 on c1"]) and (st5 != 200 or reach["block .221 on c1"] == 403),
              "allowlist %s reached c1: %s; block %s acts on c1: %s" % (st4, reach["allow 10.99.0.4 on c1"], st5, reach["block .221 on c1"]))
    os.remove(fill)
    t, snaps = wait_same(ds4, 30)
    lab.check("c.full", "space again: every node shows the same state within 30 s", t is not None, "after %s s; %s" % (t and round(t, 2), diff_snaps(names + ["c4"], snaps)))
    n4.kill9()
    n4.start()
    r = n4.wait_ready(40)
    t, snaps = wait_same(ds4, 30)
    bad = n4.loglines(BAD, mark)
    lab.check("c.full", "c4 restarted afterwards: ready, same state, no damaged store in its log", r is not None and t is not None and not bad,
              "ready %s s; %s; bad lines %s" % (r and round(r, 2), diff_snaps(names + ["c4"], snaps), bad[:2]))
    probe.finish()
    for nd in all4:
        nd.kill9()
