"""Scenario 1: faults between the nodes, through a userspace TCP proxy in front of every mesh listener.

Run for three gateways and for a pair. Each node's cluster.advertise and every entry of cluster.peers name a port
of the proxy (tool/main.go, `proxy`), which can hold the bytes of one direction between two nodes (a cut: nothing
arrives, nothing is lost, the connection stays open), refuse connections and delay bytes.
"""
import time

from hard import (allow_all, Dash, HNode, Probe, acts, diff_snaps, first_setup, group, hget, member_states, metric, now, served_clean,
                  snapshot, wait_for, wait_group, wait_same)


def detect(observers, target, timeout=30.0):
    """Seconds until each observer's dashboard no longer lists the target as ok."""
    t0, seen = now(), {}
    while now() - t0 < timeout and len(seen) < len(observers):
        for name, d in observers.items():
            if name not in seen and member_states(d).get(target) not in ("ok", None):
                seen[name] = round(now() - t0, 2)
        time.sleep(0.05)
    return {name: seen.get(name) for name in observers}


def block(lab, d, addr):
    st, js = d.block(addr)
    if st != 200:
        raise RuntimeError("block %s on %s: %s %s" % (addr, d.node.name, st, js))
    return js["incident"]


def timed(fn):
    t = now()
    r = fn()
    return r, round((now() - t) * 1000, 1)


def faults(lab, n, idx0, tag):
    names = ["%s%d" % (tag, i + 1) for i in range(n)]
    nodes = group(lab, names, idx0=idx0, via_proxy=True)
    wait_group(lab, nodes, cid=tag + ".setup")
    ds = first_setup(lab, nodes, cid=tag + ".setup")
    byname = dict(zip(names, ds))
    first, last = nodes[0], nodes[-1]
    d1, dl = ds[0], ds[-1]
    side_a, side_b = nodes[:-1], [last]
    out = lab.data.setdefault(tag, {})
    net = lab.net
    st = net.stats()
    lab.check(tag + ".setup", "the mesh runs through the fault proxy and it knows every caller", st["unknown_callers"] == 0 and len(st["opened"]) >= n * (n - 1),
              "connections opened per pair %s, callers not identified %d" % (st["opened"], st["unknown_callers"]))
    probe = Probe(nodes)
    time.sleep(1.0)
    t_base = probe.mark()

    # ---- baseline through the proxy
    P1 = "203.0.113.%d" % (10 + idx0)
    inc_p1 = block(lab, d1, P1)
    r = acts(nodes, P1, 403, 8)
    lab.check(tag + ".base", "a block set on %s acts on every node (no fault)" % first.name, all(v is not None for v in r.values()), "seconds %s" % r)
    out["base_block_s"] = r
    # an address with events on every node, erased later on one side of the cut
    E = "198.51.100.%d" % (200 + idx0)
    for nd in nodes:
        for i in range(4):
            hget(nd.proxy, "/er-%d?q=%%3Cscript%%3Ealert(1)%%3C/script%%3E" % i, E)
    tev = wait_for(lambda: all(d.privacy(E).get("events", 0) >= 4 * n for d in ds), 20, 0.2)
    out["events_before_erasure"] = [d.privacy(E).get("events") for d in ds]
    lab.check(tag + ".base", "every node holds the %d events of an address (to be erased during the cut)" % (4 * n), tev is not None,
              "events per node %s after %s s" % (out["events_before_erasure"], tev and round(tev, 1)))

    # ---- delay
    net.rules([{"from": "*", "to": "*", "delay_ms": 300}])
    t0 = probe.mark()
    time.sleep(3.0)
    D1 = "203.0.113.%d" % (20 + idx0)
    inc_d1, api_ms = timed(lambda: block(lab, d1, D1))
    r = acts(nodes[1:], D1, 403, 15)
    time.sleep(3.0)
    states = member_states(d1)
    w = probe.window(t0)
    net.clear()
    served_clean(lab, tag + ".delay", "300 ms of delay on every byte between the nodes: no client request waits or fails", w)
    lab.check(tag + ".delay", "a block still reaches the others (300 ms each way)", all(v is not None for v in r.values()),
              "API call %s ms; acts after %s s; members as %s sees them: %s" % (api_ms, r, first.name, states))
    lab.check(tag + ".delay", "the write itself does not wait for the slow peers", api_ms < 250, "POST /blocks answered after %s ms" % api_ms, kill="waits")
    out["delay"] = {"probe": w, "block_s": r, "api_ms": api_ms, "states": states}
    for k, v in r.items():
        metric(lab, "block_propagation_delay_300ms", v, "s", nodes=n, node=k)
    time.sleep(2.0)

    # ---- the cut: side A (all but the last) and side B (the last node); also "a node that hangs": connections
    # stay open and carry no byte
    t_cut = probe.mark()
    net.partition(side_a, side_b)
    obs_a = detect({first.name: d1}, last.name)
    obs_b = detect({last.name: dl}, first.name, timeout=max(1.0, 30.0 - (now() - t_cut)))
    seen = dict(obs_a, **obs_b)
    worst = max((v for v in seen.values() if v is not None), default=None)
    lab.check(tag + ".cut", "a peer whose connection stays open and carries no byte is noticed within about 3 s (contract section 7; limit here 5 s)",
              all(v is not None and v <= 5.0 for v in seen.values()),
              "GET /group no longer lists the other side as ok after %s s (%s sees %s, %s sees %s); polled every 50 ms" % (
                  seen, first.name, last.name, last.name, first.name))
    for k, v in seen.items():
        metric(lab, "hung_peer_noticed", v, "s", nodes=n, observer=k)
    out["cut_detect_s"] = seen
    time.sleep(max(0.0, 6.0 - (now() - t_cut)))
    rz = {nd.name: hget(nd.proxy, "/.schild/readyz") for nd in nodes}
    gs = {nm: d.call("GET", "/group")[1].get("state") for nm, d in byname.items()}
    lab.check(tag + ".cut", "readiness stays 200 on both sides of the cut (a running node serves with the state it has)", all(v == 200 for v in rz.values()),
              "readyz %s; group state %s" % (rz, gs))
    want_states = {nd.name: ("interrupted" if (nd is last or n == 2) else "degraded") for nd in nodes}
    lab.check(tag + ".cut", "GET /group names the state: degraded where one gateway is missing, interrupted where none is reached", gs == want_states,
              "state %s, expected %s" % (gs, want_states))
    # both sides change different entries
    A1, B1 = "203.0.113.%d" % (30 + idx0), "203.0.113.%d" % (40 + idx0)
    A2, B2 = "192.0.2.%d" % (30 + idx0), "192.0.2.%d" % (40 + idx0)
    ms = {}
    _, ms["block_a"] = timed(lambda: block(lab, d1, A1))
    _, ms["block_b"] = timed(lambda: block(lab, dl, B1))
    (sa, _), ms["allow_a"] = timed(lambda: d1.call("POST", "/allowlist", {"ip": A2, "label": "side a", "level": "no_block"}))
    (sb, _), ms["allow_b"] = timed(lambda: dl.call("POST", "/allowlist", {"ip": B2, "label": "side b", "level": "no_block"}))
    (la, _), ms["limit_a"] = timed(lambda: d1.call("POST", "/behaviour/rate-limits", {"route": "/cut-a-%s/**" % tag, "limit": 100, "per": "1m", "burst": 100, "mode": "block", "label": "%s-side-a" % tag}))
    (lb, _), ms["limit_b"] = timed(lambda: dl.call("POST", "/behaviour/rate-limits", {"route": "/cut-b-%s/**" % tag, "limit": 100, "per": "1m", "burst": 100, "mode": "block", "label": "%s-side-b" % tag}))
    (ta, _), ms["setting_a"] = timed(lambda: d1.call("PATCH", "/settings", {"retention": {"events_days": 21}}))
    (tb, _), ms["setting_b"] = timed(lambda: dl.call("PATCH", "/settings", {"retention": {"summaries_days": 111}}))
    # the very same entry on both sides: the later clock stands
    d1.call("PATCH", "/settings", {"retention": {"raw_ip_days": 7}})
    time.sleep(1.5)
    dl.call("PATCH", "/settings", {"retention": {"raw_ip_days": 9}})
    # a lift on side A of a block from before the cut, a login on each side, an erasure on side B
    (ua, _), ms["lift_a"] = timed(lambda: d1.unblock(inc_p1))
    sess_a, sess_b = Dash(first), Dash(last)
    login_a, login_b = sess_a.login()[0], sess_b.login()[0]
    (se, je), ms["erase_b"] = timed(lambda: dl.call("POST", "/privacy/delete", {"ip": E, "confirm": True}))
    codes = {"allow_a": sa, "allow_b": sb, "limit_a": la, "limit_b": lb, "setting_a": ta, "setting_b": tb, "lift_a": ua, "login_a": login_a, "login_b": login_b, "erase_b": se}
    lab.check(tag + ".cut", "both sides stay writable during the cut", all(v in (200, 201) for v in codes.values()), "answers %s" % codes)
    slow = {k: v for k, v in ms.items() if v > 500 and k != "erase_b"}
    lab.check(tag + ".cut", "no write waits for the side that is cut off (the erasure aside: documented to wait up to 2 s)", not slow and ms["erase_b"] < 3000,
              "ms per call %s" % ms, kill="waits")
    out["cut_writes_ms"], out["erase_answer"] = ms, je
    lab.check(tag + ".cut", "the erasure names the nodes it reached and the ones still open (PrivacyDeleteResult.nodes)",
              isinstance(je, dict) and set((je.get("nodes") or {}).get("open", [])) == set(x.name for x in side_a) and (je.get("nodes") or {}).get("reached") == [last.name],
              "nodes %s" % (je.get("nodes") if isinstance(je, dict) else je))
    local = {"A1 on A": [hget(x.proxy, "/", A1) for x in side_a], "A1 on B": hget(last.proxy, "/", A1), "B1 on B": hget(last.proxy, "/", B1), "B1 on A": [hget(x.proxy, "/", B1) for x in side_a]}
    lab.check(tag + ".cut", "a block acts on its own side at once and not on the other", local == {"A1 on A": [403] * len(side_a), "A1 on B": 200, "B1 on B": 403, "B1 on A": [200] * len(side_a)}, local)
    time.sleep(2.0)
    w = probe.window(t_cut)
    served_clean(lab, tag + ".cut", "during the cut (%.0f s): no client request waits or fails on either side" % (now() - t_cut), w)
    out["cut_probe"] = w
    # heal
    t_heal = now()
    net.clear()
    t, snaps = wait_same(ds, 30)
    out["heal_same_after_s"], out["heal_snapshots"] = t and round(now() - t_heal, 2), snaps
    metric(lab, "heal_converged", t and (now() - t_heal), "s", nodes=n)
    lab.check(tag + ".heal", "after the cut every node shows the same blocks, allowlist, limits and settings", t is not None,
              "same after %s s; %s" % (t and round(now() - t_heal, 2), diff_snaps(names, snaps)))
    s0 = snaps[0]
    want = {"blocks have A1 and B1": A1 in s0["blocks"] and B1 in s0["blocks"], "lifted P1 stays lifted": P1 not in s0["blocks"],
            "allowlist has A2 and B2": A2 in s0["allowlist"] and B2 in s0["allowlist"],
            "limits of both sides": "%s-side-a" % tag in s0["limits"] and "%s-side-b" % tag in s0["limits"],
            "events_days 21 (side A)": (s0["retention"] or {}).get("events_days") == 21,
            "summaries_days 111 (side B)": (s0["retention"] or {}).get("summaries_days") == 111}
    lab.check(tag + ".heal", "both sides keep their own changes to different entries", all(want.values()),
              "%s; retention %s" % ({k: v for k, v in want.items()}, s0["retention"]), kill="weakens")
    lab.check(tag + ".heal", "the same entry changed on both sides: the later change stands on every node",
              all((s["retention"] or {}).get("raw_ip_days") == 9 for s in snaps), "raw_ip_days %s (7 on side A, 1.5 s later 9 on side B)" % [(s["retention"] or {}).get("raw_ip_days") for s in snaps])
    sess = {}
    for nd in nodes:
        sess[nd.name] = (bool(Dash(nd, sess_a).session()[1].get("authenticated")), bool(Dash(nd, sess_b).session()[1].get("authenticated")))
    lab.check(tag + ".heal", "the logins made on either side during the cut are valid on every node", all(a and b for a, b in sess.values()),
              "(login of side A, login of side B) valid on %s" % sess, kill="weakens")
    r1, r2 = acts(nodes, A1, 403, 5), acts(nodes, B1, 403, 5)
    lab.check(tag + ".heal", "the blocks of both sides act on every node", all(v is not None for v in list(r1.values()) + list(r2.values())), "A1 %s, B1 %s" % (r1, r2), kill="weakens")
    tg = wait_for(lambda: all(d.privacy(E).get("events") == 0 for d in ds), 30, 0.2)
    ev = [d.privacy(E).get("events") for d in ds]
    lab.check(tag + ".heal", "the address erased on side B is gone on every node within 30 s of the heal", tg is not None,
              "events of the address per node %s, 0 everywhere after %s s" % (ev, tg and round(now() - t_heal, 1)), kill="erased")
    time.sleep(6.0)
    ev = [d.privacy(E).get("events") for d in ds]
    lab.check(tag + ".heal", "and it does not return (6 s later)", ev == [0] * n, "events per node %s" % ev, kill="erased")
    gs = {nm: d.call("GET", "/group")[1].get("state") for nm, d in byname.items()}
    lab.check(tag + ".heal", "GET /group is back to active on every node", all(v == "active" for v in gs.values()), gs)

    # ---- one direction only: nothing travels from the last node to the first, the other way is open
    t0 = probe.mark()
    net.rules([{"from": last.name, "to": first.name, "block": True}])
    seen = detect({first.name: d1}, last.name, 15)
    O1 = "203.0.113.%d" % (50 + idx0)
    block(lab, d1, O1)
    r = acts(nodes[1:], O1, 403, 8)
    O2 = "203.0.113.%d" % (60 + idx0)
    block(lab, dl, O2)
    r_back = acts(nodes[:-1], O2, 403, 8)
    w = probe.window(t0)
    served_clean(lab, tag + ".oneway", "one direction cut (%s to %s): no client request waits or fails" % (last.name, first.name), w)
    lab.check(tag + ".oneway", "%s notices that %s no longer answers" % (first.name, last.name), seen[first.name] is not None and seen[first.name] <= 5.0, "after %s s" % seen)
    if n > 2:
        lab.check(tag + ".oneway", "a block of %s still reaches %s by way of the third node" % (first.name, last.name), r[last.name] is not None, "seconds %s" % r)
        lab.check(tag + ".oneway", "a block of %s still reaches %s by way of the third node" % (last.name, first.name), r_back[first.name] is not None, "seconds %s" % r_back)
    else:
        lab.check(tag + ".oneway", "pair, one direction cut: what crosses meanwhile", None, "block of %s on %s: %s; block of %s on %s: %s" % (first.name, last.name, r, last.name, first.name, r_back))
    out["oneway"] = {"probe": w, "detect": seen, "forward": r, "back": r_back}
    net.clear()
    t, snaps = wait_same(ds, 20)
    lab.check(tag + ".oneway", "after it ends every node shows the same state", t is not None, "after %s s; %s" % (t and round(t, 2), diff_snaps(names, snaps)))

    # ---- connections refused and coming back, ten times, while both ends write
    t0 = probe.mark()
    made = []
    for i in range(10):
        net.rules([{"from": "*", "to": "*", "refuse": True}])
        a = "203.0.113.%d" % (100 + idx0 * 20 + i)
        block(lab, ds[i % n], a)
        made.append(a)
        time.sleep(0.5)
        net.clear()
        time.sleep(0.5)
    t, snaps = wait_same(ds, 20)
    w = probe.window(t0)
    served_clean(lab, tag + ".flap", "the links between the nodes break and return ten times within 10 s: no client request waits or fails", w)
    lab.check(tag + ".flap", "the ten blocks set meanwhile, on every node in turn, end up on every node", t is not None and all(set(made) <= set(s["blocks"]) for s in snaps),
              "same after %s s; %s" % (t and round(t, 2), diff_snaps(names, snaps)), kill="weakens")
    out["flap"] = {"probe": w, "same_after_s": t}

    # ---- readiness of a node that restarts while it is cut off
    net.partition(side_a, side_b)
    time.sleep(0.5)
    R1 = "203.0.113.%d" % (70 + idx0)
    block(lab, d1, R1)  # set on side A while the last node is away: it cannot know it
    last.kill9()
    last.start()
    trace, t0 = [], now()
    while now() - t0 < 16.0:
        code = hget(last.proxy, "/.schild/readyz", timeout=1.0)
        if not trace or trace[-1][1] != code:
            trace.append((round(now() - t0, 2), code))
        if code == 200:
            break
        time.sleep(0.05)
    t_ready = trace[-1][0] if trace[-1][1] == 200 else None
    kept = {"A1": hget(last.proxy, "/", A1), "B1": hget(last.proxy, "/", B1), "allowlisted B2 listed": B2 in (allow_all(dl) or []),
            "session": bool(dl.session()[1].get("authenticated"))}
    lab.check(tag + ".ready", "restarted while cut off from every member: 503 for about 10 s, then 200 (contract section 10)",
              t_ready is not None and 9.0 <= t_ready <= 13.0 and any(c == 503 for _, c in trace), "readyz over time (s, status): %s" % trace)
    lab.check(tag + ".ready", "and it serves with the state it had: blocks, allowlist, login", kept == {"A1": 403, "B1": 403, "allowlisted B2 listed": True, "session": True}, kept, kill="weakens")
    metric(lab, "ready_after_restart_cut_off", t_ready, "s", nodes=n)
    out["ready_cut_off"] = {"trace": trace, "kept": kept}
    net.clear()
    r = acts([last], R1, 403, 15)
    lab.check(tag + ".ready", "the block it missed acts on it once the cut ends", r[last.name] is not None, "after %s s" % r)

    # ---- readiness of a node that restarts while every peer is 300 ms away
    net.rules([{"from": "*", "to": "*", "delay_ms": 300}])
    last.kill9()
    R2 = "203.0.113.%d" % (80 + idx0)
    block(lab, d1, R2)
    last.start()
    trace, t0, at_ready = [], now(), None
    while now() - t0 < 30.0:
        code = hget(last.proxy, "/.schild/readyz", timeout=1.0)
        if not trace or trace[-1][1] != code:
            trace.append((round(now() - t0, 2), code))
        if code == 200:
            at_ready = hget(last.proxy, "/", R2)
            break
        time.sleep(0.02)
    lab.check(tag + ".ready", "restarted with peers 300 ms away: at its first ready answer the block set while it was down acts",
              at_ready == 403, "readyz over time %s; request of the blocked address at the first 200: %s" % (trace, at_ready), kill="weakens")
    metric(lab, "ready_after_restart_300ms", trace[-1][0] if trace[-1][1] == 200 else None, "s", nodes=n)
    out["ready_delay"] = {"trace": trace, "blocked_at_ready": at_ready}
    net.clear()

    # ---- a fresh node whose peers accept and never answer
    fresh_name = "%s%d" % (tag, n + 1)
    peers = ["127.0.0.1:%d" % x.via for x in nodes] + ["127.0.0.1:%d" % (lab.port0 + (idx0 + n) * 10 + 5)]
    fresh = HNode(lab, fresh_name, idx0 + n, {"secret_file": lab.secret(), "peers": peers, "advertise": peers[-1]})
    net.links([fresh])
    net.rules([{"from": fresh_name, "to": "*", "block": True}, {"from": "*", "to": fresh_name, "block": True}])
    fresh.start()
    trace, t0 = [], now()
    while now() - t0 < 14.0:
        code = hget(fresh.proxy, "/.schild/readyz", timeout=1.0)
        if not trace or trace[-1][1] != code:
            trace.append((round(now() - t0, 2), code))
        time.sleep(0.05)
    early = [t for t, c in trace if c == 200]
    lab.check(tag + ".fresh", "a fresh node that reached none of its named peers does not answer ready (contract section 10: it is not in step)",
              not early, "readyz over 14 s (s, status): %s" % trace)
    out["fresh_cut_off"] = trace
    net.clear()
    took = {"A1": hget(fresh.proxy, "/", A1), "session": bool(Dash(fresh, d1).session()[1].get("authenticated"))}
    out["fresh_served_without_state"] = took
    lab.check(tag + ".fresh", "what that node serves with while it answers ready and never reached a peer", None,
              "request of an address the group blocks: %s (the group answers 403); login of the group valid: %s" % (took["A1"], took["session"]))
    net.clear()
    r = acts([fresh], A1, 403, 30)
    lab.check(tag + ".fresh", "once its peers answer it takes the blocks of the group", r[fresh_name] is not None, "after %s s" % r)
    dsf = ds + [Dash(fresh, d1)]
    t, snaps = wait_same(dsf, 20)
    lab.check(tag + ".fresh", "the group of %d shows one state" % (n + 1), t is not None, "after %s s; %s" % (t and round(t, 2), diff_snaps(names + [fresh_name], snaps)))
    still = d1.session()[1].get("authenticated")
    lab.check(tag + ".fresh", "the first node keeps its login after the fresh node joined", bool(still), "session on %s: %s" % (first.name, still), kill="weakens")

    probe.finish()
    w = probe.window(t_base, names=names)
    out["probe_all"] = w
    lab.check(tag + ".all", "over the whole scenario: requests that failed or took over 250 ms on nodes that were up", None,
              "%d requests, %d failed (the restarts of %s included), slowest %s ms, p99 %s ms" % (w["n"], w["failed"], last.name, w["max_ms"], w["p99_ms"]))
    st = net.stats()
    out["proxy"] = {"opened": st["opened"], "unknown_callers": st["unknown_callers"]}
    lab.check(tag + ".all", "the proxy identified the calling node of every connection", st["unknown_callers"] == 0, "not identified: %d of %d" % (st["unknown_callers"], sum(st["opened"].values())))
    for nd in nodes + [fresh]:
        nd.kill9()


def run(lab):
    faults(lab, 3, 1, "t")
    faults(lab, 2, 6, "p")
