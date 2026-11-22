"""Scenario 6: clock differences. One of three gateways runs with another wall clock: 30 s ahead (inside the 60 s
the contract allows), 120 s ahead and 120 s behind. The clock is given to that one process by a small library
(clockshim/shim.c) loaded with DYLD_INSERT_LIBRARIES, which shifts CLOCK_REALTIME; no root, macOS only."""
import os
import re
import time

from hard import (Dash, Probe, acts, count_requests, diff_snaps, first_setup, group, gstatus, hget, member_states, metric, now, served_clean,
                  snapshot, wait_for, wait_group, wait_same)

ATTACK = "?q=%3Cscript%3Ealert(1)%3C/script%3E"


def counters(d):
    return gstatus(d).get("counters")


def run(lab):
    shim = lab.extra_bins.get("clock_shim")
    if not shim or not os.path.exists(shim):
        lab.check("k", "clock differences between nodes", None, "NOT MEASURED: no clock shim built (run.sh builds clockshim/shim.c on macOS with cc)")
        return
    out = lab.data
    names = ["k1", "k2", "k3"]
    nodes = group(lab, names)
    wait_group(lab, nodes, cid="k.setup")
    ds = first_setup(lab, nodes, cid="k.setup")
    n1, n2, n3 = nodes
    d1, d2, d3 = ds
    probe = Probe(nodes)
    seq = [0]

    def addr():
        seq[0] += 1
        return "203.0.113.%d" % (9 + seq[0])

    def skew(ms, tag):
        n3.kill9()
        n3.start(env={"DYLD_INSERT_LIBRARIES": shim, "SG27H_CLOCK_OFFSET_MS": str(ms)})
        r = n3.wait_ready(40)
        st, js = d3.call("GET", "/group")
        seen = (js or {}).get("generated_at")
        real = time.time()
        off = None
        try:
            off = round(time.mktime(time.strptime(seen, "%Y-%m-%dT%H:%M:%SZ")) - time.timezone - real)
        except Exception:
            pass
        lab.check(tag, "k3 runs with its clock %+d s (its GET /group names the time it believes)" % (ms // 1000), r is not None and off is not None and abs(off - ms / 1000.0) <= 3,
                  "ready after %s s; generated_at %s is %s s from this machine's clock" % (r and round(r, 2), seen, off))
        return r

    def both_ways(tag, wait=8.0):
        a, b = addr(), addr()
        t0 = now()
        d3.block(a)
        from3 = acts([n1, n2], a, 403, wait)
        d1.block(b)
        to3 = acts([n3], b, 403, wait)
        return a, b, from3, to3, t0

    # ---- 30 s ahead: inside what the contract allows
    t0 = probe.mark()
    skew(30000, "k.plus30")
    a, b, from3, to3, _ = both_ways("k.plus30")
    lab.check("k.plus30", "clock of k3 30 s ahead: a block of k3 acts on the others and a block of k1 acts on k3", all(v is not None for v in list(from3.values()) + list(to3.values())),
              "block of k3 on k1, k2 after %s s; block of k1 on k3 after %s s" % (from3, to3))
    # a lift made later in real time than the block of the node whose clock runs ahead
    c = addr()
    st, js = d3.block(c)
    acts([n1, n2], c, 403, 8)
    wait_for(lambda: d1.call("GET", "/incidents/%s" % js["incident"])[0] == 200, 10, 0.05)
    st_u, _ = d1.unblock(js["incident"])
    lifted = acts(nodes, c, 200, 8)
    time.sleep(3.0)
    still = {nd.name: hget(nd.proxy, "/", c) for nd in nodes}
    lab.check("k.plus30", "a block set on k3 (clock ahead) and lifted on k1 two seconds later stays lifted everywhere", st_u == 200 and all(v == 200 for v in still.values()),
              "unblock %s; passes after %s s; 3 s later %s" % (st_u, lifted, still))
    # the same setting: k3 first, k1 later in real time
    d3.call("PATCH", "/settings", {"retention": {"raw_ip_days": 5}})
    time.sleep(2.0)
    st1, _ = d1.call("PATCH", "/settings", {"retention": {"raw_ip_days": 6}})
    time.sleep(3.0)
    vals = [(d.call("GET", "/settings")[1].get("retention") or {}).get("raw_ip_days") for d in ds]
    lab.check("k.plus30", "the same setting changed on k3 (clock 30 s ahead) and 2 s later on k1: the later change in real time stands", vals == [6, 6, 6],
              "PATCH on k1 answered %s; raw_ip_days on k1, k2, k3 three seconds later: %s (5 was set on k3 first, 6 on k1 after it)" % (st1, vals))
    out["plus30_setting"] = vals
    rc, txt = n1.cli("cluster", "status")
    lab.check("k.plus30", "`schild cluster status` reports a skew over 5 s (spec, merge)", bool(re.search(r"(?i)skew|clock|uhr", txt.split("Since the start")[0])),
              "status of k1 names no clock difference; its lines: %s" % [l for l in txt.splitlines() if re.search(r"(?i)skew|clock", l)])
    t, snaps = wait_same(ds, 20)
    lab.check("k.plus30", "the three nodes show the same state", t is not None, diff_snaps(names, snaps))
    w = probe.window(t0, names=["k1", "k2"])
    served_clean(lab, "k.plus30", "no client request waits or fails on the two nodes with the right clock", w)

    # ---- 120 s ahead: beyond the 60 s of the contract (check 4: such a record is put off and asked for again)
    t0 = probe.mark()
    skew(120000, "k.plus120")
    c_before = counters(d1)
    a, b, from3, to3, t_set = both_ways("k.plus120", wait=6.0)
    lab.check("k.plus120", "clock of k3 120 s ahead: a block of k1 acts on k3", to3["k3"] is not None, "after %s s" % to3)
    E = "198.51.100.210"
    for nd in nodes:
        for i in range(3):
            hget(nd.proxy, "/skew/%d%s" % (i, ATTACK), E)
    time.sleep(3.0)
    ev_before = [d.privacy(E).get("events") for d in ds]
    t_erase = now()
    st_e, js_e = d3.call("POST", "/privacy/delete", {"ip": E, "confirm": True})
    late = acts([n1, n2], a, 403, 100) if any(v is None for v in from3.values()) else from3
    t_block = round(now() - t_set, 1)
    c_after = counters(d1)
    lab.check("k.plus120", "a block set on k3 (120 s ahead) on the two others: put off while its clock is more than 60 s ahead, never lost", all(v is not None for v in late.values()),
              "within 6 s: %s; then acts after about %s s; counters of k1 before %s, after %s" % (from3, t_block, c_before, c_after), kill="weakens")
    metric(lab, "block_of_node_120s_ahead_acts_after", t_block if any(v is None for v in from3.values()) else max(from3.values()), "s")
    tg = wait_for(lambda: d1.privacy(E).get("events") == 0 and d2.privacy(E).get("events") == 0, 120, 0.5)
    t_gone = round(now() - t_erase, 1)
    lab.check("k.plus120", "an address erased on k3 (120 s ahead) is gone on the two reachable others within 30 s (spec, must)", tg is not None and t_gone <= 30,
              "events before %s; erasure answered %s with nodes %s; gone on k1 and k2 after %s s" % (ev_before, st_e, (js_e or {}).get("nodes") if isinstance(js_e, dict) else js_e, t_gone if tg is not None else "more than 120"))
    metric(lab, "erasure_of_node_120s_ahead_gone_after", t_gone if tg is not None else None, "s")
    # the requests k3 serves carry a time two minutes ahead
    base = [count_requests(d, lab.started - 120, time.time() + 600)[0] for d in ds]
    for i in range(300):
        hget(n3.proxy, "/ahead/%d" % (i % 10), "10.90.0.%d" % (i % 100 + 1))
    time.sleep(8.0)
    got = [count_requests(d, lab.started - 120, time.time() + 600)[0] for d in ds]
    delta = [g - b if isinstance(g, int) and isinstance(b, int) else None for g, b in zip(got, base)]
    lab.check("k.plus120", "requests served by k3 while its clock is 120 s ahead (300 and the probe's), 8 s later", None,
              "held more than before by k1, k2, k3: %s; the two others lack %s of what k3 holds (contract section 9: a node stores a request of another only when its time is not more than a minute ahead)" % (
                  delta, [delta[2] - x for x in delta[:2]] if all(x is not None for x in delta) else "?"))
    out["plus120"] = {"block_within_6s": from3, "block_after_s": t_block, "erasure_gone_s": t_gone if tg is not None else None, "requests_delta": delta, "counters": [c_before, c_after]}
    time.sleep(125.0 if not lab.quick else 5.0)
    got2 = [count_requests(d, lab.started - 120, time.time() + 600)[0] for d in ds]
    delta2 = [g - b if isinstance(g, int) and isinstance(b, int) else None for g, b in zip(got2, base)]
    lack2 = [delta2[2] - x for x in delta2[:2]] if all(x is not None for x in delta2) else None
    lab.check("k.plus120", "once the clocks of the others have passed the time of those requests (125 s later), they hold what k3 served", lack2 is not None and max(lack2) <= 0,
              "held more than before by k1, k2, k3: %s; k1 and k2 lack %s of the requests k3 holds (every node sent the probe's requests at the same rate, so equal numbers are expected)" % (delta2, lack2))
    metric(lab, "requests_of_node_120s_ahead_missing_on_others", max(lack2) if lack2 else None, "count")
    out["plus120"]["requests_delta_later"] = delta2
    w = probe.window(t0, names=["k1", "k2"])
    served_clean(lab, "k.plus120", "no client request waits or fails on the two nodes with the right clock", w)

    # ---- 120 s behind
    t0 = probe.mark()
    r = skew(-120000, "k.minus120")
    c_before = counters(d3)
    a, b, from3, to3, t_set = both_ways("k.minus120", wait=6.0)
    lab.check("k.minus120", "clock of k3 120 s behind: a block of k3 acts on the others", all(v is not None for v in from3.values()), "after %s s" % from3)
    late = acts([n3], b, 403, 100) if to3["k3"] is None else to3
    t_block = round(now() - t_set, 1)
    c_after = counters(d3)
    lab.check("k.minus120", "a block set on k1 on k3 (120 s behind): put off while k1's clock is more than 60 s ahead of k3's, never lost", late["k3"] is not None,
              "within 6 s: %s; then acts after about %s s; counters of k3 before %s, after %s" % (to3, t_block, c_before, c_after), kill="weakens")
    metric(lab, "block_on_node_120s_behind_acts_after", t_block if to3["k3"] is None else to3["k3"], "s")
    # a node that restarts behind: is it ready before it holds what the group set in the last minute?
    f = addr()
    n3.kill9()
    d1.block(f)
    n3.start(env={"DYLD_INSERT_LIBRARIES": shim, "SG27H_CLOCK_OFFSET_MS": "-120000"})
    rdy = n3.wait_ready(40)
    at_ready = hget(n3.proxy, "/", f)
    t_acts = acts([n3], f, 403, 100) if at_ready != 403 else {"k3": 0.0}
    lab.check("k.minus120", "k3 restarts 120 s behind: at its first ready answer the block set on k1 while it was down acts", at_ready == 403,
              "ready after %s s; request of the blocked address at ready %s; acts %s s after ready" % (rdy and round(rdy, 2), at_ready, t_acts["k3"]))
    out["minus120"] = {"block_within_6s": to3, "block_after_s": t_block, "ready_s": rdy, "blocked_at_ready": at_ready, "acts_after_ready_s": t_acts["k3"]}
    w = probe.window(t0, names=["k1", "k2"])
    served_clean(lab, "k.minus120", "no client request waits or fails on the two nodes with the right clock", w)

    # ---- back to the right clock
    n3.kill9()
    n3.start()
    n3.wait_ready(40)
    t, snaps = wait_same(ds, 150)
    lab.check("k.end", "k3 back on the right clock: the three nodes show the same state", t is not None, "after %s s; %s" % (t and round(t, 1), diff_snaps(names, snaps)))
    probe.finish()
    for nd in nodes:
        nd.kill9()
