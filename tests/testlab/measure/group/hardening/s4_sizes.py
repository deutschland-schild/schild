"""Scenario 4: the two ends of the supported size, sixteen gateways and a pair. Start and time to converge, a
block set on one acts on all, several nodes lost at once, a rolling restart, a 17th gateway, and memory, CPU and
connections per node idle and under moderate load."""
import random
import time

from hard import (SEED, Dash, HNode, acts, count_events, count_requests, diff_snaps, first_setup, group, gstatus, hget, load_start, load_wait,
                  member_states, metric, now, resources, run_load, short_load, snapshot, wait_for, wait_group, wait_same)


def res_line(r):
    rss = sorted(v["rss_mb"] or 0 for v in r.values())
    cpu = sorted(v["cpu_percent"] or 0 for v in r.values())
    con = sorted(v["tcp_established"] for v in r.values())
    return "RSS MiB min %.0f, median %.0f, max %.0f; CPU %% min %.1f, median %.1f, max %.1f; established TCP connections min %d, median %d, max %d" % (
        rss[0], rss[len(rss) // 2], rss[-1], cpu[0], cpu[len(cpu) // 2], cpu[-1], con[0], con[len(con) // 2], con[-1])


def held(lab, ds):
    return [count_requests(d, lab.started - 120)[0] for d in ds]


def size(lab, n, idx0, tag, lose):
    rng = random.Random(SEED + n)
    out = lab.data.setdefault(tag, {})
    names = ["%s%02d" % (tag, i + 1) for i in range(n)]
    t_start = now()
    nodes = group(lab, names, idx0=idx0)
    ready, took = wait_group(lab, nodes, timeout=120, cid=tag + ".start")
    out["ready_s"], out["all_in_contact_s"] = ready, took
    metric(lab, "group_converged_after_start", took, "s", nodes=n)
    for r in ready:
        metric(lab, "ready_after_first_start", r, "s", nodes=n)
    ds = first_setup(lab, nodes, cid=tag + ".start")
    d1 = ds[0]
    t = wait_for(lambda: all(gstatus(d).get("state") == "active" for d in ds), 30, 0.3)
    lab.check(tag + ".start", "GET /group says active on each of the %d nodes" % n, t is not None, "after %s s; states %s" % (t and round(t, 1), sorted(set(gstatus(d).get("state") for d in ds))))
    time.sleep(12.0 if not lab.quick else 3.0)
    idle = resources(nodes)
    out["resources_idle"] = idle
    lab.check(tag + ".res", "%d nodes idle: memory, CPU and connections per node" % n, None, res_line(idle))
    for nd in nodes:
        metric(lab, "rss_idle", idle[nd.name]["rss_mb"], "count", nodes=n, node=nd.name, what="MiB")
        metric(lab, "tcp_established_idle", idle[nd.name]["tcp_established"], "count", nodes=n, node=nd.name)

    # ---- a block set on one acts on all
    times, lifts, missed = [], [], 0
    for i in range(4 if lab.quick else 12):
        a = "203.0.113.%d" % (10 + i)
        k = rng.randrange(n)
        st, js = ds[k].block(a)
        r = acts([nd for j, nd in enumerate(nodes) if j != k], a, 403, 10)
        times += [v for v in r.values() if v is not None]
        missed += sum(1 for v in r.values() if v is None)
        if i % 2 == 0:
            j = (k + 1) % n
            wait_for(lambda: ds[j].call("GET", "/incidents/%s" % js["incident"])[0] == 200, 10, 0.02)
            ds[j].unblock(js["incident"])
            r = acts([nd for x, nd in enumerate(nodes) if x != j], a, 200, 10)
            lifts += [v for v in r.values() if v is not None]
            missed += sum(1 for v in r.values() if v is None)
    times.sort()
    lifts.sort()
    p95 = times[max(0, int(round(0.95 * len(times) + 0.5)) - 1)] if times else None
    lab.check(tag + ".block", "a block set on one of %d nodes acts on every other within 1 s at p95; a lift on another node too" % n, missed == 0 and p95 is not None and p95 <= 1.0,
              "%d samples of a block: p50 %s s, p95 %s s, max %s s; %d samples of a lift: p50 %s s, max %s s; never seen within 10 s: %d (each node is asked in turn, so a sample carries up to %d polls of delay)" % (
                  len(times), times[len(times) // 2] if times else None, p95, times[-1] if times else None, len(lifts), lifts[len(lifts) // 2] if lifts else None, lifts[-1] if lifts else None, missed, n))
    metric(lab, "block_propagation_p95", p95, "s", len(times), nodes=n)
    metric(lab, "block_propagation_max", times[-1] if times else None, "s", len(times), nodes=n)
    out["block_s"] = {"p50": times[len(times) // 2] if times else None, "p95": p95, "max": times[-1] if times else None, "missed": missed}
    # settings, allowlist, limit
    k = rng.randrange(n)
    ds[k].call("PATCH", "/settings", {"retention": {"events_days": 40 + n}})
    ds[(k + 1) % n].call("POST", "/allowlist", {"ip": "192.0.2.%d" % (100 + n), "label": "size", "level": "no_block"})
    st, _ = ds[(k + 2) % n].call("POST", "/behaviour/rate-limits", {"route": "/rl/**", "limit": 60, "per": "1m", "burst": 60, "mode": "block", "label": "size-limit"})
    t, snaps = wait_same(ds, 20)
    s0 = snaps[0]
    lab.check(tag + ".state", "a setting, an allowlist entry and a rate limit made on three different nodes are on all %d" % n,
              t is not None and (s0["retention"] or {}).get("events_days") == 40 + n and "192.0.2.%d" % (100 + n) in s0["allowlist"] and "size-limit" in s0["limits"],
              "same after %s s; %s" % (t and round(t, 2), diff_snaps(names, snaps)))
    metric(lab, "state_converged", t, "s", nodes=n)
    time.sleep(1.5)

    # ---- the limit for a client that spreads over every node
    one = run_load(lab, nodes[:1], 20, 15, tag + "-rl-one", conns=2, ips=1, ipnet="10.71", spread=True, fixed_path="/rl/a")
    alln = run_load(lab, nodes, 20, 15, tag + "-rl-all", conns=2, ips=1, ipnet="10.72", spread=True, fixed_path="/rl/a")
    p1, pn = one["status"].get("200", 0), alln["status"].get("200", 0)
    lab.check(tag + ".limit", "a limit of 60 a minute, one client at 20 requests a second spread over %d nodes: at most what one node lets pass plus one second of requests" % n,
              one["status"].get("429", 0) > 0 and pn <= p1 + 20, "one node: %d of %d passed; %d nodes: %d of %d passed; bound %d + 20" % (p1, one["sent"], n, pn, alln["sent"], p1))
    metric(lab, "rate_limit_passed", pn, "count", alln["sent"], nodes=n, spread="all")
    metric(lab, "rate_limit_passed", p1, "count", one["sent"], nodes=n, spread="one")
    out["limit"] = {"one_node": one["status"], "all_nodes": alln["status"]}

    # ---- moderate load: 100 requests a second per node
    rps, dur = 100 * n, (10 if lab.quick else 40)
    time.sleep(5.0)  # the requests of the limit runs have reached every node before the count
    before = held(lab, ds)
    lh = load_start(lab, nodes, rps, dur, tag + "-mod", conns=8, ips=300, ipnet="10.73", path="/mod", attack_every=100)
    time.sleep(dur * 0.6)
    under = resources(nodes)
    r = load_wait(lh)
    out["moderate_load"], out["resources_load"] = short_load(r), under
    lab.check(tag + ".load", "%d requests a second over %d nodes for %d s: no request fails" % (rps, n, dur), r["failed"] == 0,
              "achieved %.0f a second, %d sent, %d failed, statuses %s; p50 %s ms, p99 %s ms, max %s ms" % (
                  r["rps_achieved"], r["sent"], r["failed"], r["status"], r["latency_ms"].get("p50"), r["latency_ms"].get("p99"), r["latency_ms"].get("max")), kill="waits")
    lab.check(tag + ".res", "%d nodes under %d requests a second: memory, CPU and connections per node" % (n, rps), None, res_line(under))
    for nd in nodes:
        metric(lab, "rss_under_load", under[nd.name]["rss_mb"], "count", nodes=n, node=nd.name, what="MiB")
        metric(lab, "cpu_under_load", under[nd.name]["cpu_percent"], "percent", nodes=n, node=nd.name)
    metric(lab, "latency_p50", r["latency_ms"].get("p50"), "ms", r["sent"], nodes=n, rps=rps)
    metric(lab, "latency_p99", r["latency_ms"].get("p99"), "ms", r["sent"], nodes=n, rps=rps)
    want = r["sent"] - r["failed"]
    got = []
    t = wait_for(lambda: (got.clear() or got.extend(b - a for a, b in zip(before, held(lab, ds)))) or (len(set(got)) == 1 and got[0] >= want), 60, 2.0)
    lab.check(tag + ".load", "afterwards each of the %d nodes holds every request of that load" % n, t is not None,
              "answered %d; held per node (min %s, max %s)%s; all equal after %s s" % (want, min(got), max(got), "" if t is not None else " %s" % got, t and round(t, 1)))
    out["held_after_load"] = {"answered": want, "held": list(got)}
    ev = [count_events(d, "/mod", outcome="blocked") for d in ds]
    lab.check(tag + ".load", "and lists every blocked event of it", len(set(ev)) == 1 and ev[0] == r["status"].get("403", 0), "attacks answered 403: %d; blocked events per node min %s, max %s" % (
        r["status"].get("403", 0), min(ev), max(ev)))

    # ---- several nodes lost at once, under load that follows readiness like a balancer
    lost_idx = sorted(rng.sample(range(1, n), lose))
    lost = [nodes[i] for i in lost_idx]
    alive = [nd for nd in nodes if nd not in lost]
    alive_ds = [d for nd, d in zip(nodes, ds) if nd not in lost]
    E = "198.51.100.%d" % (100 + n)
    for nd in nodes:
        hget(nd.proxy, "/er?q=%3Cscript%3Ealert(1)%3C/script%3E", E)
    wait_for(lambda: all(d.privacy(E).get("events", 0) >= n for d in ds), 20, 0.3)
    ev_before = [d.privacy(E).get("events") for d in ds]
    snap_before = snapshot(alive_ds[0])
    lh = load_start(lab, nodes, 50 * n, 20, tag + "-lose", conns=8, ips=300, ipnet="10.74", path="/lose", health=True)
    time.sleep(5.0)
    t_kill = now()
    for nd in lost:
        nd.proc.kill()
    for nd in lost:
        nd.proc.wait()
    seen = {}
    while now() - t_kill < 15 and len(seen) < len(alive):
        for nd, d in zip(alive, alive_ds):
            if nd.name not in seen:
                ms = member_states(d)
                if all(ms.get(x.name) != "ok" for x in lost):
                    seen[nd.name] = round(now() - t_kill, 2)
        time.sleep(0.05)
    K = "203.0.113.%d" % (60 + n % 50)
    st, js = alive_ds[-1].block(K)
    r_block = acts(alive, K, 403, 8)
    st_e, js_e = alive_ds[0].call("POST", "/privacy/delete", {"ip": E, "confirm": True})
    r = load_wait(lh)
    tl = r.get("timeline_answered_failed") or []
    failed_alive = sum(sum(tl[i][1::2]) for i in range(n) if i not in lost_idx)
    failed_lost = sum(sum(tl[i][1::2]) for i in lost_idx)
    states = sorted(set(gstatus(d).get("state") for d in alive_ds))
    out["lost"] = {"nodes": [x.name for x in lost], "noticed_s": seen, "load": short_load(r), "failed_on_survivors": failed_alive, "failed_on_lost": failed_lost,
                   "block_s": r_block, "erase": js_e, "states": states}
    lab.check(tag + ".lose", "%d of %d nodes killed at once (kill -9) under %d requests a second: no request to a surviving node fails" % (lose, n, 50 * n), failed_alive == 0,
              "failed on survivors %d, on the killed nodes %d (in flight or sent before the client's health check saw it), of %d; p99 %s ms, max %s ms" % (
                  failed_alive, failed_lost, r["sent"], r["latency_ms"].get("p99"), r["latency_ms"].get("max")), kill="waits")
    lab.check(tag + ".lose", "every survivor notices that the nodes are gone (a stopped node: at once)", len(seen) == len(alive) and max(seen.values()) <= 5.0,
              "seconds until GET /group lists none of them as ok: min %s, max %s; group state on the survivors %s" % (min(seen.values()) if seen else None, max(seen.values()) if seen else None, states))
    want_state = "interrupted" if len(alive) == 1 else "degraded"
    lab.check(tag + ".lose", "the survivors say '%s' and keep their state" % want_state, states == [want_state] and dict(snapshot(alive_ds[0]), blocks=None) == dict(snap_before, blocks=None),
              "states %s; allowlist, limits and settings unchanged: %s" % (states, dict(snapshot(alive_ds[0]), blocks=None) == dict(snap_before, blocks=None)), kill="weakens")
    lab.check(tag + ".lose", "a block set on a survivor acts on every survivor", all(v is not None for v in r_block.values()), "seconds max %s" % max((v for v in r_block.values() if v is not None), default=None))
    nodes_e = (js_e or {}).get("nodes") or {} if isinstance(js_e, dict) else {}
    extra_open = sorted(set(nodes_e.get("open", [])) - set(x.name for x in lost))
    lab.check(tag + ".lose", "an erasure made meanwhile names every lost node as open", st_e == 200 and set(x.name for x in lost) <= set(nodes_e.get("open", [])),
              "status %s, reached %d, open %s; of these running and reachable: %s (documented: open also means slow; the answer waits at most 2 s)" % (
                  st_e, len(nodes_e.get("reached", [])), nodes_e.get("open"), extra_open or "none"))
    out["erase_open_but_alive"] = extra_open
    tg = wait_for(lambda: all(d.privacy(E).get("events") == 0 for d in alive_ds), 30, 0.3)
    lab.check(tag + ".lose", "the erased address is gone on every survivor within 30 s", tg is not None, "events before %s; gone after %s s" % (ev_before[:4], tg and round(tg, 1)), kill="erased")
    # they return
    t0 = now()
    for nd in lost:
        nd.start()
    rdy = [nd.wait_ready(60) for nd in lost]
    at_ready = {nd.name: hget(nd.proxy, "/", K) for nd in lost}
    ev_ready = {nd.name: d.privacy(E).get("events") for nd, d in zip(nodes, ds) if nd in lost}
    lab.check(tag + ".return", "the %d nodes return: ready, and at that moment the block set meanwhile acts on each" % lose, all(rdy) and all(v == 403 for v in at_ready.values()),
              "ready after %s s; request of the blocked address at ready %s" % ([r_ and round(r_, 2) for r_ in rdy], at_ready), kill="weakens")
    for r_ in rdy:
        metric(lab, "ready_after_return", r_, "s", nodes=n)
    lab.check(tag + ".return", "the address erased while they were away is not on them when they are ready", all(v == 0 for v in ev_ready.values()), "events of the address at ready %s" % ev_ready, kill="erased")
    t, snaps = wait_same(ds, 40)
    ta = wait_for(lambda: all(gstatus(d).get("state") == "active" for d in ds), 40, 0.3)
    lab.check(tag + ".return", "all %d nodes show one state and say active again" % n, t is not None and ta is not None, "same after %s s, active after %s s since the restart; %s" % (
        t and round(t, 1), ta and round(now() - t0, 1), diff_snaps(names, snaps)))
    time.sleep(6.0)
    ev_all = [d.privacy(E).get("events") for d in ds]
    lab.check(tag + ".return", "the erased address does not return on any node (6 s later)", all(v == 0 for v in ev_all), "events per node %s" % sorted(set(ev_all)), kill="erased")

    # ---- every node restarted in turn (SIGTERM, drain) under load that follows readiness
    snap_before = snapshot(d1)
    dur = n * 12 + 8
    lh = load_start(lab, nodes, 50 * n, dur, tag + "-roll", conns=8, ips=300, ipnet="10.75", path="/roll", health=True)
    time.sleep(2.0)
    t0, steps = now(), []
    for nd in nodes:
        ts = now()
        nd.term()
        gone = nd.wait_exit(30)
        nd.start()
        rr = nd.wait_ready(60)
        steps.append((nd.name, gone, round(now() - ts, 1), rr and round(rr, 2)))
        time.sleep(0.5)
    took = now() - t0
    r = load_wait(lh)
    out["rolling"] = {"steps": steps, "took_s": round(took, 1), "load": short_load(r), "first_failures": (r.get("first_failures") or [])[:10]}
    lab.check(tag + ".rolling", "all %d nodes stopped (SIGTERM, drain 2 s) and started in turn under %d requests a second that follow readyz: no request fails" % (n, 50 * n),
              r["failed"] == 0 and all(s[1] and s[3] for s in steps), "took %.0f s; %d sent, %d failed, statuses %s; per node (name, stopped, seconds down and up, ready after): %s; first failures %s" % (
                  took, r["sent"], r["failed"], r["status"], steps[:4], (r.get("first_failures") or [])[:4]), kill="waits")
    metric(lab, "rolling_restart_failed_requests", r["failed"], "count", r["sent"], nodes=n)
    metric(lab, "rolling_restart_took", took, "s", nodes=n)
    t, snaps = wait_same(ds, 40)
    sess = all(bool(d.session()[1].get("authenticated")) for d in ds)
    lab.check(tag + ".rolling", "afterwards the state is the same on every node and as before, the login valid", t is not None and snaps[0] == snap_before and sess,
              "%s; equal to before %s; sessions valid %s" % (diff_snaps(names, snaps), snaps[0] == snap_before, sess), kill="weakens")

    # ---- one gateway more than the bound (16 only)
    if n == 16:
        extra = HNode(lab, "%s17" % tag, idx0 + n, {"secret_file": lab.secret(), "peers": nodes[0].cluster["peers"] + ["127.0.0.1:%d" % (lab.port0 + (idx0 + n) * 10 + 4)]})
        extra.start()
        time.sleep(14.0)
        gateways = [m for m in gstatus(d1).get("members", []) if m.get("role") == "gateway" and m.get("state") != "removed"]
        rz = hget(extra.proxy, "/.schild/readyz")
        lines = [l[-260:] for l in extra.loglines(r"409|at most|too many|16 gateways|refus")][:2]
        blocked = hget(extra.proxy, "/", K)
        lab.check(tag + ".bound", "a 17th gateway is not taken into the group (contract section 13)", len(gateways) == 16 and extra.name not in [m["name"] for m in gateways],
                  "gateways in the member list of %s: %d; the 17th: process %s, readyz %s, a request of an address the group blocks is answered %s; its log: %s" % (
                      nodes[0].name, len(gateways), "runs" if extra.alive() else "exited", rz, blocked, lines or "no line that names the bound"))
        lab.check(tag + ".bound", "the refused 17th gateway does not answer ready (it holds none of the group's blocks)", rz != 200,
                  "readyz %s after 14 s, request of a blocked address %s" % (rz, blocked))
        out["seventeenth"] = {"gateways": len(gateways), "readyz": rz, "blocked_address": blocked, "log": lines}
        extra.kill9()
    final = resources(nodes)
    out["resources_end"] = final
    lab.check(tag + ".res", "%d nodes at the end of the scenario" % n, None, res_line(final))
    for nd in nodes:
        nd.kill9()


def run(lab):
    size(lab, 16, 1, "w", 5)
    size(lab, 2, 20, "q", 1)
