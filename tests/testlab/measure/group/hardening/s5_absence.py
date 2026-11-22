"""Scenario 5: a long absence. One of three gateways is away while the others set and lift blocks, change settings,
remove an allowlist entry, end a login, erase an address and serve more requests than the log in memory holds
(32 768 per node); one of them restarts meanwhile. Then it returns."""
import random
import re
import time

from hard import (SEED, allow_all, Dash, acts, count_events, count_requests, diff_snaps, first_setup, group, hget, load_start, load_wait, metric, now,
                  requests_of_ip, run_load, short_load, snapshot, wait_for, wait_group, wait_same)
from s3_load import RING

ATTACK = "?q=%3Cscript%3Ealert(1)%3C/script%3E"


def held(lab, ds):
    return [count_requests(d, lab.started - 120)[0] for d in ds]


def run(lab):
    out = lab.data
    rng = random.Random(SEED)
    names = ["a1", "a2", "a3"]
    nodes = group(lab, names, extra=RING)
    wait_group(lab, nodes, cid="a.setup")
    ds = first_setup(lab, nodes, cid="a.setup")
    n1, n2, n3 = nodes
    d1, d2, d3 = ds
    t_begin = time.time() - 2

    # ---- before the absence
    E = "198.51.100.200"
    for nd in nodes:
        for i in range(10):
            hget(nd.proxy, "/before/%d%s" % (i, ATTACK if i < 4 else ""), E)
    B0, B1, B2, B3, B4 = ("203.0.113.%d" % i for i in (10, 11, 12, 13, 14))
    inc0 = d1.block(B0)[1]["incident"]
    st, a0 = d1.call("POST", "/allowlist", {"ip": "192.0.2.10", "label": "to be removed while a3 is away", "level": "no_block"})
    old_sess = Dash(n2)
    old_sess.login()
    wait_for(lambda: all(d.privacy(E).get("events", 0) >= 12 for d in ds) and Dash(n3, old_sess).session()[1].get("authenticated"), 20, 0.3)
    time.sleep(3.0)
    e_before = {"events": [d.privacy(E).get("events") for d in ds], "requests": [len(requests_of_ip(d, E, t_begin) or []) for d in ds]}
    lab.check("a.before", "before the absence every node holds the events (12 refused attacks and more) and the 30 requests of the address that will be erased", min(e_before["events"]) >= 12 and len(set(e_before["events"])) == 1 and e_before["requests"] == [30] * 3,
              "events %s, requests by address %s" % (e_before["events"], e_before["requests"]))
    base = held(lab, ds)
    n3.kill9()
    t_away = now()

    # ---- while a3 is away
    d1.block(B1)
    inc2 = d2.block(B2)[1]["incident"]
    d1.block(B3)
    d2.block(B4)
    st_u0 = d1.unblock(inc0)[0]
    known = wait_for(lambda: d1.call("GET", "/incidents/%s" % inc2)[0] == 200, 10, 0.05)
    st_u2, js_u2 = d1.unblock(inc2)
    lifted_now = {"B0": [hget(n.proxy, "/", B0) for n in (n1, n2)], "B2": [hget(n.proxy, "/", B2) for n in (n1, n2)]}
    time.sleep(1.5)
    lifted_now["B2 after 1.5 s"] = [hget(n.proxy, "/", B2) for n in (n1, n2)]
    out["lifts"] = {"unblock_B0": st_u0, "incident_of_a2_known_on_a1_s": known, "unblock_B2_on_a1": [st_u2, js_u2 if st_u2 != 200 else "ok"], "requests": lifted_now}
    lab.check("a.away", "a block set on a2 and lifted on a1 a moment later, and a lift of an older block: both addresses pass on a1 and a2", st_u0 == 200 and st_u2 == 200
              and lifted_now["B0"] == [200, 200] and lifted_now["B2 after 1.5 s"] == [200, 200],
              "unblock of the older block %s; incident of a2's block known on a1 after %s s; unblock on a1 answered %s; requests of the addresses on a1, a2: %s" % (
                  st_u0, known and round(known, 2), st_u2, lifted_now))
    d1.call("PATCH", "/settings", {"retention": {"events_days": 55}})
    d2.call("PATCH", "/settings", {"retention": {"summaries_days": 222}})
    d2.call("POST", "/behaviour/rate-limits", {"route": "/away/**", "limit": 100, "per": "1m", "burst": 100, "mode": "block", "label": "made-while-away"})
    d1.call("POST", "/allowlist", {"ip": "192.0.2.11", "label": "made while away", "level": "no_block"})
    st_del = d2.call("DELETE", "/allowlist/%s" % a0.get("id"))[0] if isinstance(a0, dict) else "no id"
    new_sess = Dash(n1)
    new_sess.login()
    st_out = old_sess.call("POST", "/auth/logout")[0]
    st_e, js_e = d1.call("POST", "/privacy/delete", {"ip": E, "confirm": True})
    lab.check("a.away", "the changes made while a3 is away are answered", st_del in (200, 204) and st_out in (200, 204) and st_e == 200,
              "allowlist removal %s, logout %s, erasure %s with nodes %s" % (st_del, st_out, st_e, (js_e or {}).get("nodes") if isinstance(js_e, dict) else js_e))
    # more requests per node than its log in memory holds
    per_node = 6000 if lab.quick else 45000
    rps = 2000
    r1 = run_load(lab, [n1, n2], rps, 2 * per_node / float(rps), "away1", conns=48, ips=2000, ipnet="10.80", path="/away1", attack_every=100, per_ip=True)
    # one of the two restarts meanwhile (planned stop: SIGTERM), then both serve some more
    n1.term()
    n1.wait_exit(30)
    n1.start()
    r_n1 = n1.wait_ready(40)
    r2 = run_load(lab, [n1, n2], 1000, 5 if lab.quick else 10, "away2", conns=24, ips=500, ipnet="10.81", path="/away2", per_ip=True)
    served = r1["sent"] - r1["failed"] + r2["sent"] - r2["failed"]
    time.sleep(4.0)
    mid = held(lab, ds[:2])
    away_s = now() - t_away
    out["away"] = {"seconds": round(away_s, 1), "load1": short_load(r1), "load2": short_load(r2), "a1_restart_ready_s": r_n1, "held_a1_a2": mid, "base": base}
    lab.check("a.away", "a1 and a2 each served more than 32 768 requests while a3 was away and hold all of them", r1["failed"] == 0 and r2["failed"] == 0
              and (lab.quick or served / 2 > 32768) and mid[0] == mid[1] and mid[0] - base[0] >= served,
              "served by the two: %d (%d each, failed %d); held more than before by a1, a2: %s; away for %.0f s; a1 was stopped and started in between (ready after %s s)" % (
                  served, served // 2, r1["failed"] + r2["failed"], [m - b for m, b in zip(mid, base)], away_s, r_n1 and round(r_n1, 1)))

    # ---- it returns
    mark = n3.logsize()
    t_back = now()
    n3.start()
    rdy = n3.wait_ready(60)
    at_ready = {"B1": hget(n3.proxy, "/", B1), "B3": hget(n3.proxy, "/", B3), "B4": hget(n3.proxy, "/", B4), "B0 lifted": hget(n3.proxy, "/", B0), "B2 lifted": hget(n3.proxy, "/", B2),
                "events of the erased address": d3.privacy(E).get("events"), "ended login valid": bool(Dash(n3, old_sess).session()[1].get("authenticated")),
                "new login valid": bool(Dash(n3, new_sess).session()[1].get("authenticated"))}
    want_ready = {"B1": 403, "B3": 403, "B4": 403, "B0 lifted": 200, "B2 lifted": 200, "events of the erased address": 0, "ended login valid": False, "new login valid": True}
    lab.check("a.return", "a3 returns: at its first ready answer it holds the blocks, the lifts, the new and the ended login, and nothing of the erased address",
              rdy is not None and at_ready == want_ready, "ready after %s s; at ready %s" % (rdy and round(rdy, 2), {k: v for k, v in at_ready.items() if v != want_ready[k]} or "all as expected"),
              kill="erased" if at_ready.get("events of the erased address") else None)
    metric(lab, "ready_after_long_absence", rdy, "s")
    tl = wait_for(lambda: not Dash(n3, old_sess).session()[1].get("authenticated") and Dash(n3, new_sess).session()[1].get("authenticated"), 20, 0.05)
    on_others = {"ended login valid on a1, a2": [bool(Dash(n, old_sess).session()[1].get("authenticated")) for n in (n1, n2)],
                 "new login valid on a1, a2": [bool(Dash(n, new_sess).session()[1].get("authenticated")) for n in (n1, n2)]}
    out["logins_after_ready"] = {"right_after_s": tl, "others": on_others}
    lab.check("a.return", "the logins on a3: the one ended while it was away is refused and the new one accepted", tl is not None,
              "right %s after its first ready answer; on the two others: %s" % ("%.2f s" % tl if tl is not None else "NOT within 20 s", on_others), kill="weakens")
    t, snaps = wait_same(ds, 30)
    s0 = snaps[0]
    want = {"allowlist entry removed while away stays removed": "192.0.2.10" not in s0["allowlist"], "allowlist entry made while away": "192.0.2.11" in s0["allowlist"],
            "limit made while away": "made-while-away" in s0["limits"], "events_days 55": (s0["retention"] or {}).get("events_days") == 55,
            "summaries_days 222": (s0["retention"] or {}).get("summaries_days") == 222, "blocks": s0["blocks"] == sorted([B1, B3, B4])}
    lab.check("a.return", "the three nodes end with the same state, the one the two had", t is not None and all(want.values()),
              "same after %s s; %s; %s" % (t and round(t, 2), diff_snaps(names, snaps), {k: v for k, v in want.items() if not v} or "every change of the absence holds"), kill="weakens")
    # the requests it missed
    cur = []
    last, same_since = None, now()
    while now() - t_back < 180:
        cur = held(lab, ds)
        if cur[2] == cur[0] == cur[1]:
            break
        if cur != last:
            last, same_since = cur, now()
        elif now() - same_since > 20:
            break
        time.sleep(1.0)
    took = now() - t_back
    lacks = [max(cur[:2]) - c for c in cur]
    out["catch_up"] = {"held": cur, "lacks": lacks, "seconds": round(took, 1), "served_while_away": served}
    log = n3.loglines(r"request", mark)
    log = [re.sub(r'^.*?"msg":', "", l)[:260] for l in log if re.search(r"miss|gone|lack|behind|catch|cursor|first", l)]
    lab.check("a.return", "a3 catches up on every single request the two served while it was away (%d, more than the log in memory holds)" % served, cur[2] == cur[0] == cur[1],
              "held by a1, a2, a3: %s; a3 lacks %d of %d; %s after %.0f s; log of a3 about requests: %s" % (
                  cur, lacks[2], served, "equal" if cur[2] == cur[0] else "no longer changing", took, log[:3] or "nothing"))
    metric(lab, "requests_missing_after_absence", lacks[2], "count", served)
    metric(lab, "request_catch_up", took if cur[2] == cur[0] else None, "s", served)
    per_ip = dict(r1.get("ok_per_ip") or {})
    pick = rng.sample(sorted(per_ip), min(len(per_ip), 10 if lab.quick else 40))
    bad = []
    for ip in pick:
        got = [sum(1 for p, s in (requests_of_ip(d, ip, t_begin) or []) if s == 200) for d in ds]
        if any(g != per_ip[ip] for g in got):
            bad.append((ip, per_ip[ip], got))
    out["per_ip_bad"] = bad
    lab.check("a.return", "a sample of %d client addresses of that load: a3 holds exactly the requests the client was answered, as a1 and a2 do" % len(pick), not bad,
              "%d addresses differ; (address, answered 200, held by a1, a2, a3): %s" % (len(bad), bad[:5]))
    ev = [count_events(d, "/away1", outcome="blocked") for d in ds]
    lab.check("a.return", "the blocked events of the absence are on all three", len(set(ev)) == 1 and ev[0] == r1["status"].get("403", 0),
              "attacks answered 403: %d; blocked events on a1, a2, a3: %s" % (r1["status"].get("403", 0), ev))
    # the erased address
    time.sleep(8.0)
    e_after = {"events": [d.privacy(E).get("events") for d in ds], "requests": [len(requests_of_ip(d, E, t_begin) or []) for d in ds],
               "event_list": [count_events(d, ip=E) for d in ds]}
    out["erased"] = {"before": e_before, "after": e_after}
    lab.check("a.return", "the erased address does not return on any node: no event, no request by that address (8 s after the catch-up)",
              e_after["events"] == [0] * 3 and e_after["requests"] == [0] * 3 and e_after["event_list"] == [0] * 3,
              "before %s; after: privacy search events %s, requests by address %s, event list by address %s" % (e_before, e_after["events"], e_after["requests"], e_after["event_list"]), kill="erased")
    for nd in nodes:
        nd.kill9()
