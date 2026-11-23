"""MVP-27 lab measurement, second run: the scenarios for what was built after the first run.

s8  readiness of a node that reaches nobody: a fresh one, and one that was in step once
s9  a new group secret, server by server, on three nodes with a certificate, an edge and a light load
s10 the page data of the group (GET /api/v0/group) and the counters across nodes (`node` on the monitoring calls)
s11 a block set on one node and lifted on another 0.2 to 1 s later, 200 times, twice

Loaded by run.py; uses its results, its lab and its helpers.
"""
import datetime
import json
import random
import re
import threading
import time
import urllib.parse

from lab import Conn, Dash, Load, TlsLoad, MESH_PORT, get, now, summary, tcp_open, tls_get, wait_until
from run import (CERT_SITE, CLIENT_NET, R, SEED, Certs, first_login, fresh_group, incident_of, members_ok)


def stamp(t):
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def rounded(v, digits=2):
    return round(v, digits) if v is not None else None


# ---------------------------------------------------------------------------------------------------------------
# scenario 8: readiness of a node that reaches no member


def s8(lab):
    S = "s8"
    nodes = lab.nodes[:3]
    n1, n2, n3 = nodes
    fresh_group(lab, nodes, start=False)

    # a fresh node, its two peers are not started
    n1.start()
    t0 = now()
    codes, errors, first_200 = {}, {}, None
    while now() - t0 < 75:
        c = Conn(n1.ip, claim=lab.client.ip, timeout=1.0)
        r = c.get("/.schild/readyz", close=True)
        codes[r] = codes.get(r, 0) + 1
        if r == 0:
            errors[c.error[:60]] = errors.get(c.error[:60], 0) + 1
        if r == 200 and first_200 is None:
            first_200 = now() - t0
        time.sleep(0.5)
    direct = get(n1.ip, "/x", claim=CLIENT_NET + "10")
    d1 = Dash(n1)
    st_setup = d1.setup()[0]
    g = d1.group()
    num = {"seconds_watched": 75, "answers": {str(k): v for k, v in codes.items()}, "requests_without_an_answer_by_error": errors,
           "first_200_after_s": rounded(first_200), "web_port_open_at_the_end": tcp_open(n1.ip, 80, timeout=1.0),
           "a_visitor_sent_straight_to_the_node_gets": direct, "first_password_set_on_it": st_setup, "state": g.get("state"),
           "members": [m.get("state") for m in g.get("members", [])]}
    R.check(S, "8.01", "a fresh node that reaches none of its peers stays out of traffic for at least 60 s: /.schild/readyz never answers 200 in 75 s (it never was in step with a group)",
            first_200 is None, num, "a balancer takes a refused connection and a 503 the same way: the node is down")
    said = n1.grep("in step|not ready|no member|reaches no|waits? for|peers?", 4)
    R.check(S, "8.01b", "in that time the answer is 503, as contract section 10 and the guide say ('bleibt auf 503')", codes.get(503, 0) > 100 and not codes.get(0),
            {"answers": {str(k): v for k, v in codes.items()}, "requests_without_an_answer_by_error": errors, "web_port_open": num["web_port_open_at_the_end"]},
            "lines of the node's log that say why: %s" % (said[:700] or "none"))

    # a second node starts: both become ready
    n2.start()
    t1 = now()
    r1 = wait_until(lambda: n1.ready(1.0) == 200, 30, 0.05)
    r2 = n2.wait_ready(30)
    R.check(S, "8.02", "a second node starts: the waiting node and the new one answer ready (guide: start at least two servers at the first setup)",
            r1 is not None and r2 is not None, {"n1_ready_s_after_n2_started": rounded(r1), "n2_ready_s_after_its_start": rounded(r2)})
    time.sleep(2)
    if st_setup != 200:
        d1.setup()
    d2 = Dash(n2, d1)
    wait_until(lambda: members_ok(d1, 2) or len(d1.group().get("members", [])) >= 2, 15)
    a = CLIENT_NET + "11"
    d2.block(a)
    took = wait_until(lambda: get(n1.ip, "/x", claim=a, timeout=2) == 403, 10, 0.05)

    # a node that was in step once restarts with no member reachable: three runs
    runs = []
    for i in range(3):
        n1.kill9()
        n2.kill9()
        time.sleep(1)
        n1.start()
        t0 = now()
        seen, t_ready = {}, None
        while now() - t0 < 40:
            r = n1.ready(1.0)
            seen[r] = seen.get(r, 0) + 1
            if r == 0 and tcp_open(n1.ip, 80, timeout=0.5):
                seen["0 with the port open"] = seen.get("0 with the port open", 0) + 1
            if r == 200:
                t_ready = now() - t0
                break
            time.sleep(0.05)
        at_ready = get(n1.ip, "/x", claim=a, timeout=2) if t_ready is not None else None
        runs.append({"ready_after_s": rounded(t_ready), "polls_503_before": seen.get(503, 0), "polls_refused_before": seen.get(0, 0), "blocked_address_at_ready": at_ready,
                     "state": Dash(n1, d1).group().get("state")})
        # in step again before the next run
        n2.start()
        n2.wait_ready(30)
        wait_until(lambda: members_ok(Dash(n1, d1), 2) or Dash(n1, d1).group().get("state") in ("active", "degraded"), 15)
        time.sleep(2)
    R.check(S, "8.03", "a node that was in step once and restarts with no member reachable is not ready for about 10 s, then serves with the state it has (3 runs; pass: ready after 8 to 15 s, the block from before refused)",
            took is not None and all(r["ready_after_s"] is not None and 8 <= r["ready_after_s"] <= 15 and r["blocked_address_at_ready"] == 403 for r in runs),
            {"runs": runs, "block_reached_n1_before_s": rounded(took)})
    for n in nodes:
        n.kill9()


# ---------------------------------------------------------------------------------------------------------------
# scenario 9: a new group secret, server by server


def s9(lab):
    S = "s9"
    nodes = lab.nodes[:3]
    n1, n2, n3 = nodes
    lb = lab.lb
    tls = Certs(lab, nodes)
    if not tls.there():
        R.check(S, "9.00", "the ACME test server (pebble) is on the application VM", None, {}, "not measured: pebble was not copied to the lab")
        return
    EDGE = "/var/lib/schild-edge"
    lb.run("pkill -x schild; nft delete table inet schild 2>/dev/null; rm -rf %s; true" % EDGE)

    def code_of(n, a):
        """What a visitor with this address gets from the node (over TLS, the node told the address as a balancer does)."""
        return tls_get(n.ip, "/x", CERT_SITE, claim=a)[0]

    def everywhere(a, want):
        return all(code_of(n, a) == want for n in nodes)

    tls.pebble_start()
    tls.deploy()
    tls.haproxy()
    for n in nodes:
        n.start()
    certs = {n.name: tls.wait_cert(n, 150) for n in nodes}
    ok = all(v[0] is not None for v in certs.values())
    d = first_login(nodes)
    d1, d2, d3 = d
    conv = wait_until(lambda: all(members_ok(x, 3) for x in d), 30)
    time.sleep(3)
    fp0 = sorted(set(v[1] for v in certs.values()))
    R.check(S, "9.01", "three nodes with a TLS site started together from the same files: one certificate from the CA, shown by all three, the group active",
            ok and len(fp0) == 1 and tls.issued() == 1 and conv is not None,
            {"seconds_to_certificate": {k: rounded(v[0], 1) for k, v in certs.items()}, "certificates_shown": fp0, "issued_by_the_ca": tls.issued(),
             "orders_placed": tls.placed(), "nodes_that_asked_the_ca": tls.askers()})
    wait_until(lambda: set(tls.lb443().values()) == {"UP"}, 30, 0.2)
    g0 = d1.group()
    group0 = g0.get("group")
    ids0 = {m.get("address"): m.get("id") for m in g0.get("members", []) if m.get("role") == "gateway"}

    # an edge on the balancer VM, as in scenario 4
    rc_join, out_join = -1, "edges and join codes were removed in 5b12c2c: not run"

    load = TlsLoad(lb.ip, CERT_SITE, rate=5, workers=2, bind=CLIENT_NET + "35").start()

    # what the group holds before the change
    b1, b2, b3 = CLIENT_NET + "101", CLIENT_NET + "102", CLIENT_NET + "103"
    lifted_before, lift_during = CLIENT_NET + "104", CLIENT_NET + "105"
    e_before, e_during = CLIENT_NET + "106", CLIENT_NET + "107"
    al1, al2 = CLIENT_NET + "108", CLIENT_NET + "109"
    b_old_side, b_new_side, b_after = CLIENT_NET + "110", CLIENT_NET + "111", CLIENT_NET + "112"
    for n in nodes:                      # visits, so the nodes hold requests of the two addresses that get erased
        for a in (e_before, e_during):
            for _ in range(3):
                code_of(n, a)
    st = {"block_n1": d1.block(b1)[0], "block_n2_one_hour": d2.block(b2, duration=3600)[0], "block_n3": d3.block(b3)[0],
          "block_to_lift_before": d1.block(lifted_before)[0], "block_to_lift_during": d1.block(lift_during)[0],
          "block_erased_before": d1.block(e_before)[0], "block_erased_during": d2.block(e_during)[0],
          "allow_n3": d3.allow(al1)[0],
          "setting_n2": d2.call("PATCH", "/settings", {"retention": {"events_days": 41}})[0]}
    time.sleep(2)
    st["lift_before_on_n2"] = d2.unblock(incident_of(d2, lifted_before))[0]
    held_before = {"e_before": [x.call("GET", "/privacy/search?ip=" + e_before)[1].get("events") for x in d],
                   "e_during": [x.call("GET", "/privacy/search?ip=" + e_during)[1].get("events") for x in d]}
    st_er, js_er = d1.erase(e_before)
    st["erase_before_on_n1"] = st_er
    time.sleep(2)
    edge_drops_before = wait_until(lambda: not tcp_open(lb.ip, 443, bind=b1), 8, 0.1)
    pre = {"blocks": {x.node.name: x.blocks() for x in d}, "events_days": [((x.call("GET", "/settings")[1] or {}).get("retention") or {}).get("events_days") for x in d]}
    R.check(S, "9.02", "before the change: blocks on three nodes, a lift, an allowlist entry, a setting, an erased address, a login, an edge that drops a blocked address",
            all(v in (200, 201) for v in st.values()) and rc_join == 0 and edge_drops_before is not None
            and all(set([b1, b2, b3, lift_during, e_during]) <= set(b or []) and lifted_before not in (b or []) and e_before not in (b or []) for b in pre["blocks"].values()),
            {"statuses": st, "edge_join_exit": rc_join, "edge_drops_a_blocked_address": edge_drops_before is not None, "blocks_per_node": {k: len(v or []) for k, v in pre["blocks"].items()},
             "events_days": pre["events_days"], "events_held_of_the_two_addresses_before_erasing": held_before,
             "erasure_nodes": (js_er or {}).get("nodes") if isinstance(js_er, dict) else None})
    orders0, issued0 = tls.placed(), tls.issued()

    # the guide, "Das Cluster-Geheimnis wechseln": 1. a new secret, 2. into the file on every server, 3. restart one after the other
    rc, out = n1.run("schild cluster secret")
    new_secret = out.splitlines()[-1]
    old_secret = lab["secret"]
    for n in nodes:
        n.put("/etc/schild/cluster.secret", new_secret + "\n", "600")
    per, during = [], {}
    for i, n in enumerate(nodes):
        t0 = now()
        n.cli("cluster drain", 90)
        gone = n.wait_exit(60)
        t_stop = now() - t0
        n.start()
        t_ready = wait_until(lambda: tls_get(n.ip, "/.schild/readyz", CERT_SITE, claim=lab.client.ip)[0] == 200, 60, 0.1)
        up = wait_until(lambda: tls.lb443().get(n.name) == "UP", 30, 0.2)
        per.append({"node": n.name, "stopped_after_s": rounded(t_stop, 1), "exited": gone, "ready_after_start_s": rounded(t_ready), "balancer_up": up is not None})
        if i == 0:
            # two groups now: n1 in the new one, n2 and n3 in the old one
            time.sleep(2)
            x1 = Dash(n1, d1)
            g_new = x1.group()
            during["n1_group_is_new"] = g_new.get("group") not in (None, group0)
            during["n1_state"] = g_new.get("state")
            during["n1_members"] = sorted("%s %s" % (m.get("name"), m.get("state")) for m in g_new.get("members", []))
            during["n2_state"] = d2.group().get("state")
            during["n2_members"] = sorted("%s %s" % (m.get("name"), m.get("state")) for m in d2.group().get("members", []))
            during["session_valid_on_n1"] = x1.session()[1].get("authenticated") if isinstance(x1.session()[1], dict) else None
            during["n1_blocks_carried"] = sorted(set(x1.blocks() or []) & set([b1, b2, b3, lift_during, e_during]))
            # changes on the old side, which have to arrive in the new group with their servers
            during["block_on_n3_old_group"] = d3.block(b_old_side)[0]
            during["lift_on_n2_old_group"] = d2.unblock(incident_of(d2, lift_during))[0]
            st_e2, js_e2 = d3.erase(e_during)
            during["erase_on_n3_old_group"] = st_e2
            during["allow_on_n2_old_group"] = d2.allow(al2)[0]
            during["setting_on_n3_old_group"] = d3.call("PATCH", "/settings", {"retention": {"events_days": 42}})[0]
            # and one on the new side
            during["block_on_n1_new_group"] = x1.block(b_new_side)[0]
            time.sleep(2)
            during["new_group_holds_the_old_side_block_meanwhile"] = code_of(n1, b_old_side) == 403
            during["old_group_holds_the_new_side_block_meanwhile"] = code_of(n2, b_new_side) == 403
    d = [Dash(n, d1) for n in nodes]
    d1, d2, d3 = d
    conv = wait_until(lambda: all(members_ok(x, 3) for x in d), 40, 0.2)
    time.sleep(5)
    R.check(S, "9.03", "the three servers restarted one after the other with the new secret in the file: each stops, starts and answers ready; nothing was deleted by hand",
            all(p["exited"] and p["ready_after_start_s"] is not None and p["balancer_up"] for p in per), {"servers": per, "between_the_first_and_the_second": during},
            "guide: the first server of the new cluster waits up to ten seconds for the others before it answers ready")
    g1 = d1.group()
    groups = [x.group().get("group") for x in d]
    ids1 = {m.get("address"): m.get("id") for m in g1.get("members", []) if m.get("role") == "gateway"}
    kept = {n.name: int(n.run("ls -d /var/lib/schild/cluster.replaced-* 2>/dev/null | wc -l")[1] or 0) for n in nodes}
    R.check(S, "9.04", "afterwards: one new group of three, every node kept its id (its key), all active, the directory of the old group lies next to the new one",
            conv is not None and len(set(groups)) == 1 and groups[0] not in (None, group0) and ids1 == ids0 and all(v == 1 for v in kept.values()),
            {"all_active_after_the_last_ready_s": rounded(conv), "group_changed": groups[0] != group0, "one_group": len(set(groups)) == 1, "node_ids_kept": ids1 == ids0,
             "gateways": sum(1 for m in g1.get("members", []) if m.get("role") == "gateway"), "directories_cluster_replaced": kept}, n1.status()[:1500])

    blocks = {x.node.name: x.blocks() or [] for x in d}
    want = [b1, b2, b3, b_old_side, b_new_side]
    refused = {a: [code_of(n, a) for n in nodes] for a in want}
    R.check(S, "9.05", "blocks survive: the three from before (one of an hour, two of seven days), the one set on a server of the old group and the one set in the new group during the change are refused on every node",
            all(v == [403] * 3 for v in refused.values()) and all(set(want) <= set(b) for b in blocks.values()),
            {"answers_per_block": refused, "listed_on": {a: [k for k, b in blocks.items() if a in b] for a in want}})
    served = {a: [code_of(n, a) for n in nodes] for a in (lifted_before, lift_during)}
    R.check(S, "9.06", "lifts survive: the block lifted before the change and the block lifted on a server of the old group after the first server had carried it into the new group are served on every node",
            all(v == [200] * 3 for v in served.values()) and not any(a in b for a in served for b in blocks.values()),
            {"answers": served, "still_listed_on": {a: [k for k, b in blocks.items() if a in b] for a in served}},
            "guide: 'Eine Freigabe schlägt die ältere Sperre'")
    als = [x.allowlist() or [] for x in d]
    days = [((x.call("GET", "/settings")[1] or {}).get("retention") or {}).get("events_days") for x in d]
    R.check(S, "9.07", "settings and own addresses survive: both allowlist entries on every node, and the setting changed last (on the old side during the change) on every node",
            all(al1 in a and al2 in a for a in als) and days == [42, 42, 42], {"allowlist_entries_per_node": [len(a) for a in als], "events_days": days,
                                                                                 "first_entry_on": sum(1 for a in als if al1 in a), "second_entry_on": sum(1 for a in als if al2 in a)})
    sess = [x.session()[1].get("authenticated") is True for x in d]
    fresh = Dash(n3)
    st_login = fresh.login()[0]
    R.check(S, "9.08", "logins survive: the session from before the change is valid on every node, and the password signs in", all(sess) and st_login == 200,
            {"session_valid_on": sum(sess), "password_login_on_n3": st_login})
    # what the nodes hold is asked first: the requests of this check itself come after the erasure
    erased = {a: {"events_held": [x.call("GET", "/privacy/search?ip=" + a)[1].get("events") for x in d],
                  "listed_on": [k for k, b in blocks.items() if a in b],
                  "answers": [code_of(n, a) for n in nodes]} for a in (e_before, e_during)}
    R.check(S, "9.09", "an erased address stays erased: the one erased before the change and the one erased on a server of the old group during it are blocked on no node and no node holds an event of them",
            all(v["answers"] == [200] * 3 and not v["listed_on"] and all(x == 0 for x in v["events_held"]) for v in erased.values()), erased,
            "guide: 'eine Löschung bleibt eine Löschung'")
    time.sleep(20)
    fps = sorted(set(tls.cert_of(n)[1] for n in nodes))
    R.check(S, "9.10", "no certificate is ordered again: the CA got no order and issued nothing during and 25 s after the change, every node shows the certificate from before",
            tls.placed() == orders0 and tls.issued() == issued0 and fps == fp0,
            {"orders_placed_before": orders0, "after": tls.placed(), "issued_before": issued0, "issued_after": tls.issued(), "same_certificate_on_all": fps == fp0})
    load.stop()
    ls = load.stats()
    R.check(S, "9.11", "light load through the balancer over TLS (5 new connections a second) during all of it: no request fails", ls["not_200"] == 0, ls)

    # the edge afterwards
    x1 = Dash(n1, d1)
    st_after = x1.block(b_after)[0]
    late = wait_until(lambda: not tcp_open(lb.ip, 443, bind=b_after), 8, 0.1)
    held = not tcp_open(lb.ip, 443, bind=b1)
    edges = [{k: m.get(k) for k in ("name", "state", "last_in", "blocks_held")} for m in x1.group().get("members", []) if m.get("role") == "edge"]
    rc_fs, out_fs = lb.run("schild firewall status -data %s" % EDGE)
    R.check(S, "9.12", "the edge after the change, untouched: what it still drops and whether a block set in the new group reaches it (guide: it does not move by itself)",
            None, {"block_status": st_after, "a_block_from_before_is_still_dropped": held, "a_block_set_after_the_change_is_dropped_within_8_s": late is not None,
                   "edges_in_the_new_group_as_n1_lists_them": edges}, (lb.run("tail -4 /var/log/schild/edge.log")[1] + "\n" + out_fs)[:900])
    steps = [{"edge": "edges and join codes were removed in 5b12c2c: not run"}]
    rc_j = -1
    again = wait_until(lambda: not tcp_open(lb.ip, 443, bind=b_after), 15, 0.1)
    R.check(S, "9.13", "the edge let in again with a new code (schild cluster invite -role edge, join, firewall run -group) drops the blocks of the new group",
            rc_j == 0 and again is not None, {"steps": steps, "dropped_after_s": rounded(again), "block_from_before_dropped": not tcp_open(lb.ip, 443, bind=b1)})
    lb.run("pkill -TERM -x schild; sleep 1; nft delete table inet schild 2>/dev/null; rm -rf %s; true" % EDGE)

    # a node that still has the old secret is no member of the new group
    lab["secret"] = new_secret
    for n in nodes:
        n.kill9()
    tls.pebble_stop()
    lab["secret"] = old_secret        # the other scenarios deploy their own secret file; keep what prepare() made


# ---------------------------------------------------------------------------------------------------------------
# scenario 10: the page data of the group and the counters across nodes


def s10(lab):
    S = "s10"
    nodes = lab.nodes[:3]
    n1, n2, n3 = nodes
    fresh_group(lab, nodes)
    d = first_login(nodes)
    d1, d2, d3 = d
    wait_until(lambda: all(members_ok(x, 3) for x in d), 20)
    hosts = {n.name: n.hostname() for n in nodes}
    ids = {n.name: d1.member(n.ip).get("id") for n in nodes}
    names = {x.node.name: sorted(m.get("name") for m in x.group().get("members", [])) for x in d}
    R.check(S, "10.01", "GET /group on every node names the three gateways by their host names (name_from_host, one node_name in the one file)",
            all(v == sorted(hosts.values()) for v in names.values()) and len(set(hosts.values())) == 3, {"host_names": hosts, "names_per_node": names})
    time.sleep(22)                       # a quiet stretch, so the window of the counters starts on empty buckets

    # load on two of three nodes: 30 and 10 requests a second, none on the third
    rates = {"n1": 30, "n2": 10, "n3": 0}
    t_from = time.time()
    loads = {"n1": Load(n1.ip, rate=30, workers=3, mode="keep", claim=CLIENT_NET + "50").start(),
             "n2": Load(n2.ip, rate=10, workers=2, mode="keep", claim=CLIENT_NET + "51").start()}
    time.sleep(85)
    views = {x.node.name: x.group() for x in d}
    now_all = {x.node.name: x.call("GET", "/monitoring/now")[1] for x in d}
    now_one = {k: d3.call("GET", "/monitoring/now?node=%s" % ids[k])[1] for k in ids}
    time.sleep(5)
    for l in loads.values():
        l.stop()
    t_to = time.time()
    sent = {k: (loads[k].stats()["requests"] if k in loads else 0) for k in rates}
    not_200 = sum(l.stats()["not_200"] for l in loads.values())

    def vit(view, n):
        for m in view.get("members", []):
            if m.get("address", "").startswith(n.ip + ":"):
                return m
        return {}
    need = ("at", "service", "requests_per_s", "stopped_share", "latency_p95_ms", "cpu_usage", "memory_used_ratio", "disk_used_ratio")
    table, bad = {}, []
    for asker, view in views.items():
        for n in nodes:
            m = vit(view, n)
            v = m.get("vitals") or {}
            table["%s sees %s" % (asker, n.name)] = {"state": m.get("state"), "service": v.get("service"), "requests_per_s": v.get("requests_per_s"),
                                                     "cpu_usage": v.get("cpu_usage"), "memory_used_ratio": v.get("memory_used_ratio"),
                                                     "disk_used_ratio": v.get("disk_used_ratio"), "latency_p95_ms": v.get("latency_p95_ms"),
                                                     "clock_skew_ms": m.get("clock_skew_ms"), "has_started_at": "started_at" in v}
            if any(k not in v for k in need) or v.get("service") != "ready":
                bad.append("%s sees %s: fields missing or not ready" % (asker, n.name))
            for k in ("cpu_usage", "memory_used_ratio", "disk_used_ratio"):
                if not isinstance(v.get(k), (int, float)) or not 0 <= v[k] <= 1:
                    bad.append("%s sees %s: %s is %r" % (asker, n.name, k, v.get(k)))
    R.check(S, "10.02", "GET /group on every node carries the vitals of every member: service ready, requests per second, CPU, memory and disk as ratios, start time",
            not bad, table, "; ".join(bad)[:600])
    rps_bad = []
    for asker, view in views.items():
        for n in nodes:
            got = (vit(view, n).get("vitals") or {}).get("requests_per_s")
            want = rates[n.name]
            if got is None or abs(got - want) > max(1.0, 0.2 * want):
                rps_bad.append("%s sees %s at %r, sent %d a second" % (asker, n.name, got, want))
    R.check(S, "10.03", "the requests per second of each member over its last 60 s, as every node shows them, are what the client sent it (30, 10 and 0 a second; within 20 % or 1)",
            not rps_bad, {k: v["requests_per_s"] for k, v in table.items()}, "; ".join(rps_bad))
    skews = {k: v["clock_skew_ms"] for k, v in table.items() if k.split()[0] != k.split()[-1]}
    R.check(S, "10.04", "every node shows the clock difference to every other member (GroupMember.clock_skew_ms), and it is small on VMs with right clocks (under 1.5 s)",
            all(isinstance(v, int) and abs(v) < 1500 for v in skews.values()), skews)

    # the last minute, for the group and for one node
    def rps(js):
        return ((js or {}).get("traffic") or {}).get("requests_per_s") if isinstance(js, dict) else None
    def scope(js):
        c = (js or {}).get("cluster") or {} if isinstance(js, dict) else {}
        return {"node": c.get("node"), "nodes": sorted(x.get("name") for x in c.get("nodes", [])), "partial": [x.get("name") for x in c.get("partial_nodes", [])],
                "clients_at_least": c.get("clients_at_least")}
    num = {"group_as_asked_on": {k: rps(v) for k, v in now_all.items()}, "one_node_as_asked_on_n3": {k: rps(v) for k, v in now_one.items()},
           "cluster_of_the_group_answer_on_n3": scope(now_all["n3"]), "cluster_of_the_answer_for_n1": scope(now_one["n1"])}
    ok_now = (all(v is not None and abs(v - 40) <= 8 for v in num["group_as_asked_on"].values())
              and all(num["one_node_as_asked_on_n3"][k] is not None and abs(num["one_node_as_asked_on_n3"][k] - rates[k]) <= max(1.0, 0.2 * rates[k]) for k in rates)
              and num["cluster_of_the_group_answer_on_n3"]["nodes"] == sorted(hosts.values()) and num["cluster_of_the_group_answer_on_n3"]["partial"] == [])
    R.check(S, "10.10", "getMonitoringNow under load on two of three nodes: without `node` every gateway answers the sum (40 a second), with a node id that node alone (30, 10, 0); `cluster` names the three nodes and none as partial",
            ok_now, num, "contract 9a: the group answer ends about 20 s before the present")

    # the buckets, after they had time to travel (asked for every 10 s; a bucket is asked again for 30 s)
    time.sleep(50)
    q_from, q_to = stamp(t_from - 30), stamp(t_to + 30)
    cat = d1.call("GET", "/monitoring/catalogue")[1]
    metric = "traffic.requests"
    try:
        known = [m.get("id") for m in (cat.get("metrics") or cat.get("items") or [])]
    except AttributeError:
        known = []

    def series_total(dash, node):
        q = "/monitoring/series?metric=%s&from=%s&to=%s&resolution=10s" % (urllib.parse.quote(metric + ":sum"), q_from, q_to)
        if node:
            q += "&node=" + node
        st, js = dash.call("GET", q)
        if st != 200 or not isinstance(js, dict) or not js.get("series"):
            return {"status": st, "body": json.dumps(js)[:200]}
        vals = [v for v in js["series"][0].get("values", []) if v is not None]
        return {"total": int(round(sum(vals))), "cluster": scope(js)}
    totals = {}
    for x in d:
        row = {"no node": series_total(x, None), "all": series_total(x, "all")}
        for k in ids:
            row[k] = series_total(x, ids[k])
        totals[x.node.name] = row
    want_all = sum(sent.values())
    ok = all(row["no node"].get("total") == want_all and row["all"].get("total") == want_all
             and all(row[k].get("total") == sent[k] for k in ids) for row in totals.values())
    R.check(S, "10.11", "queryMetricSeries of traffic.requests (sum per 10 s) over the window of the load, asked on every node: `node=all` and no `node` are the sum of the three, a node id is that node alone, and each equals what the client sent",
            ok, {"sent_by_the_client": sent, "not_200_of_those": not_200, "totals_as_asked_on": {a: {k: v.get("total", v) for k, v in row.items()} for a, row in totals.items()},
                 "cluster_of_all_on_n3": totals["n3"]["all"].get("cluster"), "cluster_of_n1_on_n3": totals["n3"]["n1"].get("cluster")},
            "metric ids of the catalogue that name requests: %s" % [m for m in known if m and "request" in m][:8])

    def breakdown(dash, node):
        q = "/monitoring/traffic/breakdown?by=path&from=%s&to=%s" % (stamp(t_from - 90), stamp(t_to + 90))
        if node:
            q += "&node=" + node
        st, js = dash.call("GET", q)
        if st != 200 or not isinstance(js, dict):
            return {"status": st, "body": json.dumps(js)[:200]}
        return sum(int(i.get("requests", 0)) for i in js.get("items", []))
    time.sleep(45)                       # the 1 min ring: its newest bucket has to be closed and handed over
    bd = {x.node.name: dict([("all", breakdown(x, "all"))] + [(k, breakdown(x, ids[k])) for k in ids]) for x in d}
    R.check(S, "10.12", "getTrafficBreakdown by path over the same load, asked on every node: the requests of `node=all` are the sum of the three nodes and equal what the client sent",
            all(row["all"] == want_all and all(row[k] == sent[k] for k in ids) for row in bd.values()), {"sent_by_the_client": sent, "requests_as_asked_on": bd})
    st_bad, js_bad = d1.call("GET", "/monitoring/now?node=n-" + "0" * 32)
    R.check(S, "10.13", "a node id that is no gateway of the group is answered 400", st_bad == 400, {"status": st_bad}, json.dumps(js_bad)[:200])

    # one node stops: its history stays, the group answer has to name it as partial. Load goes on at n1 (20 a
    # second), so the sums of the group keep moving; watched for four minutes, asked every 15 s on n1 and n3.
    again = Load(n1.ip, rate=20, workers=2, mode="keep", claim=CLIENT_NET + "50")
    wall0, mono0 = time.time(), now()
    again.start()
    time.sleep(20)
    t_kill = time.time()
    n2.kill9()
    gone, polls = None, []
    while time.time() - t_kill < 240:
        time.sleep(15)
        age = round(time.time() - t_kill)
        if gone is None and age >= 22:
            gone = {x.node.name: vit(x.group(), n2) for x in (d1, d3)}
        row = {"s_after_kill": age}
        for x in (d1, d3):
            q = "/monitoring/series?metric=%s&from=%s&to=%s&resolution=10s" % (urllib.parse.quote(metric + ":sum"), stamp(time.time() - 120), stamp(time.time()))
            st, js = x.call("GET", q)
            js = js if isinstance(js, dict) else {}
            c = js.get("cluster") or {}
            row["series_" + x.node.name] = [p.get("name") for p in c.get("partial_nodes", [])]
            row["until_" + x.node.name] = [p.get("until") for p in c.get("partial_nodes", [])]
            row["points_marked_partial_" + x.node.name] = sum(1 for v in js.get("partial", []) if v)
            row["points_" + x.node.name] = len(js.get("partial", []))
            st, js = x.call("GET", "/monitoring/now")
            c = (js.get("cluster") or {}) if isinstance(js, dict) else {}
            row["now_" + x.node.name] = [p.get("name") for p in c.get("partial_nodes", [])]
            row["now_nodes_" + x.node.name] = len(c.get("nodes", []))
            row["now_rps_" + x.node.name] = ((js.get("traffic") or {}).get("requests_per_s")) if isinstance(js, dict) else None
        polls.append(row)
    late = [r for r in polls if r["s_after_kill"] >= 75]
    want = [hosts["n2"]]
    named = {k: sum(1 for r in late if r[k] == want) for k in ("series_n1", "series_n3", "now_n1", "now_n3")}
    untils = sorted(set(u for r in polls for k in ("until_n1", "until_n3") for u in r[k]))
    R.check(S, "10.20", "n2 killed: from 75 s after the kill on, every answer of queryMetricSeries for the group (10 s ring, last two minutes), asked on n1 and on n3 every 15 s for four minutes, names n2 under partial_nodes (contract 9a: a node whose newest bucket ends more than 45 s before the span does)",
            named["series_n1"] == len(late) and named["series_n3"] == len(late),
            {"answers_from_75_s_on": len(late), "of_those_name_n2_as_partial": {"asked_on_n1": named["series_n1"], "asked_on_n3": named["series_n3"]},
             "s_after_kill_of_the_answers_that_named_it": [r["s_after_kill"] for r in polls if r["series_n1"] == want],
             "s_after_kill_of_the_answers_that_did_not": [r["s_after_kill"] for r in late if r["series_n1"] != want],
             "points_marked_partial_in_the_last_answer": "%d of %d" % (polls[-1]["points_marked_partial_n1"], polls[-1]["points_n1"]),
             "until_named": untils, "killed_at": stamp(t_kill)},
            "kill criterion: a partial answer is shown as complete. The single points carry a mark `partial` of their own; this check is about `cluster.partial_nodes`, which the guide's line 'Daten von web-3 fehlen seit ...' is made of")
    R.check(S, "10.20b", "the same for getMonitoringNow (the numbers of the last minute for the group): from 75 s after the kill on every answer names n2 under partial_nodes",
            named["now_n1"] == len(late) and named["now_n3"] == len(late),
            {"answers_from_75_s_on": len(late), "of_those_name_n2_as_partial": {"asked_on_n1": named["now_n1"], "asked_on_n3": named["now_n3"]},
             "nodes_the_answers_say_they_cover": sorted(set(r["now_nodes_n1"] for r in late)),
             "requests_per_s_of_the_group_in_those_answers": sorted(set(round(r["now_rps_n1"] or 0) for r in late))},
            "n1 gets 20 requests a second, n2 is gone, n3 gets none")
    slow = {}
    for label, q in (("series_1m", "/monitoring/series?metric=%s&from=%s&to=%s&resolution=1m" % (urllib.parse.quote(metric + ":sum"), stamp(time.time() - 600), stamp(time.time()))),
                     ("breakdown", "/monitoring/traffic/breakdown?by=path&from=%s&to=%s" % (stamp(time.time() - 600), stamp(time.time())))):
        for x in (d1, d3):
            st, js = x.call("GET", q)
            c = (js.get("cluster") or {}) if isinstance(js, dict) else {}
            slow["%s_asked_on_%s" % (label, x.node.name)] = [{"name": p.get("name"), "until": p.get("until")} for p in c.get("partial_nodes", [])]
    R.check(S, "10.20c", "four minutes after the kill: the series of the 1 min ring and getTrafficBreakdown for the group name n2 under partial_nodes, with the time its numbers end",
            all([p["name"] for p in v] == want and v[0].get("until") for v in slow.values()),
            dict(slow, killed_at=stamp(t_kill)), "guide: 'Daten von web-3 fehlen seit ...'; the time named is compared with the kill in the report")
    again.stop()
    ast = again.stats()
    per = {}
    for r in again.rows:
        b = int((wall0 + (r[0] - mono0)) // 10) * 10
        per[b] = per.get(b, 0) + 1
    time.sleep(45)
    st, js = d1.call("GET", "/monitoring/series?metric=%s&from=%s&to=%s&resolution=10s&node=%s" % (urllib.parse.quote(metric + ":sum"), stamp(min(per)), stamp(max(per) + 10), ids["n1"]))
    vals = (js["series"][0].get("values") if isinstance(js, dict) and js.get("series") else []) or []
    start = js.get("from") if isinstance(js, dict) else None
    client = [per.get(b, 0) for b in range(min(per), max(per) + 10, 10)]
    diff = [(i, c, v) for i, (c, v) in enumerate(zip(client, vals)) if v is None or abs(c - v) > 3]
    R.check(S, "10.24", "the load on n1 across the kill of n2 (20 requests a second, 260 s): no request fails or waits (max under 500 ms), and every 10 s bucket of n1 holds what the client sent in it (within 3)",
            ast["not_200"] == 0 and ast["retried"] == 0 and (ast["latency_ms"].get("max") or 0) < 500 and not diff and len(vals) >= len(client),
            {"requests": ast["requests"], "not_200": ast["not_200"], "retried": ast["retried"], "latency_ms": ast["latency_ms"],
             "buckets": len(client), "buckets_that_differ": [{"bucket": stamp(min(per) + 10 * i), "client_sent": c, "n1_counted": v} for i, c, v in diff][:10],
             "series_from": start, "first_bucket_of_the_client": stamp(min(per))})
    hist = {x.node.name: series_total(x, ids["n2"]).get("total") for x in (d1, d3)}
    R.check(S, "10.21", "the numbers of the stopped node are still there: `node=<id of n2>` over the window of the first load answers what the client had sent it, on n1 and on n3",
            all(v == sent["n2"] for v in hist.values()), {"sent_to_n2": sent["n2"], "answered_on": hist})
    R.check(S, "10.22", "GET /group 30 s after the kill: n2 is unreachable and carries no vitals (guide: 'Nicht erreichbar' without numbers)",
            gone is not None and all(m.get("state") in ("unreachable", "no_contact") and not m.get("vitals") for m in gone.values()),
            {k: {"state": m.get("state"), "vitals": m.get("vitals")} for k, m in gone.items()})
    n2.start()
    n2.wait_ready(40)
    wait_until(lambda: members_ok(d1, 3), 30)
    time.sleep(6)
    threading.Thread(target=lambda: n3.cli("cluster drain", 60), daemon=True).start()
    seen = wait_until(lambda: (d1.member(n3.ip).get("vitals") or {}).get("service") == "draining", 14, 0.2)
    R.check(S, "10.23", "schild cluster drain on n3: n1 shows its service as draining within the 15 s of the delay (vitals travel every 5 s)", seen is not None,
            {"seconds": rounded(seen)})
    n3.wait_exit(60)
    for n in nodes:
        n.kill9()


# ---------------------------------------------------------------------------------------------------------------
# scenario 11: a block set on one node and lifted on another a moment later


def s11(lab):
    S = "s11"
    nodes = lab.nodes[:3]
    rnd = random.Random(SEED)
    fresh_group(lab, nodes)
    d = first_login(nodes)
    wait_until(lambda: all(members_ok(x, 3) for x in d), 20)
    offsets = {n.name: round(n.clock() - lab.client.clock(), 3) for n in nodes}
    # rounds 1 and 2 are the task: 200 pairs, the lift 0.2 to 1 s after the block. Round 3 brackets a failure: 100
    # pairs with the lift 2 to 3 s after the block, the pause in which scenario 1 (check 1.12) lifts.
    leftover, lifted = [], []
    for rnd_no, pairs, lo, hi in ((1, 200, 0.2, 1.0), (2, 200, 0.2, 1.0), (3, 100, 2.0, 3.0)):
        rows = []
        for i in range(pairs):
            a = "198.51.%d.%d" % (99 + rnd_no, i + 1) if rnd_no < 3 else "192.0.2.%d" % (i + 1)
            k = i % 3
            j = (k + 1 + (i // 3) % 2) % 3
            delay = rnd.uniform(lo, hi)
            t0 = now()
            st_b, js_b = d[k].block(a)
            t1 = now()
            inc = js_b.get("incident") if isinstance(js_b, dict) else None
            time.sleep(delay)
            t2 = now()
            st_u, js_u = d[j].unblock(inc)
            t3 = now()
            row = {"address": a, "set_on": nodes[k].name, "lifted_on": nodes[j].name, "pause_s": round(delay, 3), "block_status": st_b, "incident": inc,
                   "block_call_ms": round((t1 - t0) * 1000, 1), "lift_status": st_u, "lift_call_ms": round((t3 - t2) * 1000, 1),
                   "lift_sent_ms_after_block_sent": round((t2 - t0) * 1000, 1), "block_answer": json.dumps(js_b)[:300], "lift_answer": json.dumps(js_u)[:300]}
            if st_u != 200:
                # the lifting node did not hold the block yet: the person clicks again
                w = wait_until(lambda: d[j].unblock(inc)[0] == 200, 5, 0.05)
                row["lift_answered_200_after_ms"] = round((now() - t2) * 1000, 1) if w is not None else None
            rows.append(row)
        time.sleep(5)

        def state(a):
            """Where the address is still listed as a running block (GET /blocks) and where its requests are refused."""
            return {"listed_on": [n.name for n, x in zip(nodes, d) if a in (x.blocks() or [])],
                    "refused_on": [n.name for n in nodes if get(n.ip, "/x", claim=a, timeout=2) == 403]}

        def left():
            out, where = {}, {}
            for n, x in zip(nodes, d):
                listed = set(x.blocks() or [])
                for r in rows:
                    is_listed, is_refused = r["address"] in listed, get(n.ip, "/x", claim=r["address"], timeout=2) == 403
                    if is_listed or is_refused:
                        out.setdefault(r["address"], []).append(n.name)
                        w = where.setdefault(r["address"], {"listed_on": [], "refused_on": []})
                        if is_listed:
                            w["listed_on"].append(n.name)
                        if is_refused:
                            w["refused_on"].append(n.name)
            left.where = where
            return out
        rest = left()
        where = left.where
        leftover += sorted(rest)
        lifted += [r["address"] for r in rows]
        first_404 = [r for r in rows if r["lift_status"] != 200]
        never = [r for r in first_404 if r.get("lift_answered_200_after_ms") is None]
        evidence = ""
        later = None
        if rest:
            ev = {"remaining": [dict(r, still_blocked_on=rest[r["address"]], **where[r["address"]]) for r in rows if r["address"] in rest],
                  "clock_of_each_node_against_the_client_s": offsets,
                  "blocks_rows": {n.name: [b for b in (x.call("GET", "/blocks")[1] or {}).get("items", []) if b.get("client") in rest] for n, x in zip(nodes, d)},
                  "status": {n.name: n.status() for n in nodes}}
            time.sleep(30)
            later = left()
            ev["still_there_30_s_later"] = later
            # what a person finds who looks again: the incident on the node that lifted, and a second "Freigeben" there
            again = []
            for r in ev["remaining"][:6]:
                x = d[[n.name for n in nodes].index(r["lifted_on"])]
                before = state(r["address"])
                st_i, js_i = x.call("GET", "/incidents/%s" % r["incident"])
                st_2, js_2 = x.unblock(r["incident"])
                time.sleep(1.5)
                again.append({"address": r["address"], "before": before,
                              "incident_on_the_lifting_node": {"status": st_i, "says": (js_i or {}).get("status") if isinstance(js_i, dict) else None},
                              "second_lift_there": st_2, "second_lift_answer": json.dumps(js_2)[:200],
                              "after_1_5_s": state(r["address"])})
            ev["a_second_lift_of_the_first_six"] = again
            ev["the_others_at_that_time"] = {r["address"]: state(r["address"]) for r in ev["remaining"][6:9]}
            evidence = json.dumps(ev)
            with open("/opt/sg27/out/s11-round%d-evidence.json" % rnd_no, "w") as f:
                json.dump(dict(ev, all_rows=rows), f, indent=1)
        R.check(S, "11.0%d" % rnd_no, "round %d: %d addresses, each blocked on one of three nodes and lifted on another %s to %s s later: 5 s after the last lift no block of them is left on any node"
                % (rnd_no, pairs, lo, hi), not rest and not never,
                {"pairs": len(rows), "blocks_left": len(rest), "left_on": sorted(set(x for v in rest.values() for x in v)),
                 "left_on_all_three_nodes": sum(1 for v in rest.values() if len(v) == 3),
                 "of_those_still_listed_as_a_running_block_on_all_three": sum(1 for v in where.values() if len(v["listed_on"]) == 3),
                 "of_those_requests_still_refused_on_all_three": sum(1 for v in where.values() if len(v["refused_on"]) == 3),
                 "of_those_requests_refused_on_no_node": sum(1 for v in where.values() if not v["refused_on"]),
                 "still_left_30_s_later": len(later) if later is not None else None,
                 "of_the_left_ones_the_lift_was_answered_200_at_once": sum(1 for r in rows if r["address"] in rest and r["lift_status"] == 200),
                 "pause_s_of_the_left_ones": sorted(r["pause_s"] for r in rows if r["address"] in rest),
                 "left_per_setting_and_lifting_node": {"%s>%s" % (p, q): "%d of %d" % (sum(1 for r in rows if r["set_on"] == p and r["lifted_on"] == q and r["address"] in rest),
                                                                               sum(1 for r in rows if r["set_on"] == p and r["lifted_on"] == q))
                                                       for p in ("n1", "n2", "n3") for q in ("n1", "n2", "n3") if p != q},
                 "block_calls_not_200": sum(1 for r in rows if r["block_status"] != 200),
                 "lifts_answered_200_at_once": len(rows) - len(first_404), "lifts_first_answered_otherwise": len(first_404),
                 "first_answers_otherwise": sorted(set(r["lift_status"] for r in first_404)),
                 "of_those_the_shortest_and_longest_pause_s": [min([r["pause_s"] for r in first_404], default=None), max([r["pause_s"] for r in first_404], default=None)],
                 "ms_until_200_for_those": summary([r["lift_answered_200_after_ms"] for r in first_404 if r.get("lift_answered_200_after_ms") is not None]),
                 "lifts_never_answered_200": len(never), "lift_call_ms": summary([r["lift_call_ms"] for r in rows]),
                 "clock_of_each_node_against_the_client_s": offsets}, evidence[:6000])
    # What follows from a block that stays listed after its lift. An edge gets the block list of the group for its
    # firewall: a balancer VM joins now, as in scenario 4, and its nftables set is read.
    lb = lab.lb
    EDGE = "/var/lib/schild-edge"
    lb.run("pkill -x schild; nft delete table inet schild 2>/dev/null; rm -rf %s; true" % EDGE)
    lab.haproxy(nodes)
    lab.wait_lb({n.name: "UP" for n in nodes}, 20)
    # one of the left-over addresses becomes a real visitor: the client VM takes the address, the balancer VM and
    # the gateways route it back
    probe = leftover[0] if leftover else None
    if probe:
        lab.client.run("ip addr add %s/32 dev lo 2>/dev/null; true" % probe)
        for vm in [lb] + nodes:
            vm.run("ip route replace %s/32 via %s" % (probe, lab.client.ip))
    through_before = get(lb.ip, "/x", bind=probe, timeout=2) if probe else None
    rc_join = -1  # edges and join codes were removed in 5b12c2c: not run
    real = CLIENT_NET + "240"
    d[0].block(real)
    held = wait_until(lambda: not tcp_open(lb.ip, 80, bind=real), 8, 0.1)
    other_ok = tcp_open(lb.ip, 80, bind=CLIENT_NET + "241")
    through_after = get(lb.ip, "/x", bind=probe, timeout=2) if probe else None
    table = lb.run("nft list table inet schild")[1]

    def in_set(a):
        return re.search(r"(^|[\s,{])%s(\s|,|$)" % re.escape(a), table, re.M) is not None
    in_fw = [a for a in lifted if in_set(a)]
    timeout_of = re.search(re.escape(in_fw[0]) + r"[^,}\n]*", table).group(0) if in_fw else ""
    rc_fs, fs = lb.run("schild firewall status -data %s | head -4" % EDGE)
    R.check(S, "11.04", "an edge that joins after the three rounds: its firewall holds none of the 500 addresses whose block was lifted (each lift was answered 200)",
            rc_join == 0 and held is not None and other_ok and not in_fw,
            {"edge_join_exit": rc_join, "a_block_that_runs_is_dropped_on_the_edge": held is not None, "an_address_never_blocked_connects": other_ok,
             "lifted_addresses_in_the_firewall_set": len(in_fw),
             "a_visitor_with_one_of_them_through_the_balancer_before_the_edge_ran": through_before,
             "the_same_visitor_with_the_edge_running": through_after,
             "of_them_left_over_in_the_lists_of_the_gateways": sum(1 for a in in_fw if a in leftover), "addresses_left_over_on_the_gateways": len(leftover),
             "element_of_one_of_them": timeout_of}, fs[:500])
    lb.run("pkill -TERM -x schild; sleep 1; nft delete table inet schild 2>/dev/null; rm -rf %s; true" % EDGE)
    d[0].unblock(incident_of(d[0], real))
    if probe:
        lab.client.run("ip addr del %s/32 dev lo 2>/dev/null; true" % probe)
        for vm in [lb] + nodes:
            vm.run("ip route del %s/32 2>/dev/null; true" % probe)

    # and after the gateways restarted: do the listed blocks refuse again?
    for n in nodes:
        n.kill9()
    time.sleep(1)
    for n in nodes:
        n.start()
    ready = [n.wait_ready(40) for n in nodes]
    time.sleep(4)
    d2 = [Dash(n, d[0]) for n in nodes]
    listed = [set(x.blocks() or []) for x in d2]
    R.check(S, "11.05", "after a restart of all three gateways: what became of the blocks that stayed listed (listed, refused)", None,
            {"all_ready": all(r is not None for r in ready), "left_over_before": len(leftover),
             "still_listed_on_all_three": sum(1 for a in leftover if all(a in l for l in listed)),
             "requests_refused_on_any_node": sum(1 for a in leftover if any(get(n.ip, "/x", claim=a, timeout=2) == 403 for n in nodes)),
             "status_line": [l for l in nodes[0].status().splitlines() if l.startswith("Blocks")]})
    for n in nodes:
        n.kill9()


SCENARIOS = {"s8": s8, "s9": s9, "s10": s10, "s11": s11}
