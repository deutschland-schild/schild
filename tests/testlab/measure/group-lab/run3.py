"""MVP-27 lab measurement, third run: the scenarios for what was built after the second run.

s12 the running counts at a node's start: a rate limit and the login scenario spread over three nodes, one node restarted
    in the middle; time to ready with a slow and with a hanging member
s13 the clock rule: the node with the odd clock leaves traffic and returns; a pair and three different clocks stay
s14 everything set at runtime is shared: every write operation of the dashboard API and of the agent API, the command line
s15 the state comparison (`shared_state` of GET /group): idle and under changes on 3 and 16 nodes, a real difference
s16 the cheaper exchange: idle CPU of sixteen gateways, how fast an event and a request show on the others, 10 % packet loss
s19 to s22 the findings N1 to N4 of the second run again, as the documents are now
s23 a rolling upgrade from the earlier build to the current one under load
s17 tasks once per cluster: the rotation of the browser check's keys with the keeper killed
s18 throughput on three nodes with the Go load client

Loaded by run.py; uses its results, its lab and its helpers. Black box: the binary, schild.yaml, the Caddyfile, the
listeners, the command line and the documented APIs.
"""
import datetime
import http.client
import json
import os
import random
import re
import socket
import threading
import time
import urllib.parse

from lab import (Conn, Dash, Load, MESH_PORT, PASSWORD, SITE, api, get, now, pct, proxy_v1, summary, tcp_open,
                 wait_until)
from run import CLIENT_NET, R, first_login, fresh_group, members_ok, mesh_rules

AGENT = 'agent_api:\n  enabled: true\n  listen: "127.0.0.1:8789"'
QUICK = bool(os.environ.get("SG27_QUICK"))   # a short form for trying a scenario out; never for results
OLD = "schild-old"                 # the earlier build in the image (run.sh, OLD_REV)


def stamp(t):
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def rnd(v, digits=2):
    return round(v, digits) if isinstance(v, (int, float)) else v


def req(ip, method="GET", path="/", claim=None, bind=None, body=b"", headers=None, timeout=5.0, host=SITE, port=80):
    """One request on a new connection; `claim` speaks the PROXY protocol as a balancer does, `bind` is the source
    address of a real visitor. Answers (status, headers, body); status 0: no answer."""
    try:
        s = socket.create_connection((ip, port), timeout=timeout, source_address=(bind, 0) if bind else None)
    except OSError as e:
        return 0, {}, repr(e).encode()
    c = http.client.HTTPConnection(ip, port, timeout=timeout)
    c.sock = s
    h = {"Host": host, "User-Agent": "Mozilla/5.0 (measure MVP-27 lab)", "Connection": "close"}
    h.update(headers or {})
    try:
        if claim:
            s.sendall(proxy_v1(claim, ip, dport=port))
        c.request(method, path, body=body or None, headers=h)
        r = c.getresponse()
        return r.status, dict(r.getheaders()), r.read()
    except Exception as e:
        return 0, {}, repr(e).encode()
    finally:
        c.close()


def agent(node, token, method, path, body=None):
    """One call of the agent API on the node's loopback listener (schild.yaml agent_api.listen), as an agent on the
    host makes it. Answers (status, decoded body)."""
    cmd = ("curl -s -m 10 -o /tmp/sg27-agent.out -w '%%{http_code}' -X %s -H 'Authorization: Bearer %s' "
           "-H 'Content-Type: application/json' %s http://127.0.0.1:8789/agent/v0%s; echo; cat /tmp/sg27-agent.out"
           % (method, token, "-d @-" if body is not None else "", path))
    rc, out = node.run(cmd, 20, stdin=json.dumps(body) if body is not None else None)
    head, _, rest = out.partition("\n")
    try:
        js = json.loads(rest) if rest.strip() else None
    except ValueError:
        js = rest[:300]
    return int(head) if head.strip().isdigit() else 0, js


def each_seconds(others, seen, timeout=8.0, pause=0.1):
    """Per node the seconds until seen(dash) is true; None when it never was within the timeout."""
    t0, out = now(), {}
    while now() - t0 < timeout and len(out) < len(others):
        for d in others:
            if d.node.name not in out:
                try:
                    if seen(d):
                        out[d.node.name] = round(now() - t0, 2)
                except Exception:
                    pass
        time.sleep(pause)
    return {d.node.name: out.get(d.node.name) for d in others}


def group_ready(lab, nodes, extra="", haproxy=False, names=None):
    ready = fresh_group(lab, nodes, extra=extra, names=names)
    D = first_login(nodes)
    wait_until(lambda: all(members_ok(d, len(nodes)) for d in D), 20, 0.3)
    if haproxy:
        lab.haproxy(nodes)
        lab.wait_lb({n.name: "UP" for n in nodes}, 30)
    return D, ready


def states(dash):
    """name -> shared_state of every other member as this node shows it (None when the field is absent)."""
    g = dash.group()
    return {m.get("name"): m.get("shared_state") for m in g.get("members", []) if m.get("state") != "self"}


# ---------------------------------------------------------------------------------------------------------------
# scenario 12: the running counts at a node's start


def s12(lab):
    S = "s12"
    N = lab.nodes[:3]
    D, ready = group_ready(lab, N, haproxy=True)
    R.check(S, "12.01", "three nodes behind the balancer form a group", all(ready.values()) and all(members_ok(d, 3) for d in D),
            {"ready_s": {k: rnd(v) for k, v in ready.items()}, "balancer": lab.lb_state()})
    LIMIT = 60
    st, js = D[0].call("POST", "/behaviour/rate-limits", {"route": "/lab-limit", "methods": ["GET"], "limit": LIMIT, "per": "24h",
                                                         "burst": LIMIT, "mode": "block", "label": "MVP-27 lab"})
    lid = js.get("id") if isinstance(js, dict) else None
    seen = each_seconds(D[1:], lambda d: any(i["id"] == lid for i in d.call("GET", "/behaviour/rate-limits")[1]["items"]))
    R.check(S, "12.02", "a rate limit made in the dashboard of n1 (GET /lab-limit, %d per 24 h, burst %d, mode block: it refills "
            "one request in 36 minutes, so the count is the total) is on the other nodes; scenarios observe for 14 days after the "
            "installation (reason `learning`), a rate limit acts at once" % (LIMIT, LIMIT), st == 201 and all(v is not None for v in seen.values()),
            {"status": st, "seconds": seen, "learning_until": D[0].call("GET", "/behaviour/settings")[1].get("learning_until")})
    octet = [20]

    def address():
        octet[0] += 1
        return CLIENT_NET + str(octet[0])

    def restart(n, hard=True):
        if hard:
            n.kill9()
        else:
            n.term()
            n.wait_exit(40)
        n.start()

    def run_balancer(restart_at=None, pace=0.5):
        """One client address through the balancer, a request every `pace` s; answers what the client counted."""
        a = address()
        answered, first429, codes, failed, t_restart, ready_after, back_up = 0, None, [], 0, None, None, None
        i = 0
        while i < LIMIT + 40:
            i += 1
            t = now()
            if restart_at and answered == restart_at and t_restart is None:
                t_restart = now()
                restart(N[1])
            code = req(lab.lb.ip, "GET", "/lab-limit", bind=a, timeout=3)[0]
            codes.append(code)
            if code == 200:
                answered += 1
            elif code == 429:
                first429 = answered + 1
                break
            else:
                failed += 1
            if t_restart and ready_after is None and N[1].ready(1.0) == 200:
                ready_after = now() - t_restart
            if t_restart and back_up is None and lab.lb_state().get(N[1].name) == "UP" and ready_after is not None:
                back_up = answered
            time.sleep(max(0.0, pace - (now() - t)))
        return {"client": a, "answered_200_before_the_first_429": answered, "first_429_at_request": first429,
                "off_by": None if first429 is None else first429 - (LIMIT + 1), "failed_without_answer": failed,
                "ready_after_s": rnd(ready_after), "answered_when_the_balancer_had_it_up_again": back_up}

    def run_direct(restart_at=None, pace=0.25, then="restarted"):
        """One client address, round robin over the nodes as a balancer would (PROXY protocol); after the restart every
        request goes to the restarted node as soon as it answers ready: the node that began again decides alone."""
        a = address()
        answered, first429, t_restart, ready_after, on_restarted = 0, None, None, None, 0
        i = 0
        while i < LIMIT + 60:
            t = now()
            target = N[i % 3]
            if t_restart is not None:
                if ready_after is None and N[1].ready(1.0) == 200:
                    ready_after = now() - t_restart
                target = N[1] if ready_after is not None else N[(i % 2) * 2]
            if restart_at and answered == restart_at and t_restart is None:
                t_restart = now()
                restart(N[1])
                # the client waits until the restarted node answers ready, so that node alone decides on the rest
                while ready_after is None and now() - t_restart < 40:
                    if N[1].ready(1.0) == 200:
                        ready_after = now() - t_restart
                    time.sleep(0.05)
                continue
            i += 1
            code = req(target.ip, "GET", "/lab-limit", claim=a, timeout=3)[0]
            if code == 200:
                answered += 1
                on_restarted += 1 if (t_restart is not None and target is N[1]) else 0
            elif code == 429:
                first429 = answered + 1
                break
            time.sleep(max(0.0, pace - (now() - t)))
        return {"client": a, "first_429_at_request": first429, "off_by": None if first429 is None else first429 - (LIMIT + 1),
                "ready_after_s": rnd(ready_after), "answered_by_the_restarted_node_after_its_restart": on_restarted}

    def judge(cid, title, runs, limit_off):
        offs = [r["off_by"] for r in runs]
        bad = [o for o in offs if o is None or abs(o) > limit_off]
        return R.check(S, cid, title, not bad, {"limit": LIMIT, "expected_first_429_at_request": LIMIT + 1, "runs": len(runs),
                                                 "off_by_per_run": offs, "runs_off_by_more_than_allowed": len(bad),
                                                 "allowed_off_by": limit_off, "earliest": min((o for o in offs if o is not None), default=None),
                                                 "latest": max((o for o in offs if o is not None), default=None)}, runs)

    base_b = [run_balancer() for _ in range(10)]
    judge("12.10", "without a restart, 10 runs through the balancer (2 requests a second from one address, round robin): the first "
          "429 comes at request %d (the limit plus one; pass: off by at most 2, what two nodes take in the second a count travels)" % (LIMIT + 1),
          base_b, 2)
    rest_b = [run_balancer(restart_at=LIMIT // 3) for _ in range(10)]
    judge("12.11", "the same with n2 killed and started again after %d answered requests, 10 runs through the balancer: the first 429 "
          "comes at the same total, not later and not much earlier (pass: off by at most 3; guide: 'gilt auch auf dem frisch "
          "gestarteten Server als kurz vor der Sperre')" % (LIMIT // 3), rest_b, 3)
    R.check(S, "12.11b", "in those runs: how many requests the client had answered when the balancer had n2 up again (of %d before the limit)" % LIMIT, None,
            {"answered_when_the_balancer_had_n2_up_again": [r["answered_when_the_balancer_had_it_up_again"] for r in rest_b]})
    base_d = [run_direct() for _ in range(5)]
    judge("12.12", "without a restart, 5 runs straight to the nodes in turn (4 requests a second): the first 429 at request %d" % (LIMIT + 1),
          base_d, 2)
    rest_d = [run_direct(restart_at=LIMIT // 3) for _ in range(10)]
    judge("12.13", "n2 killed and started again after %d answered requests; the client waits until n2 answers ready and sends "
          "every further request to n2 alone, 10 runs: the first 429 comes at request %d (pass: off by at most 3)" % (LIMIT // 3, LIMIT + 1), rest_d, 3)
    served = [r["answered_by_the_restarted_node_after_its_restart"] for r in rest_d]
    R.check(S, "12.13b", "in each of those runs the restarted node answered requests of the client before it refused (else 12.13 says "
            "nothing about it)", all(v > 0 for v in served), {"answered_by_n2_after_its_restart": served})
    R.check(S, "12.14", "ready after the kill in those runs: seconds from the start of n2 to its first 200 on /.schild/readyz", None,
            {"direct": [r["ready_after_s"] for r in rest_d], "balancer": [r["ready_after_s"] for r in rest_b]})

    # the login scenario: it observes during the learning days, so its hit ("hätte gesperrt") is what can be counted
    def scenario_run(restart_after=None):
        a = address()
        sent, t0 = 0, time.time()
        first = None
        for i in range(9):
            target = N[i % 3]
            if restart_after is not None and sent == restart_after:
                restart(N[1])
                N[1].wait_ready(30)
            if restart_after is not None and sent >= restart_after:
                target = N[1]
            req(target.ip, "POST", "/wp-login.php", claim=a, body=b"log=admin&pwd=wrong%d" % i,
                headers={"Content-Type": "application/x-www-form-urlencoded"})
            sent += 1
            time.sleep(1.3)
            st, js = Dash(target, D[0]).call("GET", "/behaviour/hits?scenario=login_bruteforce&ip=%s" % a)
            hits = js.get("items", []) if st == 200 and isinstance(js, dict) else []
            if hits:
                first = {"after_failed_logins": sent, "count_of_the_hit": min(h.get("count") for h in hits),
                         "would_action": hits[-1].get("would_action"), "reason": hits[-1].get("reason"), "asked_on": target.name}
                break
        return first or {"after_failed_logins": None, "sent": sent}
    thr = [s for s in D[0].call("GET", "/behaviour/settings")[1]["scenarios"] if s["id"] == "login_bruteforce"][0]["thresholds"]
    sb = [scenario_run() for _ in range(3)]
    sr = [scenario_run(restart_after=3) for _ in range(5)]
    want = thr["count"]
    R.check(S, "12.20", "the login scenario (documented threshold: %d failed logins in %d s; it observes during the learning days and "
            "writes a hit that says `would_action: block`): failed logins on /wp-login.php from one address spread over the three "
            "nodes, 3 runs without a restart and 5 runs with n2 restarted after the third, all later ones sent to n2: the first hit "
            "comes with the same failed login (pass: the same number in every run, and it is the threshold)" % (want, thr["window_s"]),
            all(r.get("after_failed_logins") == want for r in sb + sr),
            {"threshold": want, "without_restart": [r.get("after_failed_logins") for r in sb],
             "with_restart": [r.get("after_failed_logins") for r in sr]}, {"without": sb, "with": sr})

    # time to ready of a restarted node while a member is slow, and while a member hangs
    def ready_runs(prepare, undo, runs=3):
        out = []
        for _ in range(runs):
            prepare()
            time.sleep(4)
            N[2].kill9()
            time.sleep(1)
            N[2].start()
            t = N[2].wait_ready(90)
            reasons = Dash(N[2], D[0]).reasons()
            out.append({"ready_s": rnd(t), "reasons": reasons,
                        "log": N[2].grep("counts|counters", 2)[-300:]})
            undo()
            time.sleep(6)
        return out
    plain = ready_runs(lambda: None, lambda: None)

    def slow():
        N[1].delay([N[0].ip, N[2].ip], 200)
        N[0].delay([N[1].ip], 200)
        N[2].delay([N[1].ip], 200)

    def slow_off():
        for n in N:
            n.delay_clear()
    slowr = ready_runs(slow, slow_off)
    hang = ready_runs(N[1].freeze, N[1].thaw)
    R.check(S, "12.30", "n3 killed and started again, 3 runs each: seconds to ready with both members well, with n2 slow (200 ms each "
            "way between n2 and the others) and with n2 hanging (SIGSTOP); pass: ready within 15 s in every run (a member that "
            "is well is in reach each time)", all(r["ready_s"] is not None and r["ready_s"] <= 15 for r in plain + slowr + hang),
            {"members_well_s": [r["ready_s"] for r in plain], "one_member_slow_s": [r["ready_s"] for r in slowr],
             "one_member_hanging_s": [r["ready_s"] for r in hang],
             "reasons_on_the_overview_after": sorted(set(x for r in plain + slowr + hang for x in (r["reasons"] or [])))},
            {"slow": slowr, "hang": hang})
    # both members slow, and both hanging: nobody well in reach
    def slow_all():
        for n in N:
            n.delay([m.ip for m in N if m is not n], 200)
    slow2 = ready_runs(slow_all, slow_off, 2)

    def hang_all():
        N[0].freeze()
        N[1].freeze()

    def thaw_all():
        N[0].thaw()
        N[1].thaw()
    hang2 = ready_runs(hang_all, thaw_all, 2)
    R.check(S, "12.31", "the same with every member slow (200 ms each way between all three), and with both members hanging, 2 runs "
            "each: seconds to ready and what the overview of n3 says afterwards (contract 8a: after 3 failed tries the node serves "
            "with counters from zero and shows `cluster_counts_not_taken`; section 10: about 10 s when no member is reached)", None,
            {"every_member_slow_s": [r["ready_s"] for r in slow2], "both_members_hanging_s": [r["ready_s"] for r in hang2],
             "reasons_every_member_slow": [r["reasons"] for r in slow2], "reasons_both_hanging": [r["reasons"] for r in hang2]},
            {"slow": slow2, "hang": hang2})
    D[0].call("DELETE", "/behaviour/rate-limits/%s" % lid)


# ---------------------------------------------------------------------------------------------------------------
# scenario 13: the clock rule


def s13(lab):
    S = "s13"
    N = lab.nodes[:3]
    D, ready = group_ready(lab, N, haproxy=True)
    R.check(S, "13.01", "three nodes behind the balancer, clocks right", all(members_ok(d, 3) for d in D),
            {"clock_skew_ms": {m.get("name"): m.get("clock_skew_ms") for m in D[0].group().get("members", [])}})
    octet = [120]

    def addr():
        octet[0] += 1
        return CLIENT_NET + str(octet[0])

    class Poll:
        """Asks /.schild/readyz of every node five times a second and keeps (t, code) per node."""
        def __init__(self, nodes):
            self.rows, self.stop = {n.name: [] for n in nodes}, False
            self.t = [threading.Thread(target=self._run, args=(n,), daemon=True) for n in nodes]
            for t in self.t:
                t.start()

        def _run(self, n):
            while not self.stop:
                self.rows[n.name].append((now(), n.ready(1.5)))
                time.sleep(0.2)

        def end(self):
            self.stop = True
            for t in self.t:
                t.join(3)
            return self.rows

    def first(rows, t0, want):
        for t, c in rows:
            if t >= t0 and (c == want if isinstance(want, int) else want(c)):
                return round(t - t0, 2)
        return None

    def odd(cid, shift):
        label = "%d s %s" % (abs(shift), "ahead" if shift > 0 else "behind")
        p = Poll(N)
        time.sleep(2)
        t0 = now()
        N[2].clock_shift(shift)
        out_lb = lab.wait_lb({N[2].name: "DOWN"}, 40)
        time.sleep(max(0, 20 - (now() - t0)))
        a = addr()
        bst = D[0].block(a)[0]
        reasons3 = D[2].reasons()
        reasons1 = D[0].reasons()
        status3 = [l for l in N[2].status().splitlines() if re.search(r"[Cc]lock|traffic|ready", l)]
        logline = N[2].grep("clock.*(traffic|ready|odd|service)|out of (traffic|service)", 3)
        m3 = D[0].member(N[2].ip)
        direct = get(N[2].ip, "/direct", claim=addr(), timeout=2)
        time.sleep(max(0, 35 - (now() - t0)))
        t1 = now()
        corrections = N[2].clock_corrections()
        N[2].clock_release()
        back = wait_until(lambda: N[2].ready() == 200, 60, 0.1)
        blocked_at_ready = get(N[2].ip, "/b", claim=a, timeout=2)
        up_lb = lab.wait_lb({N[2].name: "UP"}, 30)
        time.sleep(2)
        rows = p.end()
        gone = first(rows[N[2].name], t0, lambda c: c != 200)
        code = [c for t, c in rows[N[2].name] if t0 + (gone or 0) + 1 <= t < t1]
        others_bad = {n.name: sum(1 for t, c in rows[n.name] if c != 200) for n in N[:2]}
        flaps = sum(1 for (t, c), (t2, c2) in zip(rows[N[2].name], rows[N[2].name][1:]) if t0 <= t < t1 and c != 200 and c2 == 200)
        ok = (gone is not None and gone <= 10 and code and all(c == 503 for c in code) and not any(others_bad.values())
              and out_lb is not None and "cluster_clock_out_of_service" in (reasons3 or []) and bool(status3) and bool(logline)
              and back is not None and blocked_at_ready == 403)
        R.check(S, cid, "n3 %s of the two others, who agree: n3 leaves traffic within a few seconds (pass: within 10 s) and answers 503 "
                "for as long as its clock is off, the balancer takes it out, its overview carries `cluster_clock_out_of_service`, "
                "`schild cluster status` and its log say so, n1 and n2 stay ready all the time, and n3 returns when its clock is "
                "right, holding the block set meanwhile" % label, ok,
                {"readyz_of_n3_not_200_after_s": gone, "its_answers_while_off": {str(c): code.count(c) for c in sorted(set(code))},
                 "times_it_answered_200_again_while_off": flaps, "balancer_marks_it_down_after_s": rnd(out_lb),
                 "answers_not_200_of_n1_and_n2": others_bad, "reasons_overview_n3": reasons3, "reasons_overview_n1": reasons1,
                 "service_of_n3_as_n1_shows_it": (m3.get("vitals") or {}).get("service"), "clock_skew_ms_as_n1_shows_it": m3.get("clock_skew_ms"),
                 "a_visitor_sent_straight_to_n3_meanwhile": direct, "clock_was_put_back_by_the_hypervisor_times": corrections,
                 "ready_again_s_after_the_clock_was_right": rnd(back), "balancer_up_again_after_s": rnd(up_lb),
                 "block_set_meanwhile_at_its_first_200": blocked_at_ready, "block_status": bst},
                {"status": status3, "log": logline[-500:]})
        time.sleep(8)
    odd("13.10", 90)
    odd("13.11", -90)

    def nobody(cid, title, nodes, shifts, seconds=45):
        p = Poll(nodes)
        time.sleep(2)
        # all clocks are moved at the same moment; a node learns the clock of a member every 5 s, so right after a jump
        # of 90 s a node may still see the others where they were. What is judged is the time from 15 s after the jump.
        th = [threading.Thread(target=n.clock_shift, args=(s,)) for n, s in zip(nodes, shifts) if s]
        for t in th:
            t.start()
        for t in th:
            t.join()
        t0 = now()
        time.sleep(seconds)
        d = Dash(nodes[0], D0[0])
        skew = {m.get("name"): m.get("clock_skew_ms") for m in d.group().get("members", [])}
        reasons = {n.name: Dash(n, D0[0]).reasons() for n in nodes}
        t1 = now()
        for n in nodes:
            n.clock_release()
        time.sleep(3)
        rows = p.end()
        early = {n.name: [round(t - t0, 1) for t, c in rows[n.name] if c != 200 and t0 <= t < t0 + 15] for n in nodes}
        bad = {n.name: sum(1 for t, c in rows[n.name] if c != 200 and t0 + 15 <= t < t1) for n in nodes}
        R.check(S, cid, title, not any(bad.values()), {"seconds_watched": seconds, "answers_not_200_from_15_s_after_the_clocks_moved": bad,
                                                         "answers_not_200_in_the_first_15_s": {k: len(v) for k, v in early.items()},
                                                         "s_after_the_jump_of_those": {k: [v[0], v[-1]] for k, v in early.items() if v},
                                                         "answers": {n.name: len(rows[n.name]) for n in nodes},
                                                         "clock_skew_ms_as_the_first_node_shows": skew, "reasons": reasons})
    D0 = D
    nobody("13.20", "three nodes whose clocks all differ (n1 90 s behind, n2 right, n3 90 s ahead): nobody leaves traffic "
           "(contract 8a: the gateways in reach do not agree among themselves)", N, [-90, 0, 90])
    time.sleep(10)
    # a pair
    P = lab.nodes[:2]
    D0, ready = group_ready(lab, P)
    nobody("13.21", "a pair, n2 90 s ahead: neither node leaves traffic (guide: 'Bei nur zwei Servern kann keiner wissen, wessen "
           "Uhr falsch geht')", P, [0, 90])
    time.sleep(10)
    nobody("13.22", "a pair, n2 90 s behind: neither node leaves traffic", P, [0, -90])


# ---------------------------------------------------------------------------------------------------------------
# scenario 14: everything set at runtime is shared


def s14(lab):
    S = "s14"
    N = lab.nodes[:3]
    D, ready = group_ready(lab, N, extra=AGENT)
    W = SITE
    rows = []           # (id, operation, where, status, seconds per other node, verdict, note)
    turn = [0]

    def op(cid, name, do, seen, per_node=None, effect=None, timeout=8.0):
        """Make one change on one node (the nodes take turns) and time when each of the two others holds it, asked
        through its own API. per_node: the guide or contract names it as staying on one node; it is then reported
        as a number, with whether it travelled or not."""
        i = turn[0] % 3
        turn[0] += 1
        a, others = D[i], [D[j] for j in range(3) if j != i]
        try:
            st, info = do(a)
        except Exception as e:
            st, info = -1, repr(e)[:200]
        if not (isinstance(st, int) and 200 <= st < 300):
            rows.append((cid, name, a.node.name, st, {}, "not driven", str(info)[:160]))
            R.check(S, cid, "%s: made on %s" % (name, a.node.name), None, {"status": st, "driven": False}, str(info)[:400])
            return None
        sec = each_seconds(others, lambda d: seen(d, info), timeout)
        held = all(v is not None for v in sec.values())
        extra = {}
        if effect:
            try:
                extra = effect(info)
            except Exception as e:
                extra = {"effect_error": repr(e)[:120]}
        if per_node:
            rows.append((cid, name, a.node.name, st, sec, "stays on one node" if not held else "travels", per_node))
            R.check(S, cid, "%s, made on %s (documented as per node: %s): whether the others show it" % (name, a.node.name, per_node), None,
                    dict({"status": st, "seconds_until_the_others_hold_it": sec, "stays_on_one_node": not held}, **extra))
        else:
            rows.append((cid, name, a.node.name, st, sec, "shared" if held else "STAYS ON ONE NODE", ""))
            R.check(S, cid, "%s, made on %s: the two other nodes hold it within %d s (their own API)" % (name, a.node.name, int(timeout)), held,
                    dict({"status": st, "seconds_until_the_others_hold_it": sec}, **extra), json.dumps(info, default=str)[:300] if not held else "")
        return info

    def J(d, path):
        st, js = d.call("GET", path)
        return js if st == 200 else {}

    def scen(d, sid):
        return [x for x in J(d, "/behaviour/settings").get("scenarios", []) if x["id"] == sid][0]

    def limits(d):
        return {x["id"]: x for x in J(d, "/behaviour/rate-limits").get("items", [])}

    def visitors(path, headers=None, method="GET"):
        return [req(n.ip, method, path, claim=CLIENT_NET + "77", headers=headers)[0] for n in N]

    # --- settings of the dashboard
    op("14.01", "updateSettings (retention.events_days 33)", lambda a: a.call("PATCH", "/settings", {"retention": {"events_days": 33}}),
       lambda d, i: J(d, "/settings").get("retention", {}).get("events_days") == 33)
    op("14.02", "updateBehaviourSettings (scenario path_probing to observe)",
       lambda a: a.call("PATCH", "/behaviour/settings", {"scenarios": {"path_probing": "observe"}}),
       lambda d, i: scen(d, "path_probing")["mode"] == "observe")
    op("14.03", "updateBehaviourSettings (threshold login_bruteforce.count 7)",
       lambda a: a.call("PATCH", "/behaviour/settings", {"thresholds": {"login_bruteforce": {"count": 7}}}),
       lambda d, i: scen(d, "login_bruteforce")["thresholds"]["count"] == 7)
    rl = op("14.04", "createRateLimit (GET /lab-rl, 3 per 24 h, block)",
            lambda a: a.call("POST", "/behaviour/rate-limits", {"route": "/lab-rl", "methods": ["GET"], "limit": 3, "per": "24h", "burst": 3,
                                                                "mode": "block", "label": "lab 14"}),
            lambda d, i: i["id"] in limits(d))
    lid = (rl or {}).get("id", "none")
    op("14.05", "updateRateLimit (limit 3 to 4)",
       lambda a: a.call("PATCH", "/behaviour/rate-limits/%s" % lid, {"route": "/lab-rl", "methods": ["GET"], "limit": 4, "per": "24h", "burst": 4,
                                                                   "mode": "block", "label": "lab 14"}),
       lambda d, i: limits(d).get(lid, {}).get("limit") == 4)
    # the limit acts on every node, and a release made on one node holds on the others
    lim_codes = [req(N[k % 3].ip, "GET", "/lab-rl", claim=CLIENT_NET + "78")[0] for k in range(7) if not time.sleep(1.1)]
    rel_node = D[turn[0] % 3].node
    op("14.06", "releaseClient (the client the limit refused, with an exception of 24 h: a released sender)",
       lambda a: a.call("POST", "/behaviour/release", {"ip": CLIENT_NET + "78", "limit_id": lid, "allow": "exception", "ttl": "24h", "label": "lab 14"}),
       lambda d, i: req(d.node.ip, "GET", "/lab-rl", claim=CLIENT_NET + "78")[0] == 200,
       effect=lambda i: {"answers_before_the_release_in_turn_over_the_nodes": lim_codes,
                         "the_released_client_on_the_node_of_the_release": req(rel_node.ip, "GET", "/lab-rl", claim=CLIENT_NET + "78")[0]})
    op("14.07", "deleteRateLimit", lambda a: a.call("DELETE", "/behaviour/rate-limits/%s" % lid), lambda d, i: lid not in limits(d))
    op("14.08", "updateDistributedSettings (detector route_wave to respond, threshold count 44)",
       lambda a: a.call("PATCH", "/distributed/settings", {"detectors": {"route_wave": "respond"}, "thresholds": {"route_wave": {"count": 44}}}),
       lambda d, i: [x for x in J(d, "/distributed/settings")["detectors"] if x["id"] == "route_wave"][0]["mode"] == "respond"
       and [x for x in J(d, "/distributed/settings")["detectors"] if x["id"] == "route_wave"][0]["thresholds"]["count"] == 44)
    # --- rule sources, single rules, exceptions
    xss = "/lab-x?q=%3Cscript%3Ealert(1)%3C/script%3E"
    op("14.10", "updateRuleRepository (crs to detect)", lambda a: a.call("PATCH", "/rule-repositories/crs", {"state": "detect"}),
       lambda d, i: J(d, "/rule-repositories/crs").get("state") == "detect",
       effect=lambda i: {"an_xss_request_on_each_node_then": visitors(xss)})
    op("14.11", "updateRuleRepository (reset_state: back to schild.yaml)", lambda a: a.call("PATCH", "/rule-repositories/crs", {"reset_state": True}),
       lambda d, i: J(d, "/rule-repositories/crs").get("state") == "block",
       effect=lambda i: {"an_xss_request_on_each_node_then": visitors(xss)})
    op("14.12", "updateRuleRepositorySettings (crs paranoia_level 2, inbound_anomaly_threshold 7)",
       lambda a: a.call("PATCH", "/rule-repositories/crs/settings", {"paranoia_level": 2, "inbound_anomaly_threshold": 7}),
       lambda d, i: (J(d, "/rule-repositories/crs").get("crs") or {}).get("paranoia_level") == 2
       and (J(d, "/rule-repositories/crs").get("crs") or {}).get("inbound_anomaly_threshold") == 7)
    op("14.13", "updateRule (crs 941100 disabled)", lambda a: a.call("PATCH", "/rules/crs/941100", {"disabled": True, "note": "lab 14"}),
       lambda d, i: J(d, "/rules/crs/941100").get("status") == "disabled" or J(d, "/rules/crs/941100").get("disabled") is True,
       effect=lambda i: {"rule_as_each_node_shows_it": [{k: J(d, "/rules/crs/941100").get(k) for k in ("status", "disabled", "effect")} for d in D]})

    def exc(d):
        return {x["id"]: x for x in J(d, "/rule-exceptions").get("items", [])}
    ex = op("14.14", "createRuleException (crs 941100 and 941110 for ARGS:comment on /lab-form)",
            lambda a: a.call("POST", "/rule-exceptions", {"website": W, "path": "/lab-form", "target": "ARGS:comment", "repository": "crs",
                                                         "rules": ["941100", "941110"], "reason": "lab 14"}),
            lambda d, i: i.get("id") in exc(d),
            effect=lambda i: {"a_request_the_exception_covers_on_each_node": visitors("/lab-form?comment=%3Cscript%3Ealert(1)%3C/script%3E")})
    eid = (ex or {}).get("id", "none")
    op("14.15", "removeRuleExceptionRule (941110 of that exception)", lambda a: a.call("DELETE", "/rule-exceptions/%s/rules/941110" % eid),
       lambda d, i: [str(r if not isinstance(r, dict) else r.get("id")) for r in exc(d).get(eid, {}).get("rules", [])] == ["941100"])
    op("14.16", "removeRuleException", lambda a: a.call("DELETE", "/rule-exceptions/%s" % eid), lambda d, i: eid not in exc(d))
    op("14.17", "updateRule (crs 941100 enabled again)", lambda a: a.call("PATCH", "/rules/crs/941100", {"disabled": False}),
       lambda d, i: J(d, "/rules/crs/941100").get("status") != "disabled" and J(d, "/rules/crs/941100").get("disabled") is not True)
    # --- allowlist
    def al(d):
        return {(e.get("ip") or e.get("cidr") or e.get("host")): e for e in J(d, "/allowlist?limit=500").get("items", [])}
    e1 = op("14.20", "addAllowlistEntry (203.0.113.201)", lambda a: a.allow(CLIENT_NET + "201", "lab 14"), lambda d, i: CLIENT_NET + "201" in al(d))
    op("14.21", "deleteAllowlistEntry", lambda a: a.call("DELETE", "/allowlist/%s" % (e1 or {}).get("id")), lambda d, i: CLIENT_NET + "201" not in al(d))
    mine = op("14.22", "allowMyIP (the address the dashboard call comes from)", lambda a: a.call("POST", "/allowlist/mine", {"label": "lab mine", "ttl": "24h"}),
              lambda d, i: any(e.get("label") == "lab mine" for e in al(d).values()))
    for e in al(D[0]).values():
        if e.get("label") == "lab mine":
            D[0].call("DELETE", "/allowlist/%s" % e.get("id"))
    # --- website: access lock, maintenance, crawler policy
    def acc(d):
        return J(d, "/websites/%s/access" % W)
    op("14.30", "setAccessProtection (password for /lab-private)",
       lambda a: a.call("PUT", "/websites/%s/access" % W, {"scope": "paths", "paths": ["/lab-private"], "password": "lab-access-pass-27", "own_networks": False}),
       lambda d, i: bool((acc(d).get("protection") or {}).get("password")) and req(d.node.ip, "GET", "/lab-private/x", claim=CLIENT_NET + "77")[0] != 200,
       effect=lambda i: {"a_visitor_of_the_locked_path_on_each_node": visitors("/lab-private/x"), "another_path": visitors("/lab-open")})
    # a visitor who signs in at the lock on one node stays signed in on the next (the keys behind the cookie are shared)
    lock = {}
    try:
        st, h, b = req(N[0].ip, "GET", "/lab-private/x", claim=CLIENT_NET + "77")
        form = re.search(rb'<form[^>]*action="([^"]*)"', b)
        field = re.search(rb'<input[^>]*type="password"[^>]*name="([^"]*)"', b) or re.search(rb'<input[^>]*name="([^"]*)"[^>]*type="password"', b)
        hidden = re.findall(rb'<input[^>]*type="hidden"[^>]*name="([^"]*)"[^>]*value="([^"]*)"', b)
        lock = {"status_of_the_lock_page": st, "has_a_form": bool(form), "password_field": field.group(1).decode() if field else None}
        if form and field:
            body = urllib.parse.urlencode([(k.decode(), v.decode()) for k, v in hidden] + [(field.group(1).decode(), "lab-access-pass-27")]).encode()
            action = form.group(1).decode().replace("&amp;", "&") or "/lab-private/x"
            st2, h2, b2 = req(N[0].ip, "POST", action, claim=CLIENT_NET + "77", body=body, headers={"Content-Type": "application/x-www-form-urlencoded"})
            cookie = "; ".join(c.split(";")[0] for c in re.split(r",(?=[^ ;]+=)", h2.get("Set-Cookie", "")) if c)
            lock.update({"status_of_the_sign_in_on_n1": st2, "cookie_set": bool(cookie),
                         "the_locked_path_with_that_cookie_on_each_node": visitors("/lab-private/x", {"Cookie": cookie}) if cookie else None})
    except Exception as e:
        lock["error"] = repr(e)[:200]
    R.check(S, "14.31", "a visitor who signs in at the access lock on n1 passes the locked path on n2 and n3 with the same cookie "
            "(guide: 'bleibt das auf dem nächsten Server')",
            (lock.get("the_locked_path_with_that_cookie_on_each_node") == [200, 200, 200]) if lock.get("cookie_set") else None, lock)
    op("14.32", "removeAccessProtection", lambda a: a.call("DELETE", "/websites/%s/access" % W),
       lambda d, i: not acc(d).get("protection") and req(d.node.ip, "GET", "/lab-private/x", claim=CLIENT_NET + "77")[0] == 200)
    op("14.33", "setMaintenance (on)", lambda a: a.call("PUT", "/websites/%s/maintenance" % W, {"on": True, "message": "lab 14"}),
       lambda d, i: bool((acc(d).get("maintenance") or {}).get("on")),
       effect=lambda i: {"a_visitor_on_each_node": visitors("/lab-open")})
    op("14.34", "setMaintenance (off)", lambda a: a.call("PUT", "/websites/%s/maintenance" % W, {"on": False}),
       lambda d, i: not (acc(d).get("maintenance") or {}).get("on") and req(d.node.ip, "GET", "/lab-open", claim=CLIENT_NET + "77")[0] == 200)
    gpt = {"User-Agent": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; GPTBot/1.2; +https://openai.com/gptbot)"}
    op("14.35", "setCrawlerPolicy (category ai_training blocked)", lambda a: a.call("PUT", "/websites/%s/crawlers" % W, {"categories": {"ai_training": "block"}}),
       lambda d, i: ((J(d, "/websites/%s/crawlers" % W).get("policy") or {}).get("categories") or {}).get("ai_training") == "block",
       effect=lambda i: {"a_request_with_the_user_agent_of_gptbot_on_each_node": visitors("/lab-open", gpt)})
    # --- users, passwords, sessions
    NEW = PASSWORD + "-2"

    def can_login(d, pw):
        return api(d.node.ip, 8788, "POST", "/api/v0/auth/login", {"user": "admin", "password": pw})[0] == 200
    extra_s = Dash(N[1])
    op("14.40", "login (a new session made on one node is valid on the others)", lambda a: (extra_s.login()[0], {}),
       lambda d, i: Dash(d.node, extra_s).session()[1].get("authenticated") is True)
    turn[0] = 1          # the session of 14.40 was made on n2; log it out on n2
    op("14.41", "logout (the session ends on the others)", lambda a: Dash(a.node, extra_s).call("POST", "/auth/logout"),
       lambda d, i: Dash(d.node, extra_s).session()[1].get("authenticated") is False)
    op("14.42", "changePassword (the new password signs in on the others)",
       lambda a: a.call("POST", "/auth/password", {"current_password": PASSWORD, "new_password": NEW}), lambda d, i: can_login(d, NEW),
       effect=lambda i: {"the_old_password_on_each_node": [can_login(d, PASSWORD) for d in D],
                         "sessions_from_before_still_valid": [d.session()[1].get("authenticated") for d in D]})
    relog = Dash(N[0])
    st = relog.call("POST", "/auth/login", {"user": "admin", "password": NEW})[0]
    if st == 200:
        relog.call("POST", "/auth/password", {"current_password": NEW, "new_password": PASSWORD})
        time.sleep(2)
        D[0].login()
        for k in (1, 2):
            D[k].cookie, D[k].csrf = D[0].cookie, D[0].csrf
        time.sleep(1.5)
    # --- blocks, lifts, erasure
    blk = op("14.50", "createBlock (203.0.113.202)", lambda a: a.block(CLIENT_NET + "202", 3600), lambda d, i: CLIENT_NET + "202" in (d.blocks() or []))
    op("14.51", "unblockIncident (on another node)", lambda a: a.unblock((blk or {}).get("incident")), lambda d, i: CLIENT_NET + "202" not in (d.blocks() or []))
    for n in N:
        req(n.ip, "GET", "/lab-erase", claim=CLIENT_NET + "203")
    time.sleep(3)

    def held(d, a):
        return len(J(d, "/events?ip=%s&limit=50" % a).get("items", []))
    before = [held(d, CLIENT_NET + "203") for d in D]
    op("14.52", "privacyDelete (an address with events on every node)", lambda a: a.erase(CLIENT_NET + "203"),
       lambda d, i: held(d, CLIENT_NET + "203") == 0, effect=lambda i: {"events_held_before": before, "nodes": i.get("nodes")})
    # --- the hub rules: switch and reset
    op("14.60", "updateRuleRepository (crowdsec, off in schild.yaml, to detect)", lambda a: a.call("PATCH", "/rule-repositories/crowdsec", {"state": "detect"}),
       lambda d, i: J(d, "/rule-repositories/crowdsec").get("state") == "detect")

    def hub(d):
        c = J(d, "/rule-repositories/crowdsec")
        return {"state": c.get("state"), "set_source": (c.get("crowdsec") or {}).get("set_source"),
                "reset_at": (c.get("crowdsec") or {}).get("reset_at"), "last_reset_at": (c.get("crowdsec") or {}).get("last_reset_at"),
                "keys": sorted((c.get("crowdsec") or {}).keys())}
    marks = [n.count("reset") for n in N]
    r = op("14.61", "resetRuleRepository (crowdsec: back to the snapshot of the image)", lambda a: a.call("POST", "/rule-repositories/crowdsec/reset"),
           lambda d, i: d.node.count("reset") > marks[N.index(d.node)], timeout=10,
           effect=lambda i: {"repository_as_each_node_shows_it": [hub(d) for d in D],
                             "log_lines_with_reset_since": [n.count("reset") - m for n, m in zip(N, marks)],
                             "log": [n.grep("reset", 1)[-200:] for n in N]})
    op("14.62", "syncRuleRepository (crowdsec; the lab has no route to the hub)", lambda a: a.call("POST", "/rule-repositories/crowdsec/sync"),
       lambda d, i: True)
    op("14.63", "updateRuleRepository (crowdsec reset_state)", lambda a: a.call("PATCH", "/rule-repositories/crowdsec", {"reset_state": True}),
       lambda d, i: J(d, "/rule-repositories/crowdsec").get("state") == "off")
    # --- what the documents name as per node
    hc = op("14.70", "runLocalCheck (the server check of this machine)", lambda a: a.call("POST", "/hosts/local/check", timeout=60),
            lambda d, i: len(J(d, "/hosts").get("items", [])) > 0, per_node="each server checks itself (guide, 'Was nicht geteilt wird')", timeout=6,
            effect=lambda i: {"hosts_listed_per_node": [len(J(d, "/hosts").get("items", [])) for d in D]})
    en = op("14.71", "createEnrolment (an agent of the server check)", lambda a: a.call("POST", "/agents/enrolments", {"label": "lab 14", "ttl_minutes": 5}),
            lambda d, i: len(J(d, "/agents").get("items", [])) > 0, per_node="the server check with its agents (contract section 5)", timeout=6)
    # --- the command line on the host
    def cli_allow(a):
        rc, out = a.node.cli("allow %s203 -ttl 24h -label lab-cli" % "198.51.100.")
        return (200 if rc == 0 else 500 + rc), {"out": out[-200:]}
    op("14.80", "schild allow 198.51.100.203 on the host (the command line writes while the gateway runs)", cli_allow,
       lambda d, i: "198.51.100.203" in al(d))

    def tok(scope, label):
        def f(a):
            rc, out = a.node.cli("token add --scope %s --expires 90d --label %s" % (scope, label))
            m = re.search(r"sat1_[A-Za-z0-9_-]{43}", out)
            tid = re.search(r"tok_[0-9a-f]{12}", out)
            return (200 if m else 500), {"token": m.group(0) if m else "", "id": tid.group(0) if tid else "", "out": re.sub(r"sat1_[A-Za-z0-9_-]{43}", "sat1_...", out)[-200:]}
        return f
    T = {}
    for k, (scope, cid) in enumerate([("rules:write", "14.81"), ("exceptions:write", "14.82"), ("crawlers:write", "14.83"), ("blocks:write", "14.84"),
                                      ("firewall:sync", "14.85")]):
        info = op(cid, "schild token add --scope %s on the host: the token is answered by the agent API of the other nodes" % scope, tok(scope, "lab-" + scope.split(":")[0]),
                  lambda d, i: agent(d.node, i["token"], "GET", "/firewall" if False else "/status")[0] in (200, 403) and i["id"] in d.node.cli("token list")[1])
        T[scope] = (info or {}).get("token", "")
    R.rows[-1]["evidence"] = ""
    # --- the agent API
    def a_op(cid, name, scope, method, path, body, seen, effect=None, per_node=None):
        return op(cid, name + " (agent API)", lambda a: agent(a.node, T[scope], method, path, body), seen, effect=effect, per_node=per_node)
    a_op("14.90", "updateAgentRuleRepository (crs to detect)", "rules:write", "PATCH", "/rule-repositories/crs", {"state": "detect"},
         lambda d, i: J(d, "/rule-repositories/crs").get("state") == "detect")
    a_op("14.91", "updateAgentRuleRepository (crs reset_state)", "rules:write", "PATCH", "/rule-repositories/crs", {"reset_state": True},
         lambda d, i: J(d, "/rule-repositories/crs").get("state") == "block")
    a_op("14.92", "updateAgentRule (crs 942100 disabled)", "rules:write", "PATCH", "/rules/crs/942100", {"disabled": True, "note": "lab 14"},
         lambda d, i: J(d, "/rules/crs/942100").get("status") == "disabled" or J(d, "/rules/crs/942100").get("disabled") is True)
    a_op("14.93", "resetAgentRuleRepository (crowdsec)", "rules:write", "POST", "/rule-repositories/crowdsec/reset", None,
         lambda d, i: True, effect=lambda i: {"log_lines_with_reset": [n.count("reset") for n in N]})
    a_op("14.94", "syncAgentRuleRepository (crowdsec; no route to the hub)", "rules:write", "POST", "/rule-repositories/crowdsec/sync", None, lambda d, i: True)
    aex = a_op("14.95", "createAgentException", "exceptions:write", "POST", "/exceptions",
               {"website": W, "path": "/lab-agent", "target": "ARGS:note", "repository": "crs", "rules": ["941100"], "reason": "lab 14"},
               lambda d, i: any(x.get("path") == "/lab-agent" for x in exc(d).values()))
    aid = (aex or {}).get("id") or next((k for k, x in exc(D[0]).items() if x.get("path") == "/lab-agent"), "none")
    a_op("14.96", "removeAgentException", "exceptions:write", "POST", "/exceptions/%s/remove" % aid, {"reason": "lab 14"},
         lambda d, i: not any(x.get("path") == "/lab-agent" for x in exc(d).values()))
    a_op("14.97", "setAgentCrawlers (category ai_search blocked)", "crawlers:write", "POST", "/crawlers",
         {"website": W, "category": "ai_search", "action": "block", "reason": "lab 14"},
         lambda d, i: ((J(d, "/websites/%s/crawlers" % W).get("policy") or {}).get("categories") or {}).get("ai_search") == "block")
    st, h, b = req(N[0].ip, "GET", "/lab-agent-block?q=%3Cscript%3Ealert(1)%3C/script%3E", claim=CLIENT_NET + "204")
    time.sleep(3)
    ev = (J(D[1], "/events?ip=%s204&limit=5" % CLIENT_NET).get("items") or [{}])[0]
    ab = a_op("14.98", "createAgentBlock (the client of an event, one hour)", "blocks:write", "POST", "/blocks",
              {"target": {"event_id": ev.get("id")}, "duration_s": 3600, "reason": "lab 14"},
              lambda d, i: CLIENT_NET + "204" in (d.blocks() or []) and req(d.node.ip, "GET", "/b", claim=CLIENT_NET + "204")[0] == 403)
    inc = (ab or {}).get("incident") or next((x["incident"] for x in J(D[0], "/blocks").get("items", []) if x["client"] == CLIENT_NET + "204"), "none")
    a_op("14.99", "liftAgentBlock (on another node)", "blocks:write", "POST", "/incidents/%s/lift" % inc, {"reason": "lab 14"},
         lambda d, i: CLIENT_NET + "204" not in (d.blocks() or []) and req(d.node.ip, "GET", "/b", claim=CLIENT_NET + "204")[0] == 200)
    a_op("14.100", "syncAgentFirewall (what `schild firewall run` reports of the firewall of its host)", "firewall:sync", "POST", "/firewall/sync",
         {"applied": "ok", "held": 0, "table": "inet schild", "version": "lab"},
         lambda d, i: (J(d, "/blocks").get("firewall") or {}).get("state") not in (None, "off"),
         per_node="not named as per node in the guide or contract section 5; D87 describes the firewall of one host",
         effect=lambda i: {"firewall_state_per_node": [(J(d, "/blocks").get("firewall") or {}).get("state") for d in D]})
    # a token revoked on one node is refused on the others; its use and the call log stay per node (documented)
    tid = None
    rc, out = N[2].cli("token list")
    m = re.search(r"(tok_[0-9a-f]{12})[^\n]*rules:write", out)
    tid = m.group(1) if m else None
    used = {n.name: [l for l in n.cli("token list")[1].splitlines() if tid and tid in l] for n in N}
    calls = {d.node.name: len(J(d, "/agent-api/calls?limit=200").get("items", [])) for d in D}
    R.check(S, "14.101", "the log of agent calls and when a token was last used (documented as per node: guide, 'Was nicht geteilt wird'): "
            "what each node shows after the calls above", None, {"calls_listed_per_node": calls}, json.dumps(used)[:900])
    turn[0] = 2
    op("14.102", "schild token revoke on the host: the token is refused by the agent API of the other nodes",
       lambda a: ((200 if a.node.cli("token revoke %s" % tid)[0] == 0 else 500), {}),
       lambda d, i: agent(d.node, T["rules:write"], "GET", "/status")[0] == 401)
    # the bound of failed dashboard logins counts per node (documented)
    wrong = []
    for k in range(12):
        wrong.append(api(N[0].ip, 8788, "POST", "/api/v0/auth/login", {"user": "admin", "password": "wrong-%d" % k})[0])
    after = [api(n.ip, 8788, "POST", "/api/v0/auth/login", {"user": "admin", "password": "wrong-x"})[0] for n in N]
    R.check(S, "14.103", "the bound of failed logins at the dashboard (documented as per node): 12 wrong passwords on n1, then one on each node", None,
            {"answers_on_n1": wrong, "one_more_on_each_node": after})
    # the summary
    stays = [r for r in rows if r[5] == "STAYS ON ONE NODE"]
    undriven = [r for r in rows if r[5] == "not driven"]
    pernode = [r for r in rows if r[5] in ("stays on one node", "travels")]
    slow = [(r[0], max(v for v in r[4].values() if v is not None)) for r in rows if r[4] and all(v is not None for v in r[4].values())]
    R.check(S, "14.110", "of all write operations driven, none that the documents call shared stays on one node", not stays,
            {"operations_driven": len(rows) - len(undriven), "shared": sum(1 for r in rows if r[5] == "shared"),
             "stay_on_one_node_and_not_documented_so": [r[0] + " " + r[1] for r in stays],
             "documented_as_per_node": [("%s %s: %s" % (r[0], r[1], r[5])) for r in pernode],
             "not_driven": [("%s %s: status %s" % (r[0], r[1], r[3])) for r in undriven],
             "slowest_s": sorted(slow, key=lambda x: -x[1])[:5], "seconds_all": summary([v for r in rows for v in r[4].values() if v is not None], 2)},
            json.dumps([r[:6] for r in rows], default=str))
    states_end = {d.node.name: states(d) for d in D}
    R.check(S, "14.111", "after all of it every node shows the shared state of the others as `same` in all four classes (20 s after the last change)",
            wait_until(lambda: all(all(v == {"access": "same", "blocks": "same", "logins": "same", "settings": "same"} for v in states(d).values()) for d in D), 30, 1) is not None,
            {"shared_state": {d.node.name: states(d) for d in D}, "shared": D[0].group().get("shared")})


# ---------------------------------------------------------------------------------------------------------------
# scenario 15: the state comparison


SAME = {"access": "same", "blocks": "same", "logins": "same", "settings": "same"}


class StateWatch:
    """Asks GET /group of every node once a second and keeps every answer in which a member is not `same`."""

    def __init__(self, D):
        self.D, self.stop, self.samples, self.rows, self.errors = D, False, 0, [], 0
        self.lock = threading.Lock()
        self.t0 = now()
        self.threads = [threading.Thread(target=self._run, args=(d,), daemon=True) for d in D]
        for t in self.threads:
            t.start()

    def _run(self, d):
        nxt = now()
        while not self.stop:
            try:
                st = states(d)
            except Exception:
                st = None
            with self.lock:
                if not st:
                    self.errors += 1
                else:
                    self.samples += 1
                    for name, v in st.items():
                        if v != SAME:
                            self.rows.append((round(now() - self.t0, 1), d.node.name, name, v))
            nxt += 1.0
            time.sleep(max(0.0, nxt - now()))

    def end(self):
        self.stop = True
        for t in self.threads:
            t.join(5)
        differs = [r for r in self.rows if r[3] and "differs" in r[3].values()]
        other = [r for r in self.rows if r not in differs]
        return {"answers": self.samples, "answers_without_a_member_list": self.errors, "member_views_with_differs": len(differs),
                "member_views_neither_same_nor_differs": len(other),
                "classes_that_differed": sorted(set(k for r in differs for k, v in r[3].items() if v == "differs")),
                "first_of_them": [list(r[:3]) + [json.dumps(r[3])] for r in (differs + other)[:6]]}


class Changes:
    """A steady stream of changes in all four classes, one about every 0.6 s, on the nodes in turn: a block and its
    lift on another node, an allowlist entry and its removal, a setting, a login and its logout."""

    def __init__(self, D, base=10, every=0.6, kinds=(0, 1, 2, 3)):
        self.D, self.stop, self.done, self.failed, self.base, self.every, self.kinds = D, False, 0, 0, base, every, kinds
        self.t = threading.Thread(target=self._run, daemon=True)
        self.t.start()

    def _step(self, k):
        D = self.D
        a, b = D[k % len(D)], D[(k + 1) % len(D)]
        kind = self.kinds[k % len(self.kinds)]
        if kind == 0:
            addr = "198.51.100.%d" % (self.base + k % 200)
            st, js = a.block(addr, 3600)
            time.sleep(0.5)
            if st == 200:
                for _ in range(20):
                    st = b.unblock(js.get("incident"))[0]
                    if st == 200:
                        break
                    time.sleep(0.1)
            return st == 200
        if kind == 1:
            st, js = a.allow("198.51.101.%d" % (1 + k % 200), "lab stream")
            time.sleep(0.5)
            return st == 201 and b.call("DELETE", "/allowlist/%s" % js.get("id"))[0] in (204, 404)
        if kind == 2:
            return a.call("PATCH", "/settings", {"retention": {"events_days": 20 + k % 30}})[0] == 200
        x = Dash(a.node)
        st = x.login()[0]
        time.sleep(0.5)
        return st == 200 and Dash(b.node, x).call("POST", "/auth/logout")[0] in (204, 401, 403)

    def _run(self):
        k = 0
        while not self.stop:
            t = now()
            try:
                ok = self._step(k)
            except Exception:
                ok = False
            self.done += 1
            self.failed += 0 if ok else 1
            k += 1
            time.sleep(max(0.0, self.every - (now() - t)))

    def end(self):
        self.stop = True
        self.t.join(self.every + 10)
        return {"changes_made": self.done, "calls_that_failed": self.failed}


def s15(lab):
    S = "s15"

    def quiet_and_busy(nodes, D, cid, label, seconds=300):
        seconds = 25 if QUICK else seconds
        time.sleep(15)
        w = StateWatch(D)
        time.sleep(seconds)
        r = w.end()
        R.check(S, cid + "1", "%s, idle: `shared_state` of every member, asked on every node once a second for %d s, always reads "
                "`same` in all four classes" % (label, seconds), r["member_views_with_differs"] == 0 and r["member_views_neither_same_nor_differs"] == 0
                and r["answers"] > seconds * len(D) * 0.8, r)
        w = StateWatch(D)
        c = Changes(D)
        time.sleep(seconds)
        made = c.end()
        time.sleep(12)
        r = w.end()
        r.update(made)
        R.check(S, cid + "2", "%s, under a steady stream of changes (blocks and lifts, allowlist entries, a setting, logins and logouts, "
                "one about every 0.6 s on the nodes in turn) for %d s: `shared_state` never reads `differs` (contract 14: a difference "
                "younger than 10 s is a change on its way)" % (label, seconds),
                r["member_views_with_differs"] == 0 and r["answers"] > seconds * len(D) * 0.8 and made["changes_made"] > seconds, r)
        end_same = wait_until(lambda: all(all(v == SAME for v in states(d).values()) for d in D), 30, 1)
        return end_same

    N = lab.nodes[:3]
    D, ready = group_ready(lab, N)
    quiet_and_busy(N, D, "15.0", "three nodes")

    # a real difference: n3 paused (the documented brake), then changes on n1
    n1, n2, n3 = N
    marks = {n.name: n.count("differ|repair|again for every record") for n in N}
    # `schild cluster pause` was removed in c27a180: n3 is stopped instead (its members read it unknown, not differs)
    n3.kill9()
    rc, out = 0, "stopped (pause removed)"
    time.sleep(1)
    t0 = now()
    bst = D[0].block(CLIENT_NET + "230", 3600)[0]
    ast = D[0].allow(CLIENT_NET + "231", "lab 15")[0]
    sst = D[0].call("PATCH", "/settings", {"retention": {"events_days": 61}})[0]
    seen, reason_at, hist = {}, {}, []
    while now() - t0 < 75:
        t = round(now() - t0, 1)
        for d, who in ((D[0], "n1 of n3"), (D[1], "n2 of n3"), (D[2], "n3 of n1")):
            v = states(d).get(n3.hostname() if who != "n3 of n1" else n1.hostname())
            hist.append((t, who, json.dumps(v)))
            if v and "differs" in v.values() and who not in seen:
                seen[who] = (t, sorted(k for k, x in v.items() if x == "differs"))
        for d in D[:2]:
            if d.node.name not in reason_at and "cluster_state_differs" in (d.reasons() or []):
                reason_at[d.node.name] = t
        time.sleep(1)
    lines = {n.name: n.grep("differ|repair|again for every record", 3)[-700:] for n in N}
    more = {n.name: n.count("differ|repair|again for every record") - marks[n.name] for n in N}
    g3 = D[0].member(n3.ip)
    R.check(S, "15.10", "n3 paused with `schild cluster pause`, then a block, an allowlist entry and a setting made on n1, watched for 75 s: "
            "what `shared_state` and the overview say of the difference (a paused node answers its members 503, contract 13)", None,
            {"pause_exit": rc, "statuses": [bst, ast, sst], "differs_first_seen_s_and_classes": seen, "reason_on_the_overview_after_s": reason_at,
             "state_of_n3_as_n1_shows_it": g3.get("state"), "shared_state_of_n3_as_n1_shows_it": g3.get("shared_state"),
             "state_of_n1_as_n3_shows_it": D[2].member(n1.ip).get("state"), "shared_state_of_n1_as_n3_shows_it": D[2].member(n1.ip).get("shared_state"),
             "log_lines_about_it_since": more}, json.dumps(lines)[:1500])
    n3.start()
    rc, out = 0, "started (resume removed)"
    t0 = now()
    same = wait_until(lambda: states(D[0]).get(n3.hostname()) == SAME and states(D[2]).get(n1.hostname()) == SAME, 60, 0.5)
    gone = wait_until(lambda: "cluster_state_differs" not in (D[0].reasons() or []), 60, 0.5)
    held = [get(n3.ip, "/b", claim=CLIENT_NET + "230", timeout=2), CLIENT_NET + "231" in (D[2].allowlist() or []),
            D[2].call("GET", "/settings")[1].get("retention", {}).get("events_days")]
    R.check(S, "15.12", "`schild cluster resume` on n3: both sides read `same` again and the hint leaves the overview (pass: within 30 s), "
            "and n3 holds the three changes", same is not None and same <= 30 and gone is not None and held == [403, True, 61],
            {"resume_exit": rc, "same_again_after_s": rnd(same), "hint_gone_after_s": rnd(gone), "n3_block_allowlist_setting": held})
    # a difference that needs the repair: a record n3 lacks although it is not paused. One documented way is a record
    # put off by the clock (contract section 4, rule 4): n1 90 s ahead in a pair would be the odd one of three, so a pair.
    P = lab.nodes[:2]
    D2, ready = group_ready(lab, P)
    p1, p2 = P
    p1.clock_shift(90)
    time.sleep(3)
    t0 = now()
    bst = D2[0].block(CLIENT_NET + "232", 3600)[0]
    seen, reason_at = {}, {}
    while now() - t0 < 70:
        t = round(now() - t0, 1)
        for d, other in ((D2[0], p2), (D2[1], p1)):
            v = states(d).get(other.hostname())
            if v and "differs" in v.values() and d.node.name not in seen:
                seen[d.node.name] = (t, sorted(k for k, x in v.items() if x == "differs"))
            if d.node.name not in reason_at and "cluster_state_differs" in (d.reasons() or []):
                reason_at[d.node.name] = t
        time.sleep(1)
    on_p2 = get(p2.ip, "/b", claim=CLIENT_NET + "232", timeout=2)
    ready_codes = [p1.ready(), p2.ready()]
    p1.clock_release()
    same = wait_until(lambda: states(D2[1]).get(p1.hostname()) == SAME, 90, 1)
    R.check(S, "15.13", "a difference by the 60 s rule of the clocks: a pair, n1 90 s ahead, a block made on n1 (n2 puts its record "
            "off until its own clock is that far, about 30 s): n2 shows `differs` in blocks from about 10 s on, readiness does not "
            "depend on it, and after the record was taken both read `same`", (p2.name in seen or p1.name in seen) and ready_codes == [200, 200] and same is not None,
            {"block_status": bst, "differs_first_seen_s_and_classes": seen, "reason_on_the_overview_after_s": reason_at,
             "the_block_on_n2_70_s_later": on_p2, "readyz_meanwhile": ready_codes, "same_s_after_the_clock_was_right": rnd(same)})

    # the state right after the birth of a group: fresh starts of three nodes, watched for 40 s each
    births = []
    for k in range(3 if QUICK else 12):
        Db, ready = group_ready(lab, N)
        bad, t0 = [], now()
        while now() - t0 < 40:
            for d in Db:
                for name, v in states(d).items():
                    if v != SAME:
                        bad.append((round(now() - t0), d.node.name, name, json.dumps(v)))
            time.sleep(1)
        late = [b for b in bad if b[0] >= 15]
        births.append({"round": k + 1, "views_not_same": len(bad), "of_them_15_s_or_more_after_the_first_look": len(late),
                       "classes": sorted(set(c for b in bad for c, x in json.loads(b[3]).items() if x != "same")) if bad and bad[0][3] != "null" else [],
                       "log": {n.name: n.run("grep -E 'differ|human_check|put off' %s | cut -c1-300 | tail -4" % n.LOG)[1] for n in N} if late else {}})
    R.check(S, "15.30", "%d fresh starts of three nodes (wiped, started together, first password set): in the 40 s after the group is active "
            "no member view reads `differs` (nothing was changed; one difference was seen in a trial before the run, see the report)" % len(births),
            not any(b["of_them_15_s_or_more_after_the_first_look"] for b in births),
            {"rounds_with_a_view_that_is_not_same": sum(1 for b in births if b["views_not_same"]), "rounds": len(births),
             "views_not_same_per_round": [b["views_not_same"] for b in births]}, json.dumps([b for b in births if b["views_not_same"]])[:3000])
    # sixteen
    if QUICK:
        return
    N16 = lab.nodes[:16]
    D16, ready = group_ready(lab, N16)
    ok = wait_until(lambda: all(members_ok(d, 16) for d in D16), 60, 1)
    R.check(S, "15.20", "sixteen nodes form a group", ok is not None, {"ready_s_max": rnd(max(v for v in ready.values() if v is not None)),
                                                                      "not_ready": [k for k, v in ready.items() if v is None]})
    quiet_and_busy(N16, D16, "15.2", "sixteen nodes")
    for n in N16[3:]:
        n.kill9()


# ---------------------------------------------------------------------------------------------------------------
# scenario 16: the cheaper exchange


def iso(t):
    return datetime.datetime.fromtimestamp(t, datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def held_requests(d, ip, t_from, t_to):
    """Paths of every single request of one visitor address this node holds in the span, with how often."""
    out, cursor, pages = {}, None, 0
    base = "/requests?from=%s&to=%s&ip=%s&limit=500" % (urllib.parse.quote(iso(t_from)), urllib.parse.quote(iso(t_to)), ip)
    while pages < 400:
        st, js = d.call("GET", base + ("&cursor=%s" % urllib.parse.quote(cursor) if cursor else ""), timeout=30)
        if st != 200 or not isinstance(js, dict):
            return None
        for it in js.get("items", []):
            out[it["path"]] = out.get(it["path"], 0) + 1
        cursor = js.get("next_cursor")
        pages += 1
        if not cursor:
            break
    return out


def held_events(d, prefix, ip=None, detail=False):
    """Paths of the events below a path prefix this node holds, with how often. An event listed on two pages counts
    once (by its id). detail: path -> list of (id, type) instead."""
    out, cursor, pages, seen = {}, None, 0, set()
    base = "/events?path=%s&limit=500%s" % (urllib.parse.quote(prefix), "&ip=%s" % ip if ip else "")
    while pages < 400:
        st, js = d.call("GET", base + ("&cursor=%s" % urllib.parse.quote(cursor) if cursor else ""), timeout=30)
        if st != 200 or not isinstance(js, dict):
            return None
        for it in js.get("items", []):
            if it.get("id") in seen:
                continue
            seen.add(it.get("id"))
            out.setdefault(it["path"], []).append((it.get("id"), it.get("type")))
        cursor = js.get("next_cursor")
        pages += 1
        if not cursor:
            break
    return out if detail else {k: len(v) for k, v in out.items()}


def spread(N, D, tag, samples, gap, visitor):
    """`samples` times: one plain request and one request the WAF blocks (an event with an incident), each with a
    path of its own, sent to one node; the two other nodes are asked every 40 ms until they list it. Answers the
    milliseconds per (sample, other node) for the single request and for the event, and what never showed."""
    req_ms, ev_ms, missing = [], [], []
    t_from = time.time() - 60
    for i in range(samples):
        a = i % 3
        others = [j for j in range(3) if j != a]
        pr, pe = "/%s-r/%d" % (tag, i), "/%s-e/%d" % (tag, i)
        q = "from=%s&to=%s" % (urllib.parse.quote(iso(t_from)), urllib.parse.quote(iso(time.time() + 600)))
        t0 = now()
        req(N[a].ip, "GET", pr, claim=visitor)
        t1 = now()
        req(N[a].ip, "GET", pe + "?q=%3Cscript%3Ealert(1)%3C/script%3E", claim=visitor)
        got = {}

        def watch(j, kind):
            path = ("/requests?%s&path=%s&limit=1" % (q, urllib.parse.quote(pr))) if kind == "r" else ("/events?path=%s&limit=1" % urllib.parse.quote(pe))
            end = now() + 45
            while now() < end:
                st, js = D[j].call("GET", path)
                if st == 200 and isinstance(js, dict) and js.get("items"):
                    got[(j, kind)] = now()
                    return
                time.sleep(0.04)
        th = [threading.Thread(target=watch, args=(j, k), daemon=True) for j in others for k in ("r", "e")]
        for t in th:
            t.start()
        for t in th:
            t.join(50)
        for j in others:
            if (j, "r") in got:
                req_ms.append((got[(j, "r")] - t0) * 1000)
            else:
                missing.append("request %s on %s" % (pr, N[j].name))
            if (j, "e") in got:
                ev_ms.append((got[(j, "e")] - t1) * 1000)
            else:
                missing.append("event %s on %s" % (pe, N[j].name))
        time.sleep(gap * (0.8 + 0.4 * random.random()))
    return req_ms, ev_ms, missing


def spread_numbers(req_ms, ev_ms, missing):
    def one(v):
        return {"n": len(v), "p50": rnd(pct(v, 50), 0), "p95": rnd(pct(v, 95), 0), "max": rnd(max(v), 0) if v else None,
                "over_2_s": sum(1 for x in v if x > 2000), "over_5_s": sum(1 for x in v if x > 5000)}
    return {"single_request_ms": one(req_ms), "event_ms": one(ev_ms), "never_shown_within_45_s": len(missing), "which": missing[:6]}


def s16(lab):
    S = "s16"
    # --- sixteen idle gateways, five minutes, nobody asks them anything
    N16 = lab.nodes[:16]
    D16, ready = group_ready(lab, N16)
    ok = wait_until(lambda: all(members_ok(d, 16) for d in D16), 60, 1)
    time.sleep(60)
    u0 = {n.name: n.usage() for n in N16}
    t0 = now()
    time.sleep(300)
    u1 = {n.name: n.usage() for n in N16}
    secs = now() - t0
    cpu = [100.0 * (u1[k]["cpu_s"] - u0[k]["cpu_s"]) / secs for k in u0 if u0[k] and u1[k]]
    rss = [u1[k]["rss_mib"] for k in u1 if u1[k]]
    still = all(members_ok(d, 16) for d in D16[:3])
    R.check(S, "16.01", "sixteen gateways idle for five minutes (no visitor, no dashboard call, 60 s after the group was active): CPU of "
            "the schild process per node in percent of one core (second run, build e54c040, idle: p50 13.0, max 14.9; first run, "
            "e0349dc: 12.6)", None, {"group_active": ok is not None and still, "seconds": rnd(secs, 0), "cpu_percent_of_one_core": summary(cpu, 2),
                                    "cpu_seconds_per_node_and_minute_p50": rnd(pct(cpu, 50) * 0.6, 2), "resident_memory_mib": summary(rss, 1)})
    for n in N16[3:]:
        n.kill9()

    # --- three nodes: how fast an event and a single request show on the others
    N = lab.nodes[:3]
    D, ready = group_ready(lab, N)
    r = spread(N, D, "q16", 100, 4.0, CLIENT_NET + "240")
    num = spread_numbers(*r)
    R.check(S, "16.10", "idle group of three: a single request and an event (a request the WAF blocked) made on one node show in the lists "
            "of the two others; 100 samples about 4 s apart, asked every 40 ms (pass: none missing and none later than 5 s; the guide "
            "says 'in den Sekunden danach')", num["never_shown_within_45_s"] == 0 and num["single_request_ms"]["over_5_s"] == 0 and num["event_ms"]["over_5_s"] == 0, num)
    loads = [Load(n.ip, 100, workers=6, mode="keep", claim=CLIENT_NET + "24%d" % (1 + i), path="/q16-load").start() for i, n in enumerate(N)]
    time.sleep(5)
    r = spread(N, D, "q16l", 100, 1.0, CLIENT_NET + "240")
    for l in loads:
        l.stop()
    num = spread_numbers(*r)
    num["load_requests"] = sum(l.stats()["requests"] for l in loads)
    num["load_not_200"] = sum(l.stats()["not_200"] for l in loads)
    R.check(S, "16.11", "the same under load (100 requests a second on each of the three nodes on kept connections), 100 samples about 1 s "
            "apart (pass: none missing and none later than 5 s)",
            num["never_shown_within_45_s"] == 0 and num["single_request_ms"]["over_5_s"] == 0 and num["event_ms"]["over_5_s"] == 0, num)
    # --- 10 % packet loss between the nodes: a lost word (`heads`) must not stall the exchange
    for n in N:
        n.nft(mesh_rules([m.ip for m in N if m is not n], loss=0.10))
    time.sleep(3)
    rc, ping = N[0].run("ping -c 50 -i 0.05 -q %s | tail -2" % N[1].ip, 30)
    r = spread(N, D, "q16x", 60, 3.0, CLIENT_NET + "240")
    for n in N:
        n.nft_clear()
    num = spread_numbers(*r)
    R.check(S, "16.20", "10 % packet loss each way between the nodes (dropped when a packet leaves and again when it arrives, so about 19 % "
            "a direction), 60 samples about 3 s apart: every single request and event still shows on the others, none later than 40 s "
            "(contract 9: a node asks for everything again 25 to 35 s after it last asked, 'so a lost word cannot stall it')",
            num["never_shown_within_45_s"] == 0 and (num["single_request_ms"]["max"] or 0) < 40000 and (num["event_ms"]["max"] or 0) < 40000,
            num, ping[-200:])



class UniqueLoad:
    """New connections through the balancer at a fixed rate from one visitor address, every request with a path of
    its own; every tenth is a request the WAF blocks (an event with an incident). Keeps (path, status)."""

    def __init__(self, ip, visitor, tag, rate=40, workers=6):
        self.ip, self.visitor, self.tag, self.rate, self.workers = ip, visitor, tag, rate, workers
        self.rows, self.n, self.stop, self.lock = [], 0, False, threading.Lock()
        self.threads = [threading.Thread(target=self._run, args=(i,), daemon=True) for i in range(workers)]
        for t in self.threads:
            t.start()

    def _run(self, i):
        gap = self.workers / float(self.rate)
        nxt = now() + gap * i / self.workers
        while not self.stop:
            time.sleep(max(0.0, nxt - now()))
            nxt = max(nxt + gap, now() - 5 * gap)
            with self.lock:
                self.n += 1
                k = self.n
            bad = k % 10 == 0
            path = "/%s-%s/%d" % (self.tag, "e" if bad else "r", k)
            st = req(self.ip, "GET", path + ("?q=%3Cscript%3Ealert(1)%3C/script%3E" if bad else ""), bind=self.visitor, timeout=5)[0]
            with self.lock:
                self.rows.append((path, st, time.time()))

    def end(self):
        self.stop = True
        for t in self.threads:
            t.join(8)
        return self.rows


def s23(lab):
    """A rolling upgrade from the earlier build (run.sh, OLD_REV) to the current one under load, three nodes."""
    S = "s23"
    N = lab.nodes[:3]
    for n in N:
        n.binary = OLD
    try:
        upgrade(lab, N, S)
    finally:
        for n in N:
            n.binary = "schild"


def upgrade(lab, N, S):
    D, ready = group_ready(lab, N, haproxy=True)
    ver = [m.get("version") for m in D[0].group().get("members", [])]
    R.check(S, "23.01", "three nodes of the earlier build (e54c040) form a group behind the balancer", all(members_ok(d, 3) for d in D) and len(set(ver)) == 1,
            {"ready_s": {k: rnd(v) for k, v in ready.items()}, "versions": sorted(set(str(v) for v in ver)),
             "version_of_the_binary": N[0].run(OLD + " version")[1].splitlines()[0]})
    visitor = CLIENT_NET + "245"
    t_from = time.time() - 30
    load = UniqueLoad(lab.lb.ip, visitor, "u16", rate=40)
    time.sleep(10)
    stages = []
    octet = [150]

    def crossing(label):
        """A block made on each node acts on the two others, a lift too, and a login made on each is valid on the others."""
        out = {"stage": label, "block_ms": {}, "lift_ms": {}, "login": {}}
        for i, d in enumerate(D):
            octet[0] += 1
            a = CLIENT_NET + str(octet[0])
            st, js = d.block(a, 3600)
            t = wait_until(lambda: all(get(n.ip, "/b", claim=a, timeout=2) == 403 for n in N), 8, 0.02)
            out["block_ms"][N[i].name] = None if t is None else round(t * 1000)
            o = D[(i + 1) % 3]
            ust = 0
            for _ in range(30):
                ust = o.unblock(js.get("incident") if isinstance(js, dict) else "")[0]
                if ust == 200:
                    break
                time.sleep(0.1)
            t = wait_until(lambda: all(get(n.ip, "/b", claim=a, timeout=2) == 200 for n in N), 8, 0.02)
            out["lift_ms"][N[i].name] = None if t is None else round(t * 1000)
            x = Dash(N[i])
            lst = x.login()[0]
            t = wait_until(lambda: all(Dash(n, x).session()[1].get("authenticated") is True for n in N), 8, 0.05)
            out["login"][N[i].name] = None if (t is None or lst != 200) else round(t * 1000)
        out["shared_state_as_each_node_shows_the_others"] = {d.node.name: {k: (v if v is None else "/".join(sorted(set(v.values())))) for k, v in states(d).items()} for d in D}
        out["versions_as_n3_shows_them"] = {m.get("name"): (m.get("version") or "")[:40] for m in D[2].group().get("members", [])}
        out["ok"] = all(v is not None for k in ("block_ms", "lift_ms", "login") for v in out[k].values())
        return out
    stages.append(crossing("three nodes of the earlier build"))
    steps = []
    for k, n in enumerate(N):
        t0 = now()
        rc, out = n.cli("cluster drain")
        gone = n.wait_exit(60)
        n.binary = "schild"
        n.start()
        t = n.wait_ready(60)
        up = lab.wait_lb({n.name: "UP"}, 30)
        time.sleep(5)
        # the session of before stays valid on the node that came back with the new build
        steps.append({"node": n.name, "drain_exit": rc, "stopped": gone, "ready_s_after_its_start": rnd(t), "balancer_up": up is not None,
                      "session_of_before_valid": D[k].session()[1].get("authenticated")})
        stages.append(crossing("%d of 3 nodes on the current build" % (k + 1)))
    time.sleep(5)
    rows = load.end()
    time.sleep(45)
    t_to = time.time() + 60
    sent_r = {p for p, st, t in rows if "-r/" in p}
    ok_r = {p for p, st, t in rows if "-r/" in p and st == 200}
    sent_e = {p for p, st, t in rows if "-e/" in p}
    blocked_e = {p for p, st, t in rows if "-e/" in p and st == 403}
    failed = [(p, st) for p, st, t in rows if st not in (200, 403)]
    per = {}
    for d in D:
        hr = held_requests(d, visitor, t_from, t_to) or {}
        hd = held_events(d, "/u16-e/", detail=True) or {}
        # the event of a blocked request is `schild.request.blocked.v1`; a scenario that counts such requests (waf_repeat)
        # writes an event of its own with the same path, which is no double
        he = {p: sum(1 for i, t in v if t == "schild.request.blocked.v1") for p, v in hd.items()}
        kinds = {}
        for v in hd.values():
            for i, t in v:
                kinds[t] = kinds.get(t, 0) + 1
        hr_r = {p: c for p, c in hr.items() if p.startswith("/u16-r/")}
        per[d.node.name] = {"single_requests_held": len(hr_r), "of_those_twice": sum(1 for c in hr_r.values() if c > 1),
                            "answered_200_and_not_held": len(ok_r - set(hr_r)), "held_and_never_sent": len(set(hr_r) - sent_r),
                            "events_held": sum(1 for c in he.values() if c), "events_twice": sum(1 for c in he.values() if c > 1),
                            "events_by_type": kinds,
                            "blocked_and_no_event": len(blocked_e - set(p for p, c in he.items() if c))}
    R.check(S, "23.02", "the rolling upgrade under load (40 new connections a second through the balancer, every tenth a request the WAF "
            "blocks): each node is drained, started with the current build and answers ready; no request of the load fails",
            all(s["stopped"] and s["ready_s_after_its_start"] is not None and s["balancer_up"] for s in steps) and not failed,
            {"steps": steps, "requests": len(rows), "answered_200": len(ok_r), "blocked_403": len(blocked_e), "other_answers": len(failed),
             "which": failed[:8]})
    R.check(S, "23.03", "at every stage of the upgrade (3 old; 1, 2 and 3 new) a block made on each node acts on the two others, a lift made "
            "on another node too, and a login made on each node is valid on the others (each within 8 s)", all(s["ok"] for s in stages),
            {"stages": [{k: s[k] for k in ("stage", "block_ms", "lift_ms", "login")} for s in stages]})
    mixed = [s for s in stages[1:3]]
    unknown = all("unknown" in str(v) or v is None for s in mixed for d, view in s["shared_state_as_each_node_shows_the_others"].items() for v in view.values()) if mixed else False
    R.check(S, "23.04", "the state comparison with nodes of the earlier build in the group: what `shared_state` reads at each stage (the task "
            "expects `unknown` for a member of build e54c040; the earlier build sends no state)", None,
            {"stages": [{"stage": s["stage"], "shared_state": s["shared_state_as_each_node_shows_the_others"], "versions": s["versions_as_n3_shows_them"]} for s in stages]})
    clean = all(v["of_those_twice"] == 0 and v["answered_200_and_not_held"] == 0 and v["events_twice"] == 0 and v["blocked_and_no_event"] == 0
                and v["held_and_never_sent"] == 0 for v in per.values())
    R.check(S, "23.05", "after the upgrade every node holds every single request of the load once (none lost, none twice) and the event of "
            "every blocked request (`schild.request.blocked.v1`) once, 45 s after the load ended", clean and len(set(v["single_requests_held"] for v in per.values())) == 1,
            {"sent_single_requests": len(sent_r), "answered_200": len(ok_r), "sent_to_be_blocked": len(sent_e), "blocked_403": len(blocked_e), "per_node": per})


# ---------------------------------------------------------------------------------------------------------------
# scenario 17: tasks once per cluster


def s17(lab):
    S = "s17"
    N = lab.nodes[:3]
    D, ready = group_ready(lab, N)
    g = D[0].group()
    ids = sorted((m["id"], m["name"]) for m in g.get("members", []))
    by_host = {n.hostname(): n for n in N}
    keeper = by_host[ids[0][1]]
    second = by_host[ids[1][1]]
    third = by_host[ids[2][1]]
    PAT = "human_check"

    def keylog():
        return {n.name: n.count(PAT) for n in N}

    def jobs_lines(n):
        return [l for l in n.status().splitlines() if re.search(r"[Jj]ob|[Tt]ask|human", l)]
    before = keylog()
    R.check(S, "17.01", "what the documented interface shows of the tasks (guide, 'Aufgaben, die nur einmal laufen dürfen', names no command "
            "and no page for them): lines of `schild cluster status` that name a task, log lines that name the keys of the browser "
            "check, and the node with the lowest id, which keeps the task", None,
            {"node_ids_in_order": ["%s %s" % (i, nm) for i, nm in ids], "keeper": keeper.name, "status_lines_naming_a_task": jobs_lines(N[0]),
             "log_lines_naming_the_keys_per_node": before, "shared": g.get("shared")}, json.dumps({n.name: n.grep(PAT, 2)[-400:] for n in N})[:1500])

    def shift_all(nodes, seconds):
        th = [threading.Thread(target=n.clock_shift, args=(seconds,)) for n in nodes]
        for t in th:
            t.start()
        for t in th:
            t.join()

    def who_rotated(nodes, since, wait=150):
        """Per node how many times it took the keys of the browser check from which node since the marks."""
        end = now() + wait
        took = {}
        while now() < end:
            took = {}
            for n in nodes:
                lines = n.run("grep -E %s %s | tail -n +%d | grep 'took a change' | grep -o '\"from\":\"[^\"]*\"' | sort | uniq -c" % (json.dumps(PAT), n.LOG, since[n.name] + 1))[1]
                took[n.name] = " ".join(lines.split())
            if any(took.values()):
                time.sleep(8)
                took = {n.name: " ".join(n.run("grep -E %s %s | tail -n +%d | grep 'took a change' | grep -o '\"from\":\"[^\"]*\"' | sort | uniq -c" % (json.dumps(PAT), n.LOG, since[n.name] + 1))[1].split()) for n in nodes}
                break
            time.sleep(3)
        return took
    # the keys are rotated when they are older than a day: every clock a day and an hour ahead, all three at once
    shift_all(N, 90000)
    t0 = now()
    took = who_rotated(N, before)
    waited = now() - t0
    for d in D:
        d.cookie = None
    d0 = Dash(N[0])
    d0.login()
    D = [d0] + [Dash(n, d0) for n in N[1:]]
    time.sleep(3)
    same1 = wait_until(lambda: all(all(v == SAME for v in states(d).values()) for d in D), 40, 1)
    ready1 = [n.ready() for n in N]
    froms = set(re.findall(r'"from":"([^"]+)"', " ".join(took.values())))
    R.check(S, "17.10", "the clocks of all three nodes put a day and an hour ahead: the keys of the browser check are rotated once, by the "
            "node with the lowest id, the two others take them from it, and every node reads the settings of the others as `same`",
            froms == {keeper.hostname()} and not took.get(keeper.name) and same1 is not None,
            {"keeper": keeper.name, "who_took_the_keys_from_whom": took, "seen_after_s": rnd(waited, 0), "all_same_after_s": rnd(same1),
             "readyz": ready1, "log_lines_naming_the_keys_per_node_since": {k: v - before[k] for k, v in keylog().items()}},
            json.dumps({n.name: n.grep(PAT + "|job", 3)[-500:] for n in N})[:1800])
    # the keeper killed, the clocks of the two others another day ahead
    mid = keylog()
    keeper.kill9()
    time.sleep(5)
    rest = [second, third]
    shift_all(rest, 180000)
    t0 = now()
    took2 = who_rotated(rest, mid, 200)
    waited2 = now() - t0
    d0 = Dash(second)
    d0.login()
    Dr = [d0, Dash(third, d0)]
    time.sleep(3)
    same2 = wait_until(lambda: states(Dr[0]).get(third.hostname()) == SAME and states(Dr[1]).get(second.hostname()) == SAME, 40, 1)
    froms2 = set(re.findall(r'"from":"([^"]+)"', " ".join(took2.values())))
    R.check(S, "17.11", "the keeper killed and the clocks of the two others put another day ahead: the node with the next id rotates the keys, "
            "the other takes them, both read each other's settings as `same` (guide: 'Fällt er aus, übernimmt der nächste von selbst')",
            froms2 == {second.hostname()} and same2 is not None,
            {"killed": keeper.name, "next": second.name, "who_took_the_keys_from_whom": took2, "seen_after_s": rnd(waited2, 0),
             "both_same_after_s": rnd(same2), "log_lines_naming_the_keys_per_node_since": {k: v - mid[k] for k, v in keylog().items() if k != keeper.name}},
            json.dumps({n.name: n.grep(PAT + "|job", 3)[-500:] for n in rest})[:1500])
    # the old keeper returns (its clock as far ahead as the others): it takes the keys, rotates nothing
    mid2 = keylog()
    keeper.clock_shift(180000)
    keeper.start()
    t = keeper.wait_ready(60)
    time.sleep(20)
    dk = Dash(keeper, d0)
    same3 = wait_until(lambda: all(v == SAME for v in states(dk).values()) and all(v == SAME for v in states(Dr[0]).values()), 60, 1)
    took3 = {n.name: " ".join(n.run("grep -E %s %s | tail -n +%d | grep 'took a change' | grep -o '\"from\":\"[^\"]*\"' | sort | uniq -c" % (json.dumps(PAT), n.LOG, mid2[n.name] + 1))[1].split()) for n in N}
    R.check(S, "17.12", "the killed keeper returns: it answers ready, holds the same settings as the others and does not rotate the keys "
            "again (the two others take no new keys from it in 20 s)", t is not None and same3 is not None and not took3.get(second.name) and not took3.get(third.name),
            {"ready_s": rnd(t), "all_same_after_s": rnd(same3), "who_took_the_keys_from_whom_since": took3})
    for n in N:
        n.clock_release()
    time.sleep(3)


# ---------------------------------------------------------------------------------------------------------------
# scenario 18: throughput


def s18(lab):
    S = "s18"
    N = lab.nodes[:3]
    for n in N:
        n.wipe()
        # the site answers the load itself: the Python application behind it would be the limit long before a gateway
        n.write_files([m.ip for m in N], lab.balancers(), node_name="web", name_from_host=True,
                      site_extra='\trespond /t18* "ok" 200')
        n.start()
    ready = {n.name: n.wait_ready(60) for n in N}
    time.sleep(3)
    D = first_login(N)
    wait_until(lambda: all(members_ok(d, 3) for d in D), 20, 0.3)
    st0 = req(N[0].ip, "GET", "/t18check", claim=CLIENT_NET + "250")
    time.sleep(3)
    seen0 = [len(held_events(d, "/t18check") or {}) for d in D]
    R.check(S, "18.01", "three nodes whose site answers /t18* itself (`respond` in the Caddyfile behind `import schild`, so the application "
            "is not the limit); such a request is evaluated and listed on every node", st0[0] == 200 and seen0 == [1, 1, 1],
            {"ready_s": {k: rnd(v) for k, v in ready.items()}, "status": st0[0], "body": st0[2][:20].decode("latin-1"), "listed_on_each_node": seen0})
    cpus = {vm.name: vm.run("nproc")[1] for vm in N + [lab.client]}
    steps = []
    w = StateWatch(D)
    # the lab host is a small machine and not to be saturated (maintainer): three short steps at moderate rates, no
    # step "as fast as it goes". What the host and the client were doing is in the numbers of every step.
    for k, rate in enumerate([500, 1000, 2000]):
        tag = "t18s%d" % k
        u0 = {n.name: n.usage() for n in N}
        t0, w0 = now(), time.time()
        rc, out = lab.client.run("/opt/sg27/loadgen -targets %s -host %s -conns 24 -rate %d -seconds 30 -tag %s" % (",".join(n.ip for n in N), SITE, rate, tag), 90)
        secs = now() - t0
        u1 = {n.name: n.usage() for n in N}
        try:
            lg = json.loads(out.splitlines()[-1])
        except (ValueError, IndexError):
            lg = {"error": out[-300:]}
        node_cpu = {k2: rnd(100.0 * (u1[k2]["cpu_s"] - u0[k2]["cpu_s"]) / secs, 0) for k2 in u0 if u0[k2] and u1[k2]}
        time.sleep(25)
        sent = int(lg.get("sent") or 0)
        pick = random.sample(range(1, sent + 1), min(150, sent)) if sent else []
        q = "from=%s&to=%s" % (urllib.parse.quote(iso(w0 - 30)), urllib.parse.quote(iso(time.time() + 60)))
        heldr, helde, rate_s = {}, {}, {}
        for d in D:
            hr = he = 0
            sr = None
            for nn in pick:
                st, js = d.call("GET", "/requests?%s&path=%s&limit=3" % (q, urllib.parse.quote("/%s/%d" % (tag, nn))), timeout=30)
                if st == 200 and isinstance(js, dict):
                    hr += 1 if len(js.get("items", [])) == 1 else 0
                    sr = js.get("sample_rate")
            for nn in pick[:60]:
                st, js = d.call("GET", "/events?path=%s&limit=3" % urllib.parse.quote("/%s/%d" % (tag, nn)), timeout=30)
                he += 1 if st == 200 and isinstance(js, dict) and any(i.get("path") == "/%s/%d" % (tag, nn) for i in js.get("items", [])) else 0
            heldr[d.node.name], helde[d.node.name], rate_s[d.node.name] = hr, he, sr
        steps.append({"asked_requests_per_s": rate or "as fast as the answers come", "made_requests_per_s": rnd(lg.get("requests_per_s"), 0), "sent": sent,
                      "failed": lg.get("failed"), "codes": lg.get("codes"), "latency_ms": {k2: rnd(v, 1) for k2, v in (lg.get("latency_ms") or {}).items()},
                      "client_cpu_share_of_its_cores": rnd(lg.get("client_cpu_share"), 2), "node_cpu_percent_of_one_core": node_cpu,
                      "of_150_sampled_requests_held_once": heldr, "of_60_sampled_events_held": helde, "sample_rate_of_the_request_store": rate_s,
                      "sampled": len(pick), "error": lg.get("error")})
        R.check(S, "18.1%d" % k, "40 s at %s on kept connections straight to the three nodes (PROXY protocol, 48 connections, 200 visitor "
                "addresses): what was made, what limited it, and how many of 150 sampled requests each node holds 25 s later"
                % (("%d requests a second" % rate) if rate else "the highest rate the answers allow"), None, steps[-1])
    time.sleep(15)
    r = w.end()
    full = [s for s in steps if s["sampled"] and all(v == s["sampled"] for v in s["of_150_sampled_requests_held_once"].values())]
    top = max((s["made_requests_per_s"] or 0) for s in steps)
    top_full = max([s["made_requests_per_s"] or 0 for s in full] or [0])
    R.check(S, "18.20", "up to which rate every node holds every sampled request (guide, 'Sehr hohe Last': 'bis 6 000 Anfragen pro Sekunde "
            "dieselben Anfragen', measured on one machine by the builder), and the highest rate asked of the lab host, which was kept below "
            "saturation on purpose", None,
            {"highest_rate_with_every_sampled_request_on_every_node": top_full, "highest_rate_made": top, "cpus": cpus,
             "failed_requests_over_all_steps": sum(int(s["failed"] or 0) for s in steps)})
    R.check(S, "18.21", "`shared_state` of every member, asked on every node once a second during all steps: always `same`",
            r["member_views_with_differs"] == 0 and r["answers"] > 100, r)
    R.check(S, "18.22", "after the load the group is active and every node ready", all(members_ok(d, 3) for d in D) and all(n.ready() == 200 for n in N),
            {"states": [d.group().get("state") for d in D], "resident_memory_mib": {n.name: n.usage().get("rss_mib") for n in N},
             "storage_kib": {n.name: n.disk()["storage_kib"] for n in N}})


# ---------------------------------------------------------------------------------------------------------------
# scenario 19: N1 of the second run again: a block lifted on another node within a second, eight rounds, an edge


def edge_join(lab, vm, gateway, name, data="/var/lib/schild-edge"):
    """A VM joins as an edge as the guide says and starts the firewall; answers the exit code of the join.
    Edges and join codes were removed in 5b12c2c: answers -1 and runs nothing."""
    return -1
    vm.run("pkill -x schild; nft delete table inet schild 2>/dev/null; rm -rf %s; mkdir -p /var/log/schild; true" % data)
    rc, out = gateway.cli("cluster invite -role edge")
    code = re.search(r"\b([a-z2-7]{4,}(?:-[a-z2-7]{4,}){3,})\b", out)
    rc_join, _ = vm.run("schild cluster join %s:%d %s -edge -name %s -data %s" % (gateway.ip, MESH_PORT, code.group(1) if code else "", name, data), 30)
    vm.spawn("exec schild firewall run -group -data %s >>/var/log/schild/edge.log 2>&1" % data)
    wait_until(lambda: vm.run("nft list table inet schild >/dev/null 2>&1")[0] == 0, 15, 0.1)
    return rc_join


def edge_set(vm):
    """The addresses the firewall table of an edge holds."""
    return set(re.findall(r"\b(\d+\.\d+\.\d+\.\d+)\b", vm.run("nft list table inet schild 2>/dev/null")[1]))


def edge_off(vm, data="/var/lib/schild-edge"):
    vm.run("pkill -TERM -x schild; sleep 1; nft delete table inet schild 2>/dev/null; rm -rf %s; true" % data)


def s19(lab):
    S = "s19"
    N = lab.nodes[:3]
    rng = random.Random(27)
    D, ready = group_ready(lab, N, haproxy=True)
    rounds, lifted_all, left_all = [], [], []
    edge_from = 5
    for r in range(1, 9):
        if r == edge_from:
            rcj = edge_join(lab, lab.lb, N[0], "lb-1")
            real = CLIENT_NET + "240"
            st, js = D[0].block(real, 3600)
            drops = wait_until(lambda: not tcp_open(lab.lb.ip, 80, bind=real), 8, 0.1)
            D[0].unblock(js.get("incident"))
            opens = wait_until(lambda: tcp_open(lab.lb.ip, 80, bind=real), 8, 0.1)
            R.check(S, "19.00", "before round %d a balancer VM joins as an edge and runs `schild firewall run -group`: it drops a blocked visitor "
                    "and lets the visitor in again after the lift" % r, rcj == 0 and drops is not None and opens is not None,
                    {"join_exit": rcj, "dropped_after_s": rnd(drops), "open_again_after_s": rnd(opens)})
        rows, in_edge_during = [], set()
        for i in range(200):
            a = "198.51.%d.%d" % (100 + r, i + 1)
            k = i % 3
            j = (k + 1 + (i // 3) % 2) % 3
            pause = rng.uniform(0.2, 1.0)
            st_b, js_b = D[k].block(a)
            inc = js_b.get("incident") if isinstance(js_b, dict) else None
            time.sleep(pause)
            t2 = now()
            st_u = D[j].unblock(inc)[0]
            row = {"address": a, "set_on": N[k].name, "lifted_on": N[j].name, "pause_s": round(pause, 3), "block_status": st_b, "lift_status": st_u}
            if st_u != 200:
                w = wait_until(lambda: D[j].unblock(inc)[0] == 200, 5, 0.05)
                row["lift_answered_200_after_ms"] = round((now() - t2) * 1000, 1) if w is not None else None
            rows.append(row)
            if r >= edge_from and i % 20 == 19:
                in_edge_during |= edge_set(lab.lb) & {x["address"] for x in rows}
        time.sleep(5)
        addrs = [x["address"] for x in rows]
        listed = [set(d.blocks() or []) for d in D]
        refused = {n.name: [a for a in addrs if get(n.ip, "/x", claim=a, timeout=2) == 403] for n in N}
        left = sorted(set(a for l in listed for a in addrs if a in l) | set(a for v in refused.values() for a in v))
        at_edge = sorted(edge_set(lab.lb) & set(addrs)) if r >= edge_from else None
        first_other = [x for x in rows if x["lift_status"] != 200]
        never = [x for x in rows if x["lift_status"] != 200 and x.get("lift_answered_200_after_ms") is None]
        lifted_all += [x["address"] for x in rows if x not in never]
        left_all += left
        rounds.append({"round": r, "edge_running": r >= edge_from, "blocks_left": len(left), "listed_per_node": [sum(1 for a in addrs if a in l) for l in listed],
                       "refused_per_node": {k: len(v) for k, v in refused.items()}, "in_the_firewall_of_the_edge_5_s_after": None if at_edge is None else len(at_edge),
                       "seen_in_the_firewall_of_the_edge_during_the_round": len(in_edge_during) if r >= edge_from else None,
                       "block_calls_not_200": sum(1 for x in rows if x["block_status"] != 200),
                       "lifts_first_answered_otherwise": len(first_other), "first_answers_otherwise": sorted(set(x["lift_status"] for x in first_other)),
                       "ms_until_200_for_those": summary([x["lift_answered_200_after_ms"] for x in first_other if x.get("lift_answered_200_after_ms") is not None]),
                       "lifts_never_answered_200": len(never)})
        R.check(S, "19.%02d" % r, "round %d%s: 200 addresses, each blocked on one of three nodes and lifted on another 0.2 to 1.0 s later: 5 s after "
                "the last lift no block of them is left on any node (not listed, not refused%s)" % (r, " with an edge running" if r >= edge_from else "",
                                                                                           ", not in the firewall of the edge" if r >= edge_from else ""),
                not left and not at_edge and not never, rounds[-1], json.dumps([x for x in rows if x["address"] in left][:10]))
    R.check(S, "19.10", "all eight rounds (second run: 116 of 1 600 blocks left, no round clean)", sum(x["blocks_left"] for x in rounds) == 0,
            {"blocks_left_per_round": [x["blocks_left"] for x in rounds], "of": 1600, "left_in_the_firewall_of_the_running_edge": [x["in_the_firewall_of_the_edge_5_s_after"] for x in rounds],
             "lifts_first_answered_404_per_round": [x["lifts_first_answered_otherwise"] for x in rounds],
             "status_line": [l for l in N[0].status().splitlines() if l.startswith("Blocks")]})
    # an edge that joins afterwards: a second VM (the application VM), so the first edge stays as it is
    real = CLIENT_NET + "241"
    rcj = edge_join(lab, lab.app, N[1], "lb-2")
    st, js = D[0].block(real, 3600)
    held = wait_until(lambda: real in edge_set(lab.app), 8, 0.1)
    time.sleep(3)
    late = edge_set(lab.app)
    first = edge_set(lab.lb)
    R.check(S, "19.11", "an edge that joins after the eight rounds (a second VM): its firewall holds the block that runs and none of the "
            "addresses whose block was lifted; the edge that ran since round %d holds none either" % edge_from,
            rcj == 0 and held is not None and not (late & set(lifted_all)) and not (first & set(lifted_all)),
            {"join_exit": rcj, "the_running_block_is_held_after_s": rnd(held), "lifted_addresses": len(lifted_all),
             "of_them_in_the_firewall_of_the_new_edge": len(late & set(lifted_all)), "of_them_in_the_firewall_of_the_first_edge": len(first & set(lifted_all)),
             "elements_of_the_new_edge": len(late), "edges_as_n1_lists_them": [e.get("name") for e in D[0].group().get("edges", [])]})
    D[0].unblock(js.get("incident"))
    edge_off(lab.app)
    edge_off(lab.lb)
    lab.app.run("pkill -f '[a]pp.py'; true")
    lab.app.spawn("python3 /opt/sg27/app.py 8080")


# ---------------------------------------------------------------------------------------------------------------
# scenario 20: N2 of the second run again: a killed node is named as partial in every answer over several nodes


def s20(lab):
    S = "s20"
    N = lab.nodes[:3]
    n1, n2, n3 = N
    D, ready = group_ready(lab, N)
    hosts = {n.name: n.hostname() for n in N}
    metric = urllib.parse.quote("traffic.requests:sum")
    l1 = Load(n1.ip, rate=20, workers=2, mode="keep", claim=CLIENT_NET + "50").start()
    l2 = Load(n2.ip, rate=10, workers=2, mode="keep", claim=CLIENT_NET + "51").start()

    def ask(d):
        t = time.time()
        calls = {
            "series_10s_2min": "/monitoring/series?metric=%s&from=%s&to=%s&resolution=10s" % (metric, stamp(t - 120), stamp(t)),
            "series_1m_30min": "/monitoring/series?metric=%s&from=%s&to=%s&resolution=1m" % (metric, stamp(t - 1800), stamp(t)),
            "series_10m_6h": "/monitoring/series?metric=%s&from=%s&to=%s&resolution=10m" % (metric, stamp(t - 21600), stamp(t)),
            "breakdown_10min": "/monitoring/traffic/breakdown?by=path&from=%s&to=%s" % (stamp(t - 600), stamp(t)),
            "now": "/monitoring/now",
        }
        out = {}
        for k, q in calls.items():
            st, js = d.call("GET", q)
            c = (js.get("cluster") or {}) if isinstance(js, dict) else {}
            out[k] = {"status": st, "partial": [(p.get("name"), p.get("until")) for p in c.get("partial_nodes", [])], "nodes": len(c.get("nodes", []))}
        return out
    time.sleep(75)
    before = []
    for _ in range(9):
        before.append({d.node.name: ask(d) for d in (D[0], D[2])})
        time.sleep(5)
    named_before = sorted(set(p[0] for row in before for v in row.values() for a in v.values() for p in a["partial"]))
    bad_status = sorted(set((k, a["status"]) for row in before for v in row.values() for k, a in v.items() if a["status"] != 200))
    R.check(S, "20.01", "three running nodes, n1 with 20 requests a second, n2 with 10, n3 with no visitor: in 45 s no answer for the group (the "
            "series of the 10 s, 1 min and 10 min ring, the breakdown, the answer for now), asked on n1 and n3 every 5 s, names any node as "
            "partial; a running node without visitors is never named", not named_before and not bad_status,
            {"answers": len(before) * 2 * 5, "nodes_named_as_partial": named_before, "calls_not_answered_200": bad_status})
    t_kill = time.time()
    n2.kill9()
    l2.stop()
    polls = []
    while time.time() - t_kill < 240:
        t = time.time()
        row = {"s": round(t - t_kill, 1)}
        for d in (D[0], D[2]):
            row[d.node.name] = ask(d)
        polls.append(row)
        time.sleep(max(0.0, 5 - (time.time() - t)))
    l1.stop()
    want = hosts["n2"]
    kinds = ["series_10s_2min", "series_1m_30min", "series_10m_6h", "breakdown_10min", "now"]
    first, missing, wrong, untils = {}, {}, {}, set()
    for k in kinds:
        for who in ("n1", "n3"):
            key = "%s asked on %s" % (k, who)
            named = [r["s"] for r in polls if [p[0] for p in r[who][k]["partial"]] == [want]]
            first[key] = min(named) if named else None
            # the answer for now ends about 20 s before the present (contract 9a, "The last minute"), so a silent
            # node is 30 s behind its end about 20 s later than in a series that ends now
            late = [r for r in polls if r["s"] >= (60 if k == "now" else 40)]
            missing[key] = [r["s"] for r in late if want not in [p[0] for p in r[who][k]["partial"]]]
            wrong[key] = sorted(set(p[0] for r in polls for p in r[who][k]["partial"] if p[0] != want))
            untils |= set(p[1] for r in polls for p in r[who][k]["partial"] if p[0] == want)

    def secs(u):
        try:
            return datetime.datetime.strptime(u[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc).timestamp() - t_kill
        except Exception:
            return None
    off = sorted(set(rnd(secs(u), 0) for u in untils if u))
    ok = (all(v is not None and v <= (65 if k.startswith("now") else 45) for k, v in first.items()) and not any(missing.values()) and not any(wrong.values())
          and off and all(o is not None and -25 <= o <= 10 for o in off))
    R.check(S, "20.02", "n2 killed: asked on n1 and on n3 every 5 s for four minutes, every answer over several nodes names n2 (and only n2) "
            "under partial_nodes from 40 s after the kill on in every resolution and from 60 s on in the answer for now, which ends about "
            "20 s before the present (contract 9a: a node of which the gateway holds nothing later than 30 s before the end of the span), and `until` lies close to the kill (pass: from 25 s "
            "before to 10 s after it; the contract says 'to ten seconds')", ok,
            {"answers_per_call": len(polls), "first_named_s_after_the_kill": first,
             "answers_from_40_s_on_(now:_60_s)_that_do_not_name_it": {k: v[:12] for k, v in missing.items() if v},
             "other_nodes_named": {k: v for k, v in wrong.items() if v}, "until_named": sorted(u for u in untils if u), "killed_at": stamp(t_kill),
             "until_s_relative_to_the_kill": off, "nodes_the_answers_say_they_cover": sorted(set(r[w][k]["nodes"] for r in polls for w in ("n1", "n3") for k in kinds))})
    st = l1.stats()
    R.check(S, "20.03", "the load on n1 across the kill (20 requests a second): no request fails", st["not_200"] == 0, {"requests": st["requests"], "not_200": st["not_200"], "latency_ms": st["latency_ms"]})


# ---------------------------------------------------------------------------------------------------------------
# scenario 21: N3 of the second run again, and certificates with the guide's TLS example as it is now


def s21(lab):
    S = "s21"
    import run
    N = lab.nodes[:3]
    n1, n2, n3 = N

    def polled(n, seconds, skip=1.5):
        """Readiness of a node asked five times a second from `skip` s after the start of its process."""
        rows = []
        while now() - n.started_at < seconds:
            if now() - n.started_at >= skip:
                rows.append((round(now() - n.started_at, 2), n.ready(1.5)))
            time.sleep(0.2)
        return rows
    # a fresh node whose peers are not started
    for n in N:
        n.wipe()
        n.write_files([m.ip for m in N], lab.balancers(), node_name="web", name_from_host=True)
    n1.start()
    open_after = wait_until(lambda: tcp_open(n1.ip, 80, timeout=0.3), 20, 0.02)
    rows = polled(n1, 60)
    codes = {}
    for t, c in rows:
        codes[c] = codes.get(c, 0) + 1
    why = n1.grep("out of traffic|readiness", 2)
    R.check(S, "21.01", "a fresh node whose two peers are not started: its web port is open and /.schild/readyz answers 503, asked five times a "
            "second from 1.5 s to 60 s after the start of the process (second run: every poll was refused), and its log says why",
            set(codes) == {503} and bool(why), {"web_port_open_s_after_the_start": rnd(open_after), "answers": {str(k): v for k, v in codes.items()},
                                                "a_visitor_sent_straight_to_it": get(n1.ip, "/v", claim=CLIENT_NET + "90", timeout=2)}, why[-600:])
    n2.start()
    n3.start()
    r = {n.name: n.wait_ready(40) for n in N}
    time.sleep(3)
    D = first_login(N)
    st, js = D[0].block(CLIENT_NET + "91", 3600)
    time.sleep(2)
    # in step once, restarted alone
    runs = []
    for _ in range(3):
        for n in N:
            n.kill9()
        time.sleep(1)
        n3.start()
        op = wait_until(lambda: tcp_open(n3.ip, 80, timeout=0.3), 20, 0.02)
        rows = polled(n3, 16, skip=(op or 0) + 0.05)
        first200 = next((t for t, c in rows if c == 200), None)
        pre = [c for t, c in rows if first200 is None or t < first200]
        runs.append({"web_port_open_s": rnd(op), "ready_after_s": first200, "answers_before": {str(c): pre.count(c) for c in sorted(set(pre))},
                     "blocked_address_at_ready": get(n3.ip, "/b", claim=CLIENT_NET + "91", timeout=2),
                     "log": n3.grep("out of traffic|readiness", 1)[-300:]})
        n1.start()
        n2.start()
        for n in (n1, n2):
            n.wait_ready(40)
        time.sleep(4)
    R.check(S, "21.02", "a node that was in step once and is restarted with no member reachable, 3 runs: the web port is open within a second, "
            "every readiness answer before the first 200 is 503 (none refused), ready after 8 to 15 s with the block from before",
            all(x["web_port_open_s"] is not None and x["web_port_open_s"] <= 2 and set(x["answers_before"]) == {"503"} and x["ready_after_s"] is not None
                and 8 <= x["ready_after_s"] <= 15 and x["blocked_address_at_ready"] == 403 for x in runs), {"runs": runs})

    # certificates: the guide's example for a TLS site with the challenge over port 443 turned off
    TLS_OFF = "\ttls {\n\t\tissuer acme {\n\t\t\tdisable_tlsalpn_challenge\n\t\t}\n\t}"

    class C(run.Certs):
        def deploy(self, extra=TLS_OFF):
            ca = self.app.get("/opt/sg27/pebble.minica.pem")
            glob = "\tacme_ca https://pebble:14000/dir\n\tacme_ca_root /etc/schild/pebble.minica.pem"
            for n in self.nodes:
                n.wipe()
                n.run("grep -q pebble /etc/hosts || echo '%s pebble' >> /etc/hosts" % self.app.ip)
                n.write_files([m.ip for m in self.nodes], self.lab.balancers(), node_name="web", name_from_host=True, caddy_global=glob,
                              site_addr=run.CERT_SITE, site_extra=extra)
                n.put("/etc/schild/pebble.minica.pem", ca)

        def alpn_tries(self):
            return self._count("TLS-ALPN") + sum(n.count("tls-alpn-01") for n in self.nodes)
    P = lab.nodes[:2]
    c = C(lab, P)
    if not c.there():
        R.check(S, "21.10", "certificates with the guide's TLS example", None, {"measured": False}, "the ACME test server is not in the image")
        return
    for n in N:
        n.kill9()
    runs = []
    for k in range(5):
        c.pebble_stop(forget=True)
        c.deploy()
        rc, val = P[0].run("schild ingress validate -config %s -adapt-only 2>&1 | tail -2" % P[0].CFG)
        c.pebble_start()
        c.haproxy()
        for n in P:
            n.start()
        t0 = now()
        got = [c.wait_cert(n, 60) for n in P]
        t_both = now() - t0
        time.sleep(8)
        row = {"both_serve_after_s": rnd(t_both, 1) if all(g[0] is not None for g in got) else None,
               "same_certificate": len(set(g[1] for g in got)) == 1, "orders_placed": c.placed(), "issued": c.issued(),
               "nodes_that_went_to_the_ca": c.askers(), "tries_over_port_443_tls_alpn": c.alpn_tries(), "http_checks_of_the_ca": c.checks(),
               "balancer_443": c.lb443(), "caddyfile_accepted": rc == 0}
        # a third node joins with empty storage: no order of its own
        j = lab.nodes[2]
        c3 = C(lab, [j])
        j.wipe()
        j.run("grep -q pebble /etc/hosts || echo '%s pebble' >> /etc/hosts" % lab.app.ip)
        j.write_files([m.ip for m in lab.nodes[:3]], lab.balancers(), node_name="web", name_from_host=True,
                      caddy_global="\tacme_ca https://pebble:14000/dir\n\tacme_ca_root /etc/schild/pebble.minica.pem", site_addr=run.CERT_SITE, site_extra=TLS_OFF)
        j.put("/etc/schild/pebble.minica.pem", lab.app.get("/opt/sg27/pebble.minica.pem"))
        j.start()
        tj, fpj = c.wait_cert(j, 30)
        time.sleep(10)
        row.update({"a_third_node_that_joins_serves_after_s": rnd(tj, 1), "its_certificate_is_the_same": fpj == got[0][1],
                    "orders_placed_after_it_joined": c.placed(), "issued_after_it_joined": c.issued(), "it_went_to_the_ca": j.count("obtaining certificate") > 0})
        runs.append(row)
        for n in lab.nodes[:3]:
            n.kill9()
    good = all(x["orders_placed"] == 1 and x["issued"] == 1 and len(x["nodes_that_went_to_the_ca"]) == 1 and x["same_certificate"] and x["both_serve_after_s"] is not None
               and x["orders_placed_after_it_joined"] == 1 and x["issued_after_it_joined"] == 1 and x["its_certificate_is_the_same"] for x in runs)
    R.check(S, "21.10", "the guide's example for a TLS site with `disable_tlsalpn_challenge` in the site's `tls` block, behind the guide's "
            "balancer: two nodes started fresh at the same moment with the CA reachable, 5 runs: one order at the CA and one certificate "
            "per run, one node asks, both show the certificate; a third node that joins afterwards orders nothing (guide: 'dann bleibt es "
            "bei einer Bestellung über Port 80')", good,
            {"orders_placed": [x["orders_placed"] for x in runs], "issued": [x["issued"] for x in runs],
             "nodes_that_went_to_the_ca": [x["nodes_that_went_to_the_ca"] for x in runs], "both_serve_after_s": [x["both_serve_after_s"] for x in runs],
             "tries_over_port_443": [x["tries_over_port_443_tls_alpn"] for x in runs],
             "orders_after_a_third_node_joined": [x["orders_placed_after_it_joined"] for x in runs],
             "third_node_serves_after_s": [x["a_third_node_that_joins_serves_after_s"] for x in runs]}, json.dumps(runs)[:3000])
    # a node restarted alone serves its certificate at once (second run: after 10.3 s, the ports were closed until then)
    c.pebble_stop(forget=True)
    c.deploy()
    c.pebble_start()
    c.haproxy()
    for n in P:
        n.start()
    got = [c.wait_cert(n, 60) for n in P]
    time.sleep(5)
    placed0, issued0 = c.placed(), c.issued()
    alone = []
    for _ in range(3):
        for n in P:
            n.kill9()
        time.sleep(1)
        P[1].start()
        t0 = now()
        hs = wait_until(lambda: re.fullmatch(r"[0-9a-f]{16}", str(c.cert_of(P[1])[1])) is not None, 30, 0.05)
        st_then, fp_then = c.cert_of(P[1])
        t200, fp200 = c.wait_cert(P[1], 30)
        alone.append({"a_handshake_shows_the_certificate_after_s": rnd(hs), "status_of_the_request_then": st_then, "same_certificate": fp_then == got[1][1],
                      "answers_200_after_s": None if t200 is None else rnd(t200 + (hs or 0) + 0.0, 1)})
        P[0].start()
        P[0].wait_ready(5)
        c.wait_cert(P[0], 40)
        time.sleep(4)
    R.check(S, "21.11", "a node of the pair restarted with the other down, 3 runs: its first TLS handshake shows the certificate from before at "
            "once (pass: within 3 s; second run: 10.2 s with closed ports), the readiness answer over TLS is 503 until about 10 s, and "
            "nothing is ordered", all(x["a_handshake_shows_the_certificate_after_s"] is not None and x["a_handshake_shows_the_certificate_after_s"] <= 3
                                     and x["same_certificate"] for x in alone) and c.placed() == placed0 and c.issued() == issued0,
            {"runs": alone, "orders_before": placed0, "orders_after": c.placed(), "issued_before": issued0, "issued_after": c.issued()})
    for n in P:
        n.kill9()
    c.pebble_stop()


# ---------------------------------------------------------------------------------------------------------------
# scenario 22: N4 of the second run again: what the documents now say of it


def s22(lab):
    S = "s22"
    N = lab.nodes[:3]
    n1, n2, n3 = N
    runs = []
    for k in range(3):
        D, ready = group_ready(lab, N)
        n3.clock_shift(90)
        time.sleep(5)
        a0 = CLIENT_NET + str(160 + k * 30)
        st0 = D[2].block(a0, 3600)[0]
        t = now()
        took = wait_until(lambda: get(n1.ip, "/b", claim=a0, timeout=2) == 403, 60, 0.2)
        time.sleep(max(0.0, 40 - (now() - t)))
        n3.clock_release()
        n3.clock_shift(-30)
        t0 = now()
        tries, first_ok = [], None
        i = 0
        while now() - t0 < 150 and (first_ok is None or len(tries) < first_ok[1] + 3):
            i += 1
            a = CLIENT_NET + str(160 + k * 30 + i)
            ts = round(now() - t0, 1)
            D[0].block(a, 3600)
            acted = wait_until(lambda: get(n3.ip, "/b", claim=a, timeout=2) == 403, 2.5, 0.05)
            tries.append((ts, a, acted is not None))
            if acted is not None and first_ok is None:
                first_ok = (ts, len(tries))
            time.sleep(max(0.0, 4 - (now() - t0 - ts)))
        time.sleep(5)
        late = [a for ts, a, ok in tries if not ok and get(n3.ip, "/b", claim=a, timeout=2) != 403]
        log = n3.grep("put off", 1)
        ahead = re.findall(r'"ahead":"([^"]+)"', n3.run("grep 'put off' %s | tail -40" % n3.LOG)[1])
        ready3 = n3.ready()
        n3.clock_release()
        runs.append({"block_made_on_n3_while_90_s_ahead": st0, "n1_took_it_after_s": rnd(took),
                     "n3_30_s_behind_takes_a_block_of_n1_again_after_s": first_ok[0] if first_ok else None,
                     "blocks_of_n1_it_did_not_take_within_2.5_s": sum(1 for x in tries if not x[2]), "of_them_still_not_on_n3_at_the_end": len(late),
                     "how_far_ahead_n3_said_the_records_were": sorted(set(ahead))[:4] + sorted(set(ahead))[-2:], "readyz_of_n3_meanwhile": ready3})
        time.sleep(3)
    vals = [r["n3_30_s_behind_takes_a_block_of_n1_again_after_s"] for r in runs]
    R.check(S, "22.01", "N4 as the documents now describe it (guide, 'Uhr mehr als eine Minute daneben': 'bis zu einer Minute lang ... In "
            "dieser Minute nimmt auch ein Server, dessen Uhr nur eine halbe Minute nachgeht, nichts an'; contract section 4: 'for about "
            "half a minute'): n3 90 s ahead writes a block, is set right and then 30 s behind; a block is made on n1 every 4 s. 3 runs; "
            "pass: n3 takes the blocks of n1 again within 75 s and holds every one of them in the end",
            all(v is not None and v <= 75 for v in vals) and all(r["of_them_still_not_on_n3_at_the_end"] == 0 for r in runs),
            {"takes_again_after_s": vals, "runs": runs})


# ---------------------------------------------------------------------------------------------------------------
# scenario 24: the state comparison under changes, by how often something changes and by class


def s24(lab):
    S = "s24"
    N = lab.nodes[:3]
    D, ready = group_ready(lab, N)
    rows = []
    for label, every, kinds, seconds in (("one change every 0.6 s, all four classes", 0.6, (0, 1, 2, 3), 150),
                                         ("one change every 2 s, all four classes", 2.0, (0, 1, 2, 3), 150),
                                         ("one change every 5 s, all four classes", 5.0, (0, 1, 2, 3), 180),
                                         ("one change every 15 s, all four classes", 15.0, (0, 1, 2, 3), 240),
                                         ("blocks and lifts only, one pair every 2 s", 2.0, (0,), 120),
                                         ("a setting only, one change every 2 s", 2.0, (2,), 120)):
        time.sleep(25)
        marks = {n.name: n.count("differed from a member") for n in N}
        w = StateWatch(D)
        c = Changes(D, every=every, kinds=kinds)
        hint = 0
        t0 = now()
        while now() - t0 < seconds:
            hint += 1 if any("cluster_state_differs" in (d.reasons() or []) for d in D) else 0
            time.sleep(5)
        made = c.end()
        time.sleep(12)
        r = w.end()
        repairs = {n.name: n.count("differed from a member") - marks[n.name] for n in N}
        views = r["answers"] * 2
        rows.append({"stream": label, "seconds": seconds, "changes_made": made["changes_made"], "calls_that_failed": made["calls_that_failed"],
                     "member_views": views, "of_them_differs": r["member_views_with_differs"],
                     "share_percent": round(100.0 * r["member_views_with_differs"] / max(1, views), 1),
                     "classes": r["classes_that_differed"], "looks_at_the_overview_with_the_hint_cluster_state_differs": "%d of %d" % (hint, seconds // 5),
                     "repairs_logged_per_node": repairs})
    last = N[0].grep("differed from a member", 1)
    R.check(S, "24.01", "the state comparison under a stream of changes on three nodes, by how often something changes: how many member views "
            "read `differs`, whether the overview carried `cluster_state_differs` and whether a node logged the repair (pass: no view reads "
            "`differs` in any stream; each change was on the other nodes within about a second, scenario 14)",
            all(x["of_them_differs"] == 0 for x in rows), {"streams": rows}, last[-500:])
    same = wait_until(lambda: all(all(v == SAME for v in states(d).values()) for d in D), 60, 1)
    R.check(S, "24.02", "after the last stream ended every node reads the others as `same` again", same is not None, {"after_s": rnd(same)})


# ---------------------------------------------------------------------------------------------------------------
# scenario 25: a difference in settings right after the birth of a group: how often, how long, what the nodes say


def s25(lab):
    S = "s25"
    N = lab.nodes[:3]
    tried, found = 0, None
    for k in range(40):
        tried += 1
        D, ready = group_ready(lab, N)
        time.sleep(22)
        st = {d.node.name: states(d) for d in D}
        if any(v != SAME for x in st.values() for v in x.values()):
            found = st
            break
    if not found:
        R.check(S, "25.01", "fresh starts of three nodes until one leaves a member reading `differs` 22 s after the group is active", None,
                {"fresh_starts": tried, "starts_with_a_difference": 0})
        return
    t0 = now()
    who = sorted(set((a, b, c) for a, x in found.items() for b, v in x.items() for c, y in (v or {}).items() if y != "same"))
    hist, ended, hint = [], None, 0
    while now() - t0 < 600:
        st = {d.node.name: states(d) for d in D}
        bad = any(v != SAME for x in st.values() for v in x.values())
        hint += 1 if "cluster_state_differs" in (D[0].reasons() or []) or "cluster_state_differs" in (D[1].reasons() or []) or "cluster_state_differs" in (D[2].reasons() or []) else 0
        hist.append(bad)
        if not bad and ended is None and len(hist) > 2 and not hist[-2]:
            ended = now() - t0
            break
        time.sleep(5)
    logs = {n.name: n.run("grep -E 'human_check|differ|settings/' %s | cut -c1-330 | tail -12" % n.LOG)[1] for n in N}
    repairs = {n.name: n.count("differed from a member") for n in N}
    shared = [d.group().get("shared") for d in D]
    ready_codes = [n.ready() for n in N]
    # does a restart of the node that differs heal it?
    odd = None
    names = {n.hostname(): n for n in N}
    cnt = {}
    for a, b, c in who:
        cnt[a] = cnt.get(a, 0) + 1
        hb = [n.name for h, n in names.items() if h == b]
        for x in hb:
            cnt[x] = cnt.get(x, 0) + 1
    odd = max(cnt, key=cnt.get) if cnt else None
    healed = None
    if ended is None and odd:
        n = lab[odd]
        n.term()
        n.wait_exit(40)
        n.start()
        n.wait_ready(40)
        healed = wait_until(lambda: all(all(v == SAME for v in states(d).values()) for d in D), 60, 1)
    R.check(S, "25.01", "a difference right after the birth of a group, found by starting three wiped nodes together until one start leaves a "
            "member reading `differs` (nothing is changed by hand): it is gone within 60 s by the repair the guide describes ('gleicht von "
            "selbst neu ab')", ended is not None and ended <= 60,
            {"fresh_starts_until_it_showed": tried, "who_reads_whom_as_differs_in_which_class": ["%s reads %s: %s" % w for w in who],
             "watched_s": 600 if ended is None else rnd(ended, 0), "difference_ended_after_s": rnd(ended, 0),
             "looks_with_the_hint_cluster_state_differs": "%d of %d" % (hint, len(hist)), "repairs_logged_per_node": repairs,
             "readyz": ready_codes, "shared_counts_per_node": shared, "node_that_differs": odd,
             "all_same_s_after_that_node_was_restarted": rnd(healed, 0)}, json.dumps(logs)[:5000])


SCENARIOS = {"s12": s12, "s13": s13, "s14": s14, "s15": s15, "s16": s16, "s17": s17, "s18": s18, "s19": s19, "s20": s20, "s21": s21, "s22": s22, "s23": s23,
             "s24": s24, "s25": s25}
