"""Scenario 3: load. Several thousand requests a second over three gateways for a few minutes; client latency with
the cluster off and on; how many single requests and events every node holds afterwards, by rate; whether blocks
and rate limits still act for the whole group under load."""
import os
import random
import subprocess
import threading
import time

from hard import (SEED, Dash, HNode, acts, count_events, count_requests, first_setup, group, hget, load_start, load_wait, metric, now,
                  requests_of_ip, resources, run_load, short_load, wait_for, wait_group)

RING = "monitoring:\n  requests:\n    max_size_mb: 4096"   # the largest request store the config takes


def du(path):
    out = subprocess.run(["du", "-sk", path], capture_output=True, text=True).stdout.split()
    return int(out[0]) * 1024 if out else None


def settle(lab, ds, timeout=60):
    """Waits until the number of requests every node holds no longer changes; answers (counts, rates)."""
    last, same_since = None, now()
    t0 = now()
    while now() - t0 < timeout:
        got = [count_requests(d, lab.started - 120) for d in ds]
        cur = [g[0] for g in got]
        if cur != last:
            last, same_since = cur, now()
        elif now() - same_since >= 4.0:
            break
        time.sleep(1.0)
    return [g[0] for g in got], [g[1] for g in got]


def served(r):
    """Requests the gateways answered, by the client's count."""
    return r["sent"] - r["failed"]


def run(lab):
    out = lab.data
    quick = lab.quick
    singles = [HNode(lab, "s%d" % i, i, None, extra=RING).start() for i in (1, 2, 3)]
    for s in singles:
        s.wait_ready(40)
    names = ["g1", "g2", "g3"]
    nodes = group(lab, names, idx0=5, extra=RING)
    wait_group(lab, nodes, cid="l.setup")
    ds = first_setup(lab, nodes, cid="l.setup")

    # ---- by rate: what every node holds of what the three served (an address stays on one node)
    ladder = []
    first_div = None
    # SG27H_MAX_RPS caps the ladder (a laptop shared with other work)
    cap = int(os.environ.get("SG27H_MAX_RPS", "9000"))
    for k, rps in enumerate([x for x in ([300, 1000] if quick else [300, 1000, 2000, 3000, 6000, 9000]) if x <= cap]):
        dur = 10 if quick else 30
        size0 = [du(os.path.join(nd.data, "requests")) for nd in nodes]
        base, _ = settle(lab, ds, 30)
        r = run_load(lab, nodes, rps, dur, "ladder%d" % rps, conns=48, ips=2000, ipnet="10.%d" % (40 + k), path="/ladder%d" % rps)
        time.sleep(2.0)
        total, rates = settle(lab, ds)
        counts = [b - a if isinstance(a, int) and isinstance(b, int) else None for a, b in zip(base, total)]
        size1 = [du(os.path.join(nd.data, "requests")) for nd in nodes]
        want = served(r)
        row = {"rps_asked": rps, "rps_achieved": round(r["rps_achieved"], 1), "answered": want, "failed": r["failed"], "status": r["status"],
               "held": counts, "sample_rate": rates, "latency_ms": r["latency_ms"], "skipped": r["skipped"],
               "store_bytes_added": [b - a if a is not None and b is not None else None for a, b in zip(size0, size1)]}
        ints = all(isinstance(c, int) for c in counts)
        row["lacking"] = [want - c for c in counts] if ints else None
        ladder.append(row)
        equal = ints and len(set(counts)) == 1 and counts[0] == want
        if not equal and first_div is None:
            first_div = rps
        lab.check("l.ladder", "%d requests a second for %d s over three nodes: afterwards every node holds every request" % (rps, dur), equal,
                  "achieved %.0f a second; answered %d (failed %d, statuses %s); held by g1, g2, g3: %s, lacking %s; lowest sample rate the store reports %s; client p50 %s ms, p99 %s ms; request store grew by %s bytes" % (
                      r["rps_achieved"], want, r["failed"], r["status"], counts, row["lacking"], rates, r["latency_ms"].get("p50"), r["latency_ms"].get("p99"), row["store_bytes_added"]),
                  kill="waits" if r["failed"] else None)
        for nd, c in zip(nodes, counts):
            if isinstance(c, int):
                metric(lab, "requests_held_share", c / float(want) if want else 0, "ratio", want, rps=rps, node=nd.name)
        metric(lab, "load_latency_p50", r["latency_ms"].get("p50"), "ms", r["sent"], rps=rps, cluster="on")
        metric(lab, "load_latency_p99", r["latency_ms"].get("p99"), "ms", r["sent"], rps=rps, cluster="on")
    out["ladder"] = ladder
    lab.check("l.ladder", "the lowest rate at which the nodes did not all hold every request", None,
              "%s requests a second" % first_div if first_div else "none up to the highest rate tried")
    bpr = [row["store_bytes_added"][0] / float(row["held"][0]) for row in ladder[:2] if row["store_bytes_added"][0] and isinstance(row["held"][0], int) and row["held"][0]]
    if bpr:
        b = sum(bpr) / len(bpr)
        out["bytes_per_stored_request"] = b
        lab.check("l.ladder", "size of one stored request and what it means for the default request store", None,
                  "about %.0f bytes per request on disk. Inferred from the config text, not observed here (the store reported sample rate 1 throughout): a 10 min segment may use max_size_mb / 288, 1.78 MiB by default and 14.2 MiB at the maximum of 4096 used here; that would be %.0f and %.0f requests a second for the whole cluster before the next segment keeps a sample only, since every node stores the requests of all" % (
                      b, 512 * 1048576 / 288.0 / b / 600.0, 4096 * 1048576 / 288.0 / b / 600.0))

    # ---- latency, cluster off and on, in turn
    rps, dur = 3000, (8 if quick else 45)
    lat = {"off": [], "on": []}
    for rnd in range(1 if quick else 3):
        for mode, targets in (("off", singles), ("on", nodes)):
            r = run_load(lab, targets, rps, dur, "lat-%s-%d" % (mode, rnd), conns=48, ips=2000, ipnet="10.%d" % (50 + rnd), path="/lat%d" % rnd)
            lat[mode].append(short_load(r))
            metric(lab, "latency_p50", r["latency_ms"].get("p50"), "ms", r["sent"], cluster=mode, rps=rps, round=rnd + 1)
            metric(lab, "latency_p99", r["latency_ms"].get("p99"), "ms", r["sent"], cluster=mode, rps=rps, round=rnd + 1)
            time.sleep(3.0)
    out["latency"] = lat
    failed = {m: sum(x["failed"] for x in v) for m, v in lat.items()}
    p = {m: [(x["latency_ms"].get("p50"), x["latency_ms"].get("p99"), x["latency_ms"].get("max")) for x in v] for m, v in lat.items()}
    lab.check("l.latency", "%d requests a second over three gateways, %d s a round, cluster off and on in turn: no request fails" % (rps, dur),
              failed == {"off": 0, "on": 0}, "failed %s; achieved a second off %s, on %s" % (failed, [x["rps_achieved"] for x in lat["off"]], [x["rps_achieved"] for x in lat["on"]]), kill="waits")
    lab.check("l.latency", "client latency (p50, p99, max in ms) per round", None, "cluster off %s; cluster on %s" % (p["off"], p["on"]))
    for nd in singles + nodes:
        nd.kill9()

    # ---- the long run on a fresh group: blocks and limits under load, then what every node holds
    names = ["m1", "m2", "m3"]
    nodes = group(lab, names, idx0=9, extra=RING)
    wait_group(lab, nodes, cid="l.main")
    ds = first_setup(lab, nodes, cid="l.main")
    d1 = ds[0]
    st, js = d1.call("POST", "/behaviour/rate-limits", {"route": "/rl/**", "limit": 60, "per": "1m", "burst": 60, "mode": "block", "label": "load-limit"})
    time.sleep(2.0)
    rps, dur = 3000, (25 if quick else 180)
    idle = resources(nodes)
    t_from = time.time() - 1
    base, _ = settle(lab, ds, 30)
    lh = load_start(lab, nodes, rps, dur, "main", conns=48, ips=3000, ipnet="10.60", path="/main", attack_every=200, per_ip=True)
    res, stop = [], threading.Event()

    def sampler():
        while not stop.is_set():
            res.append(resources(nodes))
            stop.wait(5.0)
    th = threading.Thread(target=sampler, daemon=True)
    th.start()
    time.sleep(5.0)
    # blocks under load
    rng = random.Random(SEED)
    times = []
    for i in range(4 if quick else 12):
        a = "203.0.113.%d" % (30 + i)
        setter = i % 3
        t0 = now()
        st_b, _ = ds[setter].block(a)
        r = acts([nd for j, nd in enumerate(nodes) if j != setter], a, 403, 8)
        times += [v for v in r.values()]
        time.sleep(0.3 + rng.random() * 0.5)
    seen = sorted(v for v in times if v is not None)
    p95 = seen[max(0, int(round(0.95 * len(seen) + 0.5)) - 1)] if seen else None
    lab.check("l.main", "under %d requests a second: a block set on one node acts on the others within 1 s at p95" % rps,
              len(seen) == len(times) and p95 is not None and p95 <= 1.0, "%d samples, %d never seen in 8 s; p50 %s s, p95 %s s, max %s s" % (
                  len(times), len(times) - len(seen), seen[len(seen) // 2] if seen else None, p95, seen[-1] if seen else None))
    metric(lab, "block_propagation_under_load_p95", p95, "s", len(times), rps=rps)
    out["blocks_under_load_s"] = times
    # the limit under load: one client on one node, then one client spread over the three
    one = run_load(lab, nodes[:1], 20, 15, "rl-one", conns=4, ips=1, ipnet="10.61", spread=True, fixed_path="/rl/a")
    three = run_load(lab, nodes, 20, 15, "rl-three", conns=4, ips=1, ipnet="10.62", spread=True, fixed_path="/rl/a")
    p1, p3 = one["status"].get("200", 0), three["status"].get("200", 0)
    lab.check("l.main", "under load: a limit of 60 a minute holds for a client that spreads 20 requests a second over three nodes (at most what one node lets pass plus one second of requests)",
              one["status"].get("429", 0) > 0 and p3 <= p1 + 20, "one node: %d of %d passed (%s); three nodes: %d of %d passed (%s); bound %d + 20" % (
                  p1, one["sent"], one["status"], p3, three["sent"], three["status"], p1))
    metric(lab, "rate_limit_passed_under_load", p1, "count", one["sent"], nodes=1)
    metric(lab, "rate_limit_passed_under_load", p3, "count", three["sent"], nodes=3)
    out["limit_under_load"] = {"one": short_load(one), "three": short_load(three)}
    r = load_wait(lh, dur + 200)
    stop.set()
    th.join(6)
    t_to = time.time() + 2
    out["main_load"] = short_load(r)
    lab.check("l.main", "%d requests a second for %d s over three nodes of a group: no request fails" % (rps, dur), r["failed"] == 0 and r["skipped"] == 0,
              "achieved %.0f a second, %d sent, %d failed, %d not sent (client queue full), statuses %s; p50 %s ms, p99 %s ms, p99.9 %s ms, max %s ms" % (
                  r["rps_achieved"], r["sent"], r["failed"], r["skipped"], r["status"], r["latency_ms"].get("p50"), r["latency_ms"].get("p99"), r["latency_ms"].get("p999"), r["latency_ms"].get("max")), kill="waits")
    metric(lab, "main_latency_p50", r["latency_ms"].get("p50"), "ms", r["sent"], rps=rps)
    metric(lab, "main_latency_p99", r["latency_ms"].get("p99"), "ms", r["sent"], rps=rps)
    peak = {nd.name: {"rss_mb": max(x[nd.name]["rss_mb"] or 0 for x in res), "cpu_percent_avg": round(sum(x[nd.name]["cpu_percent"] or 0 for x in res) / max(1, len(res)), 1),
                      "tcp_established_max": max(x[nd.name]["tcp_established"] for x in res)} for nd in nodes} if res else {}
    out["resources"] = {"idle": idle, "under_load": peak}
    lab.check("l.main", "memory, CPU and connections per node, idle and under this load", None, "idle %s; under load %s" % (
        {k: (v["rss_mb"], v["cpu_percent"], v["tcp_established"]) for k, v in idle.items()}, {k: (v["rss_mb"], v["cpu_percent_avg"], v["tcp_established_max"]) for k, v in peak.items()}))
    for nd in nodes:
        metric(lab, "rss_under_load", peak.get(nd.name, {}).get("rss_mb"), "count", node=nd.name, rps=rps, what="MiB")
    time.sleep(3.0)
    total, rates = settle(lab, ds, 90)
    counts = [b - a if isinstance(a, int) and isinstance(b, int) else None for a, b in zip(base, total)]
    want = served(r)
    ints = all(isinstance(c, int) for c in counts)
    out["main_held"] = {"answered_by_main_load": want, "held": counts, "sample_rate": rates}
    lab.check("l.main", "afterwards every node holds the same number of single requests", ints and len(set(counts)) == 1,
              "held by m1, m2, m3: %s (the load answered %d, the limit and block checks add some thousand); largest difference between two nodes %s; lowest sample rate the store reports %s" % (
                  counts, want, (max(counts) - min(counts)) if ints else "?", rates))
    lab.check("l.main", "and no node lacks requests the load was answered", ints and min(counts) >= want,
              "the load alone was answered %d; lacking per node %s" % (want, [max(0, want - c) for c in counts] if ints else "?"))
    if ints:
        metric(lab, "main_requests_held_spread", max(counts) - min(counts), "count", want, rps=rps)
    # a sample of client addresses: what the client was answered against what every node holds of that address
    per_ip = r.get("ok_per_ip") or {}
    pick = rng.sample(sorted(per_ip), min(len(per_ip), 12 if quick else 45))
    bad, rows = [], []
    for ip in pick:
        got = []
        for d in ds:
            rr = requests_of_ip(d, ip, t_from, t_to)
            got.append(None if rr is None else sum(1 for p, s in rr if s == 200))
        rows.append((ip, per_ip[ip], got))
        if any(g != per_ip[ip] for g in got):
            bad.append((ip, per_ip[ip], got))
    out["per_ip_sample"] = rows
    lab.check("l.main", "a sample of %d client addresses: every node holds exactly the requests the client was answered with 200" % len(pick), not bad,
              "%d addresses differ; (address, answered, held by m1, m2, m3): %s" % (len(bad), bad[:6]))
    ev = [count_events(d, "/main", outcome="blocked") for d in ds]
    out["main_events"] = {"attacks_answered_403": r["status"].get("403", 0), "held": ev}
    lab.check("l.main", "events: every node lists the same number of events of the load, and as many as attacks were refused", len(set(ev)) == 1 and ev[0] == r["status"].get("403", 0),
              "the load sent an XSS probe with every 200th request, %d were answered 403; blocked events with that path prefix on m1, m2, m3: %s" % (r["status"].get("403", 0), ev))
    for nd in nodes:
        nd.kill9()
