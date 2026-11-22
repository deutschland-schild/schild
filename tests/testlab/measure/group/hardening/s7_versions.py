"""Scenario 7: mixed versions. Three gateways of the commit before this one are upgraded one after the other to
the build under test (same data directories), under load that follows readiness; then one goes back.
contracts/CHANGELOG.md says of the step measured here that the Ask kind `requests` is "not compatible between
nodes of the earlier draft"; everything else of that step is additive."""
import os
import re
import time

from hard import (Dash, acts, count_requests, diff_snaps, first_setup, group, gstatus, hget, load_start, load_wait, metric, now, run_load, short_load,
                  snapshot, wait_for, wait_group, wait_same)


def held(lab, ds):
    return [count_requests(d, lab.started - 120)[0] for d in ds]


def run(lab):
    old, old_rev = lab.extra_bins.get("old"), lab.extra_bins.get("old_rev")
    if not old or not os.path.exists(old):
        lab.check("v", "mixed versions", None, "NOT MEASURED: no build of an older commit given (run.sh builds one from git archive)")
        return
    out = lab.data
    out["old_rev"] = old_rev
    names = ["v1", "v2", "v3"]
    nodes = group(lab, names, binary=old)
    wait_group(lab, nodes, cid="v.old")
    ds = first_setup(lab, nodes, cid="v.old")
    d1, d2, d3 = ds
    d1.block("203.0.113.10")
    d2.call("POST", "/allowlist", {"ip": "192.0.2.10", "label": "old", "level": "no_block"})
    d3.call("PATCH", "/settings", {"retention": {"events_days": 44}})
    d1.call("POST", "/behaviour/rate-limits", {"route": "/v/**", "limit": 100, "per": "1m", "burst": 100, "mode": "block", "label": "old-limit"})
    r = run_load(lab, nodes, 300, 5, "v-old", path="/vold")
    t, snaps = wait_same(ds, 20)
    before = snaps[0]
    got = []
    tq = wait_for(lambda: (got.clear() or got.extend(held(lab, ds))) or len(set(got)) == 1, 20, 1.0)
    lab.check("v.old", "three gateways of the older commit %s: one state, every node holds every request" % old_rev, t is not None and tq is not None, "%s; requests held %s" % (diff_snaps(names, snaps), got))

    lh = load_start(lab, nodes, 300, 70 if not lab.quick else 45, "v-roll", health=True, path="/vroll", conns=8)
    time.sleep(2.0)
    steps = []
    seq = [10]

    def cross(tag, mixed):
        """Blocks, a setting and a login between every pair of nodes, and what the logs say."""
        res = {}
        for i, d in enumerate(ds):
            seq[0] += 1
            a = "203.0.113.%d" % seq[0]
            d.block(a)
            res[names[i]] = acts([nd for j, nd in enumerate(nodes) if j != i], a, 403, 8)
        ok = all(v is not None for r_ in res.values() for v in r_.values())
        lab.check(tag, "%s: a block set on each node acts on the two others" % mixed, ok, "seconds %s" % res, kill="weakens")
        s = Dash(nodes[seq[0] % 3])
        s.login()
        tl = wait_for(lambda: all(Dash(nd, s).session()[1].get("authenticated") for nd in nodes), 10, 0.1)
        lab.check(tag, "%s: a login made on one node is valid on all" % mixed, tl is not None, "after %s s" % (tl and round(tl, 2)), kill="weakens")
        return ok

    for i, nd in enumerate(nodes):
        mark = [x.logsize() for x in nodes]
        ts = now()
        nd.term()
        gone = nd.wait_exit(30)
        nd.binary = lab.bin
        nd.start()
        rdy = nd.wait_ready(40)
        ver = {m["name"]: (m.get("version") or "?")[:40] for m in gstatus(ds[i]).get("members", [])}
        t, snaps = wait_same(ds, 20)
        mixed = "%d new, %d old" % (i + 1, 2 - i)
        lab.check("v.roll", "step %d (%s): %s upgraded in place is ready and the state is the same on all three and as before" % (i + 1, mixed, nd.name),
                  gone and rdy is not None and t is not None and dict(snaps[0], blocks=None) == dict(before, blocks=None),
                  "stopped %s, ready after %s s; %s" % (gone, rdy and round(rdy, 2), diff_snaps(names, snaps)), kill="weakens")
        cross("v.roll", mixed)
        time.sleep(3.0)
        errs = {x.name: [re.sub(r'^.*?"msg":', "", l)[:200] for l in x.loglines(r'"level":"(ERROR|WARN)"', m)] for x, m in zip(nodes, mark)}
        counts = held(lab, ds)
        steps.append({"node": nd.name, "ready_s": rdy, "log_warn_error": {k: len(v) for k, v in errs.items()}, "log_examples": {k: sorted(set(v))[:3] for k, v in errs.items() if v},
                      "requests_held": counts, "group_state": [gstatus(d).get("state") for d in ds]})
        lab.check("v.roll", "step %d (%s): requests held per node, group state and what the logs say" % (i + 1, mixed), None,
                  "requests held by v1, v2, v3: %s; GET /group state %s; WARN or ERROR lines since the step %s, e.g. %s" % (
                      counts, steps[-1]["group_state"], steps[-1]["log_warn_error"], {k: sorted(set(v))[:2] for k, v in errs.items() if v}))
    r = load_wait(lh)
    out["rolling"] = {"steps": steps, "load": short_load(r), "first_failures": (r.get("first_failures") or [])[:10]}
    lab.check("v.roll", "the upgrade of all three in turn under 300 requests a second that follow readyz: no request fails", r["failed"] == 0,
              "%d sent, %d failed, statuses %s; p99 %s ms; first failures %s" % (r["sent"], r["failed"], r["status"], r["latency_ms"].get("p99"), (r.get("first_failures") or [])[:4]), kill="waits")
    metric(lab, "rolling_upgrade_failed_requests", r["failed"], "count", r["sent"])
    time.sleep(6.0)
    counts = []
    tq = wait_for(lambda: (counts.clear() or counts.extend(held(lab, ds))) or len(set(counts)) == 1, 40, 2.0)
    lab.check("v.roll", "after the upgrade every node holds the same number of single requests (those served while versions were mixed included)", tq is not None,
              "held by v1, v2, v3: %s; largest difference %s" % (counts, max(counts) - min(counts) if all(isinstance(c, int) for c in counts) else "?"))
    out["after_upgrade_requests"] = list(counts)
    metric(lab, "requests_spread_after_upgrade", max(counts) - min(counts) if all(isinstance(c, int) for c in counts) else None, "count")

    # ---- one node goes back to the older build (a rollback)
    nd = nodes[2]
    mark = nd.logsize()
    nd.term()
    nd.wait_exit(30)
    nd.binary = old
    nd.start()
    rdy = nd.wait_ready(40)
    tail = re.sub(r"\s+", " ", open(nd.log, errors="replace").read()[-400:]) if rdy is None else ""
    lab.check("v.back", "v3 goes back to the older build on the data the newer one wrote: it starts and is ready", rdy is not None,
              "ready after %s s%s" % (rdy and round(rdy, 2), "" if rdy else "; process %s; log: %s" % ("runs" if nd.alive() else "exited %s" % nd.proc.returncode, tail)))
    if rdy is not None:
        t, snaps = wait_same(ds, 20)
        lab.check("v.back", "and shows the same state as the two newer ones", t is not None, diff_snaps(names, snaps), kill="weakens")
        cross("v.back", "2 new, 1 old again")
    out["rollback_ready_s"] = rdy
    for x in nodes:
        x.kill9()
