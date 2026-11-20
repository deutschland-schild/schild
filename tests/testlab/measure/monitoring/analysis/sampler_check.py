#!/usr/bin/env python3
"""MVP-21 measurement: ServerSnapshot (every 10 s) vs reference readings taken
inside the same container every second (refloop.sh: /proc/stat, free, df,
/sys/class/net, ss, cgroup) and vmstat. TEST ONLY.
  python3 -I sampler_check.py snaps.jsonl ref.txt vmstat.txt"""
import json, re, sys
from datetime import datetime, timezone

def ts(s): return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()

snaps = {}
for line in open(sys.argv[1]):
    line = line.strip()
    if not line: continue
    try: d = json.loads(line)
    except Exception: continue
    snaps[d["sampled_at"]] = d
refs = []
for line in open(sys.argv[2]):
    p = line.split(" ", 1)
    t = float(p[0]); kv = dict(re.findall(r"(\w+)=(\S+)", p[1]))
    df = re.search(r"df=\[(\d+) (\d+) (\d+)\]", line).groups()
    stat = [float(x) for x in re.search(r"stat=\[cpu\s+([^\]]+)\]", line).group(1).split()]
    ss = re.search(r"ss=\[([^\]]*)\]", line).group(1)
    refs.append(dict(t=t, rx=int(kv["rx"]), tx=int(kv["tx"]), avail=int(kv["avail"]), total=int(kv["total"]), est=int(kv["est"]), tw=int(kv["tw"]),
                     listen=int(kv["listen"]), df=[int(x) for x in df], stat=stat, cg=int(kv["cg_usec"]), memcur=int(kv["memcur"]), ss=ss))
vm = []
for line in open(sys.argv[3]):
    f = line.split()
    if len(f) >= 19 and f[0].isdigit():
        t = datetime.strptime(f[-2] + " " + f[-1], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
        vm.append(dict(t=t, us=int(f[12]), sy=int(f[13]), id=int(f[14]), wa=int(f[15]), st=int(f[16])))

def near(t):
    return min(refs, key=lambda r: abs(r["t"] - t))

rows = []
for k in sorted(snaps):
    s = snaps[k]; S = ts(k)
    if S - 10 < refs[0]["t"] or S > refs[-1]["t"]: continue
    a, b = near(S - 10), near(S)
    dt = b["t"] - a["t"]
    if dt < 8: continue
    st0, st1 = a["stat"], b["stat"]
    tot = sum(st1[:8]) - sum(st0[:8]); idle = (st1[3] - st0[3]); iow = st1[4] - st0[4]
    ref_usage = (tot - idle - iow) / tot
    vms = [v for v in vm if S - 10 < v["t"] <= S]
    vm_busy = sum(100 - v["id"] - v["wa"] for v in vms) / max(1, len(vms)) / 100
    mem = s["memory"]
    row = {"sampled_at": k,
           "cpu_usage": s["cpu"]["usage"], "cpu_ref_procstat": round(ref_usage, 4), "cpu_ref_vmstat": round(vm_busy, 4),
           "cpu_diff_pp_vs_vmstat": round(100 * (s["cpu"]["usage"] - vm_busy), 2),
           "mem_avail": mem["available_bytes"], "mem_avail_ref_free": b["avail"], "mem_diff_pp": round(100 * (mem["available_bytes"] - b["avail"]) / b["total"], 3)}
    root = [m for m in s["mounts"] if m["mount"] == "/"][0]
    size, used, av = b["df"]
    row["disk_used_ratio"] = round(root["used_ratio"], 5); row["disk_ref_df"] = round(used / (used + av), 5)
    row["disk_size_rel"] = round((root["size_bytes"] - size) / size, 6)
    eth = [i for i in s["interfaces"] if i["name"] == "eth0"]
    if eth:
        rr = (b["rx"] - a["rx"]) / dt; tr = (b["tx"] - a["tx"]) / dt
        row["net_rx_Bps"] = round(eth[0]["rx_bytes_per_s"]); row["net_rx_ref"] = round(rr)
        row["net_rx_rel"] = round((eth[0]["rx_bytes_per_s"] - rr) / rr, 4) if rr > 1000 else None
        row["net_tx_Bps"] = round(eth[0]["tx_bytes_per_s"]); row["net_tx_ref"] = round(tr)
        row["net_tx_rel"] = round((eth[0]["tx_bytes_per_s"] - tr) / tr, 4) if tr > 1000 else None
    row["tcp_est"] = s["tcp"]["established"]; row["tcp_est_ss"] = b["est"]; row["tcp_tw"] = s["tcp"]["time_wait"]; row["tcp_tw_ss"] = b["tw"]
    row["tcp_listen"] = s["tcp"]["listen"]; row["tcp_listen_ss"] = b["listen"]
    c = s.get("container") or {}
    row["ctr_cpu"] = c.get("cpu_usage"); row["ctr_cpu_ref_cores"] = round((b["cg"] - a["cg"]) / 1e6 / dt, 4)
    row["ctr_mem"] = c.get("memory_used_bytes"); row["ctr_mem_ref"] = b["memcur"]
    row["sampler_ms"] = s["schild"]["sampler_ms"]
    rows.append(row)
for r in rows:
    print(json.dumps(r))
