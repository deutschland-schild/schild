#!/usr/bin/env python3
"""MVP-21 measurement: search metrics.db (raw bytes and every decoded bucket)
and saved API responses for IP addresses (TEST ONLY).
  python3 -I privacy_grep.py --db metrics.db [--wal metrics.db-wal] [--files resp/*.json ...]"""
import argparse, re, sqlite3, zlib, sys, json, collections

V4 = re.compile(rb"(?<![0-9.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![0-9])")
V6 = re.compile(rb"(?i)2001:0?db8[0-9a-f:]*|::ffff:[0-9.]+")
PREFIXES = [rb"198.51.100.", rb"203.0.113.", rb"192.0.2.", rb"172.20.", rb"10.231.21.", rb"198-51-100", rb"203-0-113"]

def scan(name, data, hits):
    for m in V4.finditer(data):
        if all(0 <= int(x) <= 255 for x in m.groups()):
            ctx = data[max(0, m.start() - 60):m.end() + 20]
            hits.append((name, "ipv4", m.group().decode(), ctx.decode("utf-8", "replace")))
    for m in V6.finditer(data):
        ctx = data[max(0, m.start() - 60):m.end() + 20]
        hits.append((name, "ipv6", m.group().decode(), ctx.decode("utf-8", "replace")))
    for p in PREFIXES:
        i = data.find(p)
        while i >= 0:
            hits.append((name, "prefix", p.decode(), data[max(0, i - 60):i + 30].decode("utf-8", "replace")))
            i = data.find(p, i + 1)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db")
    ap.add_argument("--wal")
    ap.add_argument("--files", nargs="*", default=[])
    a = ap.parse_args()
    hits = []
    counts = collections.Counter()
    if a.db:
        raw = open(a.db, "rb").read()
        scan("metrics.db(raw)", raw, hits)
        if a.wal:
            scan("metrics.db-wal(raw)", open(a.wal, "rb").read(), hits)
        con = sqlite3.connect("file:" + a.db + "?mode=ro", uri=True)
        for tbl in ["ring_10s", "ring_1m", "ring_10m"]:
            for slot, t, blob in con.execute(f"SELECT slot, t, bucket FROM {tbl}"):
                data = zlib.decompress(blob, -15)
                counts[tbl] += 1
                scan(f"{tbl}[t={t}]", data, hits)
        for tbl, in con.execute("SELECT name FROM sqlite_master WHERE type='table'"):
            if tbl.startswith("ring_"):
                continue
            for row in con.execute(f"SELECT * FROM {tbl}"):
                scan(f"{tbl}", repr(row).encode(), hits)
    for f in a.files:
        data = open(f, "rb").read()
        counts["files"] += 1
        scan(f, data, hits)
    print(json.dumps({"scanned": counts, "hits": len(hits)}))
    seen = collections.Counter()
    for h in hits:
        key = (h[0].split("[")[0], h[1], h[2])
        seen[key] += 1
        if seen[key] <= 2:
            print("HIT", h[0], h[1], h[2], "|", h[3].replace("\n", " "))
    for k, v in seen.items():
        print("SUM", k, v)

main()
