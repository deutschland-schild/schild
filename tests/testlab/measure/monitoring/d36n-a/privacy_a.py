#!/usr/bin/env python3
"""D36 re-measurement part A (TEST ONLY, adapted from d36/privacy_d36.py for the
spec21 replay ranges 198.51.100/24, 203.0.113/24, 192.0.2/24, 100.64/10, 2001:db8::/32): search metrics.db (raw file, WAL, every
decoded core and top blob of the three rings, the other tables) and saved API
responses for client addresses of the replay (10.0.0.0/8) and their /24
prefixes (also written with '-' or as reversed/hex forms is not attempted).

usage: privacy_d36.py --db metrics.db [--wal metrics.db-wal] --files a.json b.json ...

Allowed: client_net of agent responses as /24 ("10.1.2.0/24") - reported
separately, as the contract allows it there.
"""
import argparse
import collections
import json
import re
import sqlite3
import zlib

V4 = re.compile(rb"(?<![0-9.])(?:198\.51\.100|203\.0\.113|192\.0\.2|100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.\d{1,3})\.(\d{1,3})(?![0-9])")
P24 = re.compile(rb"(?<![0-9.])(?:198\.51\.100|203\.0\.113|192\.0\.2)\.(?![0-9])|(?i:2001:0?db8:[0-9a-f:]*)")
DASH = re.compile(rb"(?<![0-9-])(?:198-51-100|203-0-113|192-0-2)-(\d{1,3})(?![0-9])")
CLIENT_NET = re.compile(rb'\\?"client_net\\?"\s*:\s*\\?"[0-9a-f.:]+/(?:24|48|64)\\?"')


def uvarint(b, i):
    x, s = 0, 0
    while True:
        c = b[i]
        i += 1
        x |= (c & 0x7F) << s
        if c < 0x80:
            return x, i
        s += 7


def top_sections(blob):
    """codec v2 top column: version, flag, then sections (index byte, with
    0x80 a website id, uvarint length, raw deflate data)."""
    out, i = [], 2
    while i < len(blob):
        idx = blob[i]
        i += 1
        site = b""
        if idx & 0x80:
            n, i = uvarint(blob, i)
            site, i = blob[i:i + n], i + n
        n, i = uvarint(blob, i)
        out.append(site + b" " + zlib.decompress(blob[i:i + n], -15))
        i += n
    return out


def scan(name, data, hits, allowed):
    for m in CLIENT_NET.finditer(data):
        allowed[name] += 1
    clean = CLIENT_NET.sub(b'"client_net":"<allowed>"', data)
    for rx, kind in ((V4, "ipv4"), (P24, "prefix24"), (DASH, "ipv4-dashed")):
        for m in rx.finditer(clean):
            ctx = clean[max(0, m.start() - 50):m.end() + 20]
            hits.append((name, kind, m.group().decode(), ctx.decode("utf-8", "replace")))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db")
    ap.add_argument("--wal")
    ap.add_argument("--files", nargs="*", default=[])
    a = ap.parse_args()
    hits, counts, allowed, undecoded = [], collections.Counter(), collections.Counter(), collections.Counter()
    if a.db:
        scan("metrics.db(raw)", open(a.db, "rb").read(), hits, allowed)
        if a.wal:
            scan("metrics.db-wal(raw)", open(a.wal, "rb").read(), hits, allowed)
        con = sqlite3.connect("file:" + a.db + "?mode=ro", uri=True)
        for tbl in ["ring_10s", "ring_1m", "ring_10m"]:
            for slot, t, core, top in con.execute(f"SELECT slot, t, core, top FROM {tbl}"):
                for col, blob in (("core", core), ("top", top)):
                    if blob is None:
                        continue
                    try:
                        data = zlib.decompress(blob, -15) if col == "core" else b"\n".join(top_sections(blob))
                    except (zlib.error, IndexError):
                        undecoded[f"{tbl}.{col}"] += 1
                        data = blob
                    counts[f"{tbl}.{col}"] += 1
                    scan(f"{tbl}.{col}[t={t}]", data, hits, allowed)
        for (tbl,) in con.execute("SELECT name FROM sqlite_master WHERE type='table'"):
            if tbl.startswith("ring_"):
                continue
            for row in con.execute(f"SELECT * FROM {tbl}"):
                counts[tbl] += 1
                scan(tbl, repr(row).encode(), hits, allowed)
    for f in a.files:
        counts["files"] += 1
        scan(f, open(f, "rb").read(), hits, allowed)
    print(json.dumps({"scanned": counts, "undecoded": undecoded, "hits": len(hits), "client_net_allowed": sum(allowed.values())}))
    seen = collections.Counter()
    for h in hits:
        key = (h[0].split("[")[0], h[1])
        seen[key] += 1
        if seen[key] <= 2:
            print("HIT", h[0], h[1], h[2], "|", h[3].replace("\n", " "))
    for k, v in sorted(seen.items()):
        print("SUM", k, v)
    for k, v in sorted(allowed.items()):
        print("CLIENT_NET", k, v)


if __name__ == "__main__":
    main()
