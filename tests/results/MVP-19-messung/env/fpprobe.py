#!/usr/bin/env python3
"""TEST ONLY: send each rich-text sample and each password of fptraffic.py once and print the status (which inputs CRS blocks)."""
import importlib.util, sys, urllib.parse
sys.argv = [sys.argv[0], sys.argv[1], sys.argv[2], "0"]
spec = importlib.util.spec_from_file_location("fp", "/e/fptraffic.py"); src = open("/e/fptraffic.py").read().replace("\nmain()\n", "\n")
fp = {}; exec(compile(src, "fptraffic", "exec"), fp)
for i, html in enumerate(fp["RICH"]):
    s = fp["Session"]("academy.example.de", "10.66.40.%d" % (i + 1))
    b = fp["lw_body"](s.csrf, "editor.post-form", {"title": "x", "body": html}, {"body": html}, [{"path": "", "method": "publish", "params": []}])
    print("rich", i, s.req("POST", "/livewire/update", b, "application/json", fp["lw_headers"](s)), html[:70])
for i, pw in enumerate(["Sommer2026!", "p@ss'word\"--", "Grüne#Wiese&1", "<geheim>", "1' or '1'='1", "abc;DROP", "Passwort123"]):
    s = fp["Session"]("shop.example.de", "10.66.41.%d" % (i + 1))
    body = urllib.parse.urlencode({"_token": s.csrf, "email": "kunde@example.de", "password": pw})
    print("password", i, s.req("POST", "/login", body, "application/x-www-form-urlencoded"), pw)
