#!/usr/bin/env python3
"""D36 evening re-measurement (TEST ONLY): new handle-branch variants (h-*)
for zz_abend_derive_test.go, next to the r-*/v-*/n-* cases of
../../d36n/derive_cases.py. Real ports, no http_port.

usage: derive_cases_abend.py <out-dir>

case.json: blocks = the measurer's own reading (schild = every backend is
reached behind schild; proxies = the block reaches a backend), expect_drop =
indices of blocks the gateway must drop as broken while the others stay
(D36 fix round 2).
"""
import json
import os
import sys

UP = "127.0.0.1:19101"
S, P = "schild", f"reverse_proxy {UP}"
R = "redir https://{host}{uri} permanent"
G = "{\n\tadmin off\n}\n\n"


def block(addrs, lines):
    inner = "".join(f"\t{l}\n" for l in lines)
    return f"{', '.join(addrs)} {{\n{inner}}}\n\n"


def B(addrs, schild, proxies):
    return {"Addresses": addrs, "Schild": schild, "Proxies": proxies}


def sub(head, lines, ind="\t"):
    return [head + " {"] + [ind + l for l in lines] + ["}"]


def main(out):
    cases = {}
    allbr = sub("handle /api/*", [S, P]) + sub("handle", [S, P])
    partbr = sub("handle /api/*", [S, P]) + sub("handle", [P])
    # h01 mixed: branch-protected, top-protected, one branch without schild (unlisted -> dropped, others stay).
    cases["h01-mixed-unlisted"] = (G,
        block(["a.example.org"], allbr) + block(["b.example.org"], [S, P]) + block(["c.example.org"], partbr),
        {"resolve": ["a.example.org", "b.example.org", "c.example.org"],
         "blocks": [B(["a.example.org"], True, True), B(["b.example.org"], True, True), B(["c.example.org"], False, True)],
         "expect_drop": [2]})
    # h02 the same, c listed in unprotected_sites -> unprotected website, no error.
    cases["h02-mixed-listed"] = (G,
        block(["a.example.org"], allbr) + block(["b.example.org"], [S, P]) + block(["c.example.org"], partbr),
        {"unprotected_sites": ["c.example.org"], "resolve": ["a.example.org", "b.example.org", "c.example.org"],
         "blocks": [B(["a.example.org"], True, True), B(["b.example.org"], True, True), B(["c.example.org"], False, True)]})
    # h03 nested handle inside route, schild in every branch.
    cases["h03-route-nested-handle"] = (G,
        block(["r.example.org"], sub("route", allbr)) + block(["b.example.org"], [S, P]),
        {"resolve": ["r.example.org", "b.example.org"], "blocks": [B(["r.example.org"], True, True), B(["b.example.org"], True, True)]})
    # h04 handle_path with three branches, all schild, plus http redirect block.
    hp = sub("handle_path /a/*", [S, P]) + sub("handle_path /b/*", [S, "reverse_proxy 127.0.0.1:19102"]) + sub("handle", [S, P])
    cases["h04-handle-path-three"] = (G,
        block(["http://hp.example.org"], [R]) + block(["hp.example.org"], hp),
        {"resolve": ["hp.example.org"], "blocks": [B(["http://hp.example.org"], False, False), B(["hp.example.org"], True, True)]})
    # h05 schild on the api branch, the other branch is a static file_server (no backend without schild).
    cases["h05-branch-api-and-static"] = (G,
        block(["s.example.org"], sub("handle /api/*", [S, P]) + sub("handle", ["root * /srv", "file_server"])),
        {"resolve": ["s.example.org"], "blocks": [B(["s.example.org"], True, True)]})
    # h06 schild on the api branch, the other branch a redirect.
    cases["h06-branch-api-and-redir"] = (G,
        block(["d.example.org"], sub("handle /api/*", [S, P]) + sub("handle", ["redir https://www.example.org{uri}"])),
        {"resolve": ["d.example.org"], "blocks": [B(["d.example.org"], True, True)]})
    # h07 handle nested in handle, schild in every inner branch.
    nest = sub("handle /api/*", sub("handle /api/v1/*", [S, P]) + sub("handle", [S, P])) + sub("handle", [S, P])
    cases["h07-nested-handle-all"] = (G,
        block(["n.example.org"], nest),
        {"resolve": ["n.example.org"], "blocks": [B(["n.example.org"], True, True)]})
    # h08 nested handle with one inner branch without schild (unlisted -> dropped), next to a good block.
    nestbad = sub("handle /api/*", sub("handle /api/v1/*", [S, P]) + sub("handle", [P])) + sub("handle", [S, P])
    cases["h08-nested-one-missing"] = (G,
        block(["bad.example.org"], nestbad) + block(["ok.example.org"], [S, P]),
        {"resolve": ["bad.example.org", "ok.example.org"],
         "blocks": [B(["bad.example.org"], False, True), B(["ok.example.org"], True, True)], "expect_drop": [0]})
    # h09 schild at the top and again in each branch.
    cases["h09-top-and-branches"] = (G,
        block(["t.example.org"], [S] + allbr),
        {"resolve": ["t.example.org"], "blocks": [B(["t.example.org"], True, True)]})
    # h10 named route invoked in one branch, schild in the other.
    cases["h10-invoke-in-branch"] = (G + "&(app) {\n\t" + S + "\n\t" + P + "\n}\n\n",
        block(["i.example.org"], sub("handle /api/*", ["invoke app"]) + sub("handle", [S, P])),
        {"resolve": ["i.example.org"], "blocks": [B(["i.example.org"], True, True)]})
    # h11 named matchers.
    cases["h11-named-matchers"] = (G,
        block(["m.example.org"], ["@api path /api/*", "@admin path /admin/*"] + sub("handle @api", [S, P]) + sub("handle @admin", [S, "reverse_proxy 127.0.0.1:19102"]) + sub("handle", [S, P])),
        {"resolve": ["m.example.org"], "blocks": [B(["m.example.org"], True, True)]})
    # h12 realistic: catch-all :80 redirect, two branch-style apps, one top-level app, one listed legacy app.
    cases["h12-realistic-mix"] = (G,
        block([":80"], [R]) + block(["shop.example.org", "www.shop.example.org"], allbr)
        + block(["blog.example.org"], [S, P]) + block(["api.example.org"], hp) + block(["legacy.example.org"], [P]),
        {"unprotected_sites": ["legacy.example.org"],
         "resolve": ["shop.example.org", "www.shop.example.org", "blog.example.org", "api.example.org", "legacy.example.org", "x.example"],
         "blocks": [B([":80"], False, False), B(["shop.example.org", "www.shop.example.org"], True, True), B(["blog.example.org"], True, True),
                    B(["api.example.org"], True, True), B(["legacy.example.org"], False, True)]})
    # h13 negative control: branches all schild, but handle_errors proxies without schild (MVP-19: error route -> config error).
    cases["h13-errors-backend"] = (G,
        block(["e.example.org"], allbr + sub("handle_errors", [P])),
        {"resolve": ["e.example.org"], "blocks": [B(["e.example.org"], False, True)]})
    # h14 two unlisted broken blocks and two good ones: both broken dropped.
    cases["h14-two-broken"] = (G,
        block(["x.example.org"], partbr) + block(["a.example.org"], allbr) + block(["y.example.org"], [P]) + block(["b.example.org"], [S, P]),
        {"resolve": ["x.example.org", "a.example.org", "y.example.org", "b.example.org"],
         "blocks": [B(["x.example.org"], False, True), B(["a.example.org"], True, True), B(["y.example.org"], False, True), B(["b.example.org"], True, True)],
         "expect_drop": [0, 2]})
    for name, (glob, caddy, case) in cases.items():
        d = os.path.join(out, name)
        os.makedirs(d, exist_ok=True)
        open(os.path.join(d, "Caddyfile"), "w").write(glob + caddy)
        json.dump(case, open(os.path.join(d, "case.json"), "w"), indent=1)


if __name__ == "__main__":
    main(sys.argv[1])
