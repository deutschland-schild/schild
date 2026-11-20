#!/usr/bin/env python3
"""D36 measurement (TEST ONLY): builds the derivation cases for
scratch/zz_d36_derive_test.go.

usage: derive_cases.py <vectors-dir> <out-dir>

Two sets:
  v-*  every ingress-mode website-derive vector (valid and invalid) turned into
       a Caddyfile: a block with schild runs `schild`, a block that proxies runs
       `reverse_proxy`, a block with neither answers with `respond` (redirect /
       static stand-in). The blocks of the vector are the expected input.
  r-*  hand-written real-world Caddyfiles with the measurer's own reading of the
       blocks (schild, proxies) per D36.
"""
import json
import os
import sys

GLOBAL = "{\n\tadmin off\n\thttp_port 19190\n\thttps_port 19143\n}\n\n"
UP = "127.0.0.1:19101"


def body(schild, proxies):
    lines = []
    if schild:
        lines.append("schild")
    if proxies:
        lines.append(f"reverse_proxy {UP}")
    if not lines:
        lines.append('respond "moved" 301')
    return lines


def block(addrs, lines):
    inner = "".join(f"\t{l}\n" for l in lines)
    return f"{', '.join(addrs)} {{\n{inner}}}\n\n"


def write_case(out, name, caddy, case):
    d = os.path.join(out, name)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "Caddyfile"), "w") as f:
        f.write(caddy)
    with open(os.path.join(d, "case.json"), "w") as f:
        json.dump(case, f, indent=1)


def vectors(vdir, out):
    for kind in ("valid", "invalid"):
        p = os.path.join(vdir, "website-derive", kind)
        for fn in sorted(os.listdir(p)):
            v = json.load(open(os.path.join(p, fn)))
            inp = v.get("input_decoded")
            if not isinstance(inp, dict) or inp.get("mode") != "ingress" or not inp.get("blocks"):
                continue
            try:
                caddy = GLOBAL + "".join(block(b["addresses"], body(b["schild"], b["proxies"])) for b in inp["blocks"])
            except (KeyError, TypeError):
                continue
            case = {"unprotected_sites": inp.get("unprotected_sites", []), "resolve": inp.get("resolve", []),
                    "blocks": [{"Addresses": b["addresses"], "Schild": b["schild"], "Proxies": b["proxies"]} for b in inp["blocks"]],
                    "vector": f"{kind}/{fn}", "vector_expect": v["expect"]}
            write_case(out, f"v-{kind[0]}-{fn[:-5]}", caddy, case)


def B(addrs, schild, proxies):
    return {"Addresses": addrs, "Schild": schild, "Proxies": proxies}


def real(out):
    S, P = "schild", f"reverse_proxy {UP}"
    cases = {}
    # 1. several apps on one server, a static and an unprotected block (= main instance).
    cases["r01-several-apps"] = (
        block(["http://shop.test:19190", "http://www.shop.test:19190"], [S, P]) + block(["http://blog.test:19190"], [S, P])
        + block(["http://app.test:19190"], [S, P]) + block(["http://down.test:19190"], [S, "reverse_proxy 127.0.0.1:19103"])
        + block(["http://static.test:19190"], ["root * /tmp", "file_server"]) + block(["http://legacy.test:19190"], [P]),
        {"unprotected_sites": ["legacy.test"], "resolve": ["shop.test", "www.shop.test:19190", "static.test", "legacy.test", "nope.test"],
         "blocks": [B(["http://shop.test:19190", "http://www.shop.test:19190"], True, True), B(["http://blog.test:19190"], True, True),
                    B(["http://app.test:19190"], True, True), B(["http://down.test:19190"], True, True),
                    B(["http://static.test:19190"], False, False), B(["http://legacy.test:19190"], False, True)]})
    # 2. explicit http redirect block + https block of the same host.
    cases["r02-http-redirect-and-https"] = (
        block(["http://shop.example.org"], ["redir https://shop.example.org{uri} 308"]) + block(["shop.example.org"], [S, P]),
        {"resolve": ["shop.example.org"], "blocks": [B(["http://shop.example.org"], False, False), B(["shop.example.org"], True, True)]})
    # 3. the same with the redirect block after the https block.
    cases["r03-https-then-http-redirect"] = (
        block(["shop.example.org"], [S, P]) + block(["http://shop.example.org"], ["redir https://shop.example.org{uri} 308"]),
        {"resolve": ["shop.example.org"], "blocks": [B(["shop.example.org"], True, True), B(["http://shop.example.org"], False, False)]})
    # 4. http and https blocks of one host, both with schild (two blocks, one website).
    cases["r04-http-and-https-both-schild"] = (
        block(["http://example.org"], [S, P]) + block(["https://example.org"], [S, P]) + block(["example.org:8443"], [S, P]),
        {"resolve": ["example.org", "example.org:8443"], "blocks": [B(["http://example.org"], True, True), B(["https://example.org"], True, True),
                                                                   B(["example.org:8443"], True, True)]})
    # 5. www redirect to the apex.
    cases["r05-www-redirect"] = (
        block(["www.example.org"], ["redir https://example.org{uri}"]) + block(["example.org"], [S, P]),
        {"resolve": ["www.example.org", "example.org"], "blocks": [B(["www.example.org"], False, False), B(["example.org"], True, True)]})
    # 6. static blocks (file_server, respond) and a static block with schild.
    cases["r06-static"] = (
        block(["static.example.org"], ["root * /tmp", "file_server"]) + block(["probe.example.org"], ['respond "ok" 200'])
        + block(["docs.example.org"], [S, "root * /tmp", "file_server"]) + block(["app.example.org"], [S, P]),
        {"resolve": ["static.example.org", "docs.example.org", "app.example.org"],
         "blocks": [B(["static.example.org"], False, False), B(["probe.example.org"], False, False), B(["docs.example.org"], True, False),
                    B(["app.example.org"], True, True)]})
    # 7. wildcards and an exact host.
    cases["r07-wildcards"] = (
        block(["*.example.org"], [S, P]) + block(["api.example.org"], [S, P]) + block(["*.kunden.example.org"], [S, P]),
        {"resolve": ["api.example.org", "foo.example.org", "a.kunden.example.org", "a.b.kunden.example.org", "example.org"],
         "blocks": [B(["*.example.org"], True, True), B(["api.example.org"], True, True), B(["*.kunden.example.org"], True, True)]})
    # 8. host-less blocks.
    cases["r08-hostless"] = (
        block([":19190"], [S, P]) + block(["named.example.org"], [S, P]),
        {"resolve": ["anything.example", "named.example.org", "127.0.0.1:19190"],
         "blocks": [B([":19190"], True, True), B(["named.example.org"], True, True)]})
    cases["r08b-hostless-http-scheme"] = (
        block(["http://"], [S, P]),
        {"resolve": ["x.example"], "blocks": [B(["http://"], True, True)]})
    # 9. IDN hosts (Unicode and Punycode written for the same host).
    cases["r09-idn"] = (
        block(["bücher.example"], [S, P]) + block(["xn--bcher-kva.example:8443"], [S, P]) + block(["müller.de", "www.müller.de"], [S, P]),
        {"resolve": ["xn--bcher-kva.example", "bücher.example", "xn--mller-kva.de"],
         "blocks": [B(["bücher.example"], True, True), B(["xn--bcher-kva.example:8443"], True, True), B(["müller.de", "www.müller.de"], True, True)]})
    cases["r09b-idn-uppercase"] = (
        block(["Bücher.example"], [S, P]),
        {"resolve": [], "blocks": [B(["Bücher.example"], True, True)]})
    # 10. shared hosts across blocks (transitive), path blocks.
    cases["r10-shared-hosts"] = (
        block(["a.example.org"], [S, P]) + block(["b.example.org"], [S, P]) + block(["b.example.org:8443", "a.example.org:8443"], [S, P])
        + block(["c.example.org/api/*"], [S, P]) + block(["c.example.org"], [S, P]),
        {"resolve": ["a.example.org", "b.example.org", "c.example.org"],
         "blocks": [B(["a.example.org"], True, True), B(["b.example.org"], True, True), B(["b.example.org:8443", "a.example.org:8443"], True, True),
                    B(["c.example.org/api/*"], True, True), B(["c.example.org"], True, True)]})
    # 11. unprotected, partial, wildcard listing.
    cases["r11-unprotected-partial"] = (
        block(["legacy.example.org"], [P]) + block(["mixed.example.org"], [S, P]) + block(["http://mixed.example.org"], [P])
        + block(["old.legacy.example.org"], [P]) + block(["new.example.org"], [S, P]),
        {"unprotected_sites": ["legacy.example.org", "mixed.example.org", "*.legacy.example.org"],
         "resolve": ["legacy.example.org", "mixed.example.org", "old.legacy.example.org", "new.example.org"],
         "blocks": [B(["legacy.example.org"], False, True), B(["mixed.example.org"], True, True), B(["http://mixed.example.org"], False, True),
                    B(["old.legacy.example.org"], False, True), B(["new.example.org"], True, True)]})
    # 12. schild only on a part of a block (config error per MVP-19).
    cases["r12-partial-handle"] = (
        block(["part.example.org"], ["handle /api/* {", "\tschild", f"\t{P}", "}", "handle {", f"\t{P}", "}"]),
        {"resolve": [], "blocks": [B(["part.example.org"], False, True)]})
    # 13. IP literals.
    cases["r13-ip-literals"] = (
        block(["127.0.0.1"], [S, P]) + block(["[::1]"], [S, P]) + block(["[2001:DB8:0:0::1]:8443"], [S, P]),
        {"resolve": ["127.0.0.1", "[::1]:443", "[2001:db8::1]"],
         "blocks": [B(["127.0.0.1"], True, True), B(["[::1]"], True, True), B(["[2001:DB8:0:0::1]:8443"], True, True)]})
    # 14. probe/health block on its own port next to the apps.
    cases["r14-probe-port"] = (
        block([":19198"], ['respond /healthz "ok" 200']) + block(["app.example.org"], [S, P]),
        {"resolve": ["app.example.org", "other.example"], "blocks": [B([":19198"], False, False), B(["app.example.org"], True, True)]})
    # 15. snippet import, trailing dot and case in the Caddyfile.
    cases["r15-snippet-case-dot"] = (
        "(prot) {\n\tschild\n}\n\n" + block(["Shop.Example.ORG."], ["import prot", P]) + block(["shop.example.org:8443"], ["import prot", P]),
        {"resolve": ["shop.example.org", "SHOP.example.org:8443"],
         "blocks": [B(["Shop.Example.ORG."], True, True), B(["shop.example.org:8443"], True, True)]})
    # 16. redirect block that shares the host of an https block, with schild on https and an http redirect for www.
    cases["r16-redirect-shared-www"] = (
        block(["http://example.org", "http://www.example.org"], ["redir https://example.org{uri}"]) + block(["example.org", "www.example.org"], [S, P]),
        {"resolve": ["example.org", "www.example.org"],
         "blocks": [B(["http://example.org", "http://www.example.org"], False, False), B(["example.org", "www.example.org"], True, True)]})
    # 17. earliest block names the website (Caddy-valid variant of vector 005: other port).
    cases["r17-earliest-block-names"] = (
        block(["www.example.org"], [S, P]) + block(["example.org", "www.example.org:8443"], [S, P]),
        {"resolve": ["example.org", "www.example.org"],
         "blocks": [B(["www.example.org"], True, True), B(["example.org", "www.example.org:8443"], True, True)]})
    # 15b. trailing dot and case on plain http (Caddy refuses a trailing dot for automatic HTTPS).
    cases["r15b-case-dot-http"] = (
        block(["http://Shop.Example.ORG."], [S, P]) + block(["http://shop.example.org:8080"], [S, P]),
        {"resolve": ["shop.example.org", "SHOP.example.org:8080", "shop.example.org."],
         "blocks": [B(["http://Shop.Example.ORG."], True, True), B(["http://shop.example.org:8080"], True, True)]})
    # 9c. upper-case non-ASCII letter (the contract refuses it).
    cases["r09c-idn-nonascii-uppercase"] = (
        block(["bÜcher.example"], [S, P]),
        {"resolve": [], "blocks": [B(["bÜcher.example"], True, True)]})
    # 18. IPv6 literal in canonical form with a port (compare r13).
    cases["r18-ipv6-canonical"] = (
        block(["[2001:db8::1]:8443"], [S, P]),
        {"resolve": ["[2001:db8::1]"], "blocks": [B(["[2001:db8::1]:8443"], True, True)]})
    for name, (caddy, case) in cases.items():
        write_case(out, name, GLOBAL + caddy, case)


if __name__ == "__main__":
    vdir, out = sys.argv[1], sys.argv[2]
    os.makedirs(out, exist_ok=True)
    vectors(vdir, out)
    real(out)
