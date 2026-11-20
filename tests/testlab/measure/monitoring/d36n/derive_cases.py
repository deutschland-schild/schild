#!/usr/bin/env python3
"""D36 re-measurement after fix round 1 (TEST ONLY): builds the derivation
cases for scratch/zz_d36_derive_test.go (copy of testlab/measure/monitoring/d36, plus the
n-* set).

usage: derive_cases.py <vectors-dir> <out-dir>

Two sets:
  v-*  every ingress-mode website-derive vector (valid and invalid) turned into
       a Caddyfile: a block with schild runs `schild`, a block that proxies runs
       `reverse_proxy`, a block with neither answers with `respond` (redirect /
       static stand-in). The blocks of the vector are the expected input.
  r-*  hand-written real-world Caddyfiles with the measurer's own reading of the
       blocks (schild, proxies) per D36.
  n-*  NEW real-world-style Caddyfiles written for the re-measurement (not in
       client/internal/caddymod/testdata/websites): catch-all :80 redirect,
       redir {host} for several hosts, import snippets, www<->apex, handle_path
       partial protection, same host on two ports, non-canonical IPv6 forms,
       auto_https disable_redirects, php_fastcgi, named routes, env
       placeholders, wildcard redirects. Real ports (80/443), no http_port.
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


GLOBAL_N = "{\n\tadmin off\n}\n\n"


def real_new(out):
    S, P = "schild", f"reverse_proxy {UP}"
    R = "redir https://{host}{uri} permanent"
    cases = {}
    # n01. catch-all :80 redirect to https, two https apps.
    cases["n01-catchall-80-redir"] = (GLOBAL_N,
        block([":80"], [R]) + block(["a.example.org"], [S, P]) + block(["b.example.org"], [S, P]),
        {"resolve": ["a.example.org", "b.example.org", "other.example", "a.example.org:80"],
         "blocks": [B([":80"], False, False), B(["a.example.org"], True, True), B(["b.example.org"], True, True)]})
    # n02. one http block redirects several hosts with {host}, three https apps.
    cases["n02-redir-host-several"] = (GLOBAL_N,
        block(["http://a.example.org", "http://b.example.org", "http://c.example.org"], [R])
        + block(["a.example.org"], [S, P]) + block(["b.example.org"], [S, P]) + block(["c.example.org"], [S, P]),
        {"resolve": ["a.example.org", "b.example.org", "c.example.org"],
         "blocks": [B(["http://a.example.org", "http://b.example.org", "http://c.example.org"], False, False),
                    B(["a.example.org"], True, True), B(["b.example.org"], True, True), B(["c.example.org"], True, True)]})
    # n03. http redirect + https app, both through import snippets.
    cases["n03-import-snippets"] = (GLOBAL_N + "(app) {\n\tschild\n\theader X-Frame-Options DENY\n\t" + P + "\n}\n\n(redirect) {\n\t" + R + "\n}\n\n",
        block(["http://shop.example.org"], ["import redirect"]) + block(["shop.example.org"], ["import app"])
        + block(["http://blog.example.org"], ["import redirect"]) + block(["blog.example.org"], ["import app"]),
        {"resolve": ["shop.example.org", "blog.example.org"],
         "blocks": [B(["http://shop.example.org"], False, False), B(["shop.example.org"], True, True),
                    B(["http://blog.example.org"], False, False), B(["blog.example.org"], True, True)]})
    # n04. www -> apex on http and https, apex app.
    cases["n04-www-to-apex"] = (GLOBAL_N,
        block(["http://www.example.org", "http://example.org"], [R]) + block(["www.example.org"], ["redir https://example.org{uri} permanent"])
        + block(["example.org"], [S, P]),
        {"resolve": ["www.example.org", "example.org"],
         "blocks": [B(["http://www.example.org", "http://example.org"], False, False), B(["www.example.org"], False, False),
                    B(["example.org"], True, True)]})
    # n05. apex -> www, app on www.
    cases["n05-apex-to-www"] = (GLOBAL_N,
        block(["example.org"], ["redir https://www.example.org{uri}"]) + block(["www.example.org"], [S, P]),
        {"resolve": ["example.org", "www.example.org"],
         "blocks": [B(["example.org"], False, False), B(["www.example.org"], True, True)]})
    # n06. handle_path: schild only on /api, the rest proxied without schild (not listed: config error).
    part = ["handle_path /api/* {", "\t" + S, "\t" + P, "}", "handle {", "\t" + P, "}"]
    cases["n06-handle-path-partial"] = (GLOBAL_N,
        block(["part.example.org"], part) + block(["ok.example.org"], [S, P]),
        {"resolve": ["part.example.org", "ok.example.org"],
         "blocks": [B(["part.example.org"], False, True), B(["ok.example.org"], True, True)]})
    # n06b. the same, host listed unprotected.
    cases["n06b-handle-path-partial-listed"] = (GLOBAL_N,
        block(["part.example.org"], part) + block(["ok.example.org"], [S, P]),
        {"unprotected_sites": ["part.example.org"], "resolve": ["part.example.org", "ok.example.org"],
         "blocks": [B(["part.example.org"], False, True), B(["ok.example.org"], True, True)]})
    # n06c. handle_path with schild in every branch (protected).
    cases["n06c-handle-path-all"] = (GLOBAL_N,
        block(["full.example.org"], ["handle_path /api/* {", "\t" + S, "\t" + P, "}", "handle {", "\t" + S, "\t" + P, "}"]),
        {"resolve": ["full.example.org"], "blocks": [B(["full.example.org"], True, True)]})
    # n07. same host on two ports, the second without schild and listed: partial.
    cases["n07-same-host-two-ports-partial"] = (GLOBAL_N,
        block(["app.example.org"], [S, P]) + block(["app.example.org:8443"], [P]),
        {"unprotected_sites": ["app.example.org"], "resolve": ["app.example.org", "app.example.org:8443"],
         "blocks": [B(["app.example.org"], True, True), B(["app.example.org:8443"], False, True)]})
    # n07b. same host on two ports, both with schild.
    cases["n07b-same-host-two-ports"] = (GLOBAL_N,
        block(["app.example.org"], [S, P]) + block(["app.example.org:8443"], [S, P]) + block(["http://app.example.org:8080"], [S, P]),
        {"resolve": ["app.example.org", "app.example.org:8443"],
         "blocks": [B(["app.example.org"], True, True), B(["app.example.org:8443"], True, True), B(["http://app.example.org:8080"], True, True)]})
    # n08. one IPv6 host in four textual forms on four ports.
    cases["n08-ipv6-forms"] = (GLOBAL_N,
        block(["[2001:db8::0:1]"], [S, P]) + block(["[2001:DB8::1]:8443"], [S, P])
        + block(["[2001:0db8:0000:0000:0000:0000:0000:0001]:9443"], [S, P]) + block(["http://[2001:db8:0:0:0:0:0:1]"], [R]),
        {"resolve": ["[2001:db8::1]", "[2001:DB8::1]:443", "[2001:db8:0::1]"],
         "blocks": [B(["[2001:db8::0:1]"], True, True), B(["[2001:DB8::1]:8443"], True, True),
                    B(["[2001:0db8:0000:0000:0000:0000:0000:0001]:9443"], True, True), B(["http://[2001:db8:0:0:0:0:0:1]"], False, False)]})
    # n08b. two IPv6 apps, one non-canonical, plus an http redirect in a third form.
    cases["n08b-ipv6-two-apps"] = (GLOBAL_N,
        block(["[2001:db8::a]"], [S, P]) + block(["[2001:0DB8:0:0:0:0:0:B]"], [S, P]) + block(["http://[2001:db8:0::a]", "http://[2001:db8::b]"], [R]),
        {"resolve": ["[2001:db8::a]", "[2001:db8::b]", "[2001:db8::c]"],
         "blocks": [B(["[2001:db8::a]"], True, True), B(["[2001:0DB8:0:0:0:0:0:B]"], True, True),
                    B(["http://[2001:db8:0::a]", "http://[2001:db8::b]"], False, False)]})
    # n09. several apps behind one explicit redirect block (static, php and proxy apps).
    cases["n09-several-apps-one-redirect"] = (GLOBAL_N,
        block(["http://a.example.org", "http://www.a.example.org", "http://b.example.org", "http://c.example.org"], ["redir https://{host}{uri} 308"])
        + block(["a.example.org", "www.a.example.org"], [S, P]) + block(["b.example.org"], [S, "reverse_proxy 127.0.0.1:19102"])
        + block(["c.example.org"], [S, "root * /srv", "file_server"]),
        {"resolve": ["a.example.org", "www.a.example.org", "b.example.org", "c.example.org"],
         "blocks": [B(["http://a.example.org", "http://www.a.example.org", "http://b.example.org", "http://c.example.org"], False, False),
                    B(["a.example.org", "www.a.example.org"], True, True), B(["b.example.org"], True, True), B(["c.example.org"], True, False)]})
    # n10. auto_https disable_redirects with explicit http redirect block; an http-only app.
    cases["n10-disable-redirects"] = ("{\n\tadmin off\n\tauto_https disable_redirects\n}\n\n",
        block(["http://shop.example.org"], ["redir https://shop.example.org{uri} 301"]) + block(["shop.example.org"], [S, P])
        + block(["http://intranet.example.org"], [S, P]),
        {"resolve": ["shop.example.org", "intranet.example.org"],
         "blocks": [B(["http://shop.example.org"], False, False), B(["shop.example.org"], True, True), B(["http://intranet.example.org"], True, True)]})
    # n11. php_fastcgi app with schild + http redirect; an old php app listed unprotected.
    cases["n11-php-fastcgi"] = (GLOBAL_N,
        block(["http://wp.example.org"], [R]) + block(["wp.example.org"], [S, "root * /var/www/wp", "php_fastcgi unix//run/php/php-fpm.sock", "file_server"])
        + block(["old.example.org"], ["root * /var/www/old", "php_fastcgi 127.0.0.1:9000", "file_server"]),
        {"unprotected_sites": ["old.example.org"], "resolve": ["wp.example.org", "old.example.org"],
         "blocks": [B(["http://wp.example.org"], False, False), B(["wp.example.org"], True, True), B(["old.example.org"], False, True)]})
    # n11b. php_fastcgi without schild and not listed (config error).
    cases["n11b-php-fastcgi-unlisted"] = (GLOBAL_N,
        block(["old.example.org"], ["root * /var/www/old", "php_fastcgi 127.0.0.1:9000"]) + block(["app.example.org"], [S, P]),
        {"resolve": ["old.example.org"], "blocks": [B(["old.example.org"], False, True), B(["app.example.org"], True, True)]})
    # n12. named route invoked by two blocks, http redirect.
    cases["n12-named-route"] = (GLOBAL_N + "&(app) {\n\t" + S + "\n\t" + P + "\n}\n\n",
        block(["http://a.example.org"], [R]) + block(["a.example.org"], ["invoke app"]) + block(["b.example.org"], ["invoke app"]),
        {"resolve": ["a.example.org", "b.example.org"],
         "blocks": [B(["http://a.example.org"], False, False), B(["a.example.org"], True, True), B(["b.example.org"], True, True)]})
    # n13. wildcard redirect + wildcard app + exact app.
    cases["n13-wildcard-redirect"] = (GLOBAL_N,
        block(["http://*.example.org"], [R]) + block(["*.example.org"], ["tls internal", S, P]) + block(["api.example.org"], [S, P]),
        {"resolve": ["foo.example.org", "api.example.org", "example.org"],
         "blocks": [B(["http://*.example.org"], False, False), B(["*.example.org"], True, True), B(["api.example.org"], True, True)]})
    # n14. environment placeholder for the host, upper case in the redirect block.
    cases["n14-env-and-case"] = (GLOBAL_N,
        block(["http://Shop.Example.ORG"], [R]) + block(["{$D36N_HOST:env.example.org}"], [S, P]),
        {"resolve": ["env.example.org", "shop.example.org"],
         "blocks": [B(["http://Shop.Example.ORG"], False, False), B(["env.example.org"], True, True)]})
    # n15. handle blocks, all with schild, plus handle_errors and a redirect for /old.
    cases["n15-handle-all-errors"] = (GLOBAL_N,
        block(["app.example.org"], ["redir /old /new", "handle /api/* {", "\t" + S, "\t" + P, "}", "handle {", "\t" + S, "\t" + P, "}",
                                    "handle_errors {", "\trespond 500", "}"]),
        {"resolve": ["app.example.org"], "blocks": [B(["app.example.org"], True, True)]})
    # n16. bind + tls internal + http redirect, and a static block on its own port.
    cases["n16-bind-tls-internal"] = (GLOBAL_N,
        block(["http://app.example.org"], ["bind 127.0.0.1", R]) + block(["app.example.org"], ["bind 127.0.0.1", "tls internal", S, P])
        + block([":8081"], ["root * /srv/status", "file_server"]),
        {"resolve": ["app.example.org", "status.example"],
         "blocks": [B(["http://app.example.org"], False, False), B(["app.example.org"], True, True), B([":8081"], False, False)]})
    for name, (glob, caddy, case) in cases.items():
        write_case(out, name, glob + caddy, case)


if __name__ == "__main__":
    vdir, out = sys.argv[1], sys.argv[2]
    os.makedirs(out, exist_ok=True)
    vectors(vdir, out)
    real(out)
    real_new(out)
