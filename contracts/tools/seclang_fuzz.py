#!/usr/bin/env python3
"""Differential fuzz corpus for the SecLang subset.

Generates random @rx patterns and mutated rules from the golden SecLang
vectors, judges each with the Python validator of crosscheck.py and writes
a JSON corpus. The Go test contract/seclang TestDifferential reads it and
fails on any disagreement (make contracts-fuzz).

    python3 -I seclang_fuzz.py --contracts .. --seed 42 --n 100000 --out corpus.json
"""

import argparse
import glob
import importlib.util
import json
import os
import random
import warnings

ATOMS = ["a", "b", ".", "\\d", "\\w", "\\s", "\\S", "\\.", "\\-", "\\/", "\\b", "\\B", "[a-z]", "[^0-9]", "[\\]a]",
         "[a\\-z]", "(", ")", "(?:", "(?i:", "(?s:", "|", "*", "+", "?", "*?", "+?", "??", "{2}", "{1,3}", "{2,}",
         "{0}", "^", "$", "\\x41", "\\x4", "[", "-", "]", "{", "}", "\\n", "\\t", "x{", "(?i)", "\\(", ")*", "[.]",
         "[$]", "\\$", "\\^", "a{3,2}", "[z-a]", "\\[", "()", "(|a)", "a**", "a{1000}", "a{1001}", "\\0", "\\f",
         "\\v", "\\r", "[^]a]", "[]a]", "[a-]", "[-a]", "[\\d-z]", "[a-\\d]", "[\\w.-]", "\\]", "\\{", "\\}",
         "{,2}", "{2,1}", "(?is)", "(?si:", "\\*", "[\\b]", "[|]", "[(]", "[^-a]", "[a-\\x41]", "[\\x41-z]",
         "[\\s\\S]", "[^\\d]", "\\-+", "\\u0041", "\\z", "\\pL", "(?=", "\\1", "[[:alpha:]]",
         "(a+)", "(?:ab)", "(a|b)", ")+", "){2,}", "){0,1}", "a{600}", "{1}", "{0,1}", "(?:a?)", "%{", " ",
         "select", "union", "<script", "\\.\\./", "/", "GET", "Mozilla", "HTTP", "q=", "*?", "+?", "{2,3}?",
         "(?i:ab)", "\\x22", "\\x2f", "[A-Z]", "[^a-z]", "\\bwp\\b", "php$", "^/wp-", "[0-9]+$"]
TOKENS = ["(?i)", "\\d", "[a-z]", "{2,5}", "{,3}", "*", "+", "?", "|", "(", ")", ".", "^", "$", "%{", "ARGS:x",
          "REQUEST_HEADERS:Host", "@rx ", "@pm ", "!@", "&ARGS", "chain", "ctl:x", "setvar:tx.a=+1", "'", '"',
          '\\"', ",", "\n", "t:none", "id:7700001", "phase:2", "deny", "pass", " ", "REMOTE_ADDR", "@ipMatch ",
          "@within ", "  ", "@pm a  b", "REQUEST_HEADERS:Referer", "REQUEST_HEADERS:Origin", "t:length", "@streq GET",
          "@beginsWith /", "%{REMOTE_ADDR}", "\\\\", "msg:'a,b'", "&REQUEST_HEADERS", "@detectSQLi", "!@rx a",
          "@gt 1", "(a+)+", "(?:a|b)*", "x{600}y{600}", "REQUEST_HEADERS:X-Client-IP", "@rx  "]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--contracts", default=os.path.join(os.path.dirname(__file__), ".."))
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--n", type=int, default=100000)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    warnings.simplefilter("ignore")
    spec = importlib.util.spec_from_file_location("crosscheck", os.path.join(a.contracts, "tools", "crosscheck.py"))
    cc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cc)
    rnd = random.Random(a.seed)
    seeds = []
    for f in sorted(glob.glob(os.path.join(a.contracts, "vectors", "seclang", "*", "*.json"))):
        with open(f, encoding="utf-8") as fh:
            v = json.load(fh)
        seeds.append((v["input_raw"], v["context"].get("max_action", "")))
    out = []
    for i in range(a.n):
        if i % 2 == 0:
            p = "".join(rnd.choice(ATOMS) for _ in range(rnd.randint(1, 14)))
            text = 'SecRule ARGS "@rx ' + p.replace('"', '\\x22') + '" "id:7700001,phase:2,deny,severity:CRITICAL,msg:\'x\'"'
            ma = "block"
        else:
            t, ma = rnd.choice(seeds)
            t = list(t)
            for _ in range(rnd.randint(1, 3)):
                pos = rnd.randint(0, len(t))
                r = rnd.random()
                if r < 0.4:
                    t[pos:pos] = list(rnd.choice(TOKENS))
                elif r < 0.7 and t:
                    del t[min(pos, len(t) - 1)]
                elif t:
                    t[min(pos, len(t) - 1)] = rnd.choice("ab.*+?()[]{}\\|^$ ,:'\"")
            text = "".join(t)
        try:
            cc.seclang_validate(text, ma)
            verdict = "valid"
        except cc.Reject as e:
            verdict = e.code
        out.append({"text": text, "max_action": ma, "py": verdict})
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(out, f)
    print("seclang_fuzz: %d rules, %d valid (seed %d)" % (len(out), sum(o["py"] == "valid" for o in out), a.seed))


if __name__ == "__main__":
    main()
