#!/usr/bin/env python3
"""Independent second implementation of the Schild v0 contract checks.

Runs every golden vector in contracts/vectors with Python only: strict JSON
parsing, JSON Schema (python-jsonschema, a different implementation than the
Go side), DSSE PAE, Ed25519 verification (pure Python, RFC 8032 reference
arithmetic, no crypto library), threshold, rollback and expiry rules, and
the SecLang subset validator.

It compares its verdicts with the expectation in each vector and, with
--go, with the verdicts of the Go reference implementation. Any difference
fails (MVP-01 kill criterion: a vector validates differently in the two
implementations).

Run with `python3 -I` (isolated mode). Only dependency: jsonschema >= 4.18.
"""

import argparse
import base64
import calendar
import functools
import glob
import hashlib
import ipaddress
import json
import os
import re
import sys
import time
import unicodedata

try:
    import jsonschema
    import referencing
    import referencing.jsonschema
except ImportError:  # pragma: no cover
    print("crosscheck: python package jsonschema (>= 4.18) is required", file=sys.stderr)
    sys.exit(2)

# ---------------------------------------------------------------- constants

MAX_CLOCK_SKEW = 120
MAX_SIGNAL_AGE = 24 * 3600
MAX_ACK_AGE = 300
MAX_CHECKPOINT_VALIDITY = 600
MAX_BUNDLE_VALIDITY = 31 * 24 * 3600
MAX_CHALLENGE_WINDOW = 7 * 24 * 3600
FLOOR = 2
DEFAULT_K = 3
MAX_DEPTH = 32
REMOTE_ID_MIN, REMOTE_ID_MAX = 7700000, 7799999
MAX_SECLANG = 8192

LIMITS = {  # kind: (max envelope bytes, max payload bytes)
    "signal": (16384, 4096),
    "feedback": (16384, 4096),
    "ack": (65536, 49152),
    "checkpoint": (16384, 4096),
    "withdrawal": (65536, 32768),
    "rule-bundle": (1048576, 786432),
    "agent-report": (786432, 524288),  # v0.3 (host-check.md)
}
PURPOSE = {
    "signal": "signal", "feedback": "feedback", "ack": "ack",
    "checkpoint": "checkpoint", "rule-bundle": "rules", "withdrawal": "rules",
    "agent-report": "agent",
}
THRESHOLD_KINDS = ("rule-bundle", "withdrawal")
DOC_LIMITS = {
    "submission": 1 << 20, "stream": 64 << 10, "events": 64 << 10,
    "config/schild": 1 << 20, "config/lab": 1 << 20, "results": 4 << 20,
    "log-tree": 4 << 20, "peer-request": 16 << 10,  # v0.1 (cosign.md)
    "host-report": 512 << 10, "agent-ack": 4 << 10,  # v0.3 (host-check.md)
    "bot-catalogue": 4 << 20,  # v0.5 (MVP-22, D35)
    "crowdsec-set": 8 << 20,  # v0.5 (D39)
}
# v0.5 (MVP-22, D35): classifier vectors with an expected result.
RESULT_LIMITS = {"bot-match": 4 << 20, "geo-map": 64 << 10,
                 "website-derive": 1 << 20, "website-status": 1 << 20, "website-exception": 1 << 20,  # v0.5 (D36)
                 "website-visitor": 1 << 20,  # D36 amendment 2026-10-29
                 "waiting-page": 64 << 10,  # D37 (MVP-23 step 1)
                 "body-limits": 64 << 10, "agent-block": 64 << 10,  # D41, D42
                 "storage-bounds": 1 << 20,  # D38
                 "ingress-order": 1 << 20,  # D31 amendment 2026-10-29
                 "request-recheck": 64 << 10,  # D33 amendment 2026-10-29
                 "crowdsec-hub": 1 << 20,  # D39 (MVP-26)
                 "rule-effect": 4 << 10,  # D73
                 "access-gate": 64 << 10,  # D56 (MVP-14 step 1)
                 "crawler-policy": 4 << 20,  # D57 (MVP-29)
                 "human-check": 64 << 10,  # MVP-12 v1_cut
                 "audit": 1 << 20,  # draft, MVP-36
                 "cluster-record": 4 << 20}  # D105 (MVP-27)
FORBIDDEN_FIELDS = [
    "ip", "ips", "ip_address", "ip_prefix", "ip_hash", "ip_pseudonym", "oprf", "client_ip", "remote_addr", "remote_ip",
    "remote_host", "src_ip", "source_ip", "client_address", "address", "addr", "ipv4", "ipv6", "peer", "peer_ip",
    "x_forwarded_for", "x_real_ip", "true_client_ip", "cf_connecting_ip", "forwarded",
    "user_agent", "ua", "url", "uri", "query", "query_string", "path", "headers", "header", "cookies", "cookie", "body",
    "request_body", "referer", "referrer", "host", "hostname", "site", "site_id", "site_key", "domain", "server_name",
    "tenant", "account", "customer", "email", "user", "username", "login", "password", "phone", "session_id", "client",
    "client_id", "keyid", "key_id", "city", "latitude", "longitude", "auth", "token", "presentation",
]


def normalize_field(k):
    """ASCII lower case without '-', '_' and '.' (no Unicode case folding)."""
    out = []
    for ch in k:
        if ch in "-_.":
            continue
        if "A" <= ch <= "Z":
            ch = chr(ord(ch) + 32)
        out.append(ch)
    return "".join(out)


FORBIDDEN = {normalize_field(f) for f in FORBIDDEN_FIELDS}
SINGLE_SIGNER_KINDS = ("signal", "feedback", "agent-report")


def payload_type(kind):
    return "application/vnd.schild." + kind + ".v0+json"


class Reject(Exception):
    def __init__(self, code, msg=""):
        super().__init__(code + ": " + msg)
        self.code = code


# ---------------------------------------------------------------- strict JSON


def _no_dupes(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate key " + k)
        out[k] = v
    return out


def _reject_constant(name):
    raise ValueError("constant " + name)


def _walk_check(v, depth=0):
    if isinstance(v, (dict, list)):
        if depth + 1 > MAX_DEPTH:
            raise ValueError("too deep")
        items = v.values() if isinstance(v, dict) else v
        if isinstance(v, dict):
            for k in v:
                _check_str(k)
        for x in items:
            _walk_check(x, depth + 1)
    elif isinstance(v, str):
        _check_str(v)
    elif isinstance(v, float):
        if v != v or v in (float("inf"), float("-inf")):
            raise ValueError("number out of range")


def _check_str(s):
    for ch in s:
        if 0xD800 <= ord(ch) <= 0xDFFF:
            raise ValueError("lone surrogate")


def strict_parse(raw):
    try:
        text = raw.decode("utf-8")
        if text.startswith(chr(0xFEFF)):
            raise ValueError("bom")
        v = json.loads(text, object_pairs_hook=_no_dupes, parse_constant=_reject_constant)
        _walk_check(v)
        return v
    except (ValueError, RecursionError, UnicodeDecodeError) as e:
        raise Reject("malformed", str(e))


def strict_object(raw):
    v = strict_parse(raw)
    if not isinstance(v, dict):
        raise Reject("malformed", "top level is not an object")
    return v


# ---------------------------------------------------------------- JSON Schema

BASE = "https://contracts.schild.invalid/v0/"


def ecma_pattern(p):
    """Translate an ECMA-262 pattern to Python re: `$` (outside classes,
    unescaped) means end of input, i.e. \\Z. Python's `$` would also match
    before a trailing newline."""
    out, i, in_class = [], 0, False
    while i < len(p):
        c = p[i]
        if c == "\\" and i + 1 < len(p):
            out.append(p[i:i + 2])
            i += 2
            continue
        if in_class:
            if c == "]":
                in_class = False
        elif c == "[":
            in_class = True
        elif c == "$":
            out.append(r"\Z")
            i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


_pattern_cache = {}


def _pattern(validator, patrn, instance, schema):
    if not validator.is_type(instance, "string"):
        return
    rx = _pattern_cache.get(patrn)
    if rx is None:
        rx = _pattern_cache[patrn] = re.compile(ecma_pattern(patrn))
    if not rx.search(instance):
        yield jsonschema.ValidationError("%r does not match %r" % (instance, patrn))


ECMAValidator = jsonschema.validators.extend(jsonschema.Draft202012Validator, {"pattern": _pattern})


class Schemas:
    def __init__(self, root):
        resources, self.docs = [], {}
        # Exactly the files Go embeds: top-level and config/ schemas.
        paths = sorted(glob.glob(os.path.join(root, "*.schema.json")) + glob.glob(os.path.join(root, "config", "*.schema.json")))
        for path in paths:
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            with open(path, "rb") as fh:
                doc = json.loads(fh.read().decode("utf-8"))
            if doc.get("$id") != BASE + rel:
                raise SystemExit("schema %s has $id %s" % (rel, doc.get("$id")))
            self.docs[rel[: -len(".schema.json")]] = doc
            resources.append((doc["$id"], referencing.Resource.from_contents(doc, referencing.jsonschema.DRAFT202012)))
        self.registry = referencing.Registry().with_resources(resources)
        self.validators = {}
        for name, doc in self.docs.items():
            ECMAValidator.check_schema(doc)
            self.validators[name] = ECMAValidator(doc, registry=self.registry)

    def validate(self, name, value, code="schema"):
        err = jsonschema.exceptions.best_match(self.validators[name].iter_errors(value))
        if err is not None:
            raise Reject(code, "%s: %s" % (name, err.message[:300]))


# ---------------------------------------------------------------- Ed25519 (RFC 8032, verification only)

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)


def _add(Pt, Qt):
    X1, Y1, Z1, T1 = Pt
    X2, Y2, Z2, T2 = Qt
    A = (Y1 - X1) * (Y2 - X2) % P
    B = (Y1 + X1) * (Y2 + X2) % P
    C = T1 * 2 * D * T2 % P
    Dd = Z1 * 2 * Z2 % P
    E, F, G, H = B - A, Dd - C, Dd + C, B + A
    return (E * F % P, G * H % P, F * G % P, E * H % P)


def _mul(s, Pt):
    Q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            Q = _add(Q, Pt)
        Pt = _add(Pt, Pt)
        s >>= 1
    return Q


def _equal(Pt, Qt):
    X1, Y1, Z1, _ = Pt
    X2, Y2, Z2, _ = Qt
    return (X1 * Z2 - X2 * Z1) % P == 0 and (Y1 * Z2 - Y2 * Z1) % P == 0


def _recover_x(y, sign):
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(D * y * y + 1, P - 2, P)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


_GY = 4 * pow(5, P - 2, P) % P
_GX = _recover_x(_GY, 0)
G = (_GX, _GY, 1, _GX * _GY % P)


def _decompress(s):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


def _compress(Pt):
    X, Y, Z, _ = Pt
    zi = pow(Z, P - 2, P)
    x, y = X * zi % P, Y * zi % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def ed25519_public_from_seed(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return _compress(_mul(a, G))


def ed25519_verify(public, msg, sig):
    if len(public) != 32 or len(sig) != 64:
        return False
    A = _decompress(public)
    R = _decompress(sig[:32])
    if A is None or R is None:
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= L:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + public + msg).digest(), "little") % L
    return _equal(_mul(s, G), _add(R, _mul(h, A)))


# ---------------------------------------------------------------- DSSE


def pae(ptype, payload):
    t = ptype.encode("utf-8")
    return b"DSSEv1 " + str(len(t)).encode() + b" " + t + b" " + str(len(payload)).encode() + b" " + payload


def b64_canonical(s):
    try:
        b = base64.b64decode(s, validate=True)
    except Exception:
        raise Reject("envelope", "invalid base64")
    if base64.b64encode(b).decode("ascii") != s:
        raise Reject("envelope", "non-canonical base64")
    return b


# ---------------------------------------------------------------- time


def parse_time(s, field):
    try:
        return calendar.timegm(time.strptime(s, "%Y-%m-%dT%H:%M:%SZ"))
    except (ValueError, TypeError):
        raise Reject("schema", field + ": invalid time")


# ---------------------------------------------------------------- context


class Ctx:
    def __init__(self, c, keys):
        self.now = parse_time(c.get("now") or "2026-10-26T12:00:00Z", "now")
        self.trust = {}
        for name in c.get("trust", []):
            k = keys[name]
            self.trust[k["keyid"]] = k
        self.threshold = c.get("threshold", 0)
        self.channel = c.get("channel", "")
        self.seen = set(c.get("seen_ids", []))
        self.in_reply_to = c.get("expected_in_reply_to", "")
        st = c.get("state") or {}
        self.bundle_version = st.get("bundle_version", 0)
        self.bundle_digest = st.get("bundle_digest", "")
        self.withdrawal_seq = st.get("withdrawal_seq", 0)
        self.withdrawal_digest = st.get("withdrawal_digest", "")
        self.cp_seq = st.get("checkpoint_seq", {})
        self.cp_digest = st.get("checkpoint_digest", {})
        self.sim = c.get("simulated_operators", {})
        self.max_action = c.get("max_action", "")
        self.skip_state = False
        # v0.3: revoked agent keys (by key name) and the expected gateway.
        self.revoked = {keys[n]["keyid"] for n in c.get("revoked", [])}
        self.gateway = c.get("gateway", "")

    def k(self):
        k = self.threshold or DEFAULT_K
        return max(k, FLOOR)

    def operator(self, key):
        return self.sim.get(key.get("lab", ""), key.get("operator", ""))


def digest(b):
    return "sha256:" + hashlib.sha256(b).hexdigest()


# ---------------------------------------------------------------- signed messages


class Checker:
    def __init__(self, schemas):
        self.s = schemas

    def signed(self, kind, raw, ctx):
        if len(raw) > LIMITS[kind][0]:
            raise Reject("oversize", "envelope")
        return self.signed_value(kind, strict_object(raw), ctx)

    def signed_value(self, kind, env, ctx):
        self.s.validate("envelope", env, code="envelope")
        payload = b64_canonical(env["payload"])
        sigs = [b64_canonical(x["sig"]) for x in env["signatures"]]
        if kind in SINGLE_SIGNER_KINDS and len(sigs) != 1:
            raise Reject("envelope", "exactly one signature")
        if len(payload) > LIMITS[kind][1]:
            raise Reject("oversize", "payload")
        if env["payloadType"] != payload_type(kind):
            raise Reject("payload_type", env["payloadType"])
        msg = pae(env["payloadType"], payload)
        signers, operators, seen, revoked = [], [], set(), False
        for i, s in enumerate(env["signatures"]):
            kid = s["keyid"]
            if kid in seen:
                continue
            key = ctx.trust.get(kid)
            if key is None or PURPOSE[kind] not in key["purposes"]:
                continue
            if not ed25519_verify(key["pub"], msg, sigs[i]):
                continue
            if kid in ctx.revoked:
                revoked = True
                continue
            seen.add(kid)
            signers.append(key)
            op = ctx.operator(key)
            if op and op not in operators:
                operators.append(op)
        if kind in THRESHOLD_KINDS:
            if len(operators) < ctx.k():
                raise Reject("threshold", "%d < %d" % (len(operators), ctx.k()))
        elif not signers:
            if revoked:
                raise Reject("revoked", "only a revoked key signed")
            raise Reject("signature", "no trusted signature")
        pv = strict_object(payload)
        if kind in ("signal", "feedback"):
            check_forbidden(pv)
        if kind == "agent-report":
            host_forbidden(pv)
        self.s.validate(kind, pv)
        getattr(self, "sem_" + kind.replace("-", "_"))(pv, signers, digest(payload), ctx)

    @staticmethod
    def issued(ctx, at):
        if at > ctx.now + MAX_CLOCK_SKEW:
            raise Reject("clock_skew", "future")

    def bucket(self, pv, ctx):
        t = parse_time(pv["time_bucket"], "time_bucket")
        if t > ctx.now + MAX_CLOCK_SKEW:
            raise Reject("clock_skew", "time_bucket")
        if t + MAX_SIGNAL_AGE < ctx.now:
            raise Reject("expired", "time_bucket")
        if pv["id"] in ctx.seen:
            raise Reject("replay", pv["id"])

    def sem_signal(self, pv, signers, dg, ctx):
        rules = pv["waf_rules"]
        if any(rules[i] <= rules[i - 1] for i in range(1, len(rules))):
            raise Reject("schema", "waf_rules not strictly ascending")
        self.bucket(pv, ctx)

    def sem_feedback(self, pv, signers, dg, ctx):
        self.bucket(pv, ctx)

    def sem_ack(self, pv, signers, dg, ctx):
        if not any(k.get("lab") == pv["lab"] for k in signers):
            raise Reject("signature", "lab binding")
        at = parse_time(pv["issued_at"], "issued_at")
        self.issued(ctx, at)
        if at + MAX_ACK_AGE < ctx.now:
            raise Reject("expired", "ack")
        if ctx.in_reply_to and pv["in_reply_to"] != ctx.in_reply_to:
            raise Reject("replay", "in_reply_to")

    def sem_checkpoint(self, pv, signers, dg, ctx):
        if not any(k.get("lab") == pv["lab"] for k in signers):
            raise Reject("signature", "lab binding")
        at = parse_time(pv["issued_at"], "issued_at")
        exp = parse_time(pv["expires"], "expires")
        self.issued(ctx, at)
        if exp <= ctx.now:
            raise Reject("expired", "checkpoint")
        if exp <= at or exp - at > MAX_CHECKPOINT_VALIDITY:
            raise Reject("validity", "checkpoint")
        if ctx.skip_state:
            return
        last = ctx.cp_seq.get(pv["lab"], 0)
        if pv["seq"] < last:
            raise Reject("rollback", "checkpoint")
        if pv["seq"] == last and last > 0 and ctx.cp_digest.get(pv["lab"], "") != dg:
            raise Reject("equivocation", "checkpoint")

    def sem_rule_bundle(self, pv, signers, dg, ctx):
        at = parse_time(pv["issued_at"], "issued_at")
        exp = parse_time(pv["expires"], "expires")
        self.issued(ctx, at)
        if exp <= ctx.now:
            raise Reject("expired", "bundle")
        if exp <= at or exp - at > MAX_BUNDLE_VALIDITY:
            raise Reject("validity", "bundle")
        if ctx.channel and pv["bundle_id"] != ctx.channel:
            raise Reject("channel", pv["bundle_id"])
        if not ctx.skip_state:
            if pv["version"] < ctx.bundle_version:
                raise Reject("rollback", "bundle")
            if pv["version"] == ctx.bundle_version and ctx.bundle_digest != dg:
                raise Reject("equivocation", "bundle")
        rule_ids, sec_ids = set(), set()
        for r in pv["rules"]:
            sec_id = seclang_validate(r["seclang"], r["max_action"])
            level = evidence_level(r["class"], r["evidence"])
            if RANK.get(r["max_action"], 0) > RANK.get(level, 0):
                raise Reject("evidence", r["rule_id"])
            if "max_action_until" in r:
                until = parse_time(r["max_action_until"], "max_action_until")
                if until <= at or until > exp:
                    raise Reject("validity", "max_action_until")
                if r["max_action"] == "challenge" and until - at > MAX_CHALLENGE_WINDOW:
                    raise Reject("validity", "challenge window")
            if r["rule_id"] in rule_ids or sec_id in sec_ids:
                raise Reject("duplicate_rule", r["rule_id"])
            rule_ids.add(r["rule_id"])
            sec_ids.add(sec_id)

    def sem_withdrawal(self, pv, signers, dg, ctx):
        at = parse_time(pv["issued_at"], "issued_at")
        self.issued(ctx, at)
        if ctx.channel and pv["bundle_id"] != ctx.channel:
            raise Reject("channel", pv["bundle_id"])
        if ctx.skip_state:
            return
        if pv["seq"] < ctx.withdrawal_seq:
            raise Reject("rollback", "withdrawal")
        if pv["seq"] == ctx.withdrawal_seq and ctx.withdrawal_digest != dg:
            raise Reject("equivocation", "withdrawal")

    def sem_agent_report(self, pv, signers, dg, ctx):
        host_report_check(pv["report"])
        if pv["report"]["host"]["agent_key_id"] != signers[0]["keyid"]:
            raise Reject("signature", "report names another agent key")
        agent_message(ctx, pv)

    def enrolment(self, raw, ctx):
        """v0.3 enrolment request: self-signed by the key it enrols."""
        if len(raw) > 16 << 10:
            raise Reject("oversize", "enrolment envelope")
        env = strict_object(raw)
        self.s.validate("envelope", env, code="envelope")
        payload = b64_canonical(env["payload"])
        sigs = [b64_canonical(x["sig"]) for x in env["signatures"]]
        if len(sigs) != 1:
            raise Reject("envelope", "exactly one signature")
        if len(payload) > 4 << 10:
            raise Reject("oversize", "enrolment payload")
        if env["payloadType"] != ENROLMENT_PAYLOAD_TYPE:
            raise Reject("payload_type", env["payloadType"])
        pv = strict_object(payload)
        host_forbidden(pv)
        self.s.validate("agent-enrolment", pv)
        pub = base64.b64decode(pv["public_key"][len("ed25519:"):])
        if env["signatures"][0]["keyid"] != pv["keyid"] or not ed25519_verify(pub, pae(env["payloadType"], payload), sigs[0]):
            raise Reject("signature", "not signed by the enrolled key")
        agent_message(ctx, pv)

    # ------------------------------------------------------------ documents

    def document(self, name, raw, ctx):
        if len(raw) > DOC_LIMITS[name]:
            raise Reject("oversize", name)
        v = strict_object(raw)
        if name == "host-report":
            host_forbidden(v)
        self.s.validate(name, v)
        if name == "host-report":
            host_report_check(v)
        elif name == "stream":
            self.stream(v, ctx)
        elif name == "config/schild":
            site_config(v)
        elif name == "config/lab":
            lab_config(v)
        elif name == "results":
            if parse_time(v["finished_at"], "finished_at") < parse_time(v["started_at"], "started_at"):
                raise Reject("schema", "finished before started")
        elif name == "log-tree":
            log_tree_check(v)
        elif name == "peer-request":
            peer_request_check(v, ctx)
        elif name == "bot-catalogue":
            bot_catalogue_check(v)
        elif name == "crowdsec-set":
            hub_set_check(v)

    def stream(self, v, ctx):
        typ = v["type"]
        env = v.get("checkpoint" if typ == "schild.dist.heartbeat.v1" else "envelope")
        if not isinstance(env, dict):
            return
        kind = {"schild.dist.checkpoint.v1": "checkpoint", "schild.dist.heartbeat.v1": "checkpoint",
                "schild.dist.bundle.v1": "rule-bundle", "schild.dist.withdrawal.v1": "withdrawal"}[typ]
        if env.get("payloadType") != payload_type(kind):
            raise Reject("payload_type", typ)
        ctx.skip_state = True
        self.signed_value(kind, env, ctx)


def check_forbidden(v):
    if isinstance(v, dict):
        for k, x in v.items():
            if normalize_field(k) in FORBIDDEN:
                raise Reject("forbidden_field", k)
            check_forbidden(x)
    elif isinstance(v, list):
        for x in v:
            check_forbidden(x)


RANK = {"observe": 1, "challenge": 2, "block": 3}


def evidence_level(cls, e):
    if cls == "virtual_patch" and e["reproduced_operators"] >= 2 and e["human_approval_orgs"] >= 2:
        return "block"
    if e["reproduced_operators"] >= 1 or e["sensor_operators"] >= 2:
        return "challenge"
    if e["sensor_operators"] >= 1 or (e["tip_issuers"] >= 3 and e["max_issuer_share"] <= 0.34):
        return "observe"
    return ""


def _dup(seen, what, x):
    if x in seen:
        raise Reject("config", "duplicate %s %s" % (what, x))
    seen.add(x)


def site_config(v):
    keyids, pubs = set(), set()
    agents = v.get("host_check", {}).get("agents", {})
    for k in agents.get("keys", []):  # v0.3
        _dup(keyids, "keyid", k["keyid"])
        _dup(pubs, "public key", k["public_key"])
    resp = v.get("behaviour", {}).get("distributed", {}).get("responses", {})  # v0.4 MVP-18
    for obj, lo, hi, dlo, dhi in (("route_tighten", "minutes", "max_minutes", 20, 120), ("account_slowdown", "start_s", "max_s", 5, 60)):
        m = resp.get(obj, {})
        if m.get(lo, dlo) > m.get(hi, dhi):
            raise Reject("config", "%s.%s above %s" % (obj, lo, hi))
    lids = set()
    for lim in v.get("behaviour", {}).get("rate_limits", []):  # v0.4: explicit rate limit ids are unique
        if "id" in lim:
            _dup(lids, "rate limit id", lim["id"])
    keep = v.get("monitoring", {}).get("keep", {})  # v0.4 MVP-21: coarse never shorter than fine
    ten, minute, days = keep.get("ten_seconds_hours", 6), keep.get("minute_hours", 48), keep.get("ten_minute_days", 14)
    if ten > minute or minute > days * 24:
        raise Reject("config", "monitoring.keep order")
    mon = v.get("monitoring", {})  # v0.5 MVP-22: the request ring needs the monitoring counters
    if mon.get("requests", {}).get("enabled") is True and mon.get("enabled") is False:
        raise Reject("config", "monitoring.requests without monitoring")
    waf = v.get("waf", {})  # D41: the body limits nest; one body of the largest size fits the byte limit
    body = waf.get("body", {})
    per_client, per_net = body.get("max_per_client", 8), body.get("max_per_network", 32)
    if per_client > per_net or ("max_in_flight" in body and per_net > body["max_in_flight"]):
        raise Reject("config", "waf.body limits do not nest")
    if body.get("max_in_flight_bytes", 4 << 30) < 2 * waf.get("request_body_limit_bytes", 13107200):
        raise Reject("config", "waf.body.max_in_flight_bytes below twice the body limit")
    wait_client, wait_net = body.get("max_waiting_bytes_per_client", 64 << 20), body.get("max_waiting_bytes_per_network", 256 << 20)
    if wait_client > wait_net or ("max_waiting_bytes" in body and wait_net > body["max_waiting_bytes"]):  # D44
        raise Reject("config", "waf.body waiting limits do not nest")
    req = waf.get("requests", {})  # D45
    req_client, req_net = req.get("max_waiting_per_client", 1024), req.get("max_waiting_per_network", 4096)
    if req_client > req_net or ("max_waiting" in req and req_net > req["max_waiting"]):
        raise Reject("config", "waf.requests limits do not nest")
    conns = waf.get("connections", {})  # D46
    conn_client, conn_net = conns.get("max_per_client", 2048), conns.get("max_per_network", 8192)
    if conn_client > conn_net or ("max_open" in conns and conn_net > conns["max_open"]):
        raise Reject("config", "waf.connections limits do not nest")
    if "agent_api" in v:  # v0.4 MVP-21: own loopback listener, never the dashboard or metrics one
        lis = v.get("listen", {})
        al = v["agent_api"].get("listen", "127.0.0.1:8789")
        if al in (lis.get("dashboard", "127.0.0.1:8788"), lis.get("metrics", "127.0.0.1:9101")):
            raise Reject("config", "agent_api.listen shared")


def lab_config(v):
    issuers, keyids, peers, pubs = set(), set(), set(), set()
    for i in v["issuers"]:
        _dup(issuers, "issuer", i["id"])
    for k in v["keys"]:
        _dup(keyids, "keyid", k["keyid"])
    for c in v["clients"]:
        _dup(keyids, "keyid", c["keyid"])
        if c["issuer"] not in issuers:
            raise Reject("config", "unknown issuer")
        _dup(pubs, "public key", c["public_key"])
    for p in v.get("peers", []):
        if p["lab"] == v["identity"]["lab"]:
            raise Reject("config", "self peer")
        _dup(peers, "peer", p["lab"])
        for k in p["keys"]:
            _dup(pubs, "public key", k["public_key"])


# ---------------------------------------------------------------- SecLang subset (contracts/seclang-subset.md)

COLLECTIONS = {"ARGS", "ARGS_GET", "ARGS_POST", "ARGS_NAMES", "ARGS_GET_NAMES", "ARGS_POST_NAMES", "REQUEST_COOKIES",
               "REQUEST_COOKIES_NAMES", "REQUEST_HEADERS", "REQUEST_HEADERS_NAMES", "FILES", "FILES_NAMES"}
SCALARS = {"REQUEST_URI", "REQUEST_URI_RAW", "REQUEST_FILENAME", "REQUEST_BASENAME", "REQUEST_LINE", "REQUEST_METHOD",
           "REQUEST_PROTOCOL", "QUERY_STRING", "REQUEST_BODY"}
FORBIDDEN_HEADERS = {"host", "x-forwarded-host", "x-forwarded-server", "x-original-host", "x-host", "forwarded",
                     "forwarded-for", "x-forwarded", "x-forwarded-for", "x-real-ip", "x-client-ip",
                     "x-cluster-client-ip", "client-ip", "true-client-ip", "cf-connecting-ip", "cf-connecting-ipv6",
                     "fastly-client-ip", "x-envoy-external-address", "x-originating-ip", "x-remote-ip",
                     "x-remote-addr", "via"}
DETECT_ONLY_HEADERS = {"referer", "origin"}
STRING_OPS = {"rx", "pm", "streq", "contains", "beginsWith", "endsWith", "within"}
NUMERIC_OPS = {"eq", "gt", "ge", "lt", "le"}
NOARG_OPS = {"detectSQLi", "detectXSS", "validateUrlEncoding", "validateUtf8Encoding"}
TRANSFORMS = {"none", "lowercase", "urlDecode", "urlDecodeUni", "htmlEntityDecode", "jsDecode", "cssDecode", "cmdLine",
              "compressWhitespace", "removeWhitespace", "removeNulls", "replaceNulls", "removeComments", "replaceComments",
              "normalizePath", "normalisePath", "normalizePathWin", "normalisePathWin", "base64Decode", "base64DecodeExt",
              "hexDecode", "utf8toUnicode", "length", "trim", "trimLeft", "trimRight", "escapeSeqDecode", "sqlHexDecode"}
SEVERITIES = {"CRITICAL", "ERROR", "WARNING", "NOTICE", "2", "3", "4", "5"}
ONCE = {"id", "phase", "deny", "block", "pass", "status", "severity", "msg", "logdata", "rev", "ver", "maturity",
        "accuracy", "chain", "multiMatch", "log", "auditlog"}
HEAD_ONLY = {"id", "phase", "deny", "block", "pass", "status", "severity", "msg", "logdata", "rev", "ver", "maturity",
             "accuracy", "tag", "setvar", "log", "auditlog"}
RE_VAR = re.compile(r"[A-Z_]+\Z")
RE_SEL = re.compile(r"[A-Za-z0-9_.-]{1,64}\Z")
RE_HUB_SEL = re.compile(r"[A-Za-z0-9_.\[\]-]{1,128}\Z")  # D39: hub profile
HUB_JSON_BODY = "TX:json_request_body"
HUB_RULE_ID_MIN, HUB_RULE_ID_MAX = 60000000, 99999999
RE_OPNAME = re.compile(r"[A-Za-z0-9]+\Z")
RE_ACT = re.compile(r"[a-zA-Z]+\Z")
RE_STATIC = re.compile(r"[A-Za-z0-9 _.:;/()\[\]#+=-]*\Z")
RE_SETVAR = re.compile(r"tx\.(inbound_anomaly_score_pl[1-4]|schild_remote_hits)=\+([1-9]|10|%\{tx\.(critical|error|warning|notice)_anomaly_score\})\Z")
RE_INT = re.compile(r"(0|[1-9][0-9]{0,8})\Z")
RE_REPEAT = re.compile(r"\{([0-9]+)(,([0-9]*))?\}")
MAX_REPEAT_TOTAL = 1000

# contracts/seclang-benign-corpus.json (seclang-subset.md, catch-all check). The
# Go side holds the same list in contract/seclang/benign.go; a Go test keeps
# that copy equal to the file.
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "seclang-benign-corpus.json"), "rb") as _f:
    BENIGN_CORPUS = json.loads(_f.read().decode("utf-8"))["values"]


def sl(msg):
    raise Reject("seclang", msg)


def seclang_validate(text, max_action, hub=False):
    """Returns the SecRule id of the head; raises Reject('seclang'). hub: the D39 profile."""
    if not text or len(text.encode("utf-8")) > MAX_SECLANG:
        sl("length")
    for ch in text:
        if ch != "\n" and not (" " <= ch <= "~"):
            sl("non-printable")
    lines = text.split("\n")
    if len(lines) > (8 if hub else 4):
        sl("too many lines")
    head, specific = None, False
    for i, line in enumerate(lines):
        rid, chain, spec = _line(line, i == 0, max_action, hub)
        if i == 0:
            head = rid
        specific = specific or spec
        last = i == len(lines) - 1
        if chain and last:
            sl("dangling chain")
        if not chain and not last:
            sl("more than one rule")
    if not specific:
        sl("catch-all: no specific line")
    return head


def _quoted(s):
    if not s.startswith('"'):
        sl("expected quote")
    end = s.find('"', 1)
    if end < 0:
        sl("unterminated")
    v = s[1:end]
    if v.endswith("\\"):
        sl("ends with backslash")
    return v, s[end + 1:]


def _line(line, is_head, max_action, hub=False):
    if not line.startswith("SecRule "):
        sl("only SecRule")
    rest = line[len("SecRule "):]
    sp = rest.find(" ")
    if sp <= 0:
        sl("missing variables")
    count, detect_only = _variables(rest[:sp], hub)
    op, rest = _quoted(rest[sp + 1:])
    if not rest.startswith(" "):
        sl("space before actions")
    acts, rest = _quoted(rest[1:])
    if rest != "":
        sl("trailing")
    name, arg, neg = _operator(op, is_head)
    rid, chain, length = _actions(acts, is_head, max_action, hub)
    numeric = name in NUMERIC_OPS
    if count and not numeric:
        sl("& only with numeric operator")
    if length and not numeric:
        sl("t:length only with numeric operator")
    if detect_only and name not in NOARG_OPS:
        sl("detect-only header")
    specific = not neg and (name in NOARG_OPS or (name in STRING_OPS and not matches_benign(name, arg)))
    return rid, chain, specific


def _hub_selector(name, sel):
    if RE_HUB_SEL.match(sel):
        return
    if name != "REQUEST_HEADERS" and 3 <= len(sel) <= 128 and sel[0] == "/" and sel[-1] == "/":
        p = sel[1:-1]
        if not any(c in p for c in '| "/'):
            _regex(p)
            return
    sl("selector")


def _variables(s, hub=False):
    parts = s.split("|")
    if len(parts) > 16:
        sl("too many variables")
    positive, count_used, detect_only = 0, False, False
    for p in parts:
        neg = count = False
        if p.startswith("!"):
            neg, p = True, p[1:]
        elif p.startswith("&"):
            count, p = True, p[1:]
        if hub and p == HUB_JSON_BODY:
            positive += 1
            continue
        name, has_sel, sel = p.partition(":")
        has_sel = has_sel == ":"
        if not RE_VAR.match(name):
            sl("invalid variable")
        is_coll = name in COLLECTIONS
        if not is_coll and name not in SCALARS:
            sl("variable not allowed: " + name)
        if has_sel:
            if not is_coll:
                sl("selector on scalar")
            if hub:
                _hub_selector(name, sel)
            elif not RE_SEL.match(sel):
                sl("selector")
        if name == "REQUEST_HEADERS":
            if not has_sel:
                sl("REQUEST_HEADERS without name")
            h = sel.lower()
            if h in FORBIDDEN_HEADERS:
                sl("forbidden header")
            if h in DETECT_ONLY_HEADERS and not neg:
                detect_only = True
        if neg:
            if not is_coll or not has_sel:
                sl("exclusion")
            continue
        if count:
            count_used = True
        positive += 1
    if positive == 0:
        sl("no variable")
    return count_used, detect_only


def _operator(op, is_head):
    if not op or len(op) > 2048:
        sl("operator length")
    if "%{" in op:
        sl("macro in operator argument")
    neg = False
    if op.startswith("!"):
        neg, op = True, op[1:]
    if not op.startswith("@"):
        sl("implicit operator")
    name, has_arg, arg = op[1:].partition(" ")
    has_arg = has_arg == " "
    if not RE_OPNAME.match(name):
        sl("operator name")
    if neg and is_head:
        sl("negated head")
    if has_arg and (arg == "" or arg[0] == " " or arg[-1] == " "):
        sl("argument starts or ends with a space")
    if name in STRING_OPS:
        if not has_arg:
            sl("argument required")
        if name == "rx":
            _regex(arg)
        elif name == "pm":
            phrases = arg.split(" ")
            if len(phrases) > 100:
                sl("too many phrases")
            if "" in phrases:
                sl("empty phrase")
        return name, arg, neg
    if name in NUMERIC_OPS:
        if is_head:
            sl("numeric head")
        if not has_arg or not RE_INT.match(arg):
            sl("integer argument")
        return name, arg, neg
    if name in NOARG_OPS:
        if has_arg:
            sl("no argument expected")
        return name, arg, neg
    sl("operator not allowed: " + name)


def _regex(p):
    if len(p) > 1024:
        sl("regex length")
    for bad in ("(?=", "(?!", "(?<", "(?>", "(?P", "(?#", "[[:", "*+", "++", "?+", "}+", "{,", "[]", "[^]"):
        if bad in p:
            sl("regex construct " + bad)
    stack = [[False, False]]  # per open group: [has quantifier, has alternation]
    in_class, i, after_assertion = False, 0, False
    atom_complex, prev_quant = False, False
    while i < len(p):
        c = p[i]
        if not in_class and after_assertion and c in "*+?{":
            sl("quantifier after an assertion")
        after_assertion = not in_class and c in "^$"
        if c == "\\":
            if i + 1 >= len(p):
                sl("trailing backslash")
            e = p[i + 1]
            i += 1
            if not e.isascii() or not e.isalnum():
                pass
            elif e in "dDwWsSnrtfv":
                pass
            elif e in "bB" and not in_class:
                after_assertion = True
            elif e == "x":
                h = p[i + 1:i + 3]
                if len(h) != 2 or any(ch not in "0123456789abcdefABCDEF" for ch in h):
                    sl("hex escape")
                i += 2
            else:
                sl("escape \\" + e)
            if not in_class:
                atom_complex = prev_quant = False
        elif in_class:
            if c == "]":
                in_class = False
                atom_complex = prev_quant = False
            if c == "-" and i + 1 < len(p) and p[i + 1] != "]":
                if i >= 2 and p[i - 2] == "\\" and p[i - 1] in "dDwWsS":
                    sl("range next to a class escape")
                if i + 2 < len(p) and p[i + 1] == "\\" and p[i + 2] in "dDwWsS":
                    sl("range next to a class escape")
        elif c == "[":
            in_class = True
        elif c == "(":
            atom_complex = prev_quant = False
            if p[i + 1:i + 2] == "?":
                tail = p[i + 2:]
                skip = -1
                for f in (":", "i:", "s:", "is:", "si:"):
                    if tail.startswith(f):
                        skip = len(f)
                if skip >= 0:
                    stack.append([False, False])
                    i += 2 + skip
                    continue
                for f in ("i)", "s)", "is)", "si)"):
                    if tail.startswith(f) and i == 0:
                        skip = len(f)
                if skip < 0:
                    sl("group flags")
                i += 2 + skip
                continue
            stack.append([False, False])
        elif c == ")":
            prev_quant = False
            if len(stack) == 1:
                atom_complex = False
            else:
                q, a = stack.pop()
                stack[-1][0] = stack[-1][0] or q
                stack[-1][1] = stack[-1][1] or a
                atom_complex = q or a
        elif c == "|":
            stack[-1][1] = True
            atom_complex = prev_quant = False
        elif c in "*+?" or (c == "{" and RE_REPEAT.match(p, i)):
            if c == "?" and prev_quant:
                prev_quant = False
                i += 1
                continue
            repeating = c in "*+"
            if c == "{":
                m = RE_REPEAT.match(p, i)
                hi = int(m.group(1))
                if m.group(2):
                    hi = int(m.group(3)) if m.group(3) else -1
                repeating = hi < 0 or hi >= 2
                i += len(m.group(0)) - 1
            if repeating and atom_complex:
                sl("nested quantifier")
            stack[-1][0] = True
            atom_complex, prev_quant = False, True
        else:
            atom_complex = prev_quant = False
        i += 1
    if in_class:
        sl("unterminated class")
    total = 0
    for m in RE_REPEAT.finditer(p):
        hi = 0
        for g in (m.group(1), m.group(3)):
            if not g:
                continue
            if len(g) > 1 and g[0] == "0":
                sl("repeat count with leading zero")
            if int(g) > 1000:
                sl("repeat count")
            hi = max(hi, int(g))
        total += hi
    if total > MAX_REPEAT_TOTAL:
        sl("repeat sum")
    try:
        re.compile(p)
    except re.error as e:
        sl("does not compile: %s" % e)


# ---------------------------------------------------------------- benign corpus matching
#
# The catch-all check needs to run patterns on the corpus. Python's re
# backtracks (".*.*.*.*.*x" takes minutes on a user agent), so this is an
# independent set-based matcher over the parse tree of the (already
# validated) pattern: polynomial, and a second regex engine next to RE2.

try:
    import re._parser as _sre_parse
    import re._constants as _sre_c
except ImportError:  # Python < 3.11
    import sre_parse as _sre_parse
    import sre_constants as _sre_c

_WORD = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")
_CATEGORY = {
    _sre_c.CATEGORY_DIGIT: lambda ch: "0" <= ch <= "9",
    _sre_c.CATEGORY_NOT_DIGIT: lambda ch: not ("0" <= ch <= "9"),
    _sre_c.CATEGORY_SPACE: lambda ch: ch in "\t\n\f\r ",
    _sre_c.CATEGORY_NOT_SPACE: lambda ch: ch not in "\t\n\f\r ",
    _sre_c.CATEGORY_WORD: lambda ch: ch in _WORD,
    _sre_c.CATEGORY_NOT_WORD: lambda ch: ch not in _WORD,
}


def _swap(ch):
    return ch.lower() if ch.isupper() else ch.upper()


def _in_class(items, ch, icase):
    def raw(c):
        neg, hit = False, False
        for op, av in items:
            if op is _sre_c.NEGATE:
                neg = True
            elif op is _sre_c.LITERAL:
                hit = hit or c == chr(av)
            elif op is _sre_c.RANGE:
                hit = hit or av[0] <= ord(c) <= av[1]
            elif op is _sre_c.CATEGORY:
                hit = hit or _CATEGORY[av](c)
            else:
                raise ValueError("class item %s" % op)
        return hit, neg
    hit, neg = raw(ch)
    if icase and not hit:
        hit = raw(_swap(ch))[0]
    return hit != neg


class _Matcher:
    def __init__(self, pattern):
        tree = _sre_parse.parse(pattern)
        self.root = self._freeze(tree)
        self.flags = tree.state.flags

    def _freeze(self, sub):
        """Converts the parse tree into nested tuples that live as long as the
        matcher, so id() keys in the memo stay unique."""
        out = []
        for op, av in sub:
            if op is _sre_c.SUBPATTERN:
                av = (av[0], av[1], av[2], self._freeze(av[3]))
            elif op is _sre_c.BRANCH:
                av = (None, tuple(self._freeze(alt) for alt in av[1]))
            elif op in (_sre_c.MAX_REPEAT, _sre_c.MIN_REPEAT):
                av = (av[0], av[1], self._freeze(av[2]))
            elif op is _sre_c.IN:
                av = tuple(av)
            out.append((op, av))
        return tuple(out)

    def search(self, s):
        self.s, self.memo = s, {}
        return any(self._seq(self.root, 0, start, self.flags) for start in range(len(s) + 1))

    def _char(self, op, av, ch, flags):
        icase = bool(flags & re.IGNORECASE)
        if op is _sre_c.LITERAL:
            return ch == chr(av) or (icase and _swap(ch) == chr(av))
        if op is _sre_c.NOT_LITERAL:
            return not (ch == chr(av) or (icase and _swap(ch) == chr(av)))
        if op is _sre_c.ANY:
            return ch != "\n" or bool(flags & re.DOTALL)
        if op is _sre_c.IN:
            return _in_class(av, ch, icase)
        raise ValueError("op %s" % op)

    def _at(self, av, pos):
        s, n = self.s, len(self.s)
        if av is _sre_c.AT_BEGINNING:
            return pos == 0
        if av is _sre_c.AT_END:
            return pos == n
        if av in (_sre_c.AT_BOUNDARY, _sre_c.AT_NON_BOUNDARY):
            before = pos > 0 and s[pos - 1] in _WORD
            after = pos < n and s[pos] in _WORD
            return (before != after) == (av is _sre_c.AT_BOUNDARY)
        raise ValueError("at %s" % av)

    def _seq(self, nodes, i, pos, flags):
        """Set of end positions of nodes[i:] matched from pos."""
        key = (id(nodes), i, pos, flags)
        if key in self.memo:
            return self.memo[key]
        self.memo[key] = frozenset()  # guards against cycles (none expected)
        if i == len(nodes):
            out = frozenset([pos])
        else:
            op, av = nodes[i]
            mids = self._node(op, av, pos, flags)
            out = frozenset().union(*(self._seq(nodes, i + 1, m, flags) for m in mids)) if mids else frozenset()
        self.memo[key] = out
        return out

    def _node(self, op, av, pos, flags):
        if op in (_sre_c.LITERAL, _sre_c.NOT_LITERAL, _sre_c.ANY, _sre_c.IN):
            if pos < len(self.s) and self._char(op, av, self.s[pos], flags):
                return {pos + 1}
            return set()
        if op is _sre_c.AT:
            return {pos} if self._at(av, pos) else set()
        if op is _sre_c.SUBPATTERN:
            _, add, delete, sub = av
            return set(self._seq(sub, 0, pos, (flags | add) & ~delete))
        if op is _sre_c.BRANCH:
            out = set()
            for alt in av[1]:
                out |= self._seq(alt, 0, pos, flags)
            return out
        if op in (_sre_c.MAX_REPEAT, _sre_c.MIN_REPEAT):
            lo, hi, sub = av
            # Paths with more than lo + len(s) + 1 repetitions contain empty
            # repetitions that can be dropped: iterating that far is enough.
            limit = lo + len(self.s) + 1
            if hi is not _sre_c.MAXREPEAT and hi < limit:
                limit = hi
            cur, out = {pos}, set()
            if lo == 0:
                out.add(pos)
            for k in range(1, limit + 1):
                nxt = set()
                for p in cur:
                    nxt |= self._seq(sub, 0, p, flags)
                cur = nxt
                if not cur:
                    break
                if k >= lo:
                    out |= cur
            return out
        raise ValueError("op %s" % op)


def matches_benign(op, arg):
    """Same semantics as contract/seclang/benign.go MatchesBenign."""
    if op == "rx":
        try:
            m = _Matcher(arg)
        except (re.error, ValueError):
            return True
        return any(m.search(v) for v in BENIGN_CORPUS)
    if op == "pm":
        phrases = arg.lower().split(" ")
        return any(ph in v.lower() for v in BENIGN_CORPUS for ph in phrases)
    tests = {
        "streq": lambda v: v == arg,
        "contains": lambda v: arg in v,
        "beginsWith": lambda v: v.startswith(arg),
        "endsWith": lambda v: v.endswith(arg),
        "within": lambda v: v in arg,
    }
    if op not in tests:
        return True
    return any(tests[op](v) for v in BENIGN_CORPUS)


def _split_actions(s):
    out, cur, in_q, i = [], [], False, 0
    while i < len(s):
        c = s[i]
        if in_q and c == "\\" and s[i + 1:i + 2] == "'":
            cur.append("\\'")
            i += 2
            continue
        if c == "'":
            in_q = not in_q
            cur.append(c)
        elif c == "," and not in_q:
            out.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    if in_q:
        sl("unterminated single quote")
    out.append("".join(cur))
    return out


def _action_value(v):
    if v.startswith("'"):
        if len(v) < 2 or not v.endswith("'"):
            sl("bad quoting")
        inner = v[1:-1]
        if "'" in inner.replace("\\'", ""):
            sl("stray quote")
        return inner.replace("\\'", "'")
    if "'" in v:
        sl("stray quote")
    return v


def _actions(s, is_head, max_action, hub=False):
    if s == "":
        sl("empty actions")
    if "\\" in s:
        sl("backslash in actions")
    seen, rid, phase, disruptive, chain, severity, status = {}, 0, 0, "", False, False, ""
    length = False
    for it in _split_actions(s):
        name, has_val, val = it.partition(":")
        has_val = has_val == ":"
        if not RE_ACT.match(name):
            sl("invalid action")
        if not is_head and name in HEAD_ONLY:
            sl("head-only action in chain")
        seen[name] = seen.get(name, 0) + 1
        if name in ONCE and seen[name] > 1:
            sl("action twice")
        v = _action_value(val)
        if name == "id":
            lo, hi = (HUB_RULE_ID_MIN, HUB_RULE_ID_MAX) if hub else (REMOTE_ID_MIN, REMOTE_ID_MAX)
            if not RE_INT.match(v) or not (lo <= int(v) <= hi):
                sl("id range")
            rid = int(v)
        elif name == "phase":
            if v not in ("1", "2"):
                sl("phase")
            phase = int(v)
        elif name in ("deny", "block", "pass"):
            if has_val:
                sl("value on disruptive")
            if disruptive:
                sl("two disruptive")
            disruptive = name
        elif name == "status":
            if v not in ("403", "429"):
                sl("status")
            status = v
        elif name == "severity":
            if v not in SEVERITIES:
                sl("severity")
            severity = True
        elif name in ("msg", "logdata", "tag", "rev", "ver", "maturity", "accuracy"):
            mx = 200 if name in ("msg", "logdata") else 64
            if not has_val or v == "" or len(v) > mx:
                sl(name + " length")
            if "%{" in v:
                sl(name + " macro")
            if not RE_STATIC.match(v):
                sl(name + " characters")
            if name == "tag" and seen[name] > 8:
                sl("too many tags")
        elif name == "t":
            if v not in TRANSFORMS and not (hub and v == "uppercase"):
                sl("transformation")
            length = length or v == "length"
            if seen[name] > 16:
                sl("too many transformations")
        elif name == "setvar":
            if not RE_SETVAR.match(v):
                sl("setvar")
            if seen[name] > 2:
                sl("too many setvar")
        elif name == "chain":
            if has_val:
                sl("chain value")
            chain = True
        elif name in ("multiMatch", "log", "auditlog"):
            if has_val:
                sl(name + " value")
        else:
            sl("action not allowed: " + name)
    if is_head:
        if rid == 0:
            sl("id required")
        if phase == 0:
            sl("phase required")
        if disruptive == "":
            sl("disruptive required")
        if not severity:
            sl("severity required")
        if seen.get("msg", 0) == 0:
            sl("msg required")
        if status and disruptive != "deny":
            sl("status only with deny")
        if max_action == "observe" and disruptive != "pass":
            sl("observe requires pass")
    return rid, chain, length


def selftest():
    """Checks the building blocks against published test vectors."""
    # RFC 8032, section 7.1, TEST 1 (empty message).
    sk = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
    pk = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    sig = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    assert ed25519_public_from_seed(sk) == pk, "ed25519 public key derivation"
    assert ed25519_verify(pk, b"", sig), "ed25519 verify RFC 8032 test 1"
    assert not ed25519_verify(pk, b"x", sig), "ed25519 must reject another message"
    bad = bytearray(sig)
    bad[10] ^= 1
    assert not ed25519_verify(pk, b"", bytes(bad)), "ed25519 must reject a flipped bit"
    # request_sig canonical form (contracts/signal.md), fixed value shared with Go.
    canon = ("schild.request-shape/1\nmethod:POST\npath:/wp-login.php\nparams:log,pwd\n"
             "content_type:application/x-www-form-urlencoded\nrules:930120,949110\n")
    assert digest(canon.encode()) == "sha256:1ce928e7e35ea61e1a1e634babf6bc3a4da2ecd301152aa3ada4169905dbc08e", "request_sig"
    # RFC 6962 tree hash: published roots for the first leaves of the CT test data.
    ct = [b"", b"\x00", b"\x10", b"\x20\x21", b"\x30\x31", b"\x40\x41\x42\x43"]
    assert mth(ct[:1]).hex() == "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d", "rfc6962 1 leaf"
    assert mth(ct[:3]).hex() == "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77", "rfc6962 3 leaves"
    assert mth(ct[:6]).hex() == "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef", "rfc6962 6 leaves"
    assert mth([]).hex() == hashlib.sha256(b"").hexdigest()
    # DSSE protocol example.
    assert pae("http://example.com/HelloWorld", b"hello world") == b"DSSEv1 29 http://example.com/HelloWorld 11 hello world"
    # ECMA `$` is end of input, unlike Python's.
    assert re.search(ecma_pattern("^[a-z]+$"), "abc\n") is None
    assert re.search(ecma_pattern("^[$a]+$"), "$a") is not None
    for bad_json in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":"\\ud800"}', b"[" * 33 + b"]" * 33, b"\xef\xbb\xbf{}"):
        try:
            strict_parse(bad_json)
        except Reject:
            continue
        raise AssertionError("strict_parse accepted %r" % bad_json)


# ---------------------------------------------------------------- v0.1: public log tree (RFC 6962)


def log_leaf_data(e):
    env = e["envelope_sha256"] or ""
    return ("schild.log-leaf/1\nindex:%d\ntime:%s\nkind:%s\nref:%s\ndigest:%s\nsummary:%s\nenvelope:%s\n"
            % (e["index"], e["time"], e["kind"], e["ref"], e["digest"], e["summary"], env)).encode("ascii")


def mth(leaves):
    """RFC 6962 section 2.1, written from the definition (recursive split)."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return hashlib.sha256(b"\x00" + leaves[0]).digest()
    k = 1
    while k * 2 < n:
        k *= 2
    return hashlib.sha256(b"\x01" + mth(leaves[:k]) + mth(leaves[k:])).digest()


def log_tree_check(v):
    entries = v["entries"]
    if v["head"]["size"] != len(entries):
        raise Reject("schema", "head size differs from the number of entries")
    for i, e in enumerate(entries):
        if e["index"] != i:
            raise Reject("schema", "entry %d has index %d" % (i, e["index"]))
    root = "sha256:" + mth([log_leaf_data(e) for e in entries]).hex()
    if root != v["head"]["root"]:
        raise Reject("log_root", root)


# ---------------------------------------------------------------- v0.1: peer request signatures

PEER_PAYLOAD_TYPE = "application/vnd.schild.peer-request.v0+text"
RE_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,62}\Z")
RE_KEYID = re.compile(r"[a-z0-9][a-z0-9._/-]{0,127}\Z")
RE_TS = re.compile(r"20[0-9]{2}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z\Z")


def peer_request_check(v, ctx):
    tokens = v["authorization"].split(" ")
    if len(tokens) != 5 or tokens[0] != "v1":
        raise Reject("malformed", "header syntax")
    vals = []
    for tok, prefix in zip(tokens[1:], ("lab=", "keyid=", "ts=", "sig=")):
        if not tok.startswith(prefix):
            raise Reject("malformed", "token order")
        vals.append(tok[len(prefix):])
    lab, keyid, ts, sig_b64 = vals
    try:
        sig = b64_canonical(sig_b64)
    except Reject:
        raise Reject("malformed", "sig base64")
    if not RE_ID.match(lab) or not RE_KEYID.match(keyid) or not RE_TS.match(ts):
        raise Reject("schema", "lab, keyid or ts format")
    at = parse_time(ts, "ts")
    key = ctx.trust.get(keyid)
    if key is None or "rules" not in key["purposes"] or key.get("lab") != lab:
        raise Reject("signature", "not a rules key of " + lab)
    message = ("schild.peer-request/1\nmethod:%s\npath:%s\ntarget:%s\nfrom:%s\nkeyid:%s\nts:%s\nbody:%s\n"
               % (v["method"], v["path"], v["target"], lab, keyid, ts, v["body_sha256"])).encode("utf-8")
    if len(sig) != 64 or not ed25519_verify(key["pub"], pae(PEER_PAYLOAD_TYPE, message), sig):
        raise Reject("signature", "peer signature")
    if at > ctx.now + MAX_CLOCK_SKEW:
        raise Reject("clock_skew", "ts in the future")
    if at < ctx.now - MAX_CLOCK_SKEW:
        raise Reject("expired", "ts too old")


# ---------------------------------------------------------------- v0.3: host reports and agents (host-check.md)

ENROLMENT_PAYLOAD_TYPE = "application/vnd.schild.agent-enrolment.v0+json"
MAX_AGENT_AGE = 300
HOST_FORBIDDEN_FIELDS = [
    "env", "envs", "environ", "environment", "env_vars", "environment_variables",
    "password", "passwd", "passphrase", "secret", "secrets", "secret_key", "private_key", "privkey",
    "api_key", "apikey", "token", "tokens", "access_token", "auth_token", "bearer", "credential", "credentials",
    "cookie", "cookies", "session", "authorization",
    "content", "contents", "file_content", "file_contents", "file_body", "body", "raw", "raw_output",
    "output", "stdout", "stderr", "cmdline", "command_line", "argv", "config_file", "shadow",
]
HOST_FORBIDDEN = {normalize_field(f) for f in HOST_FORBIDDEN_FIELDS}
PEM_MARKERS = ("-----begin ", "-----end ", "private key-----", "putty-user-key-file")
RE_SECRET_ASSIGN = re.compile(r"(password|passwd|secret|token|api_?key|access_?key|private_?key|credentials?)[a-z0-9_]*=[!-~]")
RE_ENV_ASSIGN = re.compile(r"(^|[ ;\t\n\x00])[A-Z_][A-Z0-9_]{1,63}=")
ENV_DUMP_MIN = 3


def ascii_lower(s):
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in s)


def forbidden_content(s):
    low = ascii_lower(s)
    if any(m in low for m in PEM_MARKERS):
        return "pem"
    if RE_SECRET_ASSIGN.search(low):
        return "secret assignment"
    if sum(1 for _ in RE_ENV_ASSIGN.finditer(s)) >= ENV_DUMP_MIN:
        return "environment dump"
    return ""


def host_forbidden(v):
    """Two passes, as in Go: key names first, then content of keys and strings."""
    def keys_pass(x, at=()):
        if isinstance(x, dict):
            for k, y in x.items():
                # v0.5 (D38): fix_config.content is checked against the
                # gateway templates instead (host_report_check).
                fix = k == "content" and len(at) >= 3 and at[-1] == "fix_config" and isinstance(at[-2], int) \
                    and at[-3] == "findings" and at[:-3] in ((), ("report",))
                if not fix and normalize_field(k) in HOST_FORBIDDEN:
                    raise Reject("forbidden_field", k)
                keys_pass(y, at + (k,))
        elif isinstance(x, list):
            for i, y in enumerate(x):
                keys_pass(y, at + (i,))

    def content_pass(x):
        if isinstance(x, str):
            r = forbidden_content(x)
            if r:
                raise Reject("forbidden_content", r)
        elif isinstance(x, dict):
            for k, y in x.items():
                r = forbidden_content(k)
                if r:
                    raise Reject("forbidden_content", "key: " + r)
                content_pass(y)
        elif isinstance(x, list):
            for y in x:
                content_pass(y)

    keys_pass(v)
    content_pass(v)


def host_report_check(r):
    seen = set()
    for f in r["findings"]:
        k = (f["id"], f.get("subject", ""))
        if k in seen:
            raise Reject("schema", "duplicate finding %s %s" % k)
        seen.add(k)
    for f in r["findings"]:
        fc = f.get("fix_config")
        if fc is not None and not fix_config_known(f["id"], fc["path"], fc["content"]):
            raise Reject("schema", "fix_config of %s is not a template rendering" % f["id"])


# v0.5 (D38): gateway-side fix templates (hostcheck.FixTemplates).
FIX_LOGROTATE = "${file} {\n  daily\n  rotate ${rotate}\n  maxsize ${max_size_mb}M\n  missingok\n  notifempty\n  compress\n  delaycompress\n  copytruncate\n}\n"
FIX_TEMPLATES = {
    "logs.docker_unbounded": [("/etc/docker/daemon.json",
                               '{"log-driver": "local", "log-opts": {"max-size": "${max_size_mb}m", "max-file": "${max_files}"}}\n')],
    "logs.journald_size": [("/etc/systemd/journald.conf.d/50-schild-size.conf",
                            "[Journal]\nSystemMaxUse=${max_use_mb}M\nSystemKeepFree=${keep_free_mb}M\nMaxRetentionSec=1month\n")],
    "logs.logrotate_config": [("/etc/logrotate.d/schild-${slug}", FIX_LOGROTATE)],
    "logs.large_file": [("/etc/logrotate.d/schild-${slug}", FIX_LOGROTATE)],
}
FIX_NUM = "[1-9][0-9]{0,6}"
FIX_VARS = {
    "slug": ("[a-z0-9][a-z0-9-]{0,47}", None),
    "file": ("/[A-Za-z0-9_@+-][A-Za-z0-9._@+-]{0,63}(?:/[A-Za-z0-9_@+-][A-Za-z0-9._@+-]{0,63}){0,7}", None),
    "max_size_mb": (FIX_NUM, (1, 10240)),
    "max_files": (FIX_NUM, (1, 20)),
    "max_use_mb": (FIX_NUM, (64, 65536)),
    "keep_free_mb": (FIX_NUM, (64, 1048576)),
    "rotate": (FIX_NUM, (1, 365)),
}
FIX_ROOTS = ("/var/log/", "/srv/", "/opt/", "/var/www/")
FIX_PLACEHOLDER = re.compile(r"\$\{([a-z_]{1,32})\}")


def fix_compile(t):
    out, names, rest = "", [], t
    while True:
        m = FIX_PLACEHOLDER.search(rest)
        if m is None:
            break
        out += re.escape(rest[:m.start()]) + "(" + FIX_VARS[m.group(1)][0] + ")"
        names.append(m.group(1))
        rest = rest[m.end():]
    return re.compile(out + re.escape(rest)), names


def fix_match(t, s, vars_):
    rx, names = fix_compile(t)
    m = rx.fullmatch(s)
    if m is None:
        return False
    for i, n in enumerate(names):
        if n in vars_ and vars_[n] != m.group(i + 1):
            return False
        vars_[n] = m.group(i + 1)
    return True


def fix_var_ok(n, v):
    bounds = FIX_VARS[n][1]
    if bounds is not None:
        return bounds[0] <= int(v) <= bounds[1]
    if n == "file":
        for r in FIX_ROOTS:
            if v.startswith(r) and len(v) > len(r):
                return r == "/var/log/" or v.endswith(".log")
        return False
    return True


def fix_config_known(fid, path, content):
    for tp, tc in FIX_TEMPLATES.get(fid, []):
        vars_ = {}
        if fix_match(tp, path, vars_) and fix_match(tc, content, vars_) and all(fix_var_ok(n, v) for n, v in vars_.items()):
            return True
    return False


def agent_message(ctx, pv):
    at = parse_time(pv["issued_at"], "issued_at")
    if at > ctx.now + MAX_CLOCK_SKEW:
        raise Reject("clock_skew", "issued_at in the future")
    if at + MAX_AGENT_AGE < ctx.now:
        raise Reject("expired", "issued_at too old")
    if ctx.gateway and pv["gateway"] != ctx.gateway:
        raise Reject("channel", "other gateway")
    if pv["nonce"] in ctx.seen:
        raise Reject("replay", pv["nonce"])


# ---------------------------------------------------------------- runner


def load_keys(path):
    with open(path, "rb") as f:
        kf = json.loads(f.read().decode("utf-8"))
    keys = {}
    for k in kf["keys"]:
        seed = bytes.fromhex(k["seed_hex"])
        # v0.2 (D24): test lab keys carry their own seed_domain.
        domain = k.get("seed_domain", "schild/testkey/v0/")
        if domain not in ("schild/testkey/v0/", "schild/testlab/v0/"):
            raise SystemExit("keys.json: unknown seed_domain of %s" % k["name"])
        if hashlib.sha256((domain + k["name"]).encode()).digest() != seed:
            raise SystemExit("keys.json: seed of %s is not the documented derivation" % k["name"])
        pub = base64.b64decode(k["public_key"][len("ed25519:"):])
        if ed25519_public_from_seed(seed) != pub:
            raise SystemExit("keys.json: public key of %s does not match its seed" % k["name"])
        k = dict(k)
        k["pub"] = pub
        keys[k["name"]] = k
    return keys


# ---------------------------------------------------------------- bots and geo (v0.5, MVP-22, D35)

BOT_UA_BYTES = 512
BOT_STALE = 30 * 24 * 3600
GEO_MAX_ASN = 2 ** 32 - 1
GEO_MAX_NAME = 256
MISSING = object()


def _schema_dup(seen, what, x):
    if x in seen:
        raise Reject("schema", "duplicate %s %s" % (what, x))
    seen.add(x)


def bot_network(s):
    """A canonical prefix: no host bits, no IPv4-mapped IPv6."""
    try:
        net = ipaddress.ip_network(s, strict=True)
    except ValueError:
        return None
    if net.version == 6 and net.network_address.ipv4_mapped is not None:
        return None
    return net


def bot_catalogue_check(v):
    """Semantic checks of bot-catalogue.schema.json; returns range sets by id."""
    sources, ranges, tokens, ids = set(), {}, {}, set()
    for s in v["sources"]:
        _schema_dup(sources, "source", s["id"])
    for r in v["ranges"]:
        if r["id"] in ranges:
            raise Reject("schema", "duplicate range set " + r["id"])
        nets = []
        for p in r["prefixes"]:
            n = bot_network(p)
            if n is None:
                raise Reject("schema", "prefix not canonical: " + p)
            nets.append(n)
        ranges[r["id"]] = {"t": parse_time(r["fetched_at"], "fetched_at"), "nets": nets}
    for t in v["automation_tokens"]:
        k = ascii_lower(t)
        if k in tokens:
            raise Reject("schema", "duplicate automation token")
        tokens[k] = "automation_tokens"
    for b in v["bots"]:
        _schema_dup(ids, "bot", b["id"])
        rid = b["verify"].get("ranges")
        if rid is not None and rid not in ranges:
            raise Reject("schema", "unknown range set " + rid)
        if "source" in b and b["source"] not in sources:
            raise Reject("schema", "unknown source " + b["source"])
        for t in b["ua_match"]:
            k = ascii_lower(t)
            if k in tokens:
                raise Reject("schema", "ua_match token used twice")
            tokens[k] = b["id"]
    return ranges


def bot_classify(cat, ranges, ua, addr, name, opt, now):
    low = ua.encode("utf-8")[:BOT_UA_BYTES].lower()  # bytes.lower() touches ASCII letters only
    best, best_len = None, 0
    for b in cat["bots"]:
        for t in b["ua_match"]:
            tb = t.encode("ascii").lower()
            if len(tb) > best_len and tb in low:
                best, best_len = b, len(tb)
    if best is None:
        auto = not low or not low.startswith(b"mozilla/") or any(t.encode("ascii").lower() in low for t in cat["automation_tokens"])
        return {"bot": None, "category": "likely_automated" if auto else "likely_browser", "verification": None}
    fc = ""
    suffixes = best["verify"].get("rdns_suffixes", [])
    if opt["fcrdns"] and suffixes and name:
        n = ascii_lower(name)
        if n.endswith("."):
            n = n[:-1]
        fc = "match" if any(n == s or n.endswith("." + s) for s in suffixes) else "nomatch"
    rg = ""
    rid = best["verify"].get("ranges")
    if opt["ranges"] and rid is not None:
        r = ranges[rid]
        if now - r["t"] > BOT_STALE:
            rg = "stale"
        elif any(addr in n for n in r["nets"]):
            rg = "in"
        else:
            rg = "out"
    if fc == "match" or rg == "in":
        ver = "verified"
    elif fc == "nomatch" or rg == "out":
        ver = "mismatch"
    elif rg == "stale":
        ver = "unknown_stale"
    else:
        ver = "claimed"
    return {"bot": best["id"], "category": best["category"], "verification": ver}


def bot_match(v, now):
    ranges = bot_catalogue_check(v["catalogue"])
    req = v["request"]
    try:
        addr = ipaddress.ip_address(req["ip"])
    except ValueError:
        raise Reject("schema", "request.ip")
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    o = v.get("options", {})
    opt = {"ranges": o.get("ranges", True), "fcrdns": o.get("fcrdns", False)}
    return bot_classify(v["catalogue"], ranges, req["user_agent"], addr, req.get("fcrdns_name", ""), opt, now)


# ---------------------------------------------------------------- crawler control (v0.5, D57, MVP-29)

CRAWLER_PRESETS = {"block_ai_training": {"ai_training": "block"}}


def crawler_policy(v, now):
    """Which rule of a website's crawler policy blocks a request, and what
    the gateway mode and the allowlist make of it."""
    cat = v["catalogue"]
    ranges = bot_catalogue_check(cat)
    ids = {b["id"] for b in cat["bots"]}
    pol = v["policy"]
    for bid in sorted(pol.get("bots", {})):
        if bid not in ids:
            raise Reject("schema", "unknown bot " + bid)
    cats = dict(pol.get("categories", {}))
    bot_rules = dict(pol.get("bots", {}))
    imp = pol.get("impersonators", "allow")
    if "preset" in v:
        cats = dict(CRAWLER_PRESETS[v["preset"]])
        bot_rules = {}
    req = v["request"]
    try:
        addr = ipaddress.ip_address(req["ip"])
    except ValueError:
        raise Reject("schema", "request.ip")
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    cl = bot_classify(cat, ranges, req["user_agent"], addr, "", {"ranges": True, "fcrdns": False}, now)
    rule = "none"
    if cl["bot"] is not None:
        if imp == "block" and cl["verification"] == "mismatch":
            rule = "impersonator"
        elif cl["bot"] in bot_rules:
            rule = "bot" if bot_rules[cl["bot"]] == "block" else "none"
        elif cats.get(cl["category"]) == "block":
            rule = "category"
    outcome, reason, status = "passed", "", 0
    if rule != "none":
        if v["mode"] == "observe":
            outcome, reason = "would_block", "gateway_observe"
        elif v.get("allowlisted", False):
            outcome, reason = "would_block", "allowlist"
        else:
            outcome, status = "blocked_crawler", 403
    out = dict(cl)
    out.update({"rule": rule, "outcome": outcome, "reason": reason, "status": status})
    return out


def geo_get(rec, path):
    cur = rec
    for p in path.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return MISSING
        cur = cur[p]
    return cur


def geo_first(rec, paths):
    for p in paths:
        x = geo_get(rec, p)
        if x is not MISSING:
            return x
    return MISSING


def geo_flag(rec, paths):
    out = None
    for p in paths:
        x = geo_get(rec, p)
        if x is MISSING:
            continue
        if not isinstance(x, bool):
            raise Reject("schema", p + ": not a boolean")
        out = bool(out) or x
    return out


def geo_name(rec, paths):
    x = geo_first(rec, paths)
    if x is MISSING:
        return ""
    if not isinstance(x, str):
        raise Reject("schema", "name: not a string")
    if len(x.encode("utf-8")) > GEO_MAX_NAME or any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in x):
        return ""
    return x


def geo_country(rec, paths):
    x = geo_first(rec, paths)
    if x is MISSING:
        return "ZZ"
    if not isinstance(x, str) or not re.fullmatch(r"[A-Za-z]{2}", x):
        raise Reject("schema", "country")
    return x.upper()


def geo_map(provider, rec):
    out, flags, carrier = {}, {}, ""
    if provider in ("dbip", "maxmind"):
        out["country"] = geo_country(rec, ["country.iso_code", "registered_country.iso_code"])
        asn = None
        x = geo_get(rec, "autonomous_system_number")
        if x is not MISSING:
            if isinstance(x, bool) or not isinstance(x, int) or not 0 <= x <= GEO_MAX_ASN:
                raise Reject("schema", "autonomous_system_number")
            asn = x or None
        out["asn"] = asn
        as_name = geo_name(rec, ["autonomous_system_organization"])
        if provider == "maxmind":
            both = lambda k: [k, "traits." + k]  # noqa: E731
            flags["is_vpn"] = geo_flag(rec, both("is_anonymous_vpn"))
            flags["is_proxy"] = geo_flag(rec, both("is_public_proxy") + both("is_residential_proxy"))
            flags["is_tor"] = geo_flag(rec, both("is_tor_exit_node"))
            flags["is_hosting"] = geo_flag(rec, both("is_hosting_provider"))
            ct = geo_first(rec, both("connection_type"))
            if ct is not MISSING:
                if not isinstance(ct, str):
                    raise Reject("schema", "connection_type")
                flags["is_mobile"] = ct == "Cellular"
            if geo_first(rec, both("mobile_network_code")) is not MISSING:
                carrier = geo_name(rec, both("isp"))
    else:  # ipinfo
        out["country"] = geo_country(rec, ["country_code"])
        asn = None
        x = geo_get(rec, "asn")
        if x is not MISSING:
            if not isinstance(x, str) or (x != "" and not re.fullmatch(r"AS[0-9]{1,10}", x)):
                raise Reject("schema", "asn")
            if x:
                n = int(x[2:])
                if n > GEO_MAX_ASN:
                    raise Reject("schema", "asn range")
                asn = n or None
        out["asn"] = asn
        as_name = geo_name(rec, ["as_name"])
        d = geo_get(rec, "as_domain")
        if d is not MISSING:
            if not isinstance(d, str):
                raise Reject("schema", "as_domain")
            if re.fullmatch(r"[a-z0-9.-]{1,253}", d):
                out["as_domain"] = d
        flags["is_vpn"] = geo_flag(rec, ["is_vpn", "vpn"])
        flags["is_proxy"] = geo_flag(rec, ["is_proxy", "proxy"])
        flags["is_tor"] = geo_flag(rec, ["is_tor", "tor"])
        flags["is_hosting"] = geo_flag(rec, ["is_hosting", "hosting"])
        flags["is_mobile"] = geo_flag(rec, ["is_mobile"])
        carrier = geo_name(rec, ["carrier_name", "carrier.name"])
    if as_name:
        out["as_name"] = as_name
    for k, x in flags.items():
        if x is not None:
            out[k] = x
    if carrier:
        out["carrier"] = carrier
    for k, cls in (("is_tor", "tor"), ("is_vpn", "vpn"), ("is_proxy", "proxy"), ("is_mobile", "mobile"), ("is_hosting", "hosting")):
        if flags.get(k):
            out["net_class"] = cls
            break
    return out


# ---------------------------------------------------------------- websites (v0.5, D36)

WS_MAX_TRACKED = 32
WS_MIN_COUNT = 10


def ws_ascii_lower(x):
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in x)


def ws_valid_port(p):
    return p != "" and len(p) <= 5 and p[0] != "0" and all("0" <= c <= "9" for c in p) and 1 <= int(p) <= 65535


def ws_is_ipv4(x):
    parts = x.split(".")
    if len(parts) != 4:
        return False
    for q in parts:
        if q == "" or len(q) > 3 or (len(q) > 1 and q[0] == "0") or not all("0" <= c <= "9" for c in q) or int(q) > 255:
            return False
    return True


def ws_valid_ldh(lbl):
    if lbl == "" or len(lbl) > 63 or lbl[0] == "-" or lbl[-1] == "-":
        return False
    return all("a" <= c <= "z" or "0" <= c <= "9" or c == "-" for c in lbl)


def ws_name(host, allow_wild):
    """Normalised host name: returns (key, kind) with kind name or ipv4."""
    if host.endswith("."):
        host = host[:-1]
    if host == "":
        raise Reject("schema", "host: empty name")
    host = ws_ascii_lower(host)
    if ws_is_ipv4(host):
        return host, "ipv4"
    labels = host.split(".")
    for i, lbl in enumerate(labels):
        if lbl == "*":
            if not allow_wild:
                raise Reject("schema", "host: wildcard")
            continue
        if any(ord(c) >= 0x80 for c in lbl):
            if any(ord(c) >= 0x80 and unicodedata.category(c) == "Lu" for c in lbl):
                raise Reject("schema", "host: upper-case non-ASCII letter")
            lbl = "xn--" + lbl.encode("punycode").decode("ascii")
            labels[i] = lbl
        if not ws_valid_ldh(lbl):
            raise Reject("schema", "host: label %r" % lbl)
    key = ".".join(labels)
    if len(key) > 253:
        raise Reject("schema", "host: too long")
    return key, "name"


def ws_hostport(hp, allow_wild):
    host = hp
    if hp.startswith("["):
        end = hp.find("]")
        if end < 0:
            raise Reject("schema", "host: unclosed bracket")
        host = hp[1:end]
        after = hp[end + 1:]
        if after != "" and not (after.startswith(":") and ws_valid_port(after[1:])):
            raise Reject("schema", "host: bad port")
        if "%" in host:
            raise Reject("schema", "host: zone")
        try:
            a = ipaddress.IPv6Address(host)
        except ValueError:
            raise Reject("schema", "host: not an IPv6 address")
        if a.ipv4_mapped is not None:
            raise Reject("schema", "host: IPv4-mapped")
        return a.compressed, "ipv6"
    i = hp.rfind(":")
    if i >= 0:
        if not ws_valid_port(hp[i + 1:]):
            raise Reject("schema", "host: bad port")
        host = hp[:i]
    if host == "":
        return "", "any"
    return ws_name(host, allow_wild)


def ws_address(addr):
    if addr == "" or len(addr.encode("utf-8")) > 1024:
        raise Reject("schema", "address: empty or too long")
    for c in addr:
        if c <= " " or c == "\x7f" or c in "{}" or c.isspace():
            raise Reject("schema", "address: space, control character or placeholder")
    rest = addr
    i = rest.find("://")
    if i >= 0:
        if ws_ascii_lower(rest[:i]) not in ("http", "https"):
            raise Reject("schema", "address: scheme")
        rest = rest[i + 3:]
    j = rest.find("/")
    if j >= 0:
        rest = rest[:j]
    return ws_hostport(rest, True)


def ws_id(key, kind):
    if kind == "any":
        return "_any"
    if kind == "ipv6":
        return "ipv6-" + key.replace(":", "-")
    if kind == "name":
        return ".".join("_" if x == "*" else x for x in key.split("."))
    return key


def ws_label(key, kind):
    if kind == "any":
        return "_any"
    if kind == "ipv6":
        return "[" + key + "]"
    if kind == "name":
        out = []
        for x in key.split("."):
            if x.startswith("xn--"):
                try:
                    u = x[4:].encode("ascii").decode("punycode")
                    if u != "" and not any(0xD800 <= ord(c) <= 0xDFFF for c in u):
                        x = u
                except (UnicodeError, ValueError):
                    pass
            out.append(x)
        return ".".join(out)
    return key


def ws_listed(h, lst):
    for e in lst:
        e = ws_ascii_lower(e)
        if e == h:
            return True
        if e.startswith("*.") and h.endswith(e[1:]):
            lbl = h[: len(h) - len(e) + 1]
            if lbl != "" and "." not in lbl:
                return True
    return False


def website_derive(v):
    mode = v["mode"]
    index = None
    if mode == "proxy":
        w = {"id": "default", "label": "default", "hosts": [], "protection": "protected", "tracked": True}
        for i, a in enumerate(v.get("site_hosts", [])):
            key, kind = ws_name(a, True)
            if i == 0:
                w["id"], w["label"] = ws_id(key, kind), ws_label(key, kind)
            if key not in w["hosts"]:
                w["hosts"].append(key)
        sites = [w]
    else:
        blocks = v["blocks"]
        parsed = [[ws_address(a) for a in b["addresses"]] for b in blocks]
        unprot = v.get("unprotected_sites", [])
        parent = list(range(len(blocks)))

        def find(i):
            while parent[i] != i:
                i = parent[i]
            return i
        counting = [False] * len(blocks)
        owner = {}
        for i, b in enumerate(blocks):
            listed = all(kind != "any" and ws_listed(key, unprot) for key, kind in parsed[i])
            if b["schild"]:
                pass
            elif b["proxies"] and listed:
                pass
            elif b["proxies"]:
                raise Reject("config", "block %d proxies without schild" % (i + 1))
            else:
                continue
            counting[i] = True
            for key, kind in parsed[i]:
                if key in owner:
                    a, c = find(i), find(owner[key])
                    if a < c:
                        a, c = c, a
                    parent[a] = c
                else:
                    owner[key] = i
        groups, order = {}, []
        for i, b in enumerate(blocks):
            if not counting[i]:
                continue
            r = find(i)
            if r not in groups:
                groups[r] = {"hosts": [], "protected": 0, "listed": 0}
                order.append(groups[r])
            g = groups[r]
            for h in parsed[i]:
                if h[0] not in [x[0] for x in g["hosts"]]:
                    g["hosts"].append(h)
            if b["schild"]:
                g["protected"] += 1
            else:
                g["listed"] += 1
        sites, tracked = [], 0
        index = {"exact": {}, "wild": [], "any": None}
        for g in order:
            key0, kind0 = next((h for h in g["hosts"] if h[1] != "any"), ("", "any"))
            prot = "protected"
            if g["protected"] == 0:
                prot = "unprotected"
            elif g["listed"] > 0:
                prot = "partial"
            w = {"id": ws_id(key0, kind0), "label": ws_label(key0, kind0), "hosts": [], "protection": prot, "tracked": False}
            if prot != "unprotected" and tracked < WS_MAX_TRACKED:
                w["tracked"] = True
                tracked += 1
            idx = len(sites)
            for key, kind in g["hosts"]:
                if kind == "any":
                    index["any"] = idx
                    continue
                w["hosts"].append(key)
                if "*" in key:
                    index["wild"].append((key.split("."), idx, key.count("*")))
                else:
                    index["exact"][key] = idx
            sites.append(w)
    out = {"websites": sites}
    if "resolve" in v:
        out["resolved"] = [ws_resolve(mode, sites, index, hh) for hh in v["resolve"]]
    if "own_hosts" in v:  # D36 amendment 2026-10-29: referrer _intern
        out["own"] = [ws_own_host(mode, sites, index, hh) for hh in v["own_hosts"]]
    return out


def ws_match(index, key, kind):
    """Index of the website whose exact or wildcard host matches; never the catch-all."""
    if key in index["exact"]:
        return index["exact"][key]
    if kind == "name":
        labels = key.split(".")
        best, best_stars = None, 0
        for wl, idx, stars in index["wild"]:
            if len(wl) != len(labels):
                continue
            if all(a == "*" or a == b for a, b in zip(wl, labels)):
                if best is None or stars < best_stars or (stars == best_stars and idx < best):
                    best, best_stars = idx, stars
        return best
    return None


def ws_own_host(mode, sites, index, hh):
    if mode == "proxy":
        index = {"exact": {}, "wild": [], "any": None}
        for h in sites[0]["hosts"]:
            if "*" in h:
                index["wild"].append((h.split("."), 0, h.count("*")))
            else:
                index["exact"][h] = 0
    try:
        key, kind = ws_hostport(hh, False)
    except Reject:
        return False
    if kind == "any":
        return False
    return ws_match(index, key, kind) is not None


def website_visitor(v):
    """D36 amendment 2026-10-29: "Besucher" are browser requests schild forwarded."""
    browser = v["ua_class"] == "browser" and v["bot_category"] == "likely_browser"
    return {"visitor": browser and v["outcome"] in ("passed", "would_block"), "bot_client": not browser}


def ws_split_host_port(hp):
    """Go's net.SplitHostPort: the host, or None on an error."""
    i = hp.rfind(":")
    if i < 0:
        return None
    j = k = 0
    if hp[0] == "[":
        end = hp.find("]")
        if end < 0 or end + 1 != i:
            return None
        host, j, k = hp[1:end], 1, end + 1
    else:
        host = hp[:i]
        if ":" in host:
            return None
    if "[" in hp[j:] or "]" in hp[k:]:
        return None
    return host


# Non-ASCII letters Go's strings.EqualFold or strings.ToLower take for an ASCII one.
WS_HOST_FOLD = {"K": "k", "ſ": "s", "İ": "i"}


def ws_resolve(mode, sites, index, hh):
    """D69: the request Host as Caddy's host matcher reads it."""
    if mode == "proxy":
        return sites[0]["id"]
    any_id = sites[index["any"]]["id"] if index["any"] is not None else None
    name = ws_split_host_port(hh)
    if name is None:
        name = hh[1:] if hh.startswith("[") else hh
        name = name[:-1] if name.endswith("]") else name
    name = ws_ascii_lower("".join(WS_HOST_FOLD.get(c, c) for c in name))
    if name.endswith("."):
        name = name[:-1]
    if name == "":
        return any_id
    if ":" in name:
        try:
            name = ipaddress.IPv6Address(name).compressed
        except ValueError:
            pass
    if name in index["exact"]:
        return sites[index["exact"][name]]["id"]
    labels = name.split(".")
    best, best_stars = None, 0
    for wl, idx, stars in index["wild"]:
        if len(wl) != len(labels):
            continue
        if all(a == "*" or a == b for a, b in zip(wl, labels)):
            if best is None or stars < best_stars or (stars == best_stars and idx < best):
                best, best_stars = idx, stars
    if best is not None:
        return sites[best]["id"]
    return any_id


def ws_at_least(n, total, per_mil):
    return n >= WS_MIN_COUNT and n * 1000 >= per_mil * total


def ws_reason(code, node=None, hint=None, obj=None):
    r = {"code": code}
    if node:
        r["node"] = node
    if hint:
        r["hint"] = hint
    if obj:
        r["object"] = obj
    return r


def website_status(v):
    servers = v["servers"]
    nodes = [s["node"] for s in servers]
    if len(set(nodes)) != len(nodes):
        raise Reject("schema", "servers: duplicate node")
    if v["protection"] == "unprotected":
        return {"status": "unknown", "reasons": [{"code": "unprotected"}]}
    if not servers:
        return {"status": "unknown", "reasons": [{"code": "no_server"}]}
    hard, soft, downs = [], [], []
    for s in servers:
        if s["state"] != "ok":
            downs.append(ws_reason(s["state"], s["node"]))
        elif s["baseline_protection"] == "off":
            downs.append(ws_reason("baseline_off", s["node"]))
    if len(downs) == len(servers):
        hard += downs
    else:
        soft += downs
    t = v.get("traffic")
    numbers = v["monitoring"] and v["tracked"] and t is not None
    if numbers:
        if ws_at_least(t["fail_closed"], t["requests"], 50):
            hard.append(ws_reason("fail_closed"))
        if ws_at_least(t["upstream_errors"] + t["upstream_timeouts"], t["forwarded"], 200):
            hard.append(ws_reason("upstream_unreachable"))
        if ws_at_least(t["status_5xx"], t["requests"], 200):
            hard.append(ws_reason("errors_5xx"))
    for h in v.get("site_hints", []):
        soft.append(ws_reason("site_hint", hint=h["code"], obj=h.get("object")))
    for s in servers:
        if s["state"] == "ok" and s["baseline_protection"] == "degraded":
            soft.append(ws_reason("baseline_degraded", s["node"]))
        for h in s["hints"]:
            # D36 open items / D38: schild's own store marks only the server.
            if h["code"] in ("store_near_cap", "store_cap_unreachable", "storage_budget"):
                continue
            soft.append(ws_reason("server_hint", s["node"], h["code"], h.get("object")))
    if hard:
        return {"status": "disrupted", "reasons": hard + soft}
    if soft:
        return {"status": "attention", "reasons": soft}
    if not v["monitoring"]:
        return {"status": "unknown", "reasons": [{"code": "monitoring_off"}]}
    if not v["tracked"]:
        return {"status": "unknown", "reasons": [{"code": "untracked"}]}
    if t is None:
        return {"status": "unknown", "reasons": [{"code": "no_data"}]}
    return {"status": "ok", "reasons": []}


# ---------------------------------------------------------------- waiting page (v0.5, D37, MVP-23 step 1)

WP_LIST_MAX = 32
WP_QVALUE = re.compile(r"(0(\.[0-9]{0,3})?|1(\.0{0,3})?)\Z")
WP_LABEL = re.compile(r"[a-z0-9]([a-z0-9-]*[a-z0-9])?\Z")


def wp_lower(s):
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in s)


def wp_trim(s):
    return s.strip(" \t")


def wp_list(value):
    """[(range, q in thousandths)] of the first 32 elements; invalid q skips the element."""
    out = []
    for part in value.split(",")[:WP_LIST_MAX]:
        params = part.split(";")
        rng = wp_lower(wp_trim(params[0]))
        if not rng:
            continue
        q = 1000
        for p in params[1:]:
            p = wp_trim(p)
            if wp_lower(p[:2]) == "q=":
                s = p[2:]
                if not WP_QVALUE.match(s):
                    q = None
                else:
                    whole, _, frac = s.partition(".")
                    q = int(whole) * 1000 + int((frac + "000")[:3])
                break
        if q is not None:
            out.append((rng, q))
    return out


def wp_document(method, h):
    if method not in ("GET", "HEAD", "POST"):
        return False
    if wp_trim(h.get("x_requested_with", "")):
        return False
    mode = wp_lower(wp_trim(h.get("sec_fetch_mode", "")))
    if mode and mode != "navigate":
        return False
    dest = wp_lower(wp_trim(h.get("sec_fetch_dest", "")))
    if dest:
        return dest == "document"
    html = max([q for r, q in wp_list(h.get("accept", "")) if r in ("text/html", "application/xhtml+xml")], default=0)
    js = max([q for r, q in wp_list(h.get("accept", "")) if r == "application/json" or r.endswith("+json")], default=0)
    return html > 0 and html > js


def wp_language(al):
    best, best_q = "de", 0
    for r, q in wp_list(al):
        primary = r.split("-", 1)[0]
        if primary in ("de", "en") and q > best_q:
            best, best_q = primary, q
    return best


def wp_site_name(host, website):
    if website in (None, "_any", "default") or host.startswith("["):
        return None
    h = host
    if ":" in h:
        h, _, port = h.rpartition(":")
        if not (1 <= len(port) <= 5 and port.isascii() and port.isdigit()):
            return None
    if h.endswith("."):
        h = h[:-1]
    h = wp_lower(h)
    if not 1 <= len(h) <= 253:
        return None
    for label in h.split("."):
        if len(label) > 63 or not WP_LABEL.match(label):
            return None
    return h


def waiting_page(v):
    none = {"answer": "unchanged", "variant": None, "language": None, "retry_after": None, "refresh": None, "body": None, "site_name": None,
            "marker": False, "problem_code": None}
    if not v["enabled"] or v["fail_closed"] not in ("waf_busy", "waf_timeout", "body_busy"):
        return none
    retry = 5 + v["jitter_draw"] % 4
    body = v["method"] != "HEAD"
    h = v["headers"]
    if not wp_document(v["method"], h):
        return dict(none, answer="problem", retry_after=retry, body=body, marker=True, problem_code="waiting")
    post = v["method"] == "POST"
    return {"answer": "waiting_page", "variant": "form" if post else "reload", "language": wp_language(h.get("accept_language", "")),
            "retry_after": retry, "refresh": None if post else retry, "body": body,
            "site_name": wp_site_name(v["host"], v.get("website")), "marker": True, "problem_code": None}


# ---------------------------------------------------------------- access lock (v0.5, D56 and D58, MVP-14 step 1)

AG_EXCEPT_CHARS = set(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._~!$&'()+,=:@/-")


def ag_unhex(c):
    if 48 <= c <= 57:
        return c - 48
    if 97 <= c <= 102:
        return c - 87
    if 65 <= c <= 70:
        return c - 55
    return None


def ag_decode(b):
    out, i = bytearray(), 0
    while i < len(b):
        if b[i] == 0x25 and i + 2 < len(b):
            hi, lo = ag_unhex(b[i + 1]), ag_unhex(b[i + 2])
            if hi is not None and lo is not None:
                out.append(hi * 16 + lo)
                i += 3
                continue
        out.append(b[i])
        i += 1
    return bytes(out)


def ag_canonical(raw):
    b = raw.encode("ascii")
    for _ in range(4):
        d = ag_decode(b)
        if d == b:
            break
        b = d
    b = b.replace(b"\\", b"/")
    segs = []
    for seg in b.split(b"/"):
        seg = seg.split(b"\x00", 1)[0].split(b";", 1)[0]
        if seg in (b"", b"."):
            continue
        if seg == b"..":
            if segs:
                segs.pop()
            continue
        seg = seg.rstrip(b". ")
        if seg:
            segs.append(seg)
    out = []
    for seg in segs:
        t = []
        for c in seg:
            if 65 <= c <= 90:
                t.append(chr(c + 32))
            elif c < 0x21 or c > 0x7e or c == 0x25:
                t.append("%%%02X" % c)
            else:
                t.append(chr(c))
        out.append("".join(t))
    return "/" + "/".join(out)


def ag_protected(raw, patterns):
    """D70: a pattern covers what lies below it, with or without /*; "/" alone is the root."""
    c = ag_canonical(raw)
    for p in patterns:
        below = p.endswith("/*")
        cb = ag_canonical(p[:-2] if below else p)
        if c == cb:
            return True
        if cb == "/":
            if below:
                return True
        elif c.startswith(cb + "/"):
            return True
    return False


def ag_plain(raw):
    if not raw.startswith("/") or any(ord(ch) > 127 or ord(ch) not in AG_EXCEPT_CHARS for ch in raw):
        return False
    if raw == "/":
        return True
    return all(seg != "" and not seg.endswith(".") for seg in raw[1:].split("/"))


def ag_excepted(raw, except_):
    if not ag_plain(raw):
        return False
    for e in except_:
        below = e.endswith("/*")
        base = e[:-2] if below else e
        if raw == base or (below and raw.startswith(base + "/")):
            return True
    return False


def ag_address(s):
    if "%" in s or " " in s or len(s) > 64:
        raise Reject("schema", "address")
    try:
        net = ipaddress.ip_network(s, strict=True)
    except ValueError:
        raise Reject("schema", "address")
    if "/" not in s and net.prefixlen != net.max_prefixlen:
        raise Reject("schema", "address")
    if net.version == 6 and net.network_address.ipv4_mapped is not None:
        raise Reject("schema", "address mapped")
    if net.prefixlen < (16 if net.version == 4 else 32):
        raise Reject("schema", "address too wide")
    return net


def ag_shape(p):
    scope = p["scope"]
    if scope == "site":
        if p.get("paths"):
            raise Reject("schema", "paths only with scope paths")
    else:
        if not p.get("paths"):
            raise Reject("schema", "paths empty")
        if p.get("except"):
            raise Reject("schema", "except only with scope site")
    if "/*" in p.get("paths", []):
        raise Reject("schema", "/* in scope paths")
    for e in p.get("except", []):
        if e in ("/*", "/") or not ag_plain(e[:-2] if e.endswith("/*") else e):
            raise Reject("schema", "except not plain")
    for a in p.get("addresses", []):
        ag_address(a)
    if not p["password"] and not p.get("addresses") and not p["own_networks"]:
        raise Reject("schema", "no way in")


def access_gate(v):
    p = v["protection"]
    ag_shape(p)
    raw = v["path"]
    res = {"answer": "pass", "reason": None, "status": 0, "login_form": False, "canonical_path": ag_canonical(raw)}
    client = None
    if "client_ip" in v:
        try:
            client = ipaddress.ip_address(v["client_ip"])
        except ValueError:
            raise Reject("schema", "client_ip")
        if client.version == 6 and client.ipv4_mapped is not None:
            client = client.ipv4_mapped
    # D58: outside the protection a request passes; inside, every condition
    # set must hold: the address (addresses or own networks) and the session.
    if p["scope"] == "paths" and not ag_protected(raw, p["paths"]):
        res["reason"] = "not_protected"
        return res
    if p["scope"] == "site" and ag_excepted(raw, p.get("except", [])):
        res["reason"] = "except"
        return res
    address_ok, reason = True, None
    if p.get("addresses") or p["own_networks"]:
        if client is not None and any(client.version == n.version and client in n for n in map(ag_address, p.get("addresses", []))):
            reason = "address"
        elif p["own_networks"] and v["allowlisted"]:
            reason = "own_network"
        else:
            address_ok = False
    if address_ok and p["password"] and v["session"] == "valid":
        res["reason"] = "session"
        return res
    if address_ok and not p["password"]:
        res["reason"] = reason
        return res
    res["reason"], res["login_form"] = "locked", p["password"] and address_ok
    if p["scope"] == "site":
        res["answer"], res["status"] = "maintenance", 503
    elif res["login_form"]:
        res["answer"], res["status"] = "login", 403
    else:
        res["answer"], res["status"] = "denied", 403
    return res


# ---------------------------------------------------------------- body limits (v0.5, D41)

BL_SHARED = ("cgnat", "mobile", "tor")
BL_FACTOR = ("cgnat", "mobile")
BL_GIB = 1 << 30


def bl_refusal(code, scope, draw, shared):
    if code in ("body_client_share", "body_waiting_share", "request_waiting_share") and not shared:
        return {"admitted": False, "code": code, "status": 429, "scope": scope, "class": "rejected_limit", "fail_closed": None,
                "retry_after": 5 + draw % 4}
    return {"admitted": False, "code": code, "status": 503, "scope": scope, "class": "fail_closed", "fail_closed": "body_busy",
            "retry_after": None}


def bl_admit(v):
    lim, st, nc = v["limits"], v["state"], v["net_class"]
    factor = 4 if nc in BL_FACTOR else 1
    shared = nc in BL_SHARED

    def over(held, key, f):  # D44: an absent limit applies nothing
        return key in lim and st.get(held, 0) >= lim[key] * f

    if v["client_known"]:
        if st["client"] >= lim["max_per_client"] * factor:
            return bl_refusal("body_client_share", "client", v["jitter_draw"], shared)
        if over("client_waiting_bytes", "max_waiting_bytes_per_client", factor):
            return bl_refusal("body_waiting_share", "client", v["jitter_draw"], shared)
        if st["network"] >= lim["max_per_network"] * factor:
            return bl_refusal("body_client_share", "network", v["jitter_draw"], shared)
        if over("network_waiting_bytes", "max_waiting_bytes_per_network", factor):
            return bl_refusal("body_waiting_share", "network", v["jitter_draw"], shared)
    if st["in_flight"] >= lim["max_in_flight"] or st["in_flight_bytes"] >= lim["max_in_flight_bytes"] \
            or over("waiting_bytes", "max_waiting_bytes", 1) or st.get("pressure", 0) >= 1 \
            or (st.get("large") and over("large_in_flight", "max_large_in_flight", 1)):
        return bl_refusal("body_busy", "gateway", 0, True)
    return {"admitted": True, "code": None, "status": None, "scope": None, "class": None, "fail_closed": None, "retry_after": None}


def bl_request_admit(v):  # D45
    lim, st, nc = v["request_limits"], v["request_state"], v["net_class"]
    factor = 4 if nc in BL_FACTOR else 1
    shared = nc in BL_SHARED
    if v["client_known"]:
        if st["client_waiting"] >= lim["max_waiting_per_client"] * factor:
            return bl_refusal("request_waiting_share", "client", v["jitter_draw"], shared)
        if st["network_waiting"] >= lim["max_waiting_per_network"] * factor:
            return bl_refusal("request_waiting_share", "network", v["jitter_draw"], shared)
    if st["waiting"] >= lim["max_waiting"] or st.get("pressure", 0) >= 2:
        return bl_refusal("request_busy", "gateway", 0, True)
    return {"admitted": True, "code": None, "status": None, "scope": None, "class": None, "fail_closed": None, "retry_after": None}


def bl_large_in_flight(v):  # D45
    if v.get("configured"):
        return {"max_large_in_flight": v["configured"]}
    mem = v["memory_bytes"]
    if mem == 0:
        return {"max_large_in_flight": 256}
    return {"max_large_in_flight": min(16384, max(16, mem * 128 // BL_GIB))}


def bl_request_limit(v):  # D45
    if v.get("configured"):
        return {"max_waiting": v["configured"]}
    mem = v["memory_bytes"]
    if mem == 0:
        return {"max_waiting": 4096}
    return {"max_waiting": min(1 << 20, max(256, mem // (4 * (128 << 10))))}


def bl_pressure(v):  # D45
    mem, held = v["memory_bytes"], v["held_bytes"]
    if mem <= 0:
        return {"pressure": 0}
    if held >= mem // 100 * 85:
        return {"pressure": 2}
    return {"pressure": 1 if held >= mem // 100 * 70 else 0}


def bl_read_end(v):  # D45: a stall is no attack (E10)
    gone = v["end"] != "error"
    return {"code": "client_gone" if gone else "body_read_error", "incident": not gone}


def bl_read_outcome(v):  # D46: nobody blocked a client that left or stalled
    return {"outcome": "blocked" if v["end"] == "error" else "client_gone"}


def bl_conn_admit(v):  # D46
    lim, st = v["conn_limits"], v["conn_state"]
    factor = 4 if v["net_class"] in ("cgnat", "mobile") else 1
    per_peer = v["peer_known"] and not v["proxy"]
    scope, idle = None, False
    if per_peer and st["client"] >= lim["max_per_client"] * factor:
        scope, idle = "client", st.get("client_idle", False)
    elif per_peer and st["network"] >= lim["max_per_network"] * factor:
        scope, idle = "network", st.get("network_idle", False)
    elif st["open"] >= lim["max_open"]:
        scope, idle = "gateway", st.get("open_idle", False)
    if scope is None:
        return {"admitted": True, "evict": None, "refused": None}
    return {"admitted": idle, "evict": scope if idle else None, "refused": None if idle else scope}


def bl_conn_limit(v):  # D46
    if v.get("configured"):
        return {"max_open": v["configured"]}
    mem = v["memory_bytes"]
    if mem == 0:
        return {"max_open": 8192}
    return {"max_open": min(1 << 20, max(1024, mem // (4 * (64 << 10))))}


def bl_held(v):  # D46
    s = v["stat"]
    outside = sum(s.get(k, 0) for k in ("sock", "slab", "kernel_stack", "pagetables", "shmem", "file_dirty", "file_writeback"))
    return {"held_bytes": s.get("anon", 0) + outside, "outside_bytes": outside}


def bl_in_flight(v):
    if v.get("configured"):
        return {"max_in_flight": v["configured"]}
    mem = v["memory_bytes"]
    if mem == 0:
        return {"max_in_flight": 1024}
    return {"max_in_flight": min(65536, max(64, mem * 512 // BL_GIB))}


# unicode.IsSpace of Go, which strings.TrimSpace uses. str.strip() without an
# argument also removes U+001C to U+001F.
BL_GO_SPACE = "\t\n\v\f\r \x85\xa0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000"


def bl_class(content_type):
    # strings.ToLower of Go maps U+0130 to a plain i, str.lower() to two code points.
    media = content_type.split(";", 1)[0].replace("\u0130", "i").lower().strip(BL_GO_SPACE)
    if media == "multipart/form-data":
        return "multipart"
    if media.startswith("multipart/"):
        return "raw"
    if media in ("application/x-www-form-urlencoded", "application/json", "application/xml") or media.startswith("text/") \
            or media.endswith("+json") or media.endswith("+xml"):
        return "text"
    return "raw"


def bl_size(v):
    if "content_types" in v:  # D44: a header sent more than once names no parser
        cls = "raw"
    else:
        cls = bl_class(v.get("content_type", ""))
    raw, whole, n = v["raw_limit_bytes"], v["body_limit_bytes"], v["bytes"]
    limit = min(raw, whole) if cls == "raw" else whole
    code = None
    if n > whole:
        code = "body_too_large"
    elif n > limit:
        code = "raw_body_too_large"
    return {"class": cls, "limit_bytes": limit, "code": code, "status": 413 if code else None,
            "held_bytes": n * 2 if cls == "multipart" else n}


def bl_rate(v):
    complete = v["end_ms"] // 30000
    bins = [0] * complete
    for a in v["arrivals"]:
        w = a["t_ms"] // 30000
        if w < complete:
            bins[w] += a["bytes"]
    rates = [b // 30 for b in bins]
    slow = [i for i, r in enumerate(rates) if r < 1024]
    return {"windows": rates, "below_min": bool(slow), "first_below": slow[0] if slow else None}


def bl_waiting(v):  # D44
    n, in_memory = v["bytes"], v["bytes"] <= 128 << 10
    return {"in_memory": in_memory, "waiting_bytes": (128 << 10) + (n if in_memory else min(n, 384 << 10))}  # D45


def bl_waiting_limit(v):  # D44
    if v.get("configured_bytes"):
        return {"max_waiting_bytes": v["configured_bytes"]}
    mem = v["memory_bytes"]
    if mem == 0:
        return {"max_waiting_bytes": 256 << 20}
    return {"max_waiting_bytes": min(16 * BL_GIB, max(32 << 20, mem // 4))}


def body_limits(v):
    return {"admit": bl_admit, "in_flight": bl_in_flight, "size": bl_size, "rate": bl_rate, "waiting": bl_waiting,
            "waiting_limit": bl_waiting_limit, "large_in_flight": bl_large_in_flight, "request_admit": bl_request_admit, "request_limit": bl_request_limit,
            "pressure": bl_pressure, "read_end": bl_read_end, "read_outcome": bl_read_outcome, "conn_admit": bl_conn_admit, "conn_limit": bl_conn_limit,
            "held": bl_held}[v["op"]](v)


# ---------------------------------------------------------------- agent block writes (v0.5, D42)

AB_PROTECTED = [ipaddress.ip_network(n) for n in (
    "0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16", "172.16.0.0/12", "192.168.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
    "::/128", "::1/128", "fc00::/7", "fe80::/10", "ff00::/8")]


def ab_verdict(status, code=None, allowed=False, effect=None, changed=False, limited_by=None, max_duration=None, persisted=False, counts=False, retry=None):
    return {"allowed": allowed, "status": status, "code": code, "effect": effect, "changed": changed, "limited_by": limited_by,
            "max_duration_s": max_duration, "persisted": persisted, "counts_budget": counts, "retry_after": retry}


def ab_protected(text):
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return True
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return any(ip.version == n.version and ip in n for n in AB_PROTECTED)


def ab_over_budget(b):
    if b["writes_used"] >= b["writes_per_hour"]:
        return ab_verdict(429, "block_budget", retry=max(3600 - b["oldest_write_age_s"], 1))
    return None


def ab_create(v):
    t, b = v["target"], v["budget"]
    if v["scope"] != "blocks:write":
        return ab_verdict(403, "scope_required")
    if not v["reason"].strip(" \t\r\n") or v["duration_s"] < 60:
        return ab_verdict(400, "invalid")
    if not t["exists"]:
        return ab_verdict(404, "not_found")
    if t.get("gone"):
        return ab_verdict(409, "target_gone")
    if t.get("attribution") not in ("tcp_peer", "trusted_proxy"):
        return ab_verdict(409, "unreliable_attribution")
    if ab_protected(t.get("address", "")):
        return ab_verdict(409, "private_address")
    if t.get("own"):
        return ab_verdict(409, "own_address")
    if t.get("net_class") in ("cgnat", "mobile", "tor"):
        return ab_verdict(409, "shared_address")
    if t.get("released"):
        return ab_verdict(409, "released")
    cap = 604800 if t.get("net_class") == "hosting" else 86400
    if v["duration_s"] > cap:
        return ab_verdict(400, "duration_over_cap", max_duration=cap)
    if t.get("running"):
        return ab_verdict(200, allowed=True, effect="block")
    over = ab_over_budget(b)
    if over:
        return over
    if v["mode"] == "observe":
        return ab_verdict(200, allowed=True, effect="would_block", limited_by="gateway_observe", counts=True)
    if b["running"] >= b["max_blocks"]:
        return ab_verdict(429, "block_cap", retry=3600)
    return ab_verdict(200, allowed=True, effect="block", changed=True, persisted=v["duration_s"] > 86400, counts=True)


def ab_lift(v):
    if v["scope"] != "blocks:write":
        return ab_verdict(403, "scope_required")
    if not v["reason"].strip(" \t\r\n"):
        return ab_verdict(400, "invalid")
    if v["status"] == "missing":
        return ab_verdict(404, "not_found")
    if v["status"] == "unblocked":
        return ab_verdict(200, allowed=True)
    if not v["running"]:
        return ab_verdict(409, "no_running_block")
    return ab_over_budget(v["budget"]) or ab_verdict(200, allowed=True, changed=True, counts=True)


def agent_block(v):
    return ab_create(v) if v["op"] == "create" else ab_lift(v)


# ---------------------------------------------------------------- storage bounds (v0.5, D38)

SB_MIB = 1 << 20
SB_ORDER = ["sampled", "logged", "would_block", "blocked", "incident", "record"]


def sb_class(r):
    k = r["kind"]
    if k == "incident":
        return "incident"
    if k == "agent_call":
        return "agent_call"
    t = r["type"]
    if t in ("schild.request.evaluated.v1", "schild.request.blocked.v1"):
        if r.get("sampled", False):
            return "sampled"
        o = r.get("outcome", "")
        if o == "would_block":
            return "would_block"
        if o in ("blocked", "challenged"):
            return "blocked"
        return "logged"
    if t in ("schild.session.flagged.v1", "schild.environment.anomaly.v1"):
        return "logged"
    if t in ("schild.behaviour.triggered.v1", "schild.ratelimit.exceeded.v1"):
        return "would_block" if r.get("action", "") == "observe" else "blocked"
    return "record"


def sb_cap_pass(v):
    ids = [r["id"] for r in v["rows"]]
    if len(set(ids)) != len(ids):
        raise Reject("schema", "rows: duplicate id")
    used = v["base_bytes"] + v["wal_bytes"] + sum(r["bytes"] for r in v["rows"])
    before = used
    cap = v["max_size_mb"] * SB_MIB
    if used <= cap:
        return {"used_before": before, "deleted": [], "used_after": used, "unreachable": False}
    target = cap * 950 // 1000
    by = {}
    for r in v["rows"]:
        by.setdefault(sb_class(r), []).append(r)
    for rs in by.values():
        rs.sort(key=lambda r: (r["t"], r["id"].encode()))
    deleted = []

    def drop(rs, n):
        nonlocal used
        for r in rs[:n]:
            if used <= target:
                return
            used -= r["bytes"]
            deleted.append(r["id"])

    calls = by.get("agent_call", [])
    drop(calls, len(calls) // 2)
    for c in SB_ORDER:
        rs = by.get(c, [])
        n = len(rs) - v["floor_rows"]
        if n > 0:
            drop(rs, n)
    return {"used_before": before, "deleted": deleted, "used_after": used, "unreachable": used > cap}


def sb_budget(v):
    cap = v["max_size_mb"] * SB_MIB
    b = cap + cap * 100 // 1000 + 2 * 64 * SB_MIB + v["metrics_bound_bytes"] + v["requests_max_size_mb"] * SB_MIB + v.get("body_spool_bytes", 0)
    need = max(0, b - v["schild_used_bytes"])
    reserve = max(1 << 30, min(v["fs_total_bytes"] * 50 // 1000, 20 << 30))  # 2026-10-29: capped at 20 GiB
    verdict = "ok"
    if b > v["fs_total_bytes"]:
        verdict = "error"
    elif v["fs_avail_bytes"] - need < reserve:
        verdict = "hint"
    return {"budget_bytes": b, "need_bytes": need, "reserve_bytes": reserve, "verdict": verdict}


def sb_rule_key(r):
    if "limit" in r:
        return "limit:" + r["limit"]
    return ",".join(sorted(set(r["rules"]), key=lambda x: x.encode()))


def sb_aggregate(v):
    draws = [r["draw"] for r in v["requests"]]
    if len(set(draws)) != len(draws):
        raise Reject("schema", "requests: duplicate draw")
    open_, newest, nums, incs = {}, -1, [], []
    for r in v["requests"]:
        t = r["t"]
        minute = t - t % 60000
        if minute > newest:
            open_, newest = {}, minute
        k = (r["client"], sb_rule_key(r))
        if k in open_ and minute == newest:
            a = incs[open_[k]]
            a["count"] += 1
            a["first_ms"] = min(a["first_ms"], t)
            a["last_ms"] = max(a["last_ms"], t)
            nums.append(a["incident"])
            continue
        incs.append({"incident": r["draw"], "client": r["client"], "rule_key": k[1], "minute_ms": minute, "count": 1, "first_ms": t, "last_ms": t})
        nums.append(r["draw"])
        if minute == newest and len(open_) < v["max_open"]:
            open_[k] = len(incs) - 1
    return {"numbers": nums, "incidents": incs}


def sb_projection(v):
    none = {"hint": False, "level": None, "days_left": None, "rate_bytes_per_day": None}
    pts = [(i, d["min_used_bytes"]) for i, d in enumerate(v["days"]) if d["samples"] >= 36]
    if len(pts) < 4:
        return none
    up = sum(1 for i in range(1, len(pts)) if pts[i][1] > pts[i - 1][1])
    if up * 3 < 2 * (len(pts) - 1):
        return none
    sl = [(pts[j][1] - pts[i][1], pts[j][0] - pts[i][0]) for i in range(len(pts)) for j in range(i + 1, len(pts))]
    sl.sort(key=functools.cmp_to_key(lambda a, b: (a[0] * b[1] > b[0] * a[1]) - (a[0] * b[1] < b[0] * a[1])))
    num, den = sl[(len(sl) - 1) // 2]
    if num <= 0:
        return none
    free = max(0, v["total_bytes"] - v["used_bytes"])
    left = free * den // num
    if left >= 14:
        return none
    return {"hint": True, "level": "warning" if left < 3 else "notice", "days_left": left, "rate_bytes_per_day": num // den}


def storage_bounds(v):
    op = v["op"]
    if op == "check_due":
        return {"due": v["written_bytes"] * 10 >= v["max_size_mb"] * SB_MIB or v["elapsed_s"] >= 600}
    if op == "cap_pass":
        return sb_cap_pass(v)
    if op == "disk_budget":
        return sb_budget(v)
    if op == "incident_aggregate":
        return sb_aggregate(v)
    return sb_projection(v)


WS_PLACEHOLDER = re.compile(r"\{[a-z0-9_]{1,32}\}")


# ---------------------------------------------------------------- ingress order (v0.5, D31 amendment 2026-10-29)

IO_MAX_DEPTH = 32


def io_esc(s):
    return s.replace("~", "~0").replace("/", "~1")


def io_read_route(x, p):
    if not isinstance(x, dict):
        raise Reject("schema", p + ": a route is not an object")
    for k in sorted(x):
        v = x[k]
        if k == "group":
            if not isinstance(v, str):
                raise Reject("schema", p + "/group")
        elif k == "match":
            if not isinstance(v, list) or not all(isinstance(s, dict) for s in v):
                raise Reject("schema", p + "/match")
        elif k == "terminal":
            if not isinstance(v, bool):
                raise Reject("schema", p + "/terminal")
        elif k == "handle":
            if not isinstance(v, list):
                raise Reject("schema", p + "/handle")
            for h in v:
                if not isinstance(h, dict) or not isinstance(h.get("handler"), str) or h["handler"] == "":
                    raise Reject("schema", p + "/handle: handler")
        else:
            raise Reject("schema", p + ": unknown route field " + k)
    return x


def io_read_list(v, ptr):
    if not isinstance(v, list):
        raise Reject("schema", ptr + ": routes is not an array")
    return [{"route": io_read_route(x, ptr + "/" + str(i)), "ptr": ptr + "/" + str(i), "strip": False} for i, x in enumerate(v)]


def io_handle_path_prefix(r):
    m = r.get("match")
    if not isinstance(m, list) or len(m) != 1 or not isinstance(m[0], dict) or len(m[0]) != 1:
        return None
    paths = m[0].get("path")
    if not isinstance(paths, list) or len(paths) != 1 or not isinstance(paths[0], str) or not paths[0].startswith("/"):
        return None
    p = paths[0]
    if p.endswith("/*"):
        p = p[:-2]
    elif p.endswith("*"):
        p = p[:-1]
    return p if p != "" else None


def io_is_strip(r, prefix):
    if "match" in r or "group" in r:
        return False
    hs = r.get("handle", [])
    if len(hs) != 1:
        return False
    h = hs[0]
    return len(h) == 2 and h.get("handler") == "rewrite" and h.get("strip_path_prefix") == prefix


def io_directive(h):
    if "method" in h:
        return "method"
    for k in ("strip_path_prefix", "strip_path_suffix", "uri_substring", "path_regexp", "query"):
        if k in h:
            return "uri"
    return "rewrite"


def io_lower(s):
    return "".join(chr(ord(c) + 32) if "A" <= c <= "Z" else c for c in s)


# D43: placeholders no client can put bytes into, and those that hold the Host.
IO_SERVER_PLACEHOLDERS = ("{http.request.scheme}", "{http.request.uuid}", "{http.request.proto}",
                          "{http.request.remote}", "{http.request.remote.host}", "{http.request.remote.port}",
                          "{http.reverse_proxy.upstream.host}", "{http.reverse_proxy.upstream.hostport}", "{http.reverse_proxy.upstream.port}")
IO_HOST_PLACEHOLDERS = ("{http.request.host}", "{http.request.hostport}", "{http.request.port}")


def io_value_class(s):
    for p in IO_SERVER_PLACEHOLDERS:
        s = s.replace(p, "")
    rest = s
    for p in IO_HOST_PLACEHOLDERS:
        rest = rest.replace(p, "")
    if "{" in rest:
        return "client"
    return "host" if rest != s else "literal"


def io_header_ops(v):
    if not isinstance(v, dict):
        return [], [], []
    hide, write, hosts = set(), set(), set()
    if isinstance(v.get("delete"), list):
        for x in v["delete"]:
            if isinstance(x, str):
                hide.add(io_lower(x))
    for op in ("set", "add"):
        m = v.get(op)
        if not isinstance(m, dict):
            continue
        for n, vals in m.items():
            if op == "set":
                hide.add(io_lower(n))
            for x in vals if isinstance(vals, list) else []:
                c = io_value_class(x) if isinstance(x, str) else "literal"
                if c == "client":
                    write.add(io_lower(n))
                elif c == "host":
                    hosts.add(io_lower(n))
    if isinstance(v.get("replace"), dict):
        for n in v["replace"]:
            hide.add(io_lower(n))
            write.add(io_lower(n))
    return sorted(hide), sorted(write), sorted(hosts)


def io_overlaps(hide, name):
    if "{" in hide or "{" in name or hide == "*" or name == "*":
        return True
    pre, suf = hide.startswith("*"), hide.endswith("*")
    if pre and suf:
        return hide[1:-1] in name
    if pre:
        return name.endswith(hide[1:])
    if suf:
        return name.startswith(hide[:-1])
    return hide == name


def io_common(hides, writes):
    for h in hides:
        for n in writes:
            if io_overlaps(h, n):
                return h if n == "*" or "{" in n else n
    return None


def io_nested(h, skip_top, ptr):
    out = []

    def visit(v, p, top, in_err):
        if isinstance(v, dict):
            for k in sorted(v):
                kp = p + "/" + io_esc(k)
                if k == "routes" and isinstance(v[k], list):
                    if top and skip_top:
                        continue
                    items = io_read_list(v[k], kp)
                    if items:
                        out.append((items, in_err))
                    continue
                visit(v[k], kp, False, in_err or k == "errors")
        elif isinstance(v, list):
            for i, c in enumerate(v):
                visit(c, p + "/" + str(i), False, in_err)

    visit(h, ptr, True, False)
    return out


class IOWalker:
    def __init__(self, named):
        self.named = named
        self.lists = 0
        self.events = []
        self.stack = set()

    def routes(self, items, guarded, frames, depth):
        if depth > IO_MAX_DEPTH:
            raise Reject("schema", "route lists nested too deep")
        self.lists += 1
        lst = self.lists
        guards = False
        groups = set()
        for i, it in enumerate(items):
            r = it["route"]
            match = r.get("match")
            conditional = isinstance(match, list) and len(match) > 0
            group = r.get("group", "")
            if group != "":
                if group in groups:
                    conditional = True
                groups.add(group)
            fr = frames + [(lst, i, group)]
            p = guarded
            handle = r.get("handle", [])
            for j, h in enumerate(handle):
                hp = it["ptr"] + "/handle/" + str(j)
                name = h["handler"]
                if name == "schild":
                    self.events.append({"schild": True, "ptr": hp, "frames": fr, "guarded": p})
                    p = True
                    if not conditional:
                        guarded = guards = True
                elif name == "rewrite":
                    if not it["strip"]:
                        self.events.append({"schild": False, "ptr": hp, "frames": fr, "guarded": p, "directive": io_directive(h)})
                elif name == "headers":
                    hides, writes, host = io_header_ops(h.get("request"))
                    if hides or writes or host:
                        self.events.append({"schild": False, "headers": True, "ptr": hp, "frames": fr, "guarded": p, "hides": hides, "writes": writes, "host": host})
                elif name == "reverse_proxy":
                    hs = h.get("headers")
                    if isinstance(hs, dict):
                        _, writes, host = io_header_ops(hs.get("request"))
                        if writes or host:
                            self.events.append({"schild": False, "headers": True, "ptr": hp, "frames": fr, "guarded": p, "hides": [], "writes": writes, "host": host})
                elif name == "subroute":
                    sub = io_read_list(h.get("routes"), hp + "/routes")
                    if sub and len(handle) == 1:
                        prefix = io_handle_path_prefix(r)
                        if prefix is not None and io_is_strip(sub[0]["route"], prefix):
                            sub[0]["strip"] = True
                    if self.routes(sub, p, fr, depth + 1):
                        p = True
                        if not conditional:
                            guarded = guards = True
                elif name == "invoke":
                    nm = h.get("name") if isinstance(h.get("name"), str) else ""
                    if nm not in self.named:
                        raise Reject("schema", "invoke of an unknown named route " + nm)
                    if nm in self.stack:
                        raise Reject("schema", "named route invokes itself " + nm)
                    self.stack.add(nm)
                    g = self.routes([{"route": self.named[nm], "ptr": "/named_routes/" + io_esc(nm), "strip": False}], p, fr, depth + 1)
                    self.stack.discard(nm)
                    if g:
                        p = True
                        if not conditional:
                            guarded = guards = True
                for items2, is_err in io_nested(h, name == "subroute", hp):
                    self.routes(items2, False if is_err else p, fr, depth + 1)
        return guards


def io_precedes(r, s):
    for a, b in zip(r["frames"], s["frames"]):
        if a == b:
            continue
        return not (a[0] == b[0] and a[1] != b[1] and a[2] != "" and a[2] == b[2])
    return True


def io_first(evs):
    for i, r in enumerate(evs):
        if r["schild"] or r.get("headers") or r["guarded"]:
            continue
        for s in evs[i + 1:]:
            if s["schild"] and io_precedes(r, s):
                return r, s
    return None


def io_hidden(evs, own):
    host_hidden = any(e.get("headers") and not e["guarded"] and any(io_overlaps(x, "host") for x in e["hides"]) for e in evs[:own])
    for i, h in enumerate(evs[:own]):
        if not h.get("headers") or h["guarded"] or not h["hides"]:
            continue
        for j in range(i + 1, len(evs)):
            s = evs[j]
            if not s["schild"] or not io_precedes(h, s):
                continue
            for w in evs[j + 1:]:
                if not w.get("headers"):
                    continue
                writes = sorted(set(w["writes"]) | set(w["host"])) if host_hidden else w["writes"]
                if not writes or not io_precedes(h, w) or not io_precedes(s, w):
                    continue
                name = io_common(h["hides"], writes)
                if name is not None:
                    return h, s, w, name
    return None


def ingress_order(v):
    out = []
    servers = v["servers"]
    for name in sorted(servers):
        srv = servers[name]
        named = {}
        if "named_routes" in srv:
            nr = srv["named_routes"]
            if not isinstance(nr, dict):
                raise Reject("schema", "named_routes")
            for k in sorted(nr):
                named[k] = io_read_route(nr[k], "/named_routes/" + io_esc(k))
        site = io_read_list(srv["routes"], "/routes") if "routes" in srv else []
        errs = []
        if "errors" in srv:
            if not isinstance(srv["errors"], dict):
                raise Reject("schema", "/errors")
            if "routes" in srv["errors"]:
                errs = io_read_list(srv["errors"]["routes"], "/errors/routes")

        def walk(it):
            r = {k: x for k, x in it["route"].items() if k != "match"}
            w = IOWalker(named)
            w.routes([{"route": r, "ptr": it["ptr"], "strip": False}], False, [], 1)
            return w.events

        err_events = []
        for k, it in enumerate(errs):
            for e in walk(it):
                err_events.append(dict(e, frames=[(-1 - k, 0, "")] + e["frames"]))
        for i, it in enumerate(site + errs):
            evs = walk(it)
            hosts = []
            for s in it["route"].get("match", []):
                for hh in s.get("host", []) if isinstance(s.get("host"), list) else []:
                    if isinstance(hh, str):
                        hosts.append(hh)
            hit = io_first(evs)
            if hit:
                out.append({"code": "rewrite_before_schild", "msg_key": "ingress.err.rewrite_before_schild", "server": name,
                            "route": it["ptr"], "hosts": hosts, "directive": hit[0]["directive"], "rewrite": hit[0]["ptr"], "schild": hit[1]["ptr"]})
            found = io_hidden(evs + err_events if i < len(site) else evs, len(evs))
            if found:
                out.append({"code": "header_hidden_from_schild", "msg_key": "ingress.err.header_hidden_from_schild", "server": name,
                            "route": it["ptr"], "hosts": hosts, "directive": "request_header", "hide": found[0]["ptr"], "schild": found[1]["ptr"],
                            "restore": found[2]["ptr"], "header": found[3]})
    return {"findings": out}


# ---------------------------------------------------------------- re-checked requests (v0.5, D33 amendment 2026-10-29)

def request_recheck(v):
    evs = v["evaluations"]
    stop = lambda o: o not in ("passed", "would_block")
    for e in evs[:-1]:
        if stop(e["outcome"]):
            raise Reject("schema", "a stop that is not the last evaluation")
    last = evs[-1]
    outcome = "would_block" if any(e["outcome"] == "would_block" for e in evs) else "passed"
    if stop(last["outcome"]):
        outcome = last["outcome"]
    rules, seen = [], set()
    for e in evs:
        for r in e["rules"]:
            if r not in seen and len(rules) < 128:
                seen.add(r)
                rules.append(r)
    checked = None
    if len(evs) > 1:
        checked = [e["path"] for i, e in enumerate(evs) if len(evs) <= 4 or i < 3 or i == len(evs) - 1]
    return {"requests": 1, "rechecked": len(evs) > 1, "outcome": outcome, "detection": any(e["detection"] for e in evs),
            "path": last["path"], "checked_paths": checked, "rules": rules, "score": max(e["score"] for e in evs)}


def ws_rx_escape(x):
    return "".join("\\" + c if c in "\\.+*?()|[]{}^$" else c for c in x)


def website_exception(v):
    path = v["path"]
    if any(c in WS_PLACEHOLDER.sub("", path) for c in "{}"):
        raise Reject("schema", "path: braces only as {name} segments")
    if "{" not in path and "}" not in path:
        op = "@streq " + path
    else:
        out, rest = "@rx ^", path
        while True:
            m = WS_PLACEHOLDER.search(rest)
            if m is None:
                break
            out += ws_rx_escape(rest[:m.start()]) + "[^/]+"
            rest = rest[m.end():]
        op = out + ws_rx_escape(rest) + "$"
    rule = v["rule_id"]
    ctl = "ctl:ruleRemoveById=" + rule
    if "target" in v:
        ctl = "ctl:ruleRemoveTargetById=" + rule + ";" + v["target"]
    rid = str(v["id"])
    hosts = v["website"]["hosts"]
    if not hosts:
        return {"scope": "gateway", "snippet": "# schild: exception for rule " + rule + " on " + path + ", every website of this gateway\n"
                + 'SecRule REQUEST_FILENAME "' + op + '" "id:' + rid + ',phase:1,pass,nolog,t:none,' + ctl + '"\n'}
    alts = []
    for h in hosts:
        if ":" in h:
            alts.append("\\[" + ws_rx_escape(h) + "\\]")
        else:
            alts.append("\\.".join("[a-z0-9-]+" if lbl == "*" else ws_rx_escape(lbl) for lbl in h.split(".")))
    hre = "^(?:" + "|".join(alts) + ")(?::[0-9]{1,5})?$"
    return {"scope": "website", "snippet": "# schild: exception for rule " + rule + " on " + path + ", website " + v["website"]["id"] + " only\n"
            + 'SecRule REQUEST_HEADERS:Host "@rx ' + hre + '" "id:' + rid + ',phase:1,pass,nolog,t:none,t:lowercase,chain"\n'
            + '    SecRule REQUEST_FILENAME "' + op + '" "t:none,' + ctl + '"\n'}


# ---------------------------------------------------------------- CrowdSec Hub source (D39, contracts/crowdsec-hub.md)

HUB_COLLECTION = "crowdsecurity/appsec-virtual-patching"
HUB_MAX_INDEX, HUB_MAX_RULES, HUB_MAX_CONTENT, HUB_MAX_SET = 32 << 20, 500, 64 << 10, 1 << 20
HUB_MAX_SET_LINES, HUB_COST_MAX_RATIO, HUB_COST_FLOOR_PERCENT = 2000, 4, 200  # D43
HUB_MAX_GROUPS, HUB_MAX_DEPTH, HUB_MAX_LINES = 8, 8, 8
HUB_ZONES = {"ARGS": "ARGS_GET", "ARGS_NAMES": "ARGS_GET_NAMES", "BODY_ARGS": "ARGS_POST", "BODY_ARGS_NAMES": "ARGS_POST_NAMES",
             "COOKIES": "REQUEST_COOKIES", "COOKIES_NAMES": "REQUEST_COOKIES_NAMES", "FILES": "FILES", "FILES_NAMES": "FILES_NAMES",
             "FILENAMES": "FILES", "HEADERS": "REQUEST_HEADERS", "HEADERS_NAMES": "REQUEST_HEADERS_NAMES", "METHOD": "REQUEST_METHOD",
             "PROTOCOL": "REQUEST_PROTOCOL", "URI": "REQUEST_FILENAME", "URI_FULL": "REQUEST_URI", "RAW_BODY": "REQUEST_BODY"}
HUB_SCALAR_ZONES = {"METHOD", "PROTOCOL", "URI", "URI_FULL", "RAW_BODY"}
HUB_TRANSFORMS = {"lowercase": "lowercase", "uppercase": "uppercase", "length": "length", "trim": "trim", "trim_left": "trimLeft",
                  "trim_right": "trimRight", "htmlentitydecode": "htmlEntityDecode", "html_entity_decode": "htmlEntityDecode",
                  "js_decode": "jsDecode", "css_decode": "cssDecode", "urldecode": "urlDecode", "hexdecode": "hexDecode",
                  "cmdline": "cmdLine", "b64decode": "base64Decode", "b64decode_lenient": "base64DecodeExt",
                  "normalize_path": "normalizePath", "normalizepath": "normalizePath", "normalize_path_win": "normalizePathWin",
                  "normalizepathwin": "normalizePathWin", "remove_whitespaces": "removeWhitespace",
                  "compress_whitespaces": "compressWhitespace", "remove_nulls": "removeNulls", "replace_nulls": "replaceNulls",
                  "remove_comments": "removeComments", "replace_comments": "replaceComments"}
HUB_STRING = {"regex": "rx", "equals": "streq", "startsWith": "beginsWith", "endsWith": "endsWith", "contains": "contains"}
HUB_NOARG = {"libinjectionSQL": "detectSQLi", "libinjectionXSS": "detectXSS"}
HUB_NUMERIC = {"gt": "gt", "lt": "lt", "gte": "ge", "lte": "le", "eq": "eq"}
RE_HUB_NAME = re.compile(r"crowdsecurity/vpatch-[A-Za-z0-9._-]{1,128}\Z")
RE_HUB_VERSION = re.compile(r"[0-9]{1,6}\.[0-9]{1,6}\Z")
RE_HUB_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
RE_HUB_CVE = re.compile(r"[Cc][Vv][Ee]\.(CVE-[0-9]{4}-[0-9]{4,8})\Z")
RE_HUB_CWE = re.compile(r"[Cc][Ww][Ee]\.(CWE-[0-9]{1,6})\Z")
RE_HUB_ATTACK = re.compile(r"[Aa][Tt][Tt][Aa][Cc][Kk]\.(T[0-9]{4}(\.[0-9]{3})?)\Z")


class HubSkip(Exception):
    def __init__(self, code):
        Exception.__init__(self, code)
        self.code = code


def hub_base_id(name):
    h = hashlib.sha256(("schild.crowdsec_hub.rule_id/1\n" + name).encode("utf-8")).digest()
    return HUB_RULE_ID_MIN + int.from_bytes(h[:8], "big") % ((HUB_RULE_ID_MAX - HUB_RULE_ID_MIN + 1) // HUB_MAX_GROUPS) * HUB_MAX_GROUPS


def hub_yaml(b):
    """Strict event walk: every scalar stays the text it was written as."""
    import yaml
    try:
        evs = list(yaml.parse(b.decode("utf-8"), Loader=yaml.SafeLoader))
    except (UnicodeDecodeError, yaml.YAMLError):
        raise HubSkip("yaml")
    docs = sum(1 for e in evs if isinstance(e, yaml.DocumentStartEvent))
    if docs != 1:
        raise HubSkip("yaml")
    pos = [2]

    def node(depth):
        if depth > 32:
            raise HubSkip("yaml")
        e = evs[pos[0]]
        pos[0] += 1
        if isinstance(e, yaml.AliasEvent) or getattr(e, "anchor", None):
            raise HubSkip("yaml")
        if getattr(e, "tag", None):
            raise HubSkip("yaml")
        if isinstance(e, yaml.MappingStartEvent):
            m = {}
            while not isinstance(evs[pos[0]], yaml.MappingEndEvent):
                k = evs[pos[0]]
                pos[0] += 1
                if not isinstance(k, yaml.ScalarEvent) or k.tag or k.anchor or k.value == "<<" or k.value in m:
                    raise HubSkip("yaml")
                m[k.value] = node(depth + 1)
            pos[0] += 1
            return m
        if isinstance(e, yaml.SequenceStartEvent):
            a = []
            while not isinstance(evs[pos[0]], yaml.SequenceEndEvent):
                a.append(node(depth + 1))
            pos[0] += 1
            return a
        if e.style is None and e.value in ("", "~", "null", "Null", "NULL"):
            return None
        return e.value
    return node(0)


def hub_list(v):
    if v is None:
        return []
    if not isinstance(v, list) or any(not isinstance(x, str) for x in v):
        raise HubSkip("node_shape")
    return v


def hub_value(v):
    if v == "":
        raise HubSkip("missing_value")
    if len(v.encode("utf-8")) > 2048 - 32:
        raise HubSkip("value_chars")
    if any(not (" " <= c <= "~") for c in v) or '"' in v or v.endswith("\\") or v[0] == " " or v[-1] == " " or "%{" in v:
        raise HubSkip("value_chars")


def hub_leaf(n):
    for k in sorted(n):
        if k not in ("zones", "variables", "transform", "match", "name"):
            raise HubSkip("unknown_key")
    zs = hub_list(n.get("zones"))
    if not zs:
        raise HubSkip("node_shape")
    vs = hub_list(n.get("variables"))
    ts = hub_list(n.get("transform"))
    count = length = False
    mapped = ["none"]
    for t in ts:
        if t == "count":
            count = True
            continue
        if t == "length":
            length = True
        if t not in HUB_TRANSFORMS:
            raise HubSkip("unsupported_transform")
        mapped.append(HUB_TRANSFORMS[t])
    if len(mapped) > 16:
        raise HubSkip("unsupported_transform")
    notes, out = [], []
    for z in zs:
        if z not in HUB_ZONES:
            raise HubSkip("unsupported_zone")
        mz = HUB_ZONES[z]
        if vs and z in HUB_SCALAR_ZONES:
            raise HubSkip("selector")
        if z == "HEADERS" and not vs:
            raise HubSkip("headers_without_name")
        if count and not vs:
            raise HubSkip("count_without_variable")
        if z == "RAW_BODY":
            notes.append("raw_body_partial")
            if count:
                raise HubSkip("selector")
            out += [mz, HUB_JSON_BODY]
            continue
        if not vs:
            out.append(mz)
            continue
        for v in vs:
            try:
                _hub_selector(mz, v)
            except Reject:
                raise HubSkip("selector")
            if z == "HEADERS" and v.lower() in FORBIDDEN_HEADERS:
                raise HubSkip("forbidden_header")
            out.append(("&" if count else "") + mz + ":" + v)
    if len(out) > 16:
        raise HubSkip("too_many_variables")
    m = n.get("match")
    if not isinstance(m, dict):
        raise HubSkip("node_shape")
    for k in sorted(m):
        if k not in ("type", "value", "not"):
            raise HubSkip("unknown_key")
    mt = m.get("type")
    if not isinstance(mt, str):
        raise HubSkip("node_shape")
    nv = m.get("not")
    if nv is not None and nv not in ("true", "false"):
        raise HubSkip("node_shape")
    negated = nv == "true"
    val = m.get("value")
    if val is not None and not isinstance(val, str):
        raise HubSkip("node_shape")
    neg = "!" if negated else ""

    def numeric(op):
        if not val:
            raise HubSkip("missing_value")
        if not RE_INT.match(val):
            raise HubSkip("not_numeric")
        return neg + "@" + op + " " + val
    late = negated
    if mt in HUB_NUMERIC:
        op, late = numeric(HUB_NUMERIC[mt]), True
    elif mt == "equals" and (count or length):
        op, late = numeric("eq"), True
    elif mt in HUB_NOARG:
        op = neg + "@" + HUB_NOARG[mt]
    elif mt in HUB_STRING:
        if not val:
            raise HubSkip("missing_value")
        hub_value(val)
        if mt == "regex":
            try:
                _regex(val)
            except Reject:
                raise HubSkip("regex")
        op = neg + "@" + HUB_STRING[mt] + " " + val
    else:
        raise HubSkip("unsupported_match")
    if not op.lstrip("!").startswith("@detect"):
        for z in zs:
            if z == "HEADERS" and any(v.lower() in DETECT_ONLY_HEADERS for v in vs):
                raise HubSkip("forbidden_header")
    return {"vars": "|".join(out), "op": op, "ts": mapped, "late": late}, notes


def hub_dnf(n, depth, notes):
    if not isinstance(n, dict):
        raise HubSkip("node_shape")
    if depth > HUB_MAX_DEPTH:
        raise HubSkip("node_shape")
    is_and, is_or, leaf = "and" in n, "or" in n, "zones" in n or "match" in n
    if (is_and and is_or) or ((is_and or is_or) and leaf) or (not is_and and not is_or and not leaf):
        raise HubSkip("node_shape")
    if leaf:
        l, ns = hub_leaf(n)
        notes += ns
        return [[l]]
    key = "or" if is_or else "and"
    for k in sorted(n):
        if k != key and k != "name":
            raise HubSkip("unknown_key")
    kids = n[key]
    if not isinstance(kids, list) or not kids:
        raise HubSkip("node_shape")
    acc = []
    for i, c in enumerate(kids):
        d = hub_dnf(c, depth + 1, notes)
        if is_or:
            acc = acc + d
        elif i == 0:
            acc = d
        else:
            acc = [a + b for a in acc for b in d]
        if len(acc) > HUB_MAX_GROUPS:
            raise HubSkip("too_many_groups")
    return acc


def hub_render(group, name, rid):
    ordered = [l for l in group if not l["late"]] + [l for l in group if l["late"]]
    out = []
    for i, l in enumerate(ordered):
        a = ""
        if i == 0:
            a = "id:%d,phase:2,pass," % rid
        a += ",".join("t:" + t for t in l["ts"])
        if i == 0:
            a += ",severity:CRITICAL,msg:'crowdsec hub %s',tag:crowdsec_hub" % name
        if i < len(ordered) - 1:
            a += ",chain"
        out.append('SecRule %s "%s" "%s"' % (l["vars"], l["op"], a))
    return "\n".join(out)


def hub_clean(s, n):
    out = [c for c in s if not (ord(c) < 0x20 or ord(c) == 0x7f or 0x80 <= ord(c) < 0xa0)]
    return "".join(out[:n]).strip()


def hub_convert(name, version, digest, body, fallback):
    if not RE_HUB_NAME.match(name):
        raise HubSkip("bad_name")
    if len(body) > HUB_MAX_CONTENT:
        raise HubSkip("rule_too_long")
    y = hub_yaml(body)
    if not isinstance(y, dict):
        raise HubSkip("yaml")
    if y.get("name") != name:
        raise HubSkip("name_mismatch")
    if "seclang_rules" in y or "seclang_files_rules" in y:
        raise HubSkip("raw_seclang")
    if "data" in y:
        raise HubSkip("external_data")
    for k in sorted(y):
        if k not in ("name", "description", "rules", "labels"):
            raise HubSkip("unknown_key")
    entries = y.get("rules")
    if not isinstance(entries, list) or not entries:
        raise HubSkip("no_rules")
    groups, notes = [], []
    for e in entries:
        groups += hub_dnf(e, 0, notes)
        if len(groups) > HUB_MAX_GROUPS:
            raise HubSkip("too_many_groups")
    base = hub_base_id(name)
    texts = []
    for i, g in enumerate(groups):
        if len(g) > HUB_MAX_LINES:
            raise HubSkip("too_many_lines")
        if all(l["late"] for l in g):
            raise HubSkip("catch_all")
        t = hub_render(g, name, base + i)
        if len(t.encode("utf-8")) > MAX_SECLANG:
            raise HubSkip("rule_too_long")
        try:
            seclang_validate(t, "observe", True)
        except Reject as r:
            raise HubSkip("catch_all" if "catch-all" in str(r) else "subset")
        texts.append(t)
    labels = y.get("labels") if isinstance(y.get("labels"), dict) else {}
    lbl = labels.get("label") if isinstance(labels.get("label"), str) else ""
    desc = y.get("description") if isinstance(y.get("description"), str) else ""
    cves, cwes, attack = set(), set(), set()
    cl = labels.get("classification") if isinstance(labels.get("classification"), list) else []
    for c in cl:
        if not isinstance(c, str):
            continue
        for rx, acc in ((RE_HUB_CVE, cves), (RE_HUB_CWE, cwes), (RE_HUB_ATTACK, attack)):
            m = rx.match(c)
            if m:
                acc.add(m.group(1))
                break
    seen = []
    for x in notes:
        if x not in seen:
            seen.append(x)
    return {"name": name, "version": version, "digest": digest, "base_id": base, "seclang": texts,
            "label": hub_clean(lbl, 128), "description": hub_clean(desc or fallback, 512),
            "cves": sorted(cves), "cwes": sorted(cwes), "attack": sorted(attack), "notes": seen}


def hub_update(doc):
    lim = doc.get("limits", {})
    raw = doc["index"].encode("utf-8")

    def refused(code):
        return {"outcome": "refused", "code": code, "not_selected": 0}
    if len(raw) > (lim.get("index_bytes") or HUB_MAX_INDEX):
        return refused("index_oversize")
    try:
        idx = strict_object(raw)
    except Reject:
        return refused("index_malformed")
    items = idx.get("appsec-rules")
    colls = idx.get("collections")
    coll = colls.get(HUB_COLLECTION) if isinstance(colls, dict) else None
    members = coll.get("appsec-rules") if isinstance(coll, dict) else None
    if not isinstance(items, dict) or not isinstance(members, list) or any(not isinstance(m, str) for m in members):
        return refused("index_malformed")
    members = set(members)
    names = sorted(n for n in items if n in members and n.startswith("crowdsecurity/vpatch-"))
    not_selected = len(items) - len(names)
    if len(names) > (lim.get("rules") or HUB_MAX_RULES):
        return refused("too_many_rules")
    prev = doc.get("previous", {})
    now = doc["now"]
    rules, skipped, added, changed, taken, set_bytes, set_lines = [], [], [], [], set(), 0, 0
    for name in names:
        it = items[name]
        if not isinstance(it, dict):
            return refused("index_malformed")
        path, version, content, versions = it.get("path"), it.get("version"), it.get("content"), it.get("versions")
        if not isinstance(path, str) or not isinstance(version, str) or not isinstance(content, str) \
                or not isinstance(versions, dict) or not RE_HUB_VERSION.match(version):
            return refused("index_malformed")
        try:
            body = base64.b64decode(content, validate=True)
        except ValueError:
            return refused("index_malformed")

        def sk(code):
            skipped.append({"name": name, "version": version, "code": code})
        if path != "appsec-rules/" + name + ".yaml":
            sk("name_mismatch")
            continue
        v = versions.get(version)
        v = v if isinstance(v, dict) else {}
        want = v.get("digest") if isinstance(v.get("digest"), str) else ""
        digest = hashlib.sha256(body).hexdigest()
        if not RE_HUB_DIGEST.match(want) or want != digest:
            sk("digest_mismatch")
            continue
        if v.get("deprecated") is True:
            sk("deprecated")
            continue
        desc = it.get("description") if isinstance(it.get("description"), str) else ""
        try:
            r = hub_convert(name, version, digest, body, desc)
        except HubSkip as s:
            sk(s.code)
            continue
        if r["base_id"] in taken:
            sk("id_collision")
            continue
        taken.add(r["base_id"])
        set_bytes += sum(len(t) for t in r["seclang"])
        set_lines += sum(t.count("\n") + 1 for t in r["seclang"])
        r["first_seen"], r["changed_at"] = now, now
        if name in prev:
            r["first_seen"] = prev[name]["first_seen"]
            if prev[name]["digest"] == digest:
                r["changed_at"] = prev[name]["changed_at"]
            else:
                changed.append(name)
        else:
            added.append(name)
        rules.append(r)
    if set_bytes > (lim.get("set_bytes") or HUB_MAX_SET) or set_lines > (lim.get("set_lines") or HUB_MAX_SET_LINES):
        return refused("set_too_large")
    if not rules:
        return refused("set_empty")
    base = doc.get("shrink_base", 0)
    if base == 0:
        base = len(prev)
    if base != -1 and len(rules) * 2 < base:
        return refused("shrink")
    loaded = {r["name"] for r in rules}
    removed = sorted(n for n in prev if n not in loaded)
    out = {"outcome": "accepted", "index_sha256": hashlib.sha256(raw).hexdigest(), "rules": rules, "not_selected": not_selected}
    for k, x in (("skipped", skipped), ("added", added), ("changed", changed), ("removed", removed)):
        if x:
            out[k] = x
    return out


def hub_set_check(v):
    prev = ""
    for r in v["rules"]:
        if r["name"] <= prev:
            raise Reject("schema", "rules not sorted")
        prev = r["name"]
        try:
            body = base64.b64decode(r["content"], validate=True)
        except ValueError:
            raise Reject("schema", "content")
        if hashlib.sha256(body).hexdigest() != r["digest"]:
            raise Reject("schema", "digest")
        if parse_time(r["changed_at"], "changed_at") < parse_time(r["first_seen"], "first_seen"):
            raise Reject("schema", "changed_at before first_seen")


def hub_date(c, now):
    try:
        t = parse_time(c.get("time", ""), "time")
    except Reject:
        return None
    return None if t > now + 120 else t


def hub_select(d):
    state, pin = d["state"], d.get("pin", "")
    st, im = d["stored"], d["image"]
    ok = lambda c: c.get("present") is True and c.get("valid") is True
    if state == "off":
        return {"set": "none", "pin_pending": False}
    if pin and ok(st) and st.get("commit", "") == pin:
        return {"set": "stored", "pin_pending": False}
    if pin and ok(im) and im.get("commit", "") == pin:
        return {"set": "image", "pin_pending": False}
    pending = pin != ""
    if ok(st) and ok(im):
        now = parse_time(d["now"], "now")
        a, b = hub_date(st, now), hub_date(im, now)
        return {"set": "image" if b is not None and (a is None or b > a) else "stored", "pin_pending": pending}
    if ok(st):
        return {"set": "stored", "pin_pending": pending}
    if ok(im):
        return {"set": "image", "pin_pending": pending}
    return {"set": "none", "pin_pending": pending}


# ---------------------------------------------------------------- rule repositories (D73, contract/rules)

RULE_REPOS = ("crs", "crowdsec", "local")
AGENT_WRITES = {
    "updateAgentRuleRepository": "rules:write", "syncAgentRuleRepository": "rules:write",
    "resetAgentRuleRepository": "rules:write", "updateAgentRule": "rules:write",
    "createAgentBlock": "blocks:write", "liftAgentBlock": "blocks:write",
    "createAgentException": "exceptions:write", "removeAgentException": "exceptions:write",
    "setAgentCrawlers": "crawlers:write",
    "syncAgentFirewall": "firewall:sync",
}


def rule_status(d):
    """Status and effect of one rule (rules.Compute), written from D73 and D89 alone."""
    mode, state, now = d["mode"], d["state"], d["now"]
    out = {}
    if d.get("disabled"):
        out["status"], out["disabled_by"] = "disabled", d.get("disabled_by") or "dashboard"
    elif d["origin"] == "update" and mode != "observe" and now < d.get("settling_until", 0):
        out["status"] = "settling"
    else:
        out["status"] = "active"
    st = out["status"]
    if st == "disabled" or state == "off":
        out["effect"] = "off"
    elif state == "detect":
        out["effect"], out["limited_by"] = "detect", "repository_detect"
    elif st == "settling":
        out["effect"], out["limited_by"] = "detect", "settling"
    elif mode == "observe":
        out["effect"], out["limited_by"] = "would_block", "gateway_observe"
    else:
        out["effect"] = "block"
    return {k: out[k] for k in ("status", "effect", "limited_by", "disabled_by") if k in out}


def rule_request(d):
    r = rule_status(d)
    allow = d.get("allow", "")

    def res(action, outcome, **kw):
        o = {"action": action, "outcome": outcome}
        o.update(kw)
        o["counts_as_hit"] = action == "block"
        return o
    if allow == "bypass_waf" or r["effect"] == "off":
        return res("none", "passed")
    if r["effect"] == "detect":
        wb = "settling" if r["limited_by"] == "settling" else "source_detect"
        return res("would_block", "would_block", reason=r["limited_by"], would_block_reason=wb)
    if d.get("excepted"):
        return res("excepted", "logged")
    if r["effect"] == "would_block":
        return res("would_block", "would_block", would_block_reason="gateway_observe")
    if d.get("site_mode") == "observe":
        return res("would_block", "would_block", would_block_reason="site_observe")
    if allow == "no_block":
        return res("would_block", "would_block", would_block_reason="allowlist")
    return res("block", "blocked")


def rule_repository(d):
    state, mode = d["state"], d["mode"]
    if state != "block":
        return {"effect": state}
    if mode == "observe":
        return {"effect": "would_block", "limited_by": "gateway_observe"}
    return {"effect": "block"}


def rule_effective(repo, config, overlay, by):
    if overlay:
        return overlay, "agent" if by == "agent" else "dashboard"
    if config:
        return config, "config"
    return ("detect" if repo == "crowdsec" else "block"), "default"


def rule_switch(d):
    repo = d["repository"]
    config, overlay, by = d.get("config", ""), d.get("overlay", ""), d.get("overlay_by", "")
    before, _ = rule_effective(repo, config, overlay, by)
    if d.get("reset"):
        overlay, by = "", ""
    elif d.get("requested"):
        overlay, by = d["requested"], d.get("actor", "")
    after, src = rule_effective(repo, config, overlay, by)
    default = "detect" if repo == "crowdsec" else "block"
    return {"state": after, "source": src, "changed": before != after,
            "rebuild": (before == "off") != (after == "off"),
            "differs": overlay != "" and after != (config or default)}


def rule_agent_write(d):
    if AGENT_WRITES.get(d["operation"]) == d["scope"]:
        return {"allowed": True, "status": 200}
    return {"allowed": False, "status": 403, "code": "scope_required"}


def rule_effect(d):
    op = d["op"]
    if op == "effect":
        return rule_status(d)
    if op == "request":
        return rule_request(d)
    if op == "repository":
        return rule_repository(d)
    if op == "switch":
        return rule_switch(d)
    return rule_agent_write(d)


def hub_set_cost(d):
    # D43: the verdict on a measured sample; the numbers come from the gateway.
    base = d["baseline_ns"]
    added = max(d["candidate_ns"] - base, 0)
    ref = max(d["reference_ns"] - base, base * HUB_COST_FLOOR_PERCENT // 100)
    out = {"outcome": "accepted", "added_ns": added, "allowed_ns": ref * HUB_COST_MAX_RATIO}
    if d["rounds"] < 1 or added > out["allowed_ns"]:
        out["outcome"], out["code"] = "refused", "set_too_costly"
    return out


def crowdsec_hub(d):
    op = d["op"]
    if op == "convert":
        body = d["content"].encode("utf-8")
        try:
            r = hub_convert(d["name"], d["version"], hashlib.sha256(body).hexdigest(), body, d.get("description", ""))
        except HubSkip as s:
            return {"outcome": "skipped", "code": s.code}
        return {"outcome": "converted", "rule": r}
    if op == "update":
        return hub_update(d)
    if op == "select":
        return hub_select(d)
    return hub_set_cost(d)



# ---------------------------------------------------------------- group records (D105, cluster.md)
#
# Whether a node of a group of gateways takes a record, and whether it
# replaces the record held (cluster.md sections 3 to 5). Written from the
# contract text, independent of the Go package contract/cluster.

CL_VERSION = 1
CL_MAX_DATA = 256 << 10
CL_MAX_ID = 512
CL_THINGS = {
    "settings": {"settings_overlay_v1", "behaviour_rate_limits_v1", "rules_state_by_v1", "crawler_policies_v1",
                 "access_protections_v1", "human_check_v1", "rule_exceptions_v2", "agent_pseudonym_key_v1"},
    "access": {"allowlist", "ip_exceptions", "rule_decisions"},
    "logins": {"users", "sessions", "agent_tokens"},
}
# Keys of the gateway's store that describe one node and never travel.
CL_PER_NODE_SETTINGS = {"installed_at_v1", "dashboard_setup_code_v1", "crowdsec_hub_status_v1", "crowdsec_hub_set_v1", "allow_version", "jobs_local_v1"}
CL_SETTING_KEY = re.compile(r"^[a-z][a-z0-9_]{0,63}\Z")
CL_TIME_PLAIN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}([.,]\d+)?Z$")
CL_TIME = re.compile(r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})([.,]\d+)?Z$")


class ClRefuse(Exception):
    def __init__(self, reason):
        Exception.__init__(self, reason)
        self.reason = reason


def cl_hash_id(prefix, context, pub):
    return prefix + hashlib.sha256(context.encode("ascii") + pub).hexdigest()[:32]


def cl_node_id(pub):
    return cl_hash_id("n-", "schild-node:", pub)


def cl_group_id(pub):
    return cl_hash_id("g-", "schild-group:", pub)


def cl_b64(s):
    """Standard base64, padded, canonical; None when it is none."""
    t = s.replace("\r", "").replace("\n", "")
    try:
        b = base64.b64decode(t, validate=True)
    except Exception:
        return None
    if base64.b64encode(b).decode("ascii") != t:
        return None
    return b


def cl_time(s):
    """Seconds since the epoch of a time as records carry it; None: no time."""
    m = CL_TIME.match(s) if isinstance(s, str) else None
    if not m:
        return None
    y, mo, d, h, mi, sec = (int(x) for x in m.groups()[:6])
    if not (1 <= mo <= 12 and h < 24 and mi < 60 and sec < 60):
        return None
    if d < 1 or d > calendar.monthrange(y, mo)[1] if y > 0 else True:
        return None
    frac = float("0" + m.group(7).replace(",", ".")) if m.group(7) else 0.0
    return calendar.timegm((y, mo, d, h, mi, sec)) + frac


def cl_addr(s):
    """(canonical text, is IPv4) of an IP address; None: no address."""
    try:
        a = ipaddress.ip_address(s)
    except ValueError:
        return None
    if a.version == 4:
        return str(a), True
    if a.ipv4_mapped is not None and "%" not in s:
        return "::ffff:" + str(a.ipv4_mapped), False
    return str(a), False


def cl_addr_port(s):
    i = s.rfind(":")
    if i < 0:
        return False
    host, port = s[:i], s[i + 1:]
    if not re.fullmatch(r"[0-9]+", port) or int(port) > 65535:
        return False
    if host.startswith("["):
        if not host.endswith("]"):
            return False
        a = cl_addr(host[1:-1])
        return a is not None and not a[1]
    a = cl_addr(host)
    return a is not None and a[1]


def cl_blen(s):
    return len(s.encode("utf-8", "surrogatepass"))


def cl_payload(rec):
    """The decoded data; b"" when there is none. Raises schema."""
    if rec["data"] == "":
        return b""
    p = cl_b64(rec["data"])
    if p is None or len(p) > CL_MAX_DATA:
        raise ClRefuse("schema")
    return p


def cl_signing_bytes(rec, data):
    out = b""
    for part in (b"schild-cluster-record-v1", str(rec["v"]).encode(), rec["group"].encode(), rec["class"].encode(), rec["id"].encode(),
                 rec["origin"].encode(), str(rec["seq"]).encode(), str(rec["hlc"]).encode(), b"1" if rec.get("deleted") else b"0",
                 rec.get("expires", "").encode(), data):
        out += str(len(part)).encode() + b" " + part + b" "
    return out


def cl_decode(rec, fields):
    """The data of a record as the fields of its class. A field is a string,
    an integer, a boolean or a map of strings; one that is missing or null is
    empty. An unknown field refuses the record, and so does data that is no
    JSON object (null counts as an empty one)."""
    p = cl_payload(rec)
    if len(p) == 0:
        raise ClRefuse("schema")
    try:
        doc = json.loads(p.decode("utf-8", "replace"), object_pairs_hook=lambda pairs: ("obj", pairs))
    except ValueError:
        raise ClRefuse("schema")
    out = {name: {"str": "", "int": 0, "bool": False, "map": {}}[kind] for name, kind in fields.items()}
    if doc is None:
        return out
    if not (isinstance(doc, tuple) and len(doc) == 2 and doc[0] == "obj"):
        raise ClRefuse("schema")
    fold = {name.casefold(): name for name in fields}
    for key, val in doc[1]:
        name = key if key in fields else fold.get(key.casefold())
        if name is None:
            raise ClRefuse("schema")
        kind = fields[name]
        if val is None:
            continue
        if kind == "str" and isinstance(val, str):
            out[name] = val
        elif kind == "int" and isinstance(val, int) and not isinstance(val, bool) and -(1 << 63) <= val < (1 << 63):
            out[name] = val
        elif kind == "bool" and isinstance(val, bool):
            out[name] = val
        elif kind == "map" and isinstance(val, tuple) and len(val) == 2 and val[0] == "obj":
            mp = {}
            for k, v in val[1]:
                if v is None:
                    v = ""
                if not isinstance(v, str):
                    raise ClRefuse("schema")
                mp[k] = v
            out[name] = mp
        else:
            raise ClRefuse("schema")
    return out


CL_MEMBER = {"name": "str", "role": "str", "public_key": "str", "address": "str", "joined": "str", "version": "str", "admit_public_key": "str", "admit": "str"}
CL_INCIDENT_BLOCK = {"client": "str", "bits": "int", "scope": "str", "source": "str", "level": "int", "since": "str", "until": "str", "duration_s": "int",
                     "event_id": "str", "net_class": "str", "node": "str"}
CL_INCIDENT_ID = re.compile(r"[A-Z0-9-]{1,64}\Z")
CL_SCOPE = re.compile(r"gateway\Z")


def cl_key(m):
    k = cl_b64(m["public_key"])
    return k if k is not None and len(k) == 32 else None


def cl_member(rec):
    """The member of a record of class members: (fields, key). Raises schema."""
    m = cl_decode(rec, CL_MEMBER)
    key = cl_key(m)
    ok = (key is not None and m["role"] == "gateway"
          and m["name"] != "" and cl_blen(m["name"]) <= 63 and not any(ch in m["name"] for ch in " \t\r\n/")
          and cl_addr_port(m["address"])
          and (m["admit_public_key"] == "") == (m["admit"] == "") and cl_blen(m["admit_public_key"]) <= 64 and cl_blen(m["admit"]) <= 128
          and cl_time(m["joined"]) is not None)
    if not ok or cl_node_id(key) != rec["id"]:
        raise ClRefuse("schema")
    return m, key


def cl_admitted(m, key, group):
    pub, sig = cl_b64(m["admit_public_key"]), cl_b64(m["admit"])
    if pub is None or sig is None or len(pub) != 32 or len(sig) != 64:
        return False
    return cl_group_id(pub) == group and ed25519_verify(pub, b"schild-admit:" + group.encode() + b":" + key, sig)


def cl_clean_path(p):
    if p == "" or cl_blen(p) > CL_MAX_ID:
        return False
    return not any(el in ("", ".", "..") or "\\" in el or "\x00" in el for el in p.split("/"))


def cl_thing_of(cls, rid):
    """The thing a record id of settings, access or logins names, or None."""
    i = rid.rfind("/")
    if i < 0 or len(rid) - i - 1 != 32:
        return None
    thing = rid[:i]
    if thing in CL_THINGS[cls]:
        return thing
    # Class settings takes every key of the store that is not per node.
    if cls == "settings" and CL_SETTING_KEY.match(thing) and thing not in CL_PER_NODE_SETTINGS:
        return thing
    return None


def cl_class_rules(rec):
    cls, deleted, expires = rec["class"], bool(rec.get("deleted")), rec.get("expires", "")
    if cls == "members":
        cl_member(rec)
    elif cls == "incident_blocks":
        # D109: one block per record, the id is the incident, never a tombstone.
        b = cl_decode(rec, CL_INCIDENT_BLOCK)
        a = cl_addr(b["client"])
        since, until = cl_time(b["since"]), cl_time(b["until"])
        ok = (not deleted and CL_INCIDENT_ID.match(rec["id"]) and CL_SCOPE.match(b["scope"])
              and a is not None and a[0] == b["client"] and b["bits"] == (32 if a[1] else 64)
              and since is not None and until is not None and until > since and until - since <= 7 * 86400 + 60
              and b["source"] != "" and cl_blen(b["source"]) <= 96 and 1 <= b["level"] <= 16 and 1 <= b["duration_s"] <= 7 * 86400
              and cl_blen(b["event_id"]) <= 64 and cl_blen(b["net_class"]) <= 32 and cl_blen(b["node"]) <= 63)
        if not ok or expires != b["until"]:
            raise ClRefuse("schema")
    elif cls == "lifts":
        # D109: the end of the block of one incident, without an address.
        l = cl_decode(rec, {"node": "str"})
        if deleted or not CL_INCIDENT_ID.match(rec["id"]) or cl_blen(l["node"]) > 63 or expires == "":
            raise ClRefuse("schema")
    elif cls in CL_THINGS:
        # One entry of a thing: the id is the thing and the hash of the key.
        v = cl_decode(rec, {"key": "str", "value": "str", "node": "str"})
        thing = cl_thing_of(cls, rec["id"])
        if cl_blen(v["node"]) > 63 or cl_blen(v["key"]) > 1024 or thing is None:
            raise ClRefuse("schema")
        if thing + "/" + hashlib.sha256(v["key"].encode("utf-8", "surrogatepass")).hexdigest()[:32] != rec["id"]:
            raise ClRefuse("schema")
        if deleted:
            if v["value"] != "" or expires == "":
                raise ClRefuse("schema")
        elif cl_b64(v["value"]) is None:
            raise ClRefuse("schema")
    elif cls == "erasure":
        e = cl_decode(rec, {"ip": "str", "keep_incidents": "bool", "node": "str"})
        a = cl_addr(e["ip"])
        if cl_blen(e["node"]) > 63 or a is None or a[0] != e["ip"] or e["ip"] != rec["id"] or deleted or expires == "":
            raise ClRefuse("schema")
    elif cls == "jobs":
        j = cl_decode(rec, {"at": "str", "node": "str"})
        if cl_blen(j["node"]) > 63 or not re.fullmatch(r"[a-z0-9_.-]{1,64}", rec["id"]) or deleted or not CL_TIME_PLAIN.match(j["at"]) or cl_time(j["at"]) is None:
            raise ClRefuse("schema")
    elif cls == "certificates":
        f = cl_decode(rec, {"files": "map", "node": "str"})
        files = f["files"]
        if cl_blen(f["node"]) > 63 or not cl_clean_path(rec["id"]):
            raise ClRefuse("schema")
        if deleted:
            if files:
                raise ClRefuse("schema")
            return
        if not 1 <= len(files) <= 16:
            raise ClRefuse("schema")
        for name, content in files.items():
            if name != "" and ("/" in name or not cl_clean_path(name)):
                raise ClRefuse("schema")
            if name == "" and len(files) != 1:
                raise ClRefuse("schema")
            if cl_b64(content) is None:
                raise ClRefuse("schema")


def cl_check(roster, group, rec, now):
    """Raises ClRefuse with the first failing check of cluster.md section 4."""
    cls, deleted = rec["class"], bool(rec.get("deleted"))
    if rec["v"] != CL_VERSION:
        raise ClRefuse("version")
    if rec["group"] != group:
        raise ClRefuse("group")
    if rec["group"] == "" or rec["origin"] == "" or rec["id"] == "" or cl_blen(rec["id"]) > CL_MAX_ID or rec["seq"] == 0 or rec["hlc"] == 0:
        raise ClRefuse("schema")
    if cls in CL_THINGS:
        if cl_thing_of(cls, rec["id"]) is None:
            raise ClRefuse("schema")
    elif cls in ("incident_blocks", "lifts"):
        if not CL_INCIDENT_ID.match(rec["id"]):
            raise ClRefuse("schema")
    elif cls == "blocks":
        # The class of 0.1.0-alpha.6 is gone: refused for good, not kept unread.
        raise ClRefuse("schema")
    elif cls not in ("members", "erasure", "certificates", "jobs"):
        raise ClRefuse("class")
    if rec.get("expires", "") != "" and cl_time(rec["expires"]) is None:
        raise ClRefuse("schema")
    if (rec["hlc"] >> 16) > (now + 60) * 1000:
        raise ClRefuse("clock")
    e = roster.get(rec["origin"])
    if e is not None and e["removed_at"] != 0 and rec["hlc"] >= e["removed_at"]:
        raise ClRefuse("removed")
    if e is not None:
        key = e["key"]
        # A member cannot let in a key the secret did not admit; a member
        # record that does not decode is refused by the rules of its class.
        if cls == "members" and not deleted:
            try:
                m, mkey = cl_member(rec)
            except ClRefuse:
                m = None
            if m is not None and not cl_admitted(m, mkey, group):
                raise ClRefuse("origin")
    else:
        # A node's record of itself, admitted by the group secret.
        try:
            m, key = cl_member(rec)
        except ClRefuse:
            raise ClRefuse("origin")
        if cls != "members" or rec["id"] != rec["origin"] or deleted:
            raise ClRefuse("origin")
        if not cl_admitted(m, key, group):
            raise ClRefuse("origin")
    data = cl_payload(rec)
    sig = cl_b64(rec["sig"])
    if sig is None or len(sig) != 64 or not ed25519_verify(key, cl_signing_bytes(rec, data), sig):
        raise ClRefuse("signature")
    cl_class_rules(rec)


def cl_wins(a, b):
    if a["hlc"] != b["hlc"]:
        return a["hlc"] > b["hlc"]
    da, db = bool(a.get("deleted")), bool(b.get("deleted"))
    if da != db:
        return da
    if a["origin"] != b["origin"]:
        return a["origin"] > b["origin"]
    return a["seq"] > b["seq"]


def cluster_record(v, now):
    group, roster = v["group"], {}
    for m in v["members"]:
        if m["class"] != "members":
            continue
        try:
            cl_check(roster, group, m, now)
            _, key = cl_member(m)
        except ClRefuse:
            continue
        roster[m["id"]] = {"key": key, "removed_at": m["hlc"] if m.get("deleted") else 0}
    rec = v["record"]
    try:
        cl_check(roster, group, rec, now)
    except ClRefuse as r:
        return {"taken": False, "reason": r.reason, "replaces": None}
    held = v.get("held")
    return {"taken": True, "reason": "", "replaces": cl_wins(rec, held) if held is not None else None}


# ---------------------------------------------------------------- audit log (draft, MVP-36)

AU_SECRET = ("password", "passwd", "secret", "token", "key", "hash", "cookie", "code", "seed", "credential", "credentials", "authorization")
AU_VALUES = ("before", "after", "added", "removed")
AU_DAY = 24 * 3600 * 1000
AU_ACTIONS = {}


def au_load(root):
    """Reads the catalogue of actions."""
    with open(os.path.join(root, "audit-actions.json"), "rb") as f:
        doc = strict_object(f.read())
    for a in doc["actions"]:
        if a["action"] in AU_ACTIONS:
            raise SystemExit("audit-actions: %s twice" % a["action"])
        AU_ACTIONS[a["action"]] = a


def au_fold(seg):
    return "".join(ch.lower() if "A" <= ch <= "Z" else ch for ch in seg if ch not in "-_.")


def au_is_secret(ptr):
    return any(au_fold(seg).endswith(AU_SECRET) for seg in ptr.split("/"))


def au_match(patterns, ptr):
    seg = ptr.split("/")
    return any(len(seg) == len(p.split("/")) and all(x in ("*", y) for x, y in zip(p.split("/"), seg)) for p in patterns)


def au_records(a, ptr):
    return not au_is_secret(ptr) and au_match(a["fields"], ptr)


def au_clean(s):
    def odd(o):
        return (o < 0x20 or 0x7F <= o <= 0x9F or 0x200B <= o <= 0x200F or 0x2028 <= o <= 0x202E
                or 0x2060 <= o <= 0x2069 or o == 0xFEFF)
    return "".join("�" if odd(ord(ch)) else ch for ch in s)


def au_len(s):
    return len(s.encode("utf-8"))


def au_clip(s, n):
    raw = s.encode("utf-8")
    if len(raw) <= n:
        return s, False
    return raw[:n].decode("utf-8", "ignore"), True


def au_flatten(v, ptr, out):
    if v is None:
        return
    if isinstance(v, dict):
        for k, x in v.items():
            au_flatten(x, ptr + "/" + k.replace("~", "~0").replace("/", "~1"), out)
        return
    out[ptr] = v


def au_equal(x, y):
    if isinstance(x, bool) or isinstance(y, bool):
        return x is y
    if isinstance(x, (int, float)) and isinstance(y, (int, float)):
        return x == y
    if type(x) is not type(y):
        return False
    if isinstance(x, list):
        return len(x) == len(y) and all(au_equal(p, q) for p, q in zip(x, y))
    if isinstance(x, dict):
        return set(x) == set(y) and all(au_equal(x[k], y[k]) for k in x)
    return x == y


def au_minus(a, b):
    return sorted(set(a) - set(b), key=lambda s: s.encode("utf-8"))


def au_values(f, have_b, x, have_n, y):
    """Puts the values of a field into f, returns what they cost."""
    if not isinstance(x, list) and not isinstance(y, list):
        cost = 0
        for k, there, v in (("before", have_b, x), ("after", have_n, y)):
            if not there:
                continue
            cost += 8
            if isinstance(v, str):
                v, was = au_clip(au_clean(v), 512)
                if was:
                    f["cut"] = True
                cost += au_len(v)
            f[k] = v
        return cost
    lists = []
    for there, v in ((have_b, x), (have_n, y)):
        if not there:
            v = []
        if not isinstance(v, list) or not all(isinstance(i, str) for i in v):
            f["hidden"] = "list"
            return 0
        lists.append(v)
    added, removed = au_minus(lists[1], lists[0]), au_minus(lists[0], lists[1])
    if not added and not removed:
        f["hidden"] = "order"
        return 0
    cost = 16
    for k, items in (("added", added), ("removed", removed)):
        if len(items) > 32:
            f["more"] = f.get("more", 0) + len(items) - 32
        taken = []
        for i in items[:32]:
            i, was = au_clip(au_clean(i), 256)
            if was:
                f["cut"] = True
            cost += au_len(i)
            taken.append(i)
        if taken:
            f[k] = taken
    return cost


def au_diff(v):
    a = AU_ACTIONS.get(v["action"])
    if a is None:
        raise Reject("schema", "unknown action")
    b, n = {}, {}
    au_flatten(v["before"], "", b)
    au_flatten(v["after"], "", n)
    out, used, more = [], 0, 0
    for p in sorted(set(b) | set(n), key=lambda s: s.encode("utf-8")):
        if p in b and p in n and au_equal(b[p], n[p]):
            continue
        name = au_clean(p)
        if au_len(name) > 512:
            more += 1
            continue
        kind = "added" if p not in b else "removed" if p not in n else "changed"
        base = {"field": name, "change": kind}
        f, cost = dict(base), 0
        if not au_records(a, p):
            f["hidden"] = "secret" if au_is_secret(p) else "unlisted"
        else:
            cost = au_values(f, p in b, b.get(p), p in n, n.get(p))
        head = au_len(name) + 16
        if cost and used + head + cost > 8192:
            f, cost = dict(base, hidden="size"), 0
        if used + head + cost > 8192 or len(out) == 64:
            more += 1
            continue
        used += head + cost
        out.append(f)
    res = {"fields": out}
    if more:
        res["more_fields"] = more
    return res


def au_letter(cls):
    return {"access": "a", "refused": "r"}.get(cls, "k")


def au_hide(f, why):
    for k in AU_VALUES + ("more", "cut"):
        f.pop(k, None)
    f["hidden"] = why


def au_fields(e):
    return e.get("change", {}).get("fields", [])


def au_entry(e, local):
    def need(ok, msg):
        if not ok:
            raise Reject("schema", msg)
    for k in ("time", "last"):
        if k in e:
            parse_time(e[k], k)
    cls, actor = e["class"], e["actor"]
    refused = cls == "refused"
    need(e["id"].split("-")[1] == au_letter(cls), "id")
    need((e["result"] == "refused") == refused, "result")
    if refused:
        need("change" not in e, "a refused call changes nothing")
        need(("count" in e) == ("last" in e), "count and last")
    else:
        need("count" not in e and "last" not in e, "count and last")
    need(e["operation"].split(":", 1)[0] == actor["kind"], "actor")
    if not refused and actor["kind"] in ("agent", "integration"):
        need("id" in actor, "actor id")
    sub_id, sub_kind = e["subject"].get("id"), e["subject"]["kind"]
    if sub_id is not None and sub_kind != "website":
        need(sub_kind not in ("address", "client") and au_net(sub_id) is None, "subject")
    if "last" in e:
        need(e["last"] >= e["time"], "last")
    a = AU_ACTIONS.get(e["action"])
    if a is None:
        need(not local, "unknown action")
    else:
        need(refused or cls == a["class"], "class")
        need(refused or not a.get("refused_only"), "refused only")
        need(e["subject"]["kind"] == a["subject"], "subject")
        if local:
            need(e["operation"] in a["operations"], "operation")
            need(not (a["website"] == "none" and "website" in e), "website")
            need(refused or a["website"] != "required" or "website" in e, "website")
    stripped = 0
    for f in au_fields(e):
        valued = any(k in f for k in AU_VALUES)
        need(valued != ("hidden" in f), "field")
        may = au_records(a, f["field"]) if a else not au_is_secret(f["field"])
        if valued and not may:
            need(not local, "field may not be recorded")
            au_hide(f, "secret" if au_is_secret(f["field"]) else "unlisted")
            stripped += 1
    return {"kept": au_letter(cls) == "k", "known": a is not None, "stripped": stripped}


def au_client(s):
    ip = au_addr(s)
    if ip is None:
        return ""
    if ip.version == 4:
        return str(ip)
    return str(ipaddress.ip_network((ip, 64), strict=False).network_address)


def au_refused(v):
    out, opened, minute, n = [], {}, -1, 0
    for c in v["calls"]:
        m = c["t"] // 60000
        if m > minute:
            minute, n, opened = m, 0, {}
        client, shown = au_client(c.get("address", "")), c.get("address", "")
        who = (c["action"], c["operation"], c.get("actor", ""))
        if client and who + (client,) not in opened and n >= v["max_open"]:
            client, shown = "", ""
        g = opened.get(who + (client,))
        if g is None:
            if client:
                n += 1
            g = {"action": c["action"], "operation": c["operation"], "first": c["t"], "last": c["t"], "count": 0}
            if "actor" in c:
                g["actor"] = c["actor"]
            if shown:
                g["address"] = shown
            opened[who + (client,)] = g
            out.append(g)
        g["count"] += 1
        g["first"], g["last"] = min(g["first"], c["t"]), max(g["last"], c["t"])
    return {"entries": out}


def au_keep(v):
    ids = [r["id"] for r in v["rows"]]
    if len(set(ids)) != len(ids) or any(r["id"].split("-")[1] != au_letter(r["class"]) for r in v["rows"]):
        raise Reject("schema", "rows: id")
    gone = set()
    access = 90 if v["keep_days"] is None else min(90, v["keep_days"])  # never longer than audit.keep_days
    for r in v["rows"]:
        days = access if r["class"] in ("access", "refused") else v["keep_days"]
        if days is not None and v["now"] - r["t"] >= days * AU_DAY:
            gone.add(r["id"])
    order = sorted(v["rows"], key=lambda r: (r["t"], r["id"].encode()))
    for cls in ("access", "refused"):
        left = [r for r in order if r["class"] == cls]
        for r in left[:max(0, len(left) - v["max_rows"])]:
            gone.add(r["id"])
    return {"deleted": [r["id"] for r in order if r["id"] in gone]}


def au_addr(s):
    if "%" in s:
        return None
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return None
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip


def au_net(s):
    """(address, bits) of an address or a network."""
    addr, slash, bits = s.partition("/")
    ip = au_addr(addr)
    if ip is None:
        return None
    if not slash:
        return ip, ip.max_prefixlen
    if not re.match(r"(0|[1-9][0-9]{0,2})\Z", bits) or int(bits) > ip.max_prefixlen or (":" in addr and ip.version == 4):
        return None
    return ip, int(bits)


def au_view(v):
    e, who = json.loads(json.dumps(v["entry"])), v["viewer"]
    if who["kind"] == "dashboard":
        return {"entry": e}
    if who["kind"] == "agent":
        if e["class"] not in ("change", "credential"):
            return {"entry": None}
        e.pop("address", None)
        e["actor"] = {k: x for k, x in e["actor"].items() if k in ("kind", "id", "label")}
        return {"entry": e}
    a = AU_ACTIONS.get(e["action"], {})
    if not a.get("portal") or e["class"] != "change" or e.get("website") != who["website"]:
        return {"entry": None}
    out = {k: e[k] for k in ("id", "time", "action", "subject", "website", "cause") if k in e}
    if e["actor"]["kind"] == "integration":
        out["actor"] = {"kind": "portal"}
        if "on_behalf_of" in e["actor"]:
            out["actor"]["on_behalf_of"] = e["actor"]["on_behalf_of"]
        if "reason" in e:
            out["reason"] = e["reason"]
    else:
        out["actor"] = {"kind": "operator"}
        for f in au_fields(e):
            if "hidden" not in f and (f["field"] == "/label" or au_match(a.get("addresses", []), f["field"])):
                au_hide(f, "operator")
    if "change" in e:
        out["change"] = e["change"]
    return {"entry": out}


def audit_log(v):
    op = v["op"]
    if "entry" in v and op != "entry":
        au_entry(v["entry"], False)
    if op == "diff":
        return au_diff(v)
    if op == "entry":
        return au_entry(v["entry"], v["from"] == "local")
    if op == "refused":
        return au_refused(v)
    if op == "keep":
        return au_keep(v)
    return au_view(v)


def run_vector(checker, keys, v):
    ctx = Ctx(v.get("context", {}), keys)
    raw = v["input_raw"].encode("utf-8")
    c = v["contract"]
    result = None
    try:
        if c == "envelope":
            checker.signed(v["context"]["kind"], raw, ctx)
        elif c in LIMITS:
            checker.signed(c, raw, ctx)
        elif c == "agent-enrolment":
            checker.enrolment(raw, ctx)
        elif c in DOC_LIMITS:
            checker.document(c, raw, ctx)
        elif c == "seclang":
            seclang_validate(v["input_raw"], ctx.max_action)
        elif c in RESULT_LIMITS:  # v0.5: bot-match, geo-map, website-derive, website-status
            if len(raw) > RESULT_LIMITS[c]:
                raise Reject("oversize", c)
            doc = strict_object(raw)
            checker.s.validate(c, doc)
            if c == "bot-match":
                result = bot_match(doc, ctx.now)
            elif c == "geo-map":
                result = geo_map(doc["provider"], doc["record"])
            elif c == "website-derive":
                result = website_derive(doc)
            elif c == "website-exception":
                result = website_exception(doc)
            elif c == "website-visitor":
                result = website_visitor(doc)
            elif c == "waiting-page":
                result = waiting_page(doc)
            elif c == "body-limits":
                result = body_limits(doc)
            elif c == "agent-block":
                result = agent_block(doc)
            elif c == "cluster-record":
                result = cluster_record(doc, ctx.now)
            elif c == "audit":
                result = audit_log(doc)
            elif c == "storage-bounds":
                result = storage_bounds(doc)
            elif c == "ingress-order":
                result = ingress_order(doc)
            elif c == "request-recheck":
                result = request_recheck(doc)
            elif c == "crowdsec-hub":
                result = crowdsec_hub(doc)
            elif c == "rule-effect":
                result = rule_effect(doc)
            elif c == "access-gate":
                result = access_gate(doc)
            elif c == "crawler-policy":
                result = crawler_policy(doc, ctx.now)
            elif c == "human-check":
                result = human_check(doc, ctx.now)
            else:
                result = website_status(doc)
        else:
            raise SystemExit("unknown contract " + c)
    except Reject as r:
        return {"valid": False, "error": r.code, "detail": str(r)}
    out = {"valid": True, "error": ""}
    if result is not None:
        out["result"] = result
    return out


_HUMAN_ADMIN_PREFIXES = (
    "/admin", "/wp-admin", "/wp-login.php", "/login", "/signin", "/sign-in",
    "/auth", "/user/login", "/typo3", "/backend", "/manager", "/cms",
)


def _hc_valid_except(p):
    if not p or not p.startswith("/") or p == "/*":
        return False
    body = p[:-2] if p.endswith("/*") else p
    if "*" in body or "//" in body:
        return False
    for seg in body[1:].split("/"):
        if seg in (".", ".."):
            return False
    return True


def human_check(doc, now):
    pol = doc["policy"]
    ua = pol.get("under_attack") or {}
    scope = ua.get("scope", "")
    until_s = ua.get("until", "")
    ua_active = False
    if scope in ("", "off"):
        if until_s:
            raise Reject("schema", "under_attack.until must be empty when scope is off")
    elif scope in ("admin", "all"):
        if not until_s:
            raise Reject("schema", "under_attack.until required")
        until_t = parse_time(until_s, "under_attack.until")
        if now is not None and (until_t - now) > 24 * 3600:
            raise Reject("schema", "under_attack.until > 24h")
        ua_active = now is not None and now < until_t
    else:
        raise Reject("schema", "invalid under_attack.scope")

    exc = pol.get("except") or []
    for ex in exc:
        if not _hc_valid_except(ex):
            raise Reject("schema", "invalid except path " + ex)

    method = doc["method"]
    path = doc["path"]
    accept = doc.get("accept", "")
    sfm = doc.get("sec_fetch_mode", "")
    is_nav = method in ("GET", "HEAD") and (sfm.strip().lower() == "navigate" or "text/html" in accept.lower())
    if not is_nav:
        return {"answer": "pass", "reason": "not_navigation", "status": 0}
    if path in ("/robots.txt", "/favicon.ico") or path.startswith("/.well-known/"):
        return {"answer": "pass", "reason": "bypass_path", "status": 0}
    if doc.get("good_bot"):
        return {"answer": "pass", "reason": "good_bot", "status": 0}
    if doc.get("allowlisted"):
        return {"answer": "pass", "reason": "allowlisted", "status": 0}
    for pat in exc:
        if pat.endswith("/*"):
            base = pat[:-2]
            if path == base or path.startswith(base + "/"):
                return {"answer": "pass", "reason": "excluded_path", "status": 0}
        elif path == pat:
            return {"answer": "pass", "reason": "excluded_path", "status": 0}
    if doc["clearance"] in ("pow", "nojs"):
        return {"answer": "pass", "reason": "clearance_valid", "status": 0}

    if ua_active:
        if scope == "all":
            return {"answer": "challenge", "reason": "under_attack", "status": 403}
        low = path.lower()
        if scope == "admin" and any(low == p or low.startswith(p + "/") for p in _HUMAN_ADMIN_PREFIXES):
            return {"answer": "challenge", "reason": "under_attack", "status": 403}
    if doc.get("distributed_wave"):
        return {"answer": "challenge", "reason": "distributed_wave", "status": 403}
    mode = pol["mode"]
    if mode == "always":
        return {"answer": "challenge", "reason": "always", "status": 403}
    if mode == "findings":
        if doc.get("shared_scenario_hit"):
            return {"answer": "challenge", "reason": "shared_scenario", "status": 403}
        if doc.get("aggressive_crawl_hit"):
            return {"answer": "challenge", "reason": "aggressive_crawl", "status": 403}
    if mode == "off" and not ua_active:
        return {"answer": "pass", "reason": "off", "status": 0}
    return {"answer": "pass", "reason": "no_trigger", "status": 0}


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--contracts", default=os.path.join(os.path.dirname(__file__), ".."))
    ap.add_argument("--go", help="verdicts JSON written by cmd/contracts-check")
    ap.add_argument("--out", help="write Python verdicts JSON here")
    ap.add_argument("-v", "--verbose", action="store_true")
    ap.add_argument("--agreement-only", action="store_true", help="ignore expectations, fail only on Go/Python disagreement (fuzz corpora)")
    a = ap.parse_args()
    selftest()
    root = os.path.abspath(a.contracts)
    schemas = Schemas(root)
    au_load(root if os.path.exists(os.path.join(root, "audit-actions.json")) else os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
    keys = load_keys(os.path.join(root, "testkeys", "keys.json"))
    checker = Checker(schemas)
    vdir = os.path.join(root, "vectors")
    files = []
    for dirpath, _, fs in os.walk(vdir):
        for f in fs:
            if f.endswith(".json") and os.path.basename(dirpath) in ("valid", "invalid"):
                files.append(os.path.join(dirpath, f))
    files.sort()
    verdicts, bad = [], 0
    for path in files:
        rel = os.path.relpath(path, vdir).replace(os.sep, "/")
        with open(path, "rb") as f:
            v = json.loads(f.read().decode("utf-8"))
        got = run_vector(checker, keys, v)
        exp = v["expect"]
        if not a.agreement_only and (got["valid"] != exp["valid"] or got["error"] != exp.get("error", "")
                                     or got.get("result") != exp.get("result")):
            bad += 1
            print("MISMATCH %s: expected valid=%s error=%r result=%s, got valid=%s error=%r result=%s (%s)"
                  % (rel, exp["valid"], exp.get("error", ""), exp.get("result"), got["valid"], got["error"],
                     got.get("result"), got.get("detail", "")))
        elif a.verbose:
            print("ok %s" % rel)
        row = {"file": rel, "valid": got["valid"], "error": got["error"]}
        if "result" in got:
            row["result"] = got["result"]
        verdicts.append(row)
    if not a.agreement_only:
        print("python: %d vectors, %d mismatches against expectations" % (len(verdicts), bad))
    disagree = 0
    if a.go:
        with open(a.go, "rb") as f:
            gov = {r["file"]: r for r in json.loads(f.read().decode("utf-8"))}
        mine = {r["file"]: r for r in verdicts}
        for name in sorted(set(gov) | set(mine)):
            g, p = gov.get(name), mine.get(name)
            if g is None or p is None or g["valid"] != p["valid"] or g["error"] != p["error"] or g.get("result") != p.get("result"):
                disagree += 1
                print("DISAGREE %s: go=%s python=%s" % (name, g, p))
        print("go vs python: %d vectors compared, %d disagreements" % (len(set(gov) | set(mine)), disagree))
    if a.out:
        os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
        with open(a.out, "w", encoding="utf-8") as f:
            json.dump(verdicts, f, indent=2)
            f.write("\n")
    sys.exit(1 if bad or disagree else 0)


if __name__ == "__main__":
    main()
