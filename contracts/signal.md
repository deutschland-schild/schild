# Signal and feedback: what leaves the server (contracts v0)

Decision E4 (2026-10-26): **no visitor IP, at no stage** - not truncated, not hashed, not as OPRF pseudonym. A signal carries only the positive list below. Schemas: [signal.schema.json](signal.schema.json), [feedback.schema.json](feedback.schema.json). Go: `contract/msg`, `contract/verify`.

## Signal `schild.signal/0.3`

```json
{
  "schema": "schild.signal/0.3",
  "id": "8663a79b-d4c2-4b75-aad6-70cb2530cf94",
  "kind": "tip",
  "time_bucket": "2026-10-26T11:55:00Z",
  "action_sig": "login-burst/wp-admin",
  "request_sig": "sha256:1ce928e7e35ea61e1a1e634babf6bc3a4da2ecd301152aa3ada4169905dbc08e",
  "waf_rules": [930120, 949110],
  "score": 72,
  "category": "wordpress-login-bruteforce",
  "origin": { "country": "NL", "asn": 64500, "net_class": "hosting", "attribution": "tcp_peer", "protected": false },
  "agent": { "family": "python-requests", "major": 2, "bot": false },
  "ja4": "t13d1516h2_8daaf6152771_e5627efa2ab1"
}
```

| Field | Meaning |
| --- | --- |
| `schema`, `id`, `kind` | Framing, no data about visitor or site. `id` is a random UUID v4 per signal (dedupe and ack), never derived from site, visitor or key. `kind` is always `tip` (client signals are hints, never evidence, G2). |
| `time_bucket` | Start of the 5, 10 or 15 minute bucket (`time_bucket_minutes`), always on a multiple of 5 minutes, seconds `00`. |
| `action_sig` | What was attempted, lowercase token like `sqli/rest-api`, at most 64 characters; no host, no query, nothing address-like (see "No covert addresses" below). |
| `request_sig` | Hash of the request shape (below). |
| `waf_rules` | Matched rule ids (1..32), **strictly ascending** (the canonical order of `request_sig`; any other order is rejected with `schema`, so the order cannot carry data). |
| `score` | Local anomaly score 0..100. Signals are sent for score >= 40 or a new pattern, plus a small sample (`signals.sample_rate`). |
| `category` | Attack category token, nothing address-like. |
| `origin` | Country (ISO 3166-1, `ZZ` unknown), ASN (`0` unknown, at most 2^24 - 1 so an IPv4 address cannot hide in it as an integer), net class, how the client address was attributed (`tcp_peer` or `trusted_proxy`; anything else never produces a signal, G5), whether the sender is on the protection list (G6). Derived locally from the bundled geo database (MVP-08), never looked up remotely. |
| `agent` | Browser or tool family (lower case, no dots, nothing address-like) and major version, bot flag. Never the full user agent. |
| `ja4` | Optional TLS fingerprint. Prototype and alpha only; coarse or absent from v1. |

Everything else is rejected: unknown fields are a `schema` error, never ignored. Keys from the forbidden list are rejected first with `forbidden_field`, at any depth (also inside objects in arrays). Keys are compared after normalisation: ASCII letters lower-cased, `-`, `_` and `.` removed, nothing else folded (so `client_ip`, `Client-IP`, `clientIp` and `client.ip` are all caught, while a key such as `ıp` with a non-ASCII letter is not on the positive list either and fails with `schema`; Unicode case folding would make the code depend on Unicode table versions):

`ip ips ip_address ip_prefix ip_hash ip_pseudonym oprf client_ip remote_addr remote_ip remote_host src_ip source_ip client_address address addr ipv4 ipv6 peer peer_ip x_forwarded_for x_real_ip true_client_ip cf_connecting_ip forwarded user_agent ua url uri query query_string path headers header cookies cookie body request_body referer referrer host hostname site site_id site_key domain server_name tenant account customer email user username login password phone session_id client client_id keyid key_id city latitude longitude auth token presentation`

### No covert addresses

The free-text tokens `action_sig`, `category`, `agent.family`, rule `target.software` and the feedback `match_shape.location` share one rule (`noLeak` in [common.schema.json](common.schema.json)): no dotted or dashed IPv4 (`203.0.113.7`, `203-0-113-7`), no dashed IPv6 (`2001-db8-85a3-8a2e-370-7334`), no run of 7 or more digits (an IPv4 address as a number), no run of 8 or more lower-case hex digits (hashes, hex-encoded addresses). Together with the length limits this stops accidental leaks and the obvious smuggling routes (base64 is impossible because the tokens are lower case).

Residual channels, by design: `id` (random UUID), `request_sig` (a hash) and the choice among valid values are opaque, so a malicious client could still encode something there. They are not a leak path for an honest client, and a malicious client holds the data anyway. To keep `request_sig` checkable, the client writes the canonical request shape it hashed into its local transparency log (`schild.signal.sent.v1`, field `request_shape`); an operator or auditor can recompute the hash.

The payload is the same for every auth scheme and transport ([auth.md](auth.md)); the sender's key or token is outside the payload. A signal or feedback envelope carries **exactly one** signature (code `envelope` otherwise): one sender, one issuer, so a tip can never be counted for two issuers.

### request_sig

`request_sig = "sha256:" + hex(sha256(canonical))`, where `canonical` is UTF-8 text with LF line ends:

```
schild.request-shape/1
method:<METHOD upper case>
path:<path template>
params:<parameter names, sorted, deduplicated, comma separated>
content_type:<media type lower case, without parameters>
rules:<matched rule ids, ascending, deduplicated, comma separated>
```

The path template replaces values that identify objects (numbers, UUIDs, hashes, slugs after known collection prefixes) with `{n}`, `{uuid}`, `{hex}`, `{slug}`. No host, no query values, no body, no IP. Test value (Go and Python check it): method `POST`, path `/wp-login.php`, params `log,pwd`, content type `application/x-www-form-urlencoded`, rules `930120,949110` gives `sha256:1ce928e7e35ea61e1a1e634babf6bc3a4da2ecd301152aa3ada4169905dbc08e`.

## Feedback `schild.feedback/0.2`

False-positive feedback on a network rule, created only after a human operator decided in the dashboard (K6). It carries the shape of the match (`location` such as `ARGS:text`, `content_type`, `len_bucket`), never its content.

```json
{
  "schema": "schild.feedback/0.2",
  "id": "…uuid v4…",
  "time_bucket": "2026-10-26T11:50:00Z",
  "rule_id": "schild-2026-0412",
  "bundle_version": 42,
  "verdict": "false_positive",
  "decided_by": "operator",
  "local_action": "suspended",
  "match_shape": { "location": "ARGS:text", "content_type": "application/json", "len_bucket": "256-1k" }
}
```

Feedback acts locally at once; in the network it can only lead to a narrowing proposal, never to switching a virtual patch off (G4).

## What stays local

Everything else: full IP, city, AS name, host, path, query, user agent, sessions, environment. See the local event catalogue in [events.schema.json](events.schema.json) and the transparency log event `schild.signal.sent.v1`, which records exactly the payload that left the server (and, for signals, the canonical request shape behind `request_sig`).
