# Lab co-signing, peer requests and the public log tree (contracts v0.1, v0.2)

Addendum v0.1 to the frozen contracts v0 (backwards compatible: new endpoints, new optional fields, two new vector contracts). Decision: [DECISIONS](DECISIONS.md) D22. v0.2 (D24): signed stream subscriptions of peer labs (section 1). Go: `contract/peerauth`, `contract/logtree`; Python: `tools/crosscheck.py`; browser: `ui/apps/lab-dashboard/src/lib/logverify.ts`.

## 1. Co-signing protocol on the feed port (7444)

A bundle or withdrawal needs signatures of k distinct operators (D04). The lab that assembles it signs first and collects the other signatures over its feed port; every lab is also a relay for the others (labs follow each other's `/v0/stream`).

| Endpoint | Who may call | Content |
| --- | --- | --- |
| `GET /v0/collecting` | configured peers only, with `Schild-Peer-Auth` (section 2); everyone else gets `401` | `{"lab": "<this lab>", "items": [{"kind": "rule-bundle"\|"withdrawal", "lab": "<this lab>", "digest": "sha256:<payload>", "envelope": {DSSE}}]}`: this lab's own items with status `collecting` |
| `POST /v0/signatures` | anyone (the signature authenticates itself), rate-limited per address; the signature is checked first and the budget per key counts after that (D40), because the key in the body is only a claim before the check | body `{"kind", "digest", "signature": {"keyid", "sig"}}`; answer `{"operators": n, "published": bool}` |
| `GET /v0/stream` (v0.2) | anyone (public SSE, [stream.md](stream.md)); peer labs add `Schild-Peer-Auth` (section 2, path `/v0/stream`, signed again on every reconnect) | the lab lists a subscriber with a valid peer signature as `kind: peer_lab` under the verified lab id in its dashboard (`GET /api/v0/relays`), every other subscriber as `kind: relay` under its self-reported `X-Schild-Relay` name. A missing or invalid signature never rejects the stream. |

Flow:

1. Lab A assembles a bundle (`POST /api/v0/bundles`) and signs it with its `rules` key. Status `collecting`.
2. Each peer lab polls `GET /v0/collecting` of A every 10 s, signed with its own `rules` key. It verifies every item with the contract verifier (schema, SecLang subset, evidence, validity) and checks that A signed it; then it shows the item in its dashboard with `proposed_by: lab-a`.
3. A person at the peer lab reviews the bundle and confirms with their password: `POST /api/v0/bundles/{version}/cosign` (withdrawals: `POST /api/v0/withdrawals/{seq}/cosign`). The peer lab signs **the same payload bytes** with its `rules` key and posts the signature to A (`POST /v0/signatures`).
4. A verifies the signature against the key configured for that peer. As soon as signatures of k distinct operators are present (k = `SCHILD_LAB_THRESHOLD`, floor 2; several labs of one operator count once), A publishes: feed event, checkpoint, public log. Peers following A's feed import the k-of-n envelope.

Why `/v0/collecting` is not public: a collecting bundle contains rule texts and targets that are not published yet (for example a virtual patch for an undisclosed vulnerability). Withholding them until k operators agree limits who learns about them; the peers who must review them are exactly the configured ones.

## 2. Peer request signature (`Schild-Peer-Auth`)

One header line, five space-separated tokens in this order:

```
Schild-Peer-Auth: v1 lab=<sender lab id> keyid=<keyid> ts=<YYYY-MM-DDTHH:MM:SSZ> sig=<standard base64, canonical>
```

The signature is Ed25519 over DSSE PAE (`DSSEv1 <len> <type> <len> <message>`) with payload type `application/vnd.schild.peer-request.v0+text` (domain separation from every signed document) and this message:

```
schild.peer-request/1
method:<GET|POST>
path:<request path, e.g. /v0/collecting>
target:<lab id of the receiving lab>
from:<lab id of the sender>
keyid:<keyid>
ts:<ts>
body:sha256:<hex of the request body; sha256 of the empty string for GET>
```

(every line ends with `\n`). The receiving lab accepts the request when, in this order (first failure wins, codes as in [vectors/README.md](vectors/README.md)):

| # | Code | Check |
| --- | --- | --- |
| 1 | `malformed` | not exactly the five tokens in order, unknown version, signature not canonical base64 |
| 2 | `schema` | `lab`, `keyid` or `ts` has a wrong format or an impossible date |
| 3 | `signature` | the key is not configured for a **peer** lab with purpose `rules`, it belongs to another lab than `lab=`, or the signature does not verify (another target, path, method or body) |
| 4 | `clock_skew` | `ts` more than 120 s in the future |
| 5 | `expired` | `ts` more than 120 s in the past |

A replay inside the 240 s window only returns the same list to someone who already saw it over TLS; GET is idempotent. Vectors: `vectors/peer-request/` (document `peer-request.schema.json`: the request as the receiving lab sees it).

## 3. Public log tree (RFC 6962)

Every lab keeps a public append-only log of proposal decisions, bundles, withdrawals and state-changing checkpoints. Its head `{size, root}` is signed in every checkpoint (`checkpoint.log`). v0 did not fix how the root is computed; v0.1 fixes it as the **RFC 6962 Merkle tree hash** (section 2.1), so clients, the lab dashboard and auditors can recompute it from a copy of the log:

```
leaf hash  = SHA-256(0x00 || leaf data)
node hash  = SHA-256(0x01 || left || right)
MTH({})    = SHA-256("")
MTH(D[n])  = node(MTH(D[0:k]), MTH(D[k:n])),  k = largest power of two < n
root       = "sha256:" + hex(MTH over the entries 0..size-1)
```

Leaf data of an entry (line-based text, no JSON, so every language produces the same bytes):

```
schild.log-leaf/1
index:<decimal>
time:<YYYY-MM-DDTHH:MM:SSZ>
kind:<proposal|bundle|withdrawal|checkpoint>
ref:<ref>
digest:sha256:<hex>
summary:<printable ASCII, no line break, at most 280 characters>
envelope:<sha256:hex of the exact envelope bytes, or empty for proposals>
```

Each line ends with `\n`. The checkpoint is signed before its own log entry is appended, so `checkpoint.log` covers the entries before it. The lab dashboard API returns `envelope_sha256` with every `LogEntry`; `GET /v0/log?from=&limit=` on the feed port returns the same fields plus `leaf_hash`. Logs written by v0 builds (hash chain) are rebuilt into the tree on first start. Vectors: `vectors/log-tree/` (document `log-tree.schema.json`: a log copy from index 0 with its head; error `log_root` when the root does not match). Inclusion and consistency proofs and witnesses stay open (D04, open point 2).

## 4. Dashboard API additions (v0.1)

See [api/](api/): lab `GET /api/v0/events/stream` (SSE; event name = topic: `health` LabHealth, `signals` ReceivedSignal, `log` LogEntry, other topics LiveNotice), `POST /api/v0/bundles/{version}/cosign`, `Proposal.created_by` with the four-eyes rule (the author may not approve: `403 self_approval`), typed `ProposalInput.target` (`Target`), `Bundle.proposed_by`, `Relay.bundle_version` and `Relay.withdrawal_seq`, `LogEntry.envelope_sha256`; client `Overview.series_24h` (24 hourly buckets for sparklines). Fixtures are named `<app>/<operationId>[.variant].json`.
