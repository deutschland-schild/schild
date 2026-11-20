# Relay stream: SSE with checkpoints, bundles and withdrawals (contracts v0)

Labs publish, relays forward, clients verify everything. A relay is untrusted: it can delay or withhold, never forge (MVP-04). Schema of one event: [stream.schema.json](stream.schema.json). Go: `contract/stream` (framing, ids, priorities, freeze detection) and `contract/verify` (`Document(DocStream, ...)`). Decision: [DECISIONS](DECISIONS.md) D04, D13.

## Endpoints (relays and labs alike)

| Endpoint | Content |
| --- | --- |
| `GET /v0/stream` | `text/event-stream`, one outgoing connection per client |
| `GET /v0/bundles/<bundle_id>/<version>.json` | bundle envelope bytes (static, cacheable, immutable) |
| `GET /v0/checkpoint` | newest checkpoint envelope (for the cross-check from a second source) |

Labs serve the same three endpoints on their feed port (7444); relays subscribe there (`SCHILD_RELAY_UPSTREAMS`) and serve clients on 7480. A client lists at least two relays and keeps exactly one stream open. Labs additionally serve `GET /v0/log` (public log, RFC 6962 head) and, for co-signing between labs, `GET /v0/collecting` (peer-signed requests only) and `POST /v0/signatures` (contracts v0.1, [cosign.md](cosign.md)).

## SSE framing

```
retry: 3000

id: k3x9-1042
event: schild.dist.checkpoint.v1
data: {"type":"schild.dist.checkpoint.v1","id":"k3x9-1042","envelope":{...}}

```

- One event = one `data:` line with compact JSON (at most 64 KiB), plus `id:` and `event:` equal to the JSON fields `id` and `type`. Comments (`: keep-alive`) may be sent at any time.
- Event types:

| `type` | Carries | Priority |
| --- | --- | --- |
| `schild.dist.withdrawal.v1` | `envelope`: withdrawal, k-of-n ([withdrawal.schema.json](withdrawal.schema.json)) | 0 (first) |
| `schild.dist.bundle.v1` | `envelope` (inline when the envelope is at most 32 KiB) **or** `ref` `{bundle_id, version, url_path, sha256, size}` | 1 |
| `schild.dist.checkpoint.v1` | `envelope`: checkpoint of one lab ([checkpoint.schema.json](checkpoint.schema.json)) | 2 |
| `schild.dist.heartbeat.v1` | `relay` `{id, time}` (informational) and `checkpoint`: the newest lab-signed checkpoint envelope | 3 |

- `ref.sha256` is the hash of the envelope bytes at `url_path`; the client checks it after download and then verifies the envelope like an inline one. Clients fetch referenced bundles from any relay or lab with a random delay of 0-30 s (load spreading); withdrawals are always inline.

## Ids and resume (Last-Event-ID)

- `id` = `<epoch>-<seq>`: `epoch` is random per relay process start (`[a-z0-9]{1,16}`), `seq` counts up per event on that relay.
- A reconnecting client sends `Last-Event-ID`. If the relay knows the id (same epoch, still in its buffer), it sends every later event. Otherwise (other relay, restart, too old) it sends a **full sync**: newest bundle (inline or ref), every withdrawal that still applies, newest checkpoint of each lab. Bundles are full state, so a full sync never leaves gaps.
- Buffer: at most 256 events per client; if a client falls behind, the relay closes the stream and the client reconnects (full sync). Relays never buffer without limit.

## What the client checks

Everything from [envelope.md](envelope.md), plus:

| Check | Rule |
| --- | --- |
| Bundles | k-of-n distinct operators, `version` strictly increasing (equal version must have equal digest), `expires` in the future, validity at most 31 days, channel = `bundle_id`, every rule passes [seclang-subset.md](seclang-subset.md) |
| Withdrawals | k-of-n distinct operators, `seq` strictly increasing; scope `all` = emergency stop (all network rules of bundles up to `up_to_version`), scope `rules` = listed rules |
| Checkpoints | signed by a key of the lab named in `lab`, validity at most 10 minutes, `seq` per lab increasing; the newest checkpoint tells the client which bundle version and withdrawal seq it should have |
| Freshness | Labs re-sign their checkpoint every 60 s; relays send a heartbeat every 15 s with the newest checkpoint. If no checkpoint newer than **180 s** arrives (`stream.Freshness`), the relay is frozen or withholding: switch to the next relay. Every 15 min (with jitter) the client also fetches `/v0/checkpoint` from a second source and compares. |
| Behind | If a verified checkpoint names a newer bundle version or withdrawal seq than the client has, it fetches them (resync or `ref`). |
| State | The client persists the newest accepted bundle version and digest, withdrawal seq and digest, and the newest checkpoint seq per lab, and loads them on start. Without persisted state a restart would accept an older bundle that is still unexpired (rollback). |
| Expiry | When the active bundle expires without a verified successor, the client removes all network rules (local rules and the CRS stay: "Grundschutz aktiv"), logs `schild.rule.dropped.v1` with reason `expired` and shows `bundle_expired` in the overview. Expired rules are never kept "just in case": a frozen feed must not pin old rules. |
| Withdrawals | A withdrawal applies to bundles with `version <= up_to_version`. It stays in force until a bundle with a higher version arrives, and it can only remove network rules: it never adds a rule, never raises an action and never touches local rules. |

Rejected events are logged locally (`schild.rule.dropped.v1` with reason `rejected` where a rule id is known) and counted in metrics; they never change the active rules. Relays and labs being slow or down never touch the request path: the client keeps protecting with the last verified rules (M7).

## Timing (targets, measured in MVP-04)

| | Target |
| --- | --- |
| New bundle at 95 % of clients | < 10 s (B05) |
| Emergency stop at 95 % of clients | < 10 s, kill criterion 60 s (B10) |
| Frozen relay detected | < 180 s (B12) |
