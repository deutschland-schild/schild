# Golden vectors (contracts v0.6)

Generated, deterministic test vectors for every contract: `make contracts-vectors` (Go, `contract/cmd/genvectors`; fixed clock `2026-10-26T12:00:00Z`, fixed test keys, deterministic Ed25519). `make contracts-test` runs all of them with the Go reference implementation and with the independent Python implementation (`contracts/tools/crosscheck.py`) and fails if either disagrees with the expectation or with the other (MVP-01 kill criterion).

## Layout

`vectors/<contract>/{valid,invalid}/NNN-<name>.json`. Contracts: `envelope`, `signal`, `feedback`, `ack`, `submission`, `checkpoint`, `rule-bundle`, `withdrawal`, `stream`, `events`, `config-schild`, `config-lab`, `results`, `seclang`, and since v0.1 `log-tree` and `peer-request` ([../cosign.md](../cosign.md)), since v0.3 `host-report`, `agent-report`, `agent-enrolment` and `agent-ack` ([../host-check.md](../host-check.md)), since v0.5 `bot-catalogue`, `bot-match` and `geo-map`, and `website-derive`, `website-status`, `website-exception` and `website-visitor` (D36 and its 2026-10-29 amendment), `waiting-page` (D37), `storage-bounds` (D38), `ingress-order` and `request-recheck` (amendments of 2026-10-29 evening), and unreleased `cluster-record` (D103, [../cluster.md](../cluster.md): the input names the member records a node holds, the record it is handed and optionally the one it holds; the result says whether the record is taken, the first failing check, and whether it replaces the held one). Every contract has at least 5 valid and 10 invalid vectors.

## File format

```json
{
  "contract": "signal",
  "description": "What this vector shows.",
  "context": {
    "now": "2026-10-26T12:00:00Z",
    "kind": "signal",
    "trust": ["site-a", "lab-a"],
    "threshold": 2,
    "channel": "schild-main",
    "seen_ids": ["…"],
    "expected_in_reply_to": "…",
    "state": { "bundle_version": 41, "bundle_digest": "sha256:…", "withdrawal_seq": 4, "withdrawal_digest": "sha256:…",
               "checkpoint_seq": { "lab-a": 10 }, "checkpoint_digest": { "lab-a": "sha256:…" } },
    "simulated_operators": { "lab-a": "sim-1" },
    "max_action": "block"
  },
  "input_raw": "<exact bytes to verify, as a UTF-8 string>",
  "input_decoded": { "payload": { } },
  "expect": { "valid": false, "error": "schema" }
}
```

- `input_raw` is authoritative. `input_decoded` is for humans only and ignored by both implementations.
- `context.trust` names keys from [../testkeys/keys.json](../testkeys/keys.json); their `purposes`, `operator`, `lab` and `issuer` come from that file. `evil` is never trusted unless named.
- v0.3: `context.revoked` names keys (as in `trust`) the gateway revoked; `context.gateway` is the gateway name agent reports and enrolments must address (empty = any); `seen_ids` also holds accepted agent nonces.
- `context.kind` is only used by `envelope` vectors (which kind to verify as). `threshold` 0 or absent = 3, values below 2 are raised to 2. `channel` empty = any. `simulated_operators` maps lab id to the operator counted (test profile, E5). `max_action` is only used by `seclang` vectors.

## Error codes and check order

The first failing check wins. Both implementations follow this order.

Signed kinds (`envelope`, `signal`, `feedback`, `ack`, `checkpoint`, `rule-bundle`, `withdrawal`):

| # | Code | Check |
| --- | --- | --- |
| 1 | `oversize` | raw bytes over the kind's envelope limit |
| 2 | `malformed` | strict JSON: UTF-8, no BOM, no duplicate keys, no lone surrogate escapes, depth <= 32, finite numbers, no trailing data, top level object |
| 3 | `envelope` | envelope schema; canonical standard base64 for payload and every signature; signal and feedback envelopes carry exactly one signature |
| 4 | `oversize` | decoded payload over the kind's payload limit |
| 5 | `payload_type` | payloadType differs from the kind's |
| 6 | `signature` / `threshold` | single-signer kinds: no valid signature by a trusted key with the kind's purpose. Threshold kinds: fewer than k distinct operators among valid trusted signatures. A signature is checked only against the key named by its `keyid` (no trial verification); keys without an operator never count |
| 7 | `malformed` | payload is not strict JSON object |
| 8 | `forbidden_field` | signal and feedback only: forbidden key at any depth, also in objects inside arrays; keys compared after ASCII lower-casing and removing `-`, `_`, `.` |
| 9 | `schema` | payload schema (unknown fields, types, patterns, impossible dates); signal: `waf_rules` strictly ascending |
| 10 | semantic | see below |

Semantic checks, in order:

| Kind | Checks |
| --- | --- |
| signal, feedback | `clock_skew` time_bucket > now + 120 s; `expired` time_bucket + 24 h < now; `replay` id in `seen_ids` |
| ack | `signature` no valid signer belongs to the lab named in `lab`; `clock_skew` issued_at > now + 120 s; `expired` issued_at + 5 min < now; `replay` in_reply_to differs from `expected_in_reply_to` |
| checkpoint | `signature` no valid signer belongs to the lab named in `lab`; `clock_skew`; `expired` expires <= now; `validity` expires <= issued_at or longer than 10 min; `rollback` seq < stored seq of that lab; `equivocation` seq = stored seq (> 0) with another payload digest |
| rule-bundle | `clock_skew`; `expired`; `validity` (> 31 days); `channel`; `rollback` version < stored; `equivocation` version = stored with another digest; then per rule in order: `seclang`, `evidence`, `validity` (max_action_until, challenge <= 7 days), `duplicate_rule` |
| withdrawal | `clock_skew`; `channel`; `rollback` seq < stored; `equivocation` seq = stored with another digest |

Unsigned documents (`submission`, `stream`, `events`, `config-schild`, `config-lab`, `results`, `log-tree`, `peer-request`): `oversize` (submission 1 MiB, stream event 64 KiB, local event 64 KiB, config 1 MiB, results 4 MiB, log-tree 4 MiB, peer-request 16 KiB), `malformed`, `schema`, then:

- `stream`: the embedded envelope (`envelope`, or `checkpoint` for heartbeats) must have the payload type of the event type (`payload_type`), then it is verified as that kind without stored state (codes as above). Bundles by `ref` are verified after download.
- `config-schild`: `config` for duplicate agent key ids and public keys (`host_check.agents.keys`); since v0.4 duplicate explicit `behaviour.rate_limits[].id` (a rate limit on the whole site without `confirm_site_wide: true` is a `schema` error). Since v0.4 (MVP-19) the Caddyfile ingress is checked: `ingress.caddyfile` together with `upstream` or `listen.proxy`, neither `upstream` nor `ingress.caddyfile`, `ingress.storage` or `ingress.unprotected_sites` without `ingress.caddyfile` are `schema` errors. Since v0.6 (D72) the keys of the lab network (`network`, `channel`, `labs`, `min_independent_operators`, `test_profile`, `relays`, `remote_rules`, `signals`, `site_key`, `behaviour.distributed.wave_hint`) are unknown keys (`schema`).
- D72 retired vectors: numbers of vectors of removed features stay unused so later vectors keep theirs (`config-schild` valid 018, 019, invalid 020; `events` valid 004, 005, 028).
- `config-lab`: `config` for duplicate issuers or key ids, clients with unknown issuers, duplicate public keys (across clients and peers), the lab listed as its own peer, duplicate peers.
- `results`: `schema` if `finished_at` is before `started_at`.

- `log-tree` (v0.1): `schema` if `head.size` differs from the number of entries or an entry's index is not its position (copies start at index 0); `log_root` if the RFC 6962 root over the leaf data differs from `head.root`.
- `peer-request` (v0.1): the `Schild-Peer-Auth` header is checked as in [../cosign.md](../cosign.md) section 2: `malformed` (token syntax, version, non-canonical base64), `schema` (lab, keyid, ts format), `signature` (key not a trusted `rules` key of the named lab, or the signature does not cover this method, path, target and body), `clock_skew` (ts > now + 120 s), `expired` (ts < now - 120 s). `context.trust` names the receiving lab's peers.
- `host-report` (v0.3): `oversize` (512 KiB), `malformed`, `forbidden_field`, `forbidden_content` ([../host-check.md](../host-check.md) section 2, before the schema), `schema`, then `schema` for a duplicate `(id, subject)` among findings.
- `agent-ack` (v0.3): `oversize` (4 KiB), `malformed`, `schema`.

Agent messages (v0.3, [../host-check.md](../host-check.md)):

- `agent-report` is a signed kind (purpose `agent`, envelope 768 KiB, payload 512 KiB, exactly one signature). Step 6 yields `revoked` when the only valid signature is by a key in `context.revoked`; step 8 is `forbidden_field` then `forbidden_content` with the host-report rules; step 10: duplicate findings (`schema`), `signature` (report names another key), `clock_skew` (issued_at > now + 120 s), `expired` (issued_at + 5 min < now), `channel` (gateway differs from `context.gateway`), `replay` (nonce in `seen_ids`).
- `agent-enrolment` is self-signed: `oversize` (16 KiB), `malformed`, `envelope` (exactly one signature), `oversize` (payload 4 KiB), `payload_type`, `malformed`, `forbidden_field`, `forbidden_content`, `schema`, `signature` (signature key id differs from the payload `keyid` or does not verify with the payload `public_key`), `clock_skew`, `expired`, `channel`, `replay`. No trust store.

`seclang` vectors: the raw text is validated against [../seclang-subset.md](../seclang-subset.md), including the catch-all check against [../seclang-benign-corpus.json](../seclang-benign-corpus.json); every violation is `seclang`.

v0.5 (MVP-22, D35, [../DECISIONS.md](../DECISIONS.md)):

- `bot-catalogue`: `oversize` (4 MiB), `malformed`, `schema` ([../bot-catalogue.schema.json](../bot-catalogue.schema.json)), then `schema` for duplicate bot, range set or source ids, an unknown range set or source, a prefix that is not canonical (host bits, IPv4-mapped IPv6) and a `ua_match` or `automation_tokens` entry used twice (ASCII case-insensitive).
- `bot-match` and `geo-map` are classifier vectors: a valid vector also has `expect.result`, and both implementations must return exactly that JSON value (`contracts-check` writes it into its verdicts, `crosscheck.py` compares it with the expectation and with Go). `bot-match`: `oversize` (4 MiB), `malformed`, `schema` ([../bot-match.schema.json](../bot-match.schema.json) with the embedded catalogue), the catalogue checks above and an unparsable client address (`schema`); the result is `{bot, category, verification}` at `context.now` (rules in the catalogue schema description). `geo-map`: `oversize` (64 KiB), `malformed`, `schema` ([../geo-map.schema.json](../geo-map.schema.json)), then `schema` for a mapped field of the wrong type or format (country, AS number, flags, names); the result is the normalised geo record.
- `website-derive`, `website-status` and `website-exception` (v0.5, D36) are classifier vectors too: `oversize` (1 MiB), `malformed`, `schema` (their input schemas), then the rule checks of `contract/websites` (`schema` for an address or path the rules refuse, `config` for a block that proxies without schild and is not listed, `schema` for a gateway named twice). Results: the websites (and resolved hosts; with `own_hosts` since the D36 amendment also `own`, Set.OwnHost), `{status, reasons}`, `{scope, snippet}` with the snippet compared byte for byte. `website-visitor` (D36 amendment 2026-10-29): `oversize` (1 MiB), `malformed`, `schema` ([../website-visitor.schema.json](../website-visitor.schema.json): ua_class browser with bot_category likely_browser only and the reverse, none with likely_automated only); the result is `{visitor, bot_client}` (`contract/monitoring.Visitor`, `BotClient`).
- `crowdsec-hub` (v0.5, D39, [../crowdsec-hub.md](../crowdsec-hub.md)) is a classifier contract: `oversize` (1 MiB), `malformed`, `schema` ([../crowdsec-hub.schema.json](../crowdsec-hub.schema.json)), then the result of the op. A refused rule or index is a **valid** vector whose result names the code: only a broken vector input is invalid. Rule shapes are rewritten from the public hub, see [crowdsec-hub/NOTICE](crowdsec-hub/NOTICE). `crowdsec-set`: `oversize` (8 MiB, unit test, no vector), `malformed`, `schema` ([../crowdsec-set.schema.json](../crowdsec-set.schema.json)), then `schema` for an unreadable date, unsorted or duplicate names, a digest that does not fit its content, bad base64 and `changed_at` before `first_seen`.
- `rule-effect` (v0.6, D73, `contract/rules`) is a classifier contract: `oversize` (4 KiB), `malformed`, `schema` ([../rule-effect.schema.json](../rule-effect.schema.json)), then the result of the op: `effect` (status, effect, limited_by and disabled_by of one rule of any repository from mode, repository state, origin, approval record, disabled and settling), `request` (what that rule does to one request: action, outcome, reason, would_block_reason, counts_as_hit), `repository` (the effect of a repository in a gateway mode), `switch` (the state of a repository with the settings overlay) and `agent_write` (the scope of a rule write in the agent API). It replaces the ops `effect`, `switch`, `gateway_effect` and `agent_write` of `crowdsec-hub`, whose numbers stay unused.
- `waiting-page` (v0.5, D37): `oversize` (64 KiB), `malformed`, `schema` ([../waiting-page.schema.json](../waiting-page.schema.json): fail-closed reason, method, the five headers the decision reads, Host, D36 website id, a 32-bit jitter draw). The result is `{answer, variant, language, retry_after, refresh, body, site_name, marker, problem_code}` (`marker`: the response carries `Schild-Waiting: 1`; `problem_code` `waiting` for the problem variant; both since the D37 amendment of 2026-10-29 evening; `contract/waitingpage.Decide`, rules in [../waiting-page.md](../waiting-page.md)); fields that do not apply are null.
- `storage-bounds` (v0.5, D38): `oversize` (1 MiB), `malformed`, `schema` ([../storage-bounds.schema.json](../storage-bounds.schema.json), one of five ops), then `schema` for a row id or a drawn incident number used twice. Results (`contract/storage`, rules in [../storage-bounds.md](../storage-bounds.md)): `check_due` `{due}`; `cap_pass` `{used_before, deleted, used_after, unreachable}` (deleted ids in deletion order); `disk_budget` `{budget_bytes, need_bytes, reserve_bytes, verdict}`; `incident_aggregate` `{numbers, incidents}` (the number each block page shows, the incident rows in creation order); `disk_projection` `{hint, level, days_left, rate_bytes_per_day}` (null without hint).
- `ingress-order` (v0.5, D31 amendment 2026-10-29): `oversize` (1 MiB), `malformed`, `schema` ([../ingress-order.schema.json](../ingress-order.schema.json)), then `schema` for a route the rule cannot read (route fields other than group, match, handle, terminal; a handler without a string name; an invoke of an unknown named route or an invoke cycle; route lists nested over 32 deep). The result is `{findings}`: per site and `handle_errors` route at most one `{code, msg_key, server, route, hosts, directive, rewrite, schild}` (`contract/ingress.Check`, rules in [../ingress-order.md](../ingress-order.md)).
- `body-limits` (v0.5, D41): `oversize` (64 KiB), `malformed`, `schema` ([../body-limits.schema.json](../body-limits.schema.json), one of four ops). Results (`contract/bodylimit`, rules in [../body-limits.md](../body-limits.md)): op `admit` `{admitted, code, status, scope, class, fail_closed, retry_after}`, op `in_flight` `{max_in_flight}`, op `size` `{class, limit_bytes, code, status, held_bytes}`, op `rate` `{windows, below_min, first_below}`.
- `agent-block` (v0.5, D42): `oversize` (64 KiB), `malformed`, `schema` ([../agent-block.schema.json](../agent-block.schema.json), ops `create` and `lift`). A refused write is a **valid** vector whose result names the code. Result (`contract/agentapi` `CheckBlock`, `CheckLift`): `{allowed, status, code, effect, changed, limited_by, max_duration_s, persisted, counts_budget, retry_after}`.
- `request-recheck` (v0.5, D33 amendment 2026-10-29): `oversize` (64 KiB), `malformed`, `schema` ([../request-recheck.schema.json](../request-recheck.schema.json)), then `schema` when an evaluation other than the last stopped the request. The result is `{requests, rechecked, outcome, detection, path, checked_paths, rules, score}` (`contract/monitoring.Recheck`).
- `host-report` and `agent-report` (v0.5, D38): after the duplicate check, every `fix_config` must render a template of its finding id (`hostcheck.FixTemplates`), else `schema`; the key `content` directly inside a finding's `fix_config` is exempt from `forbidden_field`.

## Differential fuzzing

`make contracts-fuzz [SEED=42] [FUZZ_N=100000] [FUZZ_VECTORS=2000]` generates a SecLang corpus (`tools/seclang_fuzz.py`) and mutated, re-signed signed-message vectors (`tools/vector_fuzz.py`) into `contracts/.check/` and fails on any Go/Python disagreement. Expectations are not checked there, only agreement.

## Adding vectors

Add cases in `contract/cmd/genvectors` (or `contract/seclang/cases.go` for SecLang), run `make contracts-vectors`, then `make contracts-test`. Never hand-edit generated files. A vector that the two implementations judge differently is a finding: fix the contract text first, then the code.
