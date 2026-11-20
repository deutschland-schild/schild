# Envelope: DSSE with Ed25519 (contracts v0)

Every signed Schild message is a [DSSE v1](https://github.com/secure-systems-lab/dsse) envelope. Schema: [envelope.schema.json](envelope.schema.json). Go: `contract/dsse`, verification: `contract/verify`. Decision: [DECISIONS](DECISIONS.md) D01.

```json
{
  "payloadType": "application/vnd.schild.signal.v0+json",
  "payload": "<standard base64 of the payload bytes>",
  "signatures": [{ "keyid": "web-1/2026-10", "sig": "<standard base64 of 64 bytes>" }]
}
```

## Signing

- Algorithm: Ed25519 (RFC 8032, pure, no prehash). Keys are 32-byte seeds; public keys are written `ed25519:<std base64>`.
- Signed bytes: `PAE(payloadType, payload) = "DSSEv1" SP LEN(payloadType) SP payloadType SP LEN(payload) SP payload`, lengths as ASCII decimal of the byte count. A signature over the raw payload is invalid.
- Encoding: standard base64 alphabet **with padding**, canonical only (no non-zero padding bits, no whitespace, no URL-safe alphabet). Envelope JSON is compact UTF-8, field order `payloadType`, `payload`, `signatures`. No other fields.
- Several signatures over the same payload are allowed (k-of-n for bundles and withdrawals), at most 16, except for **signal and feedback: exactly one signature** (code `envelope`). Duplicate key ids count once. Signatures by unknown or untrusted keys are ignored, not fatal (TUF semantics); what counts is whether enough valid trusted signatures remain.
- **The key id is binding.** A signature is verified only with the trusted key named by its `keyid`; verifiers never try other keys. A valid signature under a wrong `keyid` is ignored. One public key may appear only once in a trust store (under one key id, one lab, one operator or issuer); configurations that list a public key twice are rejected (`config`), otherwise one signature could count for two operators.

## Domain separation

One payload type per message kind, and every key has explicit purposes. A key may only sign kinds of its purposes, so a signature can never be reused across kinds.

| Kind | payloadType | Signed by (purpose) | Rule |
| --- | --- | --- | --- |
| signal | `application/vnd.schild.signal.v0+json` | site key (`signal`) | 1 valid signature (prototype and alpha; replaced by tokens in v1, [auth.md](auth.md)) |
| feedback | `application/vnd.schild.feedback.v0+json` | site key (`feedback`) | 1 valid signature |
| ack | `application/vnd.schild.ack.v0+json` | lab key (`ack`) | 1 valid signature by a key of the lab named in the payload, bound to the submission |
| checkpoint | `application/vnd.schild.checkpoint.v0+json` | lab online key (`checkpoint`) | 1 valid signature by a key of the lab named in the payload |
| rule-bundle | `application/vnd.schild.rule-bundle.v0+json` | lab keys (`rules`) | valid signatures from k **distinct operators** |
| withdrawal | `application/vnd.schild.withdrawal.v0+json` | lab keys (`rules`) | valid signatures from k distinct operators |
| agent-report (v0.3) | `application/vnd.schild.agent-report.v0+json` | agent key (`agent`), trusted only by its gateway | exactly 1 signature, by the key the report names; revoked keys yield `revoked` ([host-check.md](host-check.md)) |
| agent-enrolment (v0.3) | `application/vnd.schild.agent-enrolment.v0+json` | the new agent key itself (proof of possession) | exactly 1 signature, verified with the public key in the payload; not a trust-store kind |

k is the client's `min_independent_operators` (floor 2, default 3, [config/schild.schema.json](config/schild.schema.json)). Several labs of one operator count once. Payloads are plain JSON objects with a `schema` field (for example `schild.signal/0.3`); see [DECISIONS](DECISIONS.md) D01 for why they are not CloudEvents in v0.

## Key ids

`[a-z0-9][a-z0-9._/-]{0,127}`, recommended `<owner>/<purpose>/<yyyy-mm>` (for example `lab-uni-x/rules/2026-10`). Ids starting with `test-` are test keys ([testkeys/README.md](testkeys/README.md)); release builds refuse them and every public key of the test set, whatever its id. Rotation: add the new key to the trust configuration, sign with both for an overlap period, then remove the old key. Revocation: remove the key (lab: `revoked: true` on the client or issuer).

## Time and limits

| | Value |
| --- | --- |
| Clock skew tolerated | 120 s (issued_at / time_bucket may be up to 120 s in the future) |
| Signal and feedback age | `time_bucket` at most 24 h old; a lab remembers every accepted id at least until `time_bucket` + 24 h + 120 s (replay) and may then forget it, because the message is expired by then |
| Ack age | at most 5 min |
| Checkpoint validity | `expires - issued_at` in (0, 10 min] |
| Bundle validity | `expires - issued_at` in (0, 31 days] |
| Envelope / payload bytes | signal and feedback 16 KiB / 4 KiB, ack 64 KiB / 48 KiB, checkpoint 16 KiB / 4 KiB, withdrawal 64 KiB / 32 KiB, bundle 1 MiB / 768 KiB |

All timestamps are UTC with whole seconds: `YYYY-MM-DDTHH:MM:SSZ`.

## Verification order

The first failing check determines the error code. Go (`contract/verify`) and the Python cross-check implement exactly this order; see [vectors/README.md](vectors/README.md) for the full list including the kind-specific semantic checks.

1. `oversize` raw envelope bytes over the limit
2. `malformed` not strict JSON (duplicate keys, invalid UTF-8, lone surrogates, depth > 32, non-finite numbers, trailing data, not an object)
3. `envelope` envelope schema, non-canonical base64, signal or feedback envelope without exactly one signature
4. `oversize` decoded payload over the limit
5. `payload_type` payloadType is not the expected kind
6. `signature` (single signer) or `threshold` (k-of-n): valid signatures by trusted keys with the right purpose
7. `malformed` payload is not strict JSON
8. `forbidden_field` (signal, feedback) a forbidden key anywhere in the payload
9. `schema` payload schema, including unknown fields
10. kind-specific checks: `clock_skew`, `expired`, `validity`, `replay`, `channel`, `rollback`, `equivocation`, `seclang`, `evidence`, `duplicate_rule`
