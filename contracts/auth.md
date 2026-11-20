# Sender authentication and transport (contracts v0)

Decision E1 (2026-10-26): prototype and alpha send signals directly over HTTPS with one key per website. From v1 (labs of other operators) OHTTP is mandatory, the relay belongs to another operator than the lab, and unlinkable tokens (Privacy Pass / ARC) replace the per-site signature. Therefore authentication and transport are interfaces from day one. Go: `contract/auth`, `contract/transport`.

**The signal and feedback payloads are identical under every scheme and transport.** They never contain a site identifier, a key id or an auth token ([signal.md](signal.md)).

## Schemes

| Scheme | Stage | What the lab learns | Implementation |
| --- | --- | --- | --- |
| `site-key` | Prototype, alpha | which site key signed (and its issuer) | `auth.SiteKeySigner` / `auth.SiteKeyAuthenticator` |
| `privacypass-arc` | v1+ | only the issuer; one presentation per context `(epoch, request_sig)` | `auth.TokenSigner` / `auth.TokenAuthenticator` (stubs returning `ErrNotImplemented`) |

```go
type Signer interface {            // client
    Scheme() string
    Seal(ctx context.Context, kind contract.Kind, payload []byte) (*Sealed, error)
}
type Authenticator interface {     // lab
    Scheme() string
    Open(ctx context.Context, kind contract.Kind, raw []byte, authorization string, vctx *verify.Context) (*verify.Result, *Sender, error)
}
type Sender struct { Scheme, KeyID, Issuer string }
```

### site-key (prototype)

- Each site has its own Ed25519 key with purposes `signal` and `feedback` (key file `/etc/schild/keys/site.key`). The key id should be opaque (for example `site-` plus the first 16 hex digits of sha256 of the public key), never the host name: the lab learns which key signed, it does not need to learn the domain from the key id.
- A signal or feedback envelope carries exactly one signature; one public key is admitted at most once (one key id, one issuer).
- The lab admits sites in `lab.yaml` `clients[]` with `keyid`, `public_key` and `issuer` (the guarantor, G2). Labs count tips **per issuer**, never per client key (Sybil, T08).
- Revocation: `clients[].revoked` or `issuers[].revoked`.
- A site key can never sign acks, checkpoints, bundles or withdrawals (purposes).

### privacypass-arc (v1, interface only)

- The envelope will carry no client signature; the token travels in `Authorization: PrivateToken token=...`. The envelope schema v0 requires at least one signature, so v1 brings envelope schema v1 (open point in [DECISIONS](DECISIONS.md)).
- The token's presentation context is `sha256(epoch || request_sig)`: one tip per client, epoch and signature, without linkability.

## Transports

| Transport | Stage | Implementation |
| --- | --- | --- |
| HTTPS | Prototype, alpha | `transport.HTTPS`: `POST {lab}/v0/submit`, JSON body [submission.schema.json](submission.schema.json) |
| OHTTP (RFC 9458) | v1+ | `transport.OHTTP` stub returning `ErrNotV1Yet` |

```go
type Transport interface {
    Name() string
    Submit(ctx context.Context, lab Lab, sub *msg.Submission, authorization string) (*Response, error)
}
```

### HTTPS submit (prototype)

```
POST /v0/submit HTTP/1.1
Content-Type: application/json

{"request_id":"<fresh uuid v4>","envelopes":[<envelope>, ...]}      (1..64 envelopes, <= 1 MiB)
```

- The lab answers immediately (ingest does only cheap, bounded work, concept 21 §5.0) with a signed ack envelope ([ack.schema.json](ack.schema.json)), `in_reply_to` = `request_id`. Status `200` normally; `429` (rate limited) and `503` (queue full) **also carry a signed ack** whose `control.retry_after_ms > 0`. A full queue never times out.
- Each envelope is verified on its own; the ack lists `accepted` (durably queued, not yet scored), `duplicate` and `rejected` (`id`, `reason` = error code; `00000000-0000-4000-8000-000000000000` when the envelope could not be parsed).
- The client verifies the ack (lab key with purpose `ack`, age <= 5 min, `in_reply_to` matches) before it trusts anything in it.
- The client sends from a bounded background queue, **never in the request path**. On error it retries with exponential backoff and jitter, or sends to its other labs. Signals are at-least-once; labs dedupe by signal `id`.
- No environment proxy, no redirects, TLS only (the test lab uses its own CA via `SCHILD_TEST_CA`).
- Errors are classified as `ErrRefused` (connection refused) or `ErrTimeout`. (The fail-open rule of MVP-02 concerns the local WAF process, not labs: lab failures never change how a request is handled.)
