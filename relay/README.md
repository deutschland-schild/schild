# schild-relay (MVP-04)

> **Status: prototype, test lab only.** Built and measured in the test lab (stage 2), not released and not run in production. Since D72 ([contracts/DECISIONS.md](../contracts/DECISIONS.md)) the Schild Gateway sends no signals and takes no rule bundles, so nothing in the released product follows a relay; "clients" below are the TEST ONLY clients of the test lab and `schild-relay watch`. The network is planned to come back as a rule repository (D73), with its own decision. Open measurements: [tests/results/REPORT.md](../tests/results/REPORT.md).
>
> The module builds inside the repository's Go workspace (`go.work`) only: it imports `contract` without `require` or `replace` lines ([contracts/conventions.md](../contracts/conventions.md)), so `go install` from outside the repository does not work. Build with `make` or `relay/Dockerfile`.

Untrusted public SSE fan-out of lab-signed checkpoints, rule bundles and withdrawals (`contracts/stream.md`). Clients verify everything; a relay can only delay or withhold, and clients detect that through the signed checkpoints.

## Endpoints (port 7480)

| Endpoint | Content |
| --- | --- |
| `GET /v0/stream` | SSE, `Last-Event-ID` resume (header or `?last_event_id=`) |
| `GET /v0/bundles/<id>/<version>.json` | bundle envelope bytes, immutable. Held by the relay, or fetched from an upstream on demand: with a known reference checked against size and SHA-256 and cached; without one only passed on as `no-store` if the envelope really is that bundle (D40) |
| `GET /v0/checkpoint[?lab=<id>]` | newest checkpoint envelope |
| `GET /v0/state.json` | static fallback: a full sync as JSON `{last_event_id, full_sync, events[]}` |
| `GET /v0/poll?last_event_id=&wait=25` | long-poll fallback (same JSON), waits up to 60 s for new events |
| `GET /healthz`, `GET /readyz` | liveness; ready once an upstream is connected and a checkpoint is known |
| `:9103/metrics` | Prometheus |

## Behaviour

- **Upstreams**: `SCHILD_RELAY_UPSTREAMS` (lab feeds on 7444 or other relays), each followed with `Last-Event-ID`, reconnect with exponential backoff and full jitter (1 s .. 60 s), idle watchdog 45 s. Events are checked against the stream schema only; envelope bytes are passed on unchanged. Referenced bundles are downloaded, checked against `ref.sha256` and `ref.size`, and served from the relay.
- **Ids** `<epoch>-<seq>`, epoch random per start. Broadcast events go into a ring of 4096; a known `Last-Event-ID` gets every later event, anything else (other relay, restart, too old) a **full sync**: withdrawals that still apply, newest bundle per upstream, newest checkpoint per lab, in priority order with fresh ids. State is kept per upstream, so one upstream announcing a bogus "newest" bundle cannot hide another upstream's.
- **No gaps**: ids on one connection are strictly increasing and broadcast events are never reordered, so resuming after the last received id is exact. Priority (withdrawal > bundle > checkpoint > heartbeat) applies to the full sync order and to backlog shedding: a pending older checkpoint of the same lab or an older heartbeat is dropped first; withdrawals and bundles are never dropped. A client whose backlog still exceeds `SCHILD_RELAY_BUFFER` (256) is disconnected and resyncs.
- **Heartbeat** every 15 s with the newest lab-signed checkpoint (by `issued_at`); a keep-alive comment when idle.
- **Limits**: `SCHILD_RELAY_MAX_PER_IP` concurrent streams per source address (default 32, `429` with a random `Retry-After` 5-30 s), `SCHILD_RELAY_MAX_CLIENTS` in total (default 50,000, `503`). Write deadline 30 s per flush. Behind a proxy the source address is the proxy's unless the proxy is listed in `SCHILD_RELAY_TRUSTED_PROXIES` (comma-separated CIDRs, default none; ranges wider than /8 or /32 refuse to start): the relay then counts the rightmost address of `SCHILD_RELAY_CLIENT_IP_HEADER` (default `X-Forwarded-For`) that is no trusted proxy. The proxy must set or append that header itself.

## Commands and environment

```sh
schild-relay                     # run (env below); D24 preflight first
schild-relay preflight           # preflight only (also: schild-relay -check); exit 1 = would refuse to start
schild-relay keygen -out-dir DIR -host relay-1.example.org
                                 # TLS key (0600, outside the repo) + CSR; relays sign nothing, so this is their only key
schild-relay health              # container health check
schild-relay watch -url URL (-keys lab=op:keyid=ed25519:...,... | -test-keys lab-a,lab-b) [-k 3] [-for 30s]
                                 # follow a relay/lab like a client, one JSON line per event with the verification result
```

`SCHILD_RELAY_ID` (default: sanitised hostname), `SCHILD_RELAY_LISTEN` (`:7480`), `SCHILD_RELAY_METRICS` (`:9103`, empty disables), `SCHILD_RELAY_UPSTREAMS`, `SCHILD_RELAY_BUFFER` (256), `SCHILD_RELAY_MAX_PER_IP`, `SCHILD_RELAY_MAX_CLIENTS`, `SCHILD_RELAY_TRUSTED_PROXIES`, `SCHILD_RELAY_CLIENT_IP_HEADER`, `SCHILD_RELAY_TLS_CERT` + `SCHILD_RELAY_TLS_KEY` (serve TLS), `SCHILD_TEST_CA`, `SCHILD_ALLOW_TEST_KEYS`, `SCHILD_LOG_LEVEL`, `SCHILD_LOG_FORMAT`.

Preflight (D24, `contract/preflight`): the relay refuses to start when the test lab CA is among the CAs it trusts for upstream TLS (`SCHILD_TEST_CA`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, system bundle) or when `SCHILD_RELAY_TLS_CERT` is issued by it, unless `SCHILD_ALLOW_TEST_KEYS=1` (test lab only) is set.

## Metrics

`schild_relay_clients`, `schild_relay_events_total{type}`, `schild_relay_disconnects_total{reason}`, `schild_relay_syncs_total{mode}`, `schild_relay_fanout_seconds` (publish to written), `schild_relay_rejected_connections_total{reason}`, `schild_relay_upstream_events_total{type,result}`, `schild_relay_upstream_connected{upstream}`, `schild_relay_checkpoint_age_seconds`, `schild_relay_labs`.

## Shared packages

`relay/hub` (SSE fan-out, also the lab feed; optional `Track` and `Delivered` hooks tell the lab which relays are connected and which bundle version and withdrawal seq each has received, for the lab dashboard's relay coverage), `relay/upstream` (stream subscriber, ref download, HTTP client without proxy and redirects), `relay/metrics` (dependency-free Prometheus exposition).

## Tests

`make relay-test`: resume without gaps, unknown/too-old ids give a full sync in priority order, overflow and coalescing, long-poll, heartbeat, relay restart (new epoch) without missed state, forged/under-signed/expired/rolled-back bundles rejected by a verifying client, frozen relay detected within 180 s + one heartbeat, ref bundles checked and served byte-identical, per-IP limit, readiness. `make relay-bench`: in-process fan-out to 10,000 clients.
