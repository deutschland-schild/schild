# schild-lab (MVP-03 lab core, MVP-10 server side)

> **Status: prototype, test lab only.** Built and measured in the test lab (stage 2), not released and not run in production. Since D72 ([contracts/DECISIONS.md](../contracts/DECISIONS.md)) the Schild Gateway sends no signals and takes no rule bundles, so nothing in the released product talks to a lab; "client" below means the TEST ONLY clients of the test lab. The network is planned to come back as a rule repository (D73), with its own decision. Open measurements: [tests/results/REPORT.md](../tests/results/REPORT.md).
>
> The module builds inside the repository's Go workspace (`go.work`) only: it imports `contract` and `relay` without `require` or `replace` lines ([contracts/conventions.md](../contracts/conventions.md)), so `go install` from outside the repository does not work. Build with `make` or `lab/Dockerfile`.

Lab core of Schild: fast ingest, durable priority queue, scoring v0, pattern store, rule proposals with evidence, human approval, k-of-n bundles and withdrawals, the public log, the feed for relays, and the lab dashboard API. Go, `CGO_ENABLED=0`, contracts v0 (`contracts`, `contract`).

```text
client ──POST /v0/submit──► ingest ──group commit──► queue (segment log, priorities)
  ▲   signed ack, ms          │ verify, limits, dedupe        │
  └───────────────────────────┘                               ▼
                                   scoring v0 (own goroutine, store.db): patterns by issuer
                                                              │
                       dashboard (people) ──► proposals ─► evidence level (G2/G3) ─► approval
                                                              │
                                     bundle / withdrawal, signed by this lab
                                                              │  co-signatures of other operators
                                                              ▼  (k distinct operators)
                         feed :7444  /v0/stream (SSE) ─► relays ─► clients verify everything
                                     public log (hash chain) + checkpoint {bundle, withdrawal_seq, log root}
```

## Ports and endpoints

| Listener | Default | Endpoints |
| --- | --- | --- |
| ingest | `0.0.0.0:7443` (TLS if `tls` is set) | `POST /v0/submit`, `GET /healthz`, `GET /readyz` |
| feed | `0.0.0.0:7444` (TLS if `tls` is set) | `GET /v0/stream`, `GET /v0/bundles/<channel>/<v>.json`, `GET /v0/checkpoint`, `GET /v0/collecting` (peers only, signed request), `POST /v0/signatures`, `GET /v0/log?from=&limit=`, `GET /healthz`, `GET /readyz` |
| dashboard | `127.0.0.1:8789` | UI (embedded, `make ui`), `/api/v0/...` (lab-dashboard.openapi.yaml), `GET /healthz` |
| metrics | `127.0.0.1:9102` | `GET /metrics`, `GET /healthz` |

## Commands

```sh
schild-lab [run] [-config lab.yaml] [-check]   # default config: $SCHILD_LAB_CONFIG or /etc/schild-lab/lab.yaml
schild-lab preflight [-config lab.yaml]    # D24 preflight only (same as run -check); exit 1 = would refuse to start
schild-lab check-config                    # lab.yaml + key files
schild-lab keygen -out FILE -lab LAB [-operator OP] [-keyid ID] [-purposes ack,rules,checkpoint] [-config-path PATH]
                                           # production signing key (0600, outside the repo); prints keyid, public key
                                           # and the snippets for lab.yaml keys[], verifying clients, peers[].keys
schild-lab tls-keygen -out-dir DIR -host lab-1.example.org   # TLS key (0600) + CSR for tls.cert_file / tls.key_file
schild-lab health                          # container health check
schild-lab user add -name bob < pw.txt     # extra dashboard user (lab stopped)
schild-lab cosign -key lab.key -keyid ID [-in env.json | -from https://lab-x:7444 -digest sha256:...] [-post URL] -yes
schild-lab export d2 [-from DAY] [-to DAY] [-data DIR]   # D2: first-seen per pattern and site key, lags (no IPs); GET /export/d2 on the metrics listener
schild-lab export d2-merge FILE ...                       # combine the D2 exports of several labs
schild-lab dev-certs | dev-send            # non-release builds only (TEST ONLY helpers)
```

Preflight (D24, `contract/preflight`): before it opens a port the lab refuses to start when a key of `keys[]` (by its private key file), `clients[]` or `peers[].keys` is a key from `contracts/testkeys` or has a key id starting with `test`, when the test lab CA is among the trusted CAs (`SCHILD_TEST_CA`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, system bundle; recognised by the embedded fingerprint and by the subject marker `(TEST ONLY)`), or when `tls.cert_file` is issued by it. One ERROR log line lists every finding; exit status 1. `SCHILD_ALLOW_TEST_KEYS=1` (test lab compose files and dev scripts only) turns the refusal into a warning.

Keygen: one key with the purposes `ack`, `rules` and `checkpoint` is the default; the `rules` key also signs peer requests (`Schild-Peer-Auth`) and co-signatures. A lab that keeps its rules key offline runs `keygen` twice (`-purposes rules` offline for `cosign`, `-purposes ack,checkpoint` online). Default key id `<lab>/<YYYY-MM>-<16 hex>`. In a container: `docker run --rm --user 0 -v /etc/schild-prod/lab-1/keys:/out schild-lab:dev keygen -out /out/lab.key -lab lab-1 -operator op-1 -config-path /run/schild-lab/keys/lab.key`, then `chown 65532:65532` the file.

Environment besides `SCHILD_LAB_CONFIG`, `SCHILD_LAB_DATA_DIR`, `SCHILD_TEST_CA`, `SCHILD_ALLOW_TEST_KEYS`, `SCHILD_LOG_LEVEL`, `SCHILD_LOG_FORMAT`:

| Variable | Default | Meaning |
| --- | --- | --- |
| `SCHILD_LAB_THRESHOLD` | `3` | distinct operators needed before this lab publishes a bundle or makes a withdrawal effective (floor 2) |
| `SCHILD_LAB_SIMULATED_OPERATORS` | none | `lab-x=sim-x,...` - test profile only, never in release builds; independence that exists only through this mapping caps rules at `observe` |
| `SCHILD_LAB_QUEUE_SYNC` | `os` | durability of an ack: `os` = fsync(2) (survives a crash of the lab and of the OS); `full` = also flush the drive cache (macOS `F_FULLFSYNC`; same as `os` on Linux) |

## Ingest (hot path)

Only cheap, bounded work (concept 21 §5.0): size limit, strict JSON, an in-flight limit of about 2x the CPU cores (waits at most 15 ms for a slot, then answers `429 rate_limited`), per envelope revocation, signature and contract checks through `auth.Authenticator` (site key now, tokens in v1), per-key rate limit, per-key and per-issuer daily quota, dedupe by message id, tiered admission, one group commit. Every answer carries a signed ack (`schild.ack/0.1`), also `429` and `503` with `control.retry_after_ms > 0`. A full queue answers at once; a commit slower than 500 ms is answered `queue_full` instead of waiting (no client timeout).

The verification slot covers CPU work only; waiting for the disk happens after it is released, so many requests share one fsync.

## Queue

Own directory (`<data>/queue/`), append-only segment files with CRC-checked records, one writer goroutine, group commit with one fsync, a separate done-log written by scoring, segments deleted when drained, a torn tail cut at startup. Priorities: new patterns, repeats, sampled baseline (`score < min_score`). Admission is tiered: baseline below 80 % of `queue_max_depth`, repeats below 95 %, new patterns below 100 %, reserved atomically. Accepted ids are remembered until `time_bucket + replay_window + 2 x clock skew`; after a restart the set is rebuilt from the queue and from the ids the scorer stored.

## Scoring v0 (no AI)

Rules: drop anything address-like in free-text tokens and forbidden keys (again), drop tips whose origin is on the client's protection list and count them against the issuer (G6), keep the sampled baseline out of tip counts. Statistics per `action_sig`: signals, issuers, clients, request signatures, countries, ASNs, net classes, agents, WAF rules, first/last seen, hourly timeline. **Counting unit: one (issuer, request_sig, time_bucket)**: many client keys of one issuer (Sybil) or repeats add nothing. A pattern turns `watching` when tips of at least `min_issuers` (>= 3) issuers arrive in the window with no issuer above `max_issuer_share` (<= 0.34): that is the observe level, the highest that tips can ever reach.

## Proposals, evidence and approval

- A proposal needs a SecLang text that passes the subset (`contract/seclang`), a target and evidence. Reproductions store the raw reproducing request privately (sha256 shown and logged) plus the target container image and version (MVP-03).
- Allowed max action = `msg.EvidenceLevel` (G2) with the lab's stricter tip thresholds, capped at `observe` without a clean negative corpus run (G3 gate 1) and when independence exists only through simulated operators (E5).
- Approval names a person (logged-in user) and an organisation. The approved action can never exceed the requested action or what the evidence allows *including* this approval; the rule must pass the full contract check (`verify.Signed` on a self-check bundle). Editing an approved proposal clears its approvals. `require_human_approval` is fixed.
- Every approval and rejection is in the public log (digest of the rule text, counts only).

## Bundles, withdrawals and co-signing (k-of-n)

`POST /api/v0/bundles` assembles the next version: the rules of the newest published bundle minus withdrawn and removed rules, plus approved proposals at `min(requested, allowed, approved)`. The payload is checked with the contract verifier, signed with this lab's `rules` key and offered for co-signing. Withdrawals (`POST /withdrawals`) and the emergency stop (`POST /emergency-stop`: typed `NOT-AUS` + password) work the same way.

How a second operator co-signs:

1. Its lab lists this lab under `peers[]` (endpoint, operator, keys) and this lab lists it. Its peer manager polls `GET /v0/collecting` here every 10 s, signed with its `rules` key (`Schild-Peer-Auth`, contracts v0.1, [cosign.md](../contracts/cosign.md)); this lab answers only configured peers (everyone else: `401`), because collecting items carry rule texts that are not published yet. The peer shows the item in its dashboard (bundles and withdrawals with status `collecting`, `proposed_by` = this lab), after checking the payload with the contract verifier and this lab's signature.
2. A person there reviews it and confirms with their password (`POST /api/v0/bundles/{version}/cosign` or `POST /api/v0/withdrawals/{seq}/cosign`). Their lab signs the **same payload bytes** with its `rules` key and posts the signature here (`POST /v0/signatures`, body `{kind, digest, signature{keyid, sig}}`). This lab verifies it against the peer's configured key.
3. Offline alternative: `schild-lab cosign -from https://lab-a:7444 -digest sha256:... -key lab.key -keyid ID -yes -post https://lab-a:7444` (prints a summary first; without `-post` it prints the signature JSON).
4. As soon as signatures of `SCHILD_LAB_THRESHOLD` distinct operators are present (several labs of one operator count once), the lab publishes: feed event, checkpoint, public log. Peers following the feed import the k-of-n envelope too, so every lab serves the newest state (labs are relays).

Clients count operators themselves (`min_independent_operators`, floor 2, default 3); a lab publishing early cannot lower that.

## Public log and checkpoint

RFC 6962 Merkle tree over line-based leaf data `{index, time, kind, ref, digest, summary, sha256(envelope)}` (contracts v0.1, [cosign.md](../contracts/cosign.md), `contract/logtree`); the lab keeps the tree frontier (O(log n)) and rebuilds it once from the entries of a log written by an older build (hash chain). `Append` refuses free text, address-like strings and envelopes on proposal entries. The checkpoint (re-signed every `checkpoint_interval_s`, validity `checkpoint_ttl_s` <= 10 min) carries `log {size, root}` of the entries before it, so a log copy can be checked against a signed root (`publog.Verify`, the lab dashboard in the browser, the smoke test). Checkpoints are logged when the announced state changes and hourly.

## Dashboard API

All operations of `contracts/api/lab-dashboard.openapi.yaml` (contracts v0.1), including `GET /api/v0/events/stream` (SSE, event name = topic: `health` LabHealth at once and every 5 s, `signals` ReceivedSignal, `log` LogEntry, and a LiveNotice for `patterns`, `proposals`, `bundles`, `withdrawals`, `network`, `issuers`, `clients`, `settings` after every change) and `POST /api/v0/bundles/{version}/cosign` (body `Confirm`). Four eyes: the person who drafted a proposal (`created_by`) cannot approve it (`403 self_approval`). `GET /relays` reports per relay the newest bundle version and withdrawal seq this lab delivered to it. Settings overlay: `PATCH /settings` and quota/revocation changes are validated with the lab.yaml validator and stored in the lab store (lab.yaml may be read-only in containers).

Security: localhost sessions (loopback peer and loopback `Host`, no proxy headers) may read and draft; every decision (approve, reject, assemble, co-sign, withdraw, emergency stop, revoke, settings) needs a named user who logged in with a password (PBKDF2-SHA256, 600k iterations, 5 failures per 15 min). First-run setup from another host needs the one-time code from the lab log. Cookie `schild_lab_session` (HttpOnly, SameSite=Strict, Secure except plain localhost), `X-CSRF-Token` on state changes, strict CSP (`script-src 'self'; style-src 'self'`: no inline scripts, no inline styles), `frame-ancestors 'none'`, `nosniff`, `no-referrer`.

## Metrics

`schild_lab_ack_seconds{status}` (histogram), `schild_lab_queue_depth{priority}`, `schild_lab_queue_max_depth`, `schild_lab_queue_oldest_seconds`, `schild_lab_ack_p99_seconds`, `schild_lab_ingest_envelopes_total{result}`, `schild_lab_ingest_retry_after_total{reason}`, `schild_lab_scoring_processed_total{result}`, `schild_lab_scoring_lag_seconds`, `schild_lab_checkpoints_total`, `schild_lab_feed_*` (clients, events, disconnects, syncs, fan-out), `schild_lab_replay_ids`.

## Tests

`make lab-test` (gofmt, vet, release build, short tests), `cd lab && go test ./...` (full, includes the 10k-client burst), `make lab-bench`, `make lab-smoke` (native binaries: 3 labs with TLS and peers, relay, client, watcher), `make lab-docker-smoke` (same with the images on the internal network `10.66.33.0/24`).

## Data

`<data>/store.db` (bbolt: signals for `retention.signals_days` <= 30, aggregates for `aggregates_days`, proposals, bundles, withdrawals, log, users, settings overlay), `<data>/queue/` (segment log). The lab never receives or stores visitor IPs.
