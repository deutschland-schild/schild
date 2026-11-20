# Stage-3 baseline: M1 and M2 on pinned images (commit b18f9b2)

> Note: the raw artifacts under `raw/` (per-run JSON, logs, event exports) are not part of this repository; see [../README.md](../README.md). The paths name where they lay during the measurement.

Independent re-measurement of M1 (B01, K3, T12) and M2 (T19) on images built from the clean commit, as required by concept 23 (same image digests live as tested) and REPORT.md "Nachtrag: Vorbereitung Stufe 3", open item 1. The measuring agent built none of the components. Kill criteria are the frozen ones from concept 23 §2 (D23). Humans decide what a result means (README rule 5).

Run: 2026-10-26, 22:31–23:10 UTC.

## Environment

| | |
| --- | --- |
| Commit | `b18f9b21ef924a22a45b254d16a5b7307bb48a03`, `git status` clean at build time |
| Host | Apple M2 Max, 12 cores, 64 GiB, macOS (Darwin 25.5.0), shared dev laptop with ~30 unrelated containers running |
| Docker | Docker Desktop 29.5.2, Linux VM (12 CPU, ~23 GiB), overlay2 store, builder `desktop-linux` |
| Profiles | t0 (smoke, B01, K3, T12, T19) and t1 (smoke, T19 with effective canary IPs) |
| Platform | **linux/arm64**. amd64 production hosts need a `linux/amd64` rebuild of this commit and a re-test on it (runbook section 3); these digests do not apply there. |

### Images (local image config IDs, `docker image inspect .Id`; never pushed, so there are no registry digests)

| Image | ID |
| --- | --- |
| `schild:mvp` | `sha256:18af479c587178ba35322ad447d1267d0b53c87bb4e25cea7a679397fd7a9de6` |
| `schild-lab:mvp` | `sha256:be7fad6d1f41b0a17172d81f014ecdd8c9c96683b88f75e89b75cf37ade4c866` |
| `schild-relay:mvp` | `sha256:acee0669843d56cbd176234e93593375df732bafbf3319d208e6ba0f81176c47` |
| `schild-testlab:mvp` | `sha256:0e690e7d2561e564b814930f5207192059a48fd653fb04d93105d03157b4fdae` |
| `schild-traffic:mvp` | `sha256:be5a42934619043aeb611975c7008bd7542f96cea6ee5b1b7276f669088ad589` |
| `schild-adversary:mvp` | `sha256:63b9208f986050f5cc47821c8569bc9a06d7ab3ed88fb1df59c1f36eaecc4936` |

How the build was pinned to the commit:

- `make ui` then `BUILDX_BUILDER=desktop-linux make images` from the clean tree. The dashboards' `dist/` is gitignored and embedded into `schild` and `schild-lab`, so `make ui` was run first. Content hashes of the embedded dist: client `1b9fa8db…`, lab `5e82ad59…`.
- Every layer was a build-cache hit, and the IDs are identical to the integration build listed in REPORT.md (`18af479c5871`, `be7fad6d1f41`, `acee0669843d`, …).
- Check: `git archive b18f9b2 mvp` was extracted into an empty directory, and `make ui` plus `make images TAG=s3bverify` were run there. The result had the same dist hashes and the **same six image IDs**. The temporary tags were then removed.
- Every container in both stacks was checked to be running exactly these IDs.

## Commands

```sh
cd mvp
export SCHILD_LABEL_SECRET=schild-testlab-dev-secret SMOKE_PASSWORD=schild-testlab-passwort
make ui && BUILDX_BUILDER=desktop-linux make images
make testlab-up PROFILE=t0 && make smoke PROFILE=t0
NET=schild-testlab-t0_sites
# B01: per run `docker restart schild-testlab-t0-site-api-1` first (see "Harness findings" 1), 3 repetitions, no/with order alternated
docker run --rm --network $NET schild-testlab:mvp /usr/local/bin/measure latency -target http://site-api:8080   -label no_schild   -rps $RPS -duration 20s -warmup 3s
docker run --rm --network $NET schild-testlab:mvp /usr/local/bin/measure latency -target http://schild-api:8080 -label with_schild -rps $RPS -duration 20s -warmup 3s
# K3 (twice, fresh site-api)
docker run --rm --network $NET schild-testlab:mvp /usr/local/bin/measure k3 -schild http://schild-api:8080 -load-rps 300 -load-duration 15s
# T12 (three times) + instrumented kill-under-load repeats (see T12 section)
make testlab-t12
# T19 on t0 (also once without --ip, see "Harness findings" 2)
docker run --rm --network schild-testlab-t0_inet --ip 10.66.4.11 -e SCHILD_LABEL_SECRET schild-testlab:mvp /usr/local/bin/measure egress -stripper http://stripper-api:8080 -n 60
docker run --rm -v schild-testlab-t0_export-api:/export:ro schild-testlab:mvp /usr/local/bin/egress-check -log /export/transparency.ndjson -json \
  -canaries CANARYqv,CANARYbody,CANARYcookie,CANARYua,CANARYpath -forbidden-ips 203.0.113.66,2001:db8:dead:beef::66
make testlab-down PROFILE=t0
make testlab-up PROFILE=t1 && make smoke PROFILE=t1
# T19 on t1: same two commands with schild-testlab-t1_inet, --ip 10.66.20.11, volume schild-testlab-t1_export-api
make testlab-down PROFILE=t1
```

Measurement helpers were kept **outside the repository** (nothing was added under `testlab/cmd/measure`). The source is kept at `~/.cache/schild-s3b-probe/src`; the other scripts were working files under `/tmp`.

- `t12probe`: a stdlib Go open-loop load generator that records start and end time, method, status and transport error for every request. It ran as a throwaway image `schild-s3b-probe:local`, which has since been removed.
- `t12kill.sh`: repeats T12 phase B, which kills schild-t12 under probe load. It records `docker events` (kill/die) and the front log. For every failed POST it checks whether the item reached site-api.
- `labscan.py`: the lab-side M2 scan (see T19).

## Results

| File | Spec | What | Verdict |
| --- | --- | --- | --- |
| [smoke-t0.json](smoke-t0.json) | MVP-05 | `make smoke PROFILE=t0`: 16/16 steps, evaluator pass (bypass 0, legit blocks 0, canary 0), browser check 4 dashboards | pass |
| [smoke-t1.json](smoke-t1.json) | MVP-05 | `make smoke PROFILE=t1`: 16/16 steps, evaluator pass, browser check 6 dashboards | pass |
| [B01-latency-t0.json](B01-latency-t0.json) | MVP-02 | M1 request overhead, 3 × paired runs per rate | pass |
| [K3-resilience-t0.json](K3-resilience-t0.json) | MVP-02 | M1 bypass under timeout/overload | pass |
| [T12-failopen-t0.json](T12-failopen-t0.json) | MVP-02 | M1/D3 front-proxy fail-open, 3 runs + 14 instrumented kills | pass |
| [T19-egress-t0.json](T19-egress-t0.json) | MVP-02 | M2 egress, t0 | pass |
| [T19-egress-t1.json](T19-egress-t1.json) | MVP-02 | M2 egress, t1, with the canary source IPs in effect (the main T19 run) | pass |

All seven files validate against `contracts/results.schema.json` (with `common.schema.json` refs resolved), and every listed artifact exists under `raw/`.

### M1 — B01 / T20 overhead (fresh backend per run, 20 s, 3 s warmup, 0 request errors in all 18 runs, offered rate met)

| rps | rep | p50 no / with | p95 no / with | p99 no / with | overhead p50 / **p95** / p99 |
| --- | --- | --- | --- | --- | --- |
| 50 | 1 | 0.50 / 2.38 | 1.10 / 5.67 | 1.74 / 7.38 | +1.89 / +4.57 / +5.64 |
| 50 | 2 | 0.60 / 3.05 | 1.15 / 5.60 | 1.50 / 7.18 | +2.45 / +4.46 / +5.68 |
| 50 | 3 | 0.56 / 2.87 | 1.19 / 5.86 | 1.76 / 7.14 | +2.30 / +4.67 / +5.38 |
| **500** | 1 | 0.29 / 0.95 | 1.19 / 1.51 | 1.91 / 2.96 | +0.66 / **+0.33** / +1.05 |
| **500** | 2 | 0.30 / 0.94 | 1.23 / 1.53 | 1.98 / 2.97 | +0.64 / **+0.30** / +1.00 |
| **500** | 3 | 0.31 / 0.96 | 1.32 / 1.62 | 2.82 / 3.08 | +0.64 / **+0.31** / +0.26 |
| 2000 | 1 | 0.20 / 0.94 | 1.81 / 3.13 | 2.87 / 16.99 | +0.75 / +1.32 / +14.12 |
| 2000 | 2 | 0.18 / 1.01 | 1.74 / 3.54 | 3.07 / 10.13 | +0.82 / +1.80 / +7.07 |
| 2000 | 3 | 0.21 / 0.91 | 1.77 / 2.76 | 2.93 / 5.70 | +0.70 / +0.99 / +2.76 |

Values in ms. **Kill criterion "p95 overhead > 5 ms at 500 rps": not hit** (+0.30 to +0.33 ms). Stage 2 measured +0.81 ms.

Observation (not a kill criterion): at **50 rps** the overhead is larger than at 500 rps, about +4.5 ms at p95 and +2.3 ms at p50, and it repeated in all three runs. This fits idle wake-up latency: at low rates both proxy processes and the VM's vCPUs sleep between requests, while the baseline wakes only one process. That explanation is a hypothesis and has not been verified. The value sits close to 5 ms. If stage-3 sites mostly see low traffic, it is worth one look on the real host.

### M1 — K3 resilience corpus (2 runs, 75 corpus requests each under 300 rps benign load)

| case | status | latency ms (run 1 / 2) | handling |
| --- | --- | --- | --- |
| oversized_body (20 MiB) | 413 | 1.1 / 1.7 | hard limit, reject |
| nested_json (depth 200) | 400 | 0.8 / 2.1 | reject |
| redos_query | 404 | 1.7 / 1.2 | inspected, benign path |
| huge_urlencoded_field (2 MiB) | 503 | 1008 / 1011 | eval timeout, fail-closed |
| too_many_args (1500) | 400 | 1.7 / 4.0 | reject (`too_many_args`, D24) |

**bypass_count = 0 in both runs. Kill criterion "a single request reaches the backend uninspected on timeout/overload": not hit.**

### M1 / D3 — T12 front-proxy fail-open (`make testlab-t12`, 100 rps, front timeout 3 s)

| phase | run 1 | run 2 | run 3 |
| --- | --- | --- | --- |
| A schild up | 1000 × 2xx, 0 bypassed | same | same |
| B `docker kill` under load | 1200 × 2xx, 0 errors, 819 bypassed after the kill | 1200 × 2xx, 815 | 1200 × 2xx, 817 |
| C schild dead | 1000 × 2xx, 1000 fail-open | same | same |
| D restarted | 1000 × 2xx, 0 bypassed | same | same |
| E hung (`docker pause`) | **160 × 503, 0 bypassed** | same | same |
| F unpaused | 1000 × 2xx, 0 bypassed | same | same |

All four verdict checks were true in every run. None of the three runs produced a 502.

#### The single 502 from the integration run

That 502 could not be reproduced at 100 rps. It was investigated with 14 extra instrumented kills. Each kill was timed against the `kill` event in `docker events`, and the front log was correlated with it (`raw/t12-kill-analysis/`).

| load at kill | kills | 502s | methods of the 502s |
| --- | --- | --- | --- |
| 100 rps, measure mix (25 % POST) | 6 | 0 | – |
| 1000 rps, measure mix | 4 | 1, 2, 2, 2 | all POST |
| 1000 rps, GET only | 2 | 0, 0 | – |
| 1000 rps, POST only | 2 | 8, 5 | all POST |

- **When:** every 502 was a request whose connection to schild was open when SIGKILL took effect. Each started between −2.5 and +3.8 ms of the daemon's `kill` event and ended about 4–4.6 ms after it. The `die` event follows about 30 ms later. Each 502 matches exactly one front log line, `schild error`, with `read: connection reset by peer` (or `EOF` once). No 502 occurred outside this window.
- **Retries:** `schild front` uses Go's `http.Transport`, which **retries idempotent requests** on a reused connection that fails before a response arrives. GETs in flight at the kill were retried, hit "connection refused", and were served through fail-open: 0 errors in the GET-only kills. **POST is not replayable, so it is not retried**, and the error handler answers 502 (`default` branch in `client/internal/failopen`). That is correct: replaying a POST that schild may already have forwarded could duplicate a write.
- **Side effects:** 1 of the 20 failed POSTs had already reached the app through schild, so it was inspected; the app created the item, but the client got a 502. The other 19 never reached the app.
- **Classification:** this does **not violate M1**, because nothing reached the backend uninspected: the failed requests were inspected or never delivered. It is also **not a D3 outage**. The site stayed reachable throughout. The failures are the in-flight non-idempotent requests at the moment of a crash, a few milliseconds' worth, which is the same as any reverse-proxy crash. Expected behaviour; document it as a limitation.
- **nginx front:** with `client/deploy/nginx-front.conf` (`proxy_next_upstream off`), nginx would also answer 502 to in-flight **GETs** during a crash. That front is untested (REPORT open item 6).

### M2 — T19 egress

| | t0 | **t1 (main run)** |
| --- | --- | --- |
| Canary requests | 60 from an untrusted address + 60 from trusted 10.66.4.11 | 60 from trusted 10.66.20.11 |
| Canaries | path, query, JSON body, cookie, UA; source IP 203.0.113.66 / 2001:db8:dead:beef::66 via XFF | same |
| Positive control: canary IP in the client's **local** events | 30 + 30 (second batch only) | 30 + 30 |
| New signals from the canary requests | 60 (first batch; second batch had the same request shapes, so no new signals) | 60 (240 deliveries to 4 labs) |
| `egress-check` over the transparency log (canary / IP / field) | 213 signals: 0 / 0 / 0 | 284 signals: 0 / 0 / 0 |
| Lab side: every received signal from the lab API, schema-validated + IPv4/IPv6/canary scan | 3 labs × 71: 0 findings | 4 labs × 82: 0 findings; 60/60 T19 signals at every lab; 71/71 client-sent ids received per lab |

The lab-side scan is independent of both the client and the testlab's egress package. It checks:

- every payload against `contracts/signal.schema.json`, where `additionalProperties: false` enforces the positive list;
- canary strings;
- IPv4 literals;
- IPv6 literals, validated with Python's `ipaddress`.

Positive controls for the scanner: a planted field, a nested field and v4, v6 and v4-mapped literals are all detected, and RFC 3339 times are not flagged.

**Kill criterion "one canary value, one cleartext IP or one field outside the positive list in the capture": not hit (t0 and t1).** The capture is the client's signal log plus what the labs received. No pcap was taken.

## Verdicts against the frozen kill criteria

| Hypothesis | Test | Kill criterion | Observed | Hit? |
| --- | --- | --- | --- | --- |
| M1 | B01/T20 | p95 overhead > 5 ms at 500 rps | +0.30 / +0.31 / +0.33 ms | no |
| M1 | K3 | one request reaches the backend uninspected on timeout/overload | bypass 0 (2 × 75) | no |
| M1 | T12 | same, front proxy: nothing passes while schild hangs | 3 × 160/160 503, 0 bypassed | no |
| D3 (lab analogue) | T12 kill | outage of the website caused by schild | site served throughout; only in-flight POSTs at the crash instant got 502 | no |
| M2 | T19 | one canary / cleartext IP / field outside the positive list | 0 findings in the client log and at every lab (t0, t1) | no |

**M1 pass, M2 pass** on the pinned b18f9b2 images (arm64).

## Harness findings (test lab only, no component defect found)

1. **B01 drift in `site-api` + `measure latency`.** The latency mix sends 25 % `POST /api/items`, and `site-api` appends every item to an in-memory list. `GET /api/items?page=1&sort=name` returns the **whole list** (`site-api` ignores `page`). The response therefore grows with every request, and grows across runs.
   - Repro: run `measure latency` at 500 rps four times in a row on one stack. Baseline p95 rises 1.4 → 4.8 → 8.0 → 10.0 ms. At 2000 rps the with-schild runs collapse (p95 274 ms and 582 ms, achieved rate 1945 and 1700 rps) once the list is several MB per response. The `site-api` container reached 2.1 GiB.
   - Effect: running no_schild first and then with_schild biases the result against schild.
   - Data: `raw/b01-drift/` (not used for verdicts). The verdict table uses a `docker restart` of `site-api` before every run.
   - Suggested fix (owner MVP-05/06): `site-api` should honour `page`, or the mix should avoid unbounded growth.
   - Response bodies are not inspected (`SecResponseBodyAccess Off`), so the collapse is proxy copy cost on very large responses on a busy host. It is not WAF cost.
2. **T19 canary source IPs were not in effect in the documented command.** `measurements.md` runs `measure egress` on the inet network without a fixed address. The container got 10.66.6.3, which is outside `trusted_proxies` (`10.66.4.0/28` in t0), so schild ignored the canary XFF. The visitor IP was the container address, and **the canary-IP part of T19 was not exercised** (this probably also applies to stage 2). Fix: add `--ip 10.66.4.11` (t0) or `--ip 10.66.20.11` (t1). Both appear in this report.
   - A repeat on the same client produces no new signals, because the request shapes are the same. The canary-IP run should therefore go first on a fresh client, as on t1 here.
3. The lab-side cross-check needs a scanner that validates IPv6 properly: a naive regex flags RFC 3339 times. `labscan.py` uses `ipaddress`.

## Caveats

- **Shared host.** Absolute latencies include Docker Desktop's VM and overlay network and host scheduling, and ~30 unrelated containers were running. Host load average was 3–13 during the runs. **The with/without deltas are the load-bearing figures**; treat absolute values as upper bounds. Run B01 again on the real stage-3 host.
- **arm64 only.** For amd64 hosts, rebuild this commit for `linux/amd64`, record the new IDs, and re-run smoke, B01, K3, T12 and T19 on them.
- **Image identity.** Image IDs are local config digests, not registry digests. A rebuild without cache gives new IDs, because the `Created` timestamps change. Pin by these IDs or by `docker save` archives of these exact images.
- **Front proxy.** T12 covers `schild front` only. nginx and Caddy fronts are untested.
- **What T19 checks.** T19 checks the signal log and the lab-received signals, not a pcap. TLS transport is not inspected.
- **Run order on t0.** B01, K3 and T12 on t0 ran after the smoke's scope-`all` emergency stop: `schild_grundschutz_active=1`, no network rules active. This was also the case in stage 2.
- **Concurrent repository activity.** After the images were built, other parties made commits `eb91a4c` (UI styling) and `e0bc0ae` (MVP-11 spec), plus uncommitted edits under `mvp/ui/`, while these measurements ran. None of it came from this agent, and none of it is in the measured images, which were checked against `git archive b18f9b2`.
- **Teardown and leftovers.** Both stacks were torn down with `make testlab-down` (volumes removed). No `schild*` containers, networks or volumes remain. `alpine:3.20` was pulled and left in the local image store. No other project's resources were touched; that includes `deutschland-schild-site-1` and its volumes, which are a different project.
