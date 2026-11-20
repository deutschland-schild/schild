# Schild MVP — mechanics measurements (M1, M2, M6, M7)

Measurement owner report for the hypotheses of [docs/concept/23-mvp-verifikation.md](../../docs/concept/23-mvp-verifikation.md) §2, run with the test lab (MVP-05/06) against the pinned MVP images. Machine results, not a live-site measurement (stage 2). Humans decide what a hit kill criterion means (conventions §8); this report only observes.

Machine-readable results: [`results/MVP-02.json`](MVP-02.json) (M1, M2, M7), [`results/MVP-03.json`](MVP-03.json) (M6), [`results/MVP-04.json`](MVP-04.json) (M7 relay side), [`results/MVP-05.json`](MVP-05.json) (evaluator, detection context), [`results/MVP-06.json`](MVP-06.json) (traffic reproducibility), [`results/MVP-06-ftw.json`](MVP-06-ftw.json) (go-ftw regression subset). T12 is in MVP-02.json.

## Environment

| | |
| --- | --- |
| Host | Apple M2 Max, 12 cores, 64 GiB, macOS (Darwin 25.5.0) |
| Docker | Docker Desktop 29.5.2, Linux VM, 12 CPU / ~23 GiB to the VM, builder `desktop-linux` |
| Git | `1af9fe8` (working tree dirty: this agent added `testlab/cmd/measure` and these results) |
| Profiles | t0 (3 labs / 3 operators, 2 relays, REST API behind one schild, observe) and t1 (4 labs, 2 sites; shop = autoblock) |
| Images (local config IDs) | `schild:mvp` `sha256:2981cbdb…`, `schild-lab:mvp` `sha256:93406b68…`, `schild-relay:mvp` `sha256:88317f59…`, `schild-testlab:mvp` `sha256:a82cbc64…`, `schild-traffic:mvp` `sha256:77cb825f…` |

**Honest framing of the numbers.** This is a shared development laptop: ~30 unrelated containers (other projects) were running throughout, and Docker Desktop on macOS runs everything inside a Linux VM with a bridged overlay network. Absolute latency therefore carries VM, overlay and host-scheduling overhead and visible tail noise, especially at low request rates. **The load-bearing figure for M1/M7 is the delta (with vs without schild, and healthy vs degraded network), not the absolute millisecond value.** All container-to-container traffic stayed on internal `10.66.0.0/16` networks with no route out; attack tooling only ever hit the test lab's own strippers.

## How to run

```sh
cd mvp
export SCHILD_LABEL_SECRET=schild-testlab-dev-secret SMOKE_PASSWORD=schild-testlab-passwort
make testlab-image            # builds schild-testlab:mvp incl. the new `measure` binary
make testlab-up PROFILE=t0

NET=schild-testlab-t0_sites
run(){ docker run --rm --network $NET schild-testlab:mvp /usr/local/bin/measure "$@"; }

# M1 latency sweep (with/without schild, 50/500/2000 rps)
run latency -target http://schild-api:8080 -label with_schild -rps 500 -duration 20s
run latency -target http://site-api:8080   -label no_schild   -rps 500 -duration 20s
# M1 K3 resilience corpus (bypass under timeout/overload)
run k3 -schild http://schild-api:8080 -load-rps 300 -load-duration 15s
# M7 request path under lab/relay outage (30% suspicious traffic)
run latency -target http://schild-api:8080 -rps 500 -duration 20s -attack-share 0.3   # repeat with labs/relays stopped
# M2 egress: plant canaries via the stripper, then check the transparency log (T19)
# --ip: run from a trusted-proxy address, otherwise schild ignores the canary source IPs (stage3-baseline README; t1: --ip 10.66.20.11)
docker run --rm --network schild-testlab-t0_inet --ip 10.66.4.11 -e SCHILD_LABEL_SECRET=$SCHILD_LABEL_SECRET \
  schild-testlab:mvp /usr/local/bin/measure egress -stripper http://stripper-api:8080 -n 60
docker run --rm -v schild-testlab-t0_export-api:/export:ro schild-testlab:mvp \
  /usr/local/bin/egress-check -log /export/transparency.ndjson -json \
  -canaries CANARYqv,CANARYbody,CANARYcookie,CANARYua,CANARYpath \
  -forbidden-ips 203.0.113.66,2001:db8:dead:beef::66
# T12 front-proxy fail-open (compose profile t12; kill/pause schild under load)
make testlab-t12              # -> results/runs/t12/t12.json
# M6 B13 ingest burst against a real lab (TLS)
docker run --rm --network schild-testlab-t0_federation -e SCHILD_TEST_CA=/etc/schild-ca/ca.pem \
  -v "$PWD/testlab/compose/secrets/ca.pem:/etc/schild-ca/ca.pem:ro" \
  schild-testlab:mvp /usr/local/bin/measure burst -lab https://lab-a:7443 -rate 3000 -duration 15s \
  -metrics https://lab-a:9102/metrics
cd lab && go test ./internal/ingest -run TestBurstAckLatency -v   # 10k-client / queue-full B13

make testlab-down PROFILE=t0
```

The load/K3/burst/egress/scrape driver added for this work is [`testlab/cmd/measure/main.go`](../testlab/cmd/measure/main.go) (an independent harness; it does not reuse any component's own benchmark).

---

## M1 — "Schild barely slows the site and never passes a request uninspected"

Kill criterion: **p95 overhead > 5 ms at 500 rps**, or **a single request reaches the backend uninspected on timeout/overload**.

### B01 / T20 — request overhead (schild-api vs site-api, sites network, 20 s, 3 s warmup)

| rps | p50 ms (no / with) | p95 ms (no / with) | p99 ms (no / with) | overhead p50 / p95 / p99 |
| --- | --- | --- | --- | --- |
| 50 | 0.69 / 1.84 | 7.90 / 9.94 | 10.08 / 12.39 | +1.15 / +2.03 / +2.32 |
| **500** | 0.17 / 0.90 | **3.88 / 4.69** | 5.29 / 6.15 | +0.74 / **+0.81** / +0.86 |
| 2000 | 0.33 / 1.39 | 4.86 / 8.27 | 7.21 / 15.13 | +1.05 / +3.42 / +7.92 |

**p95 overhead at 500 rps = +0.81 ms (< 5 ms). Kill criterion not hit.** At 2000 rps the p99 overhead rises (+7.9 ms) because the WAF is CPU-bound and shares 12 cores with the rest of the host; the median stays ~1 ms. Offered rates were met exactly (open-loop with absolute scheduling). The low-rate (50 rps) tails are dominated by host/VM jitter (the no-schild baseline alone is ~8 ms p95), so the overhead delta is the meaningful number there. Builder micro-benchmarks (single clean GET ~0.4 ms CPU, CRS instance build ~60 ms) are consistent with this.

### K3 — resilience corpus, bypass under timeout/overload

75 corpus requests (15 rounds × 5 cases) through schild under 300 rps concurrent benign load. **bypass_count = 0.**

| case | status | latency ms | handling |
| --- | --- | --- | --- |
| oversized_body (20 MiB) | 413 | 1.8 | hard limit, reject |
| nested_json (depth 200) | 400 | 0.8 | reject |
| redos_query | 404 | 1.4 | inspected (RE2 linear), benign path |
| huge_urlencoded_field (2 MiB single value) | 503 | 1006.9 | eval timeout → **fail-closed 503, never passed** |
| too_many_args (1500) | 400 | 1.7 | reject |

No malicious payload reached the origin unblocked; the one payload that exceeded the 1 s eval budget was answered 503 (never a pass). **Kill criterion not hit.**

### T12 — front-proxy fail-open, live (fix-owner rerun, 2026-10-26T20:46Z)

New compose profile `t12` on t0 (`make testlab-t12`, `testlab/scripts/t12.sh`): `front-api` runs `schild front` (the reference of `client/deploy/nginx-front.conf`), `schild-t12` shares the front's network namespace and listens on 127.0.0.1:8080 as on a real host, the app is `site-api`. So a dead schild process means *connection refused* (fail-open) and a hung one means a *timeout* (503). Load: 100 rps open loop from the sites network straight at the front (the hung phase 20 rps); "bypassed" counts the front's fail-open log lines, i.e. requests sent around schild. Rebuilt `schild:mvp` `sha256:8603b523…` (only change against `2981cbdb…`: the embedded dashboard build). Report `results/runs/t12/t12.json`.

| phase | requests | answered | bypassed to app |
| --- | --- | --- | --- |
| A schild up | 1000 | 1000 × 2xx | 0 |
| B `docker kill` schild after 4 s of a 12 s run | 1200 | 1200 × 2xx, **0 errors** | 814 (after the kill) |
| C schild dead | 1000 | 1000 × 2xx | 1000 (fail-open) |
| D `docker start`, healthy again | 1000 | 1000 × 2xx | 0 |
| E schild hung (`docker pause`), front timeout 3 s | 160 | **160 × 503** | **0** |
| F unpaused | 1000 | 1000 × 2xx | 0 |

The site stayed reachable through the crash without a single failed request, fail-open happened only while the process was dead, and while schild hung nothing reached the app uninspected (503 after the timeout). **T12 pass.** Not covered: nginx/Caddy fronts themselves (the same rule, documented in `client/deploy/`), and a process that accepts but answers slowly below the timeout (that is the K3 eval-timeout path above).

**Verdict M1: pass.**

---

## M2 — "Nothing personal leaves the server"

Kill criterion: **one canary value, one cleartext IP, or one field outside the positive list in the capture.**

- **T19, planted canaries.** 60 attack requests sent through the label stripper, each carrying canary markers in the **path, query, JSON body, cookie and User-Agent**, and a canary **source IP** (`203.0.113.66` / `2001:db8:dead:beef::66`) as the visitor address. The independent `egress-check` (its own second copy of the positive list, so a client bug cannot hide behind the same bug) scanned the client's transparency log — **1053 signals, 0 canary findings, 0 IP-like tokens, 0 fields outside the positive list.**
- **Cross-check (client log ↔ lab ingest).** The t0 smoke step "signals" reads each signal the client recorded as sent and each signal every lab received, and fails on any IPv4-like token or forbidden field in either; it passed, and deliveries reached all 3 labs.
- The evaluator's egress check over the smoke run also reported `canary=0`.

**Verdict M2: pass.** (Transport is cleartext-readable by design in the test lab — the T19 path implemented is the signal-log cross-check, which needs no TLS keys; an optional tcpdump sidecar exists for manual pcap inspection.)

---

## M6 — "The lab ingest stays fast under load"

Kill criterion: **EventAck p99 > 50 ms at burst ×20**, or **timeouts instead of `retry_after`**.

### Independent container burst (measure burst → real lab-a:7443 over TLS)

3000 submissions/s open-loop for 15 s = 45,000 submissions. Only the 3 configured test site keys exist in t0, so this mostly exercises the signed-ack-under-overload path:

| metric | value |
| --- | --- |
| client-observed ack p50 / p99 | 0.91 ms / **5.94 ms** |
| lab-side `schild_lab_ack_p99_seconds` | **3.67 ms** |
| connection errors / timeouts | **0** |
| responses without a signed ack | **0** |
| 200 (accepted) / 429 (rate_limited, signed ack + retry_after) | 449 / 44,551 |

### Spec-faithful B13 (lab's own `TestBurstAckLatency`: 10,000 clients, 50k submissions = 200k signals)

| subtest | lab ack p99 | result |
| --- | --- | --- |
| burst (room in queue) | 5.66 ms | all 200 |
| burst-queue-full (scoring stopped, queue full) | 1.04 ms | 49,989 × 503 `queue_full` + retry_after, **0 timeouts** |
| saturation (closed loop, beyond ×20) | 30.64 ms | 32 × 429, rest 200, 0 failures |

Every path stays **< 50 ms** and **never times out**; a full queue answers immediately with a signed ack and `retry_after`. The 10k-client / forced-full-queue case can only be produced inside the process, so it is cited from the component's own harness (run by me) alongside the independent container burst.

**Verdict M6: pass.** (`proposals_from_single_operator` is part of the written kill criterion but belongs to M3, not an owned hypothesis; the smoke confirmed four-eyes approval and ≥3 distinct operators before publication.)

---

## M7 — "Lab or relay outages change neither protection nor latency"

Kill criterion: **website worse protected or slower while labs or the relay are missing.**

### B02 / T09 — request path under outage (500 rps, 30 % suspicious, schild-api)

| state | p50 ms | p95 ms | p99 ms | request errors |
| --- | --- | --- | --- | --- |
| labs up (baseline) | 1.48 | 9.46 | 17.09 | 0 |
| all labs stopped | 1.60 | 9.61 | 12.96 | 0 |
| all labs **and** relays stopped | 1.58 | 11.26 | 17.88 | 0 |

p95/p99 move only within host noise, with **0 request errors** in every state; `schild_grundschutz_active = 1` throughout. **network_share_of_p99 ≈ 0 ms** — by design the signal send is a non-blocking offer and the relay stream never touches the request path, so a slow/down lab or relay cannot add latency. **Kill criterion not hit.**

- Suspicious traffic still produced signals while labs were up (97 created, delivered to all 3 labs); with labs down the client kept serving at the same latency and queued/retried deliveries in the background.
- A `toxiproxy +500 ms` "slow lab" variant was **not** run (no toxiproxy image wired); the down-lab result already shows the request path is independent of lab reachability. Recorded as a refinement.

### Emergency stop and freeze (relay side, MVP-04)

- **Emergency stop (B10, approx).** The t0 smoke co-signed a scope-`all` withdrawal and it was applied on the client **~0.1 s** after it took effect (polling resolution ~0.25 s) — far under the 60 s kill criterion. This is a polled timing, not the B10 fan-out benchmark.
- **Frozen relay (B12)** and **invalid-bundle rejection (T10/T11)** were not independently re-measured live (a withholding-but-up relay and forged bundles are needed); they are covered by the relay/client verify and freeze unit tests (`make relay-test`) and the `freeze_after_s = 180` config.

**Verdict M7: pass** (for the latency/protection-unchanged criterion measured here; B10/B12 live measurements remain open).

---

## Detection quality (context — not an owned hypothesis, not a kill criterion)

- **Curated suite via the evaluator (t0 smoke, observe mode).** 95 joined events (71 attacks: SQLi variants, XSS, traversal; 24 legit): precision 1.00, recall 1.00, false-positive rate 0.00, 0 legit blocks, 0 bypass. See `results/MVP-05.json`. This is a small hand-written set, not the external suites.
- **GoTestWAF vs the autoblock shop (t1, CRS paranoia 1, anomaly threshold 5).** Overall score **63.06 %**: true-positive **47.39 %** of 671 resolved attack payloads blocked (52.61 % bypassed), true-negative **90.78 %** (9.22 % of GoTestWAF's adversarial "text" false-positive set blocked). This is a standard, honest CRS-PL1 coverage figure — PL1 is deliberately low-false-positive; higher paranoia raises recall and false positives. "Bypassed" means CRS did not flag the payload, not that an exploit succeeded (the shop backend is the inert REST API). Report: `results/tmp/gotestwaf/gotestwaf.json`.
- **go-ftw CRS regression subset (fix-owner rerun, t1, 2026-10-26T20:55Z).** The corpus directory was empty (attack-ftw ran zero tests). It now holds the lab's own small corpus in go-ftw format (`testlab/traffic/compose/ftw/tests`: 942100, 941100, 930100, 930120, 932160, 913100, 944150, plus 5 negatives under 949110), run by `make traffic-ftw` with go-ftw 1.3.0 pinned by digest, cloud mode, against the autoblock shop: **16/16 pass** (11/11 attacks answered 403, 5/5 ordinary requests passed, 0 skipped). Control: the same corpus against the observe-mode api site lets all 11 attacks through, so the 403s are schild's. Requests carry a signed ground-truth label (a first unlabelled run had polluted the t1 evaluator with `unlabelled=43`, `legit_blocks=22`; with labels the following t1 smoke evaluator reported 0/0). A regression check, not a coverage figure. `results/MVP-06-ftw.json`.
- **Traffic corpus reproducibility (MVP-06).** Scenarios T01–T05 produce identical labelled counts across two runs with the same seed (T01 200 req / 13 canaries, T02 100 / 49 malicious / 21 bypass, T03 60 malicious, T04 240 malicious, T05 40 malicious). `results/MVP-06.json`.

### Not measured (honest gaps for the detection context)

- The full external suites against the deliberately vulnerable apps — **sqlmap (T02), nuclei curated + nikto + ffuf (T03), distributed brute force over many IPs (T04)** against DVWA / Juice Shop / WordPress — were **not** run. They need the t1 `full` + `attack` profiles (third-party image pulls). GoTestWAF (coverage) and the lab's own go-ftw regression subset were run.
- T01 false-positive rate is only the curated 24-request sample (0 blocks); a 24 h legit-traffic run is not done.

## Caveats and open issues

1. All latency figures are from a busy shared macOS/Docker-Desktop host; treat absolute values as upper bounds with noise and the with/without and healthy/degraded deltas as the real signal. A quiet, bare-metal Linux run would give tighter and lower absolutes.
2. **T12 front-proxy fail-open** is now measured live (compose profile `t12`, see M1); it uses `schild front`, not nginx/Caddy.
3. **B02 "+500 ms slow lab"** (toxiproxy) and **B10 fan-out / B12 frozen-relay** live benchmarks were not run; covered here only by the down-lab/down-relay latency result, the smoke emergency-stop timing, and the component unit tests.
4. The M6 10k-client / queue-full case is the lab's own in-process harness (the only way to get 10k distinct keys and a forced-full queue); the independent container burst is limited to the 3 configured test keys and so mostly measures the signed-429 path.
5. Image identifiers recorded are local image **config IDs** (`docker image inspect .Id`), not registry manifest digests — the images are local-only (`BUILDX_BUILDER=desktop-linux`, never pushed).
6. Stage-3 live-data hypotheses (D1–D3) and the non-owned mechanics hypotheses (M3 trust model, M4 remote-rule safety, M5 supply chain) are out of scope for this report.

Fix-owner rerun (T12 on t0, go-ftw on t1, plus `make smoke` on both with the rebuilt images: t0 and t1 smoke OK, evaluator pass): both stacks were brought up and torn down again the same way; `ghcr.io/coreruleset/go-ftw` (digest `99e5d772…`) was pulled for it and left in the local image store.

Both stacks (t0, t1) were torn down (`make testlab-down`) with their volumes; no `schild-testlab-*` containers, networks or volumes remain, and no other project's containers were touched.
