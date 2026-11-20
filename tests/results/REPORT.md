# Schild MVP: stage 2 results report (2026-10-26, base 1af9fe8, working tree uncommitted, about 280 changed paths)

Sources: results/measurements.md, results/ux-review.md, results/MVP-02/03/04/05/06/06-ftw/07.json, runs/smoke-t0, runs/smoke-t1, runs/t12, runs/ftw. All seven result JSON files validate against contracts/results.schema.json (I checked with python-jsonschema). Under README rule 5 the initiator decides whether a kill criterion is hit; the verdicts below are observations.

## 1. Summary
- No kill criterion of M1–M7 was hit.
- M1, M2 and M6 were measured as the spec intends.
- M3, M4, M5 and M7 pass, but with real gaps: some parts were only proven inside one process or by unit tests, and some benchmarks were not run (B02 slow lab, B05/B06, B10 at scale, live B12, the M4 local brake).
- `make smoke` passed 16/16 steps in t0 and t1, with evaluator verdict pass and 0 browser errors.
- Stage 3: not yet (section 6).

## 2. Hypotheses M1–M7

**M1 – PASS.** Kill criterion: p95 overhead above 5 ms at 500 rps, or one request reaching the backend unchecked.
- p95 overhead at 500 rps was +0.81 ms (4.69 ms with schild, 3.88 ms without); p99 overhead +0.86 ms.
- K3 corpus, 15 rounds under 300 rps load: 0 requests got through unchecked. Oversized body 413, nested JSON 400, too many arguments 400, a 2 MiB form field 503 on the 1 s timeout, ReDoS input checked in linear time.
- T12 live, with `schild front` as the front proxy:
  - schild killed under load: 1200 of 1200 requests answered 2xx;
  - schild dead: 1000 of 1000 answered 2xx through fail-open;
  - schild hung: 160 of 160 answered 503, none reached the app.
- At 2000 rps the p99 overhead was +7.9 ms because the host was CPU-bound.

**M2 – PASS.** Kill criterion: a canary value, a cleartext IP or a field outside the positive list leaves the server.
- 60 attacks carried canaries in path, query, body, cookie and user agent, plus canary source IPs (IPv4 and IPv6).
- An independent egress check over 1053 signals found 0 canaries, 0 IPs and 0 extra fields.
- The smoke run compared the client's transparency log with what the labs received: 0 IP-like values.
- Caveat: there was no packet capture of all outgoing connections. The check covered the signal content at both ends.

**M3 – PASS, with caveats.** Kill criterion: one block of legitimate traffic caused by a single operator or by fake clients.
- T06: 0 of 4 bundles below the signature threshold accepted.
- T07: 0 of 5 poisoned bundles accepted, both in-process and live (`relay watch` with k=3 rejected all of the malicious lab's output).
- T08 live: 0 of 500 fake client keys admitted by the lab. In-process, 500 keys of one issuer counted as 1 unit.
- K6: automated feedback triggered 0 withdrawals.
- Caveat: in the MVP no network rule can actually block. Proposals do not federate between labs, and challenge is not implemented, so the "blocks legitimate traffic" outcome cannot happen by construction. What was proven is that every acceptance layer rejects the attempts.
- Counting by issuer through the real lab scorer was not run live.

**M4 – PASS for the validator only.** Kill criterion: a fuzzed rule passes the validator and switches off protection, leaks data, or hits more than 1 % of legitimate traffic without being suspended locally.
- 600,000 fuzzed rules over 3 seeds, 0 validator bypasses, checked against an independent third checker.
- A differential test with 100,000 rules: 0 bypasses. T24: 0 of 7 over-broad rules accepted.
- Not measured live: the "more than 1 % of legitimate traffic, suspended locally" part. The local brake exists and has unit tests (TestLocalBrake, TestBrake), but no network rule ever reached a blocking level in the test lab.

**M5 – PASS, with caveats.** Kill criterion: a bundle with too few signatures, a rollback or a frozen stream is accepted; or the emergency stop takes more than 60 s.
- T10: 0 of 6 invalid bundles accepted. T11: 0 of 4 rollback, equivocation or replay attempts accepted.
- A frozen stream is detected after the 180 s window.
- The emergency stop took effect on clients after about 0.1 s in t0 and 0.3 s on all clients in t1.
- Caveat: T10 and T11 ran in-process against the real verification code, not through a relay into a client container. The emergency-stop timings come from smoke polling with 1–2 clients; this is not the B10 benchmark. B05 and B06 were not run.

**M6 – PASS.** Kill criterion: ack p99 above 50 ms at a ×20 burst, or timeouts instead of `retry_after`.
- Independent burst over TLS, 45,000 submissions: p99 5.94 ms (lab metric 3.67 ms), 0 timeouts, every answer signed.
- The lab's own test with 10,000 clients:
  - burst: p99 5.66 ms;
  - full queue: p99 1.04 ms, answered with 503 plus `retry_after` (49,989 times);
  - saturation: p99 30.6 ms.
- Caveats: the independent burst only had 3 test keys. The 10,000-client case comes from the component's own test harness. Ack latency while the dashboard is in heavy use was not measured.

**M7 – PASS for outages, open for slowness.** Kill criterion: the site is less protected or slower while labs or relays are missing.
- At 500 rps with 30 % suspicious traffic, p99 was 17.1 ms with labs up, 13.0 ms with labs down and 17.9 ms with labs and relays down.
- There were 0 request errors, and the "Grundschutz aktiv" status stayed on throughout.
- Not measured: a lab that is slow (+500 ms) instead of down, B06, and a frozen but running relay live (B12).

**Applies to all latency numbers.** They come from a shared Mac running Docker Desktop alongside about 30 unrelated containers. The differences (with vs. without schild, up vs. down) are what carry weight; absolute values are noisy upper bounds.

**Process caveat.** README rule 2 (builders never measure their own work) was bent:
- the integration agent fixed both component bugs and evaluator bugs;
- the fix agent built the T12 setup and the go-ftw corpus and then ran them itself;
- the red team tested mostly in-process rather than against running containers only.

**Detection quality (context, not a kill criterion).**
- Curated set in observe mode: precision 1.00, recall 1.00, false-positive rate 0.00 over 95 events.
- GoTestWAF against the autoblock shop: score 63.06 %, 47.4 % of attacks blocked, 90.8 % of harmless requests passed. That is normal for CRS at its lowest paranoia level.
- go-ftw with our own small corpus: 16 of 16 pass.
- Not run: sqlmap, nuclei, nikto and ffuf against DVWA, Juice Shop and WordPress, the distributed brute-force test (T04), and a 24-hour false-positive baseline.

## 3. Built per spec
- **MVP-01 Contracts.** v0 frozen plus the v0.1 addendum; 462 test vectors, Go and Python agree on all of them. v0.1 still needs your freeze.
- **MVP-02 Client.** Caddy with Coraza v3.3.3 and CRS 4.25; modes, hard limits, 503 on timeout, fail-open front proxy, IP-free signals, verified bundles, local brake, atomic rule swap, retention, transparency log, embedded dashboard.
  - Not measured: rule-swap time with 50/500 remote rules (B07).
  - Not built or partial: challenge, `origin.protected` (always false), the G5 proxy self-test (static check only).
  - The nginx and Caddy front proxies were never tested live.
- **MVP-03 Lab.** Ingest with signed acks, priority queue, scoring per issuer, proposals with evidence, four-eyes approval, co-signing, signed feed, public log (RFC 6962), dashboard. Proposals do not federate between labs, so block-level evidence is never reached.
- **MVP-04 Relay.** SSE stream, checkpoints, resume after reconnect, several upstreams, a `watch` verifier. Not run: B05, B06, B10 at scale, live B12.
- **MVP-05 Test lab.** t0, t1, a t12 profile, label stripper, ground truth, evaluator (its self-test catches every planted fault), egress check, gateway, `make smoke`.
  - Never started: the t1 profiles with WordPress, DVWA and Juice Shop, and the malicious lab inside compose.
  - No packet capture; no Prometheus/Grafana run.
  - Image IDs are local config IDs, not registry digests.
- **MVP-06 Traffic.** T01–T05 generators, reproducible with the same seed, plus the go-ftw corpus and GoTestWAF. The external suites, browser traffic and replay were not run.
- **MVP-07 Adversaries.** Full suite: 529 attempts, 0 accepted.
- **MVP-08 Geo dataset.** Not built (planned). The MVP uses a test-only fixture; the DB-IP build path was not exercised in this round.
- **MVP-09 Client dashboard.** Complete; 0 accessibility violations (WCAG 2.2 AA), 0 browser errors, flows 40 of 41 (the one failure is by design), the 10k-event table is fast, JavaScript about 310 KB gzip. Not done: usability tests with 5 people and SUS, the 1,000,000-event load target, a capture of the dashboard's own outgoing traffic.
- **MVP-10 Lab dashboard.** Complete. Not done: usability tests L1–L5, ack p99 under dashboard load, emergency-stop timing from the click, a UI test for the "Mitzeichnen" button.

## 4. Known gaps
1. **Observe mode is not passive.** In every mode, including observe and the test profile, schild answers:
   - 413 for a body over the limit;
   - 415 for any compressed request body;
   - 400 for more than 1000 arguments, broken or very deep JSON, and body parse errors;
   - 503 when checking takes over 1 s. Coraza needs about 9 ms per KiB of a single form field, so a field of roughly 100 KiB or more can hit this.

   Concept 23 says observe mode blocks nothing beyond what ran before. On a live site this could cause an outage, which is the D3 kill criterion.
2. **Which image produced which result is mixed.**
   - M1, M2 and M7 ran on schild sha256:2981cbdb, which is no longer in the local image store.
   - The current schild sha256:8603b523 also contains backend changes made after that run: the gzip handler for the dashboard (client/internal/webui/gzip.go) and the test-profile error in client/internal/dashboard/api.go. The source files changed between the two builds. So the fix report's claim "only change: the embedded dashboard build" is wrong. Neither change touches the request path.
   - M6 and MVP-07 ran on lab image 93406b68; the current lab image 19e13b07 contains a later scoring change.
   - All images were built from an uncommitted tree. The current images do match the current source.
3. **Front proxy and runbook.** T12 was proven only with `schild front`. The nginx and Caddy configs that a real project would likely use were not tested. The stage 3 runbook required by concept 23 (installation, way back, privacy) does not exist.
4. **Keys.** Stage 3 is planned with non-release images (D05), and those accept the public test keys. The release check would not recognise lab-d's key id `testlab-lab-d-online` as a test key. I found no documented way to create production lab keys: `schild keygen` only creates site keys, and the test lab writes its lab key seeds with a script.
5. **Live infrastructure is not designed.** Lab and relay hosting, real TLS certificates, exposed ports and backups are all open.
6. **Still unmeasured:**
   - Benchmarks: B02 slow lab, B05, B06, B07, B10 at scale, live B12.
   - Adversary and detection runs: live T08 through the lab scorer, the M4 local brake live, the external attack suites, a 24-hour false-positive baseline.
   - Dashboards: the MVP-09/10 load targets; usability tests with people.
   - Privacy: the retention time-lapse test from concept 24 (only unit-tested).
7. **Older dependencies.** Staying on Go 1.24 pins Coraza v3.3.3, coraza-caddy v2.1.0 and Caddy v2.10.0, which miss later fixes.
8. **Visible product limits:**
   - challenge is not implemented;
   - every CRS rule shows "Wirkung: Sperren", although CRS blocks by anomaly score;
   - some English backend strings appear in the footer;
   - the setup-code field shows on localhost, and "Meine IP freischalten" offers 127.0.0.1 through a tunnel;
   - the styleguide chunk ships in production builds.
9. **Evaluator sampling.** The client records ordinary requests at most 20 per second, which affects how MVP-05 counts benign traffic and the denominator for D1.
10. **Leftovers.** The gotestwaf and go-ftw images are still in the local image store, and the working tree is uncommitted.

## 5. Decisions needed from you
1. **Kill thresholds.** Concept 23 says to freeze them before stage 3.
   - (a) Freeze as drafted and accept the verdicts with these caveats.
   - (b) Freeze, but require B02, B05, B06, B10 and B12 first.
   - (c) Tighten them.

   In observe mode with the test profile, network rules cannot block, so the live risk sits in M1 and M2, and both were measured.
2. **Independent re-check.**
   - (a) An agent that built nothing re-runs M1 (B01, K3, T12) and M2 (T19) on the final pinned images, ideally on a quiet Linux host.
   - (b) Accept the current runs.
3. **Contracts v0.1.**
   - (a) Freeze as is.
   - (b) Freeze and add a v0.2 with a `Relay.kind` field and lab-d's key id in testkeys.
   - (c) Request changes.
4. **Hard limits and the timeout in observe mode on live sites.**
   - (a) Keep rejecting, but first check each project's access logs for compressed bodies, broken JSON, more than 1000 arguments and large form fields, and tune the limits per site.
   - (b) Add a "log only" option for limits in observe mode. This contradicts M1's "never unchecked" and needs code.
   - (c) Run stage 3 with schild only mirroring traffic, outside the request path. New setup, needs code.
5. **Non-release images in stage 3 (D05).**
   - (a) Use them, plus a mandatory preflight that refuses every known or `test*` key and the test CA. That preflight does not exist yet.
   - (b) Use a release build with a new "single operator, observe only" config. This is a contract change.
   - (c) Wait for real independent operators.
6. **Toolchain.**
   - (a) Stay on Go 1.24 with Coraza 3.3.3.
   - (b) Move to Go 1.25 with Coraza 3.8, then re-run the tests, the smoke runs, M1 and K3.
7. **Front proxy for the own projects.**
   - (a) Use `schild front`, the only one tested live.
   - (b) Use nginx or Caddy, after running T12 against that config.

   The stage 3 runbook is needed in either case.
8. **Geo data.**
   - (a) DB-IP Lite (CC BY 4.0), with its build path tested before stage 3.
   - (b) IPinfo Lite (CC BY-SA; licence to be checked).
   - (c) No geo data.
9. **Third-party image pulls** for the external attack suites (pinned, internal networks only).
   - (a) Allow them.
   - (b) Accept GoTestWAF plus our go-ftw corpus as the detection context.
10. **UI wording and defaults** (none block stage 3):
    - the challenge wording, and whether "Nur prüfen" is offered at all;
    - the unblock dialog default: nothing preselected now, or "Nein oder unklar";
    - an issuer-share indicator for published patterns;
    - the "Wirkung" label for CRS rules.
11. **How the evaluator counts sampled benign requests** (the 20 per second cap).
    - (a) Count unmatched ones as "not observed".
    - (b) Raise or remove the cap in the test lab.
    - (c) Use the counters for the denominator.
12. **Housekeeping.** Commit the working tree, and keep or remove the pulled gotestwaf and go-ftw images.

## 6. Is stage 3 responsibly possible?
**Not yet.** The mechanics are not the reason: no kill criterion was hit, fail-open and the emergency stop were shown, and no visitor IP left the server. What is missing:
1. Your decisions 1, 3, 4 and 5. Decision 4 is the critical one, because as built, observe mode can return 400, 413, 415 or 503 on a live site.
2. One pinned image set: commit, rebuild from a clean tree, record the digests, then re-run `make smoke` (t0 and t1), M1 (B01, K3, T12) and M2 (T19) on exactly those images. Concept 23 requires the same digests live as tested.
3. The live setup:
   - production keys kept outside the repo, plus a preflight that refuses test keys and the test CA;
   - lab and relay hosting with real TLS;
   - the front proxy you will actually use, tested with T12;
   - the geo data path;
   - the runbook: installation, the one-minute way back, privacy.
4. The privacy steps from concept 24: updated privacy notices on the own projects, the record of processing activities, and the IP-shortening checked once on the final image.
5. Tools to measure D1–D3 before the 4–6 weeks start. Otherwise stage 3 produces no measurable answer.

Items 1 and 2 take days. Items 3–5 are setup and documentation, not redesign. After that, stage 3 in observe mode looks responsible. In observe mode with the test profile, network rules never block, so the live risk comes down to the client in the request path (M1, measured), privacy (M2, measured) and the hard-limit behaviour (decision 4).

## Verification
I ran these myself on 2026-10-26 around 22:00 CET, without the heavy test lab.

| Command | Result |
|---|---|
| `make test` | exit 0; lab tests ran with `-short`, some Go packages came from the test cache |
| `make contracts-test` | exit 0; 462 vectors, 0 disagreements |
| `make adversaries-test` | exit 0 |
| `make selftest` | exit 0; all 4 planted faults detected, the clean run stays clean |
| `make testlab-compose-config` | exit 0 |
| `pnpm check` | exit 0; unit tests ui 96, app-kit 9, lab 70, client 41 |
| `pnpm test:e2e` | exit 0; client 50/50, lab 27/27 |
| Result JSONs vs the schema | all 7 valid |
| Images vs source | schild and schild-lab are newer than every component source file |

Not re-run, taken from the reports: the smoke runs, the measurements, the live adversary runs, GoTestWAF, go-ftw, and the browser and UX checks. I started no containers.

## Nachtrag: Vorbereitung Stufe 3 (2026-10-26)

Integration of five parallel work streams on the uncommitted tree (base d78b5de). Under README rule 5 the initiator decides; this section records what changed and what was checked. M1/M2 numbers were deliberately **not** re-measured here; an independent agent does that on clean, pinned images.

### What changed (answers to section 5)
- **Decision 6 (toolchain): Go 1.25.** `go.work` `go 1.25.1` / `toolchain go1.25.14`; every Dockerfile builds from `golang:1.25.14-alpine` pinned by digest. Client on Coraza v3.8.1, coraza-caddy v2.6.0, Caddy v2.11.4, coraza-coreruleset v4.25.0 (newer coraza-caddy/Caddy need Go 1.26). Closes gap 7.
  - Real bypass found and fixed: Coraza 3.8 silently drops JSON/urlencoded body arguments beyond `SecArgumentsLimit` (1000). Rules 200004/200005 plus the gate now answer `ARGUMENTS_LIMIT_REACHED` with 400 `too_many_args` in every mode; rule 200009 rejects `URI_PARSE_ERROR`. For JSON the binding limit is therefore 1000 leaf values.
  - `Engine.Swap` now closes the previous WAF (Coraza's process-wide pattern cache would otherwise grow with every rule swap).
  - D21 Coraza semantics re-verified on v3.8.1 (`client/internal/waf/coraza_semantics_test.go`).
  - Behaviour changes to know for live sites: stricter multipart parsing, JSON whose flattened form exceeds 8x the body size gets 400, the first `Content-Type` header picks the body processor, and Caddy 2.11.4 drops request headers whose names contain `_`.
- **Decision 3 (contracts): v0.2** (D24). `Relay.kind` (`relay` | `peer_lab`) in the lab dashboard API, derived from a `Schild-Peer-Auth` signature on `GET /v0/stream`, never from the subscriber's name; the UI no longer matches names. `testlab-lab-d-online` is a listed test key. 464 vectors, Go and Python agree. Live in t1: relay-1/relay-2 listed as `relay`, lab-b/c/d as `peer_lab`.
- **Decision 5 (non-release images): preflight and keygen** (D24, closes gap 4). `contract/preflight` runs in `schild run`, `schild-lab run` and `schild-relay` before any listener opens and refuses test keys, key ids starting with `test`, the test lab CA in the trust anchors and certificates issued by it. Override `SCHILD_ALLOW_TEST_KEYS=1` only in test lab compose files and dev scripts (a test enforces it for t0/t1). `schild-lab keygen`, `schild-lab tls-keygen`, `schild-relay keygen`, `schild keygen -keyid`. Verified live: `schild-lab preflight` inside the t0 lab reports the test keys and test CA and would refuse without the override; `schild-relay preflight` on the bare image passes.
- **Decision 4 / gap 1 (hard limits): tools for the per-site check.** `schild logcheck` reads nginx/Apache/Caddy access logs and decides 413/415/400 with the client's own `waf.Precheck`, estimates 503 risk and suggests per-site limits.
- **Measurement tools for D1–D3 (section 6 item 5).** `schild report d1` (denominator from the hourly counters, never from the 20/s sampled events; sample CSV and labelled evaluation with a Wilson interval; addresses item 11 option c for D1), `schild-lab export d2` / `d2-merge`, `schild report d2-export` / `d2-ip` (offline, numbers only), `schild report d3` with a run log written by `schild run` and the ops log format (`docs/ops-log.md`). Reference: `docs/stage3-tools.md`.
- **Runbook (gap 3): `docs/runbook-stufe-3.md`** (German, du-form; exception noted in `contracts/conventions.md` §11). In this integration step every `TODO(integrate)` marker was resolved against the code (logcheck flags and formats, JSON argument counting, report d1/d2/d3, lab D2 export and merge, ops log, retention job cadence of 10 minutes, no online lab backup, dashboard labels and overlay precedence). Only `TODO(Initiator)` decisions and one missing tool remain (appendix A).

### Verification (2026-10-26, this integration step)

| Command | Result |
|---|---|
| `make contracts-test` | exit 0; 464 vectors, 0 disagreements |
| `make test` | exit 0 (includes `adversaries-test` and the release-tag contract tests) |
| `make adversaries-test` | exit 0 |
| `make selftest` | exit 0; every planted fault detected, clean run clean |
| `make testlab-compose-config` | exit 0 (t0, t1, t0+traffic) |
| `pnpm install --frozen-lockfile && pnpm check && pnpm test:e2e` | exit 0; unit lab 72, client 41; e2e client 50 passed / 4 skipped, lab 27 passed / 5 skipped (skips are viewport-specific by design) |
| `make ui`, `BUILDX_BUILDER=desktop-linux make images` | exit 0; local image IDs schild `18af479c5871`, schild-lab `be7fad6d1f41`, schild-relay `acee0669843d`, schild-testlab `0e690e7d2561`, schild-traffic `be5a42934619`, schild-adversary `63b9208f9860` (arm64, built from the uncommitted tree; not the pinned stage-3 set) |
| `make testlab-up` + `make smoke`, t0 | 16/16 steps, evaluator verdict pass (bypass 0, legit blocks 0, canary 0), browser check 4 dashboards, 0 errors |
| `make testlab-up` + `make smoke`, t1 | 16/16 steps, evaluator verdict pass, browser check 6 dashboards, 0 errors |
| `make testlab-t12` on t0 | pass: up phases all 2xx, no bypass while up, down served via fail-open (1000/1000), hung never passed (160/160 503). Kill-under-load phase: 1198 of 1199 2xx and **one 502** (stage 2: 1200/1200); one in-flight request when schild is killed, not an unchecked pass, but the independent M1 re-run should look at it |
| Stage-3 tools live in t0 | `schild report d1`, `report d3`, `report d2-export` + `d2-ip` inside the client container and `schild-lab export d2` inside lab-a ran on real data |
| Teardown | t0 and t1 down; no `schild-testlab` containers, networks or volumes left |

### Still open before stage 3
1. **Commit and pin.** Everything above is uncommitted. Commit, rebuild from a clean tree, record digests, then the independent re-run of M1 (B01, K3, T12) and M2 (T19) on exactly those images (decision 2). Check the single 502 in the T12 kill phase there.
2. **Platform.** The images are arm64 (Mac). If the production hosts are amd64, the pinned set must be built for `linux/amd64` and re-tested on it (runbook section 3).
3. **Initiator decisions in the runbook** (appendix A): simulated operators vs. the t0 layout and a full dress rehearsal (never run as one stack), issuers per site, DB-IP attribution, the extra privacy-notice sentence for the D2 offline analysis, how time-to-protect is measured, whether installation and measurement work count as care time.
4. **Access-log check per site** (runbook 5) over at least 14 days, and the resulting limit decisions, before schild goes in front of any site.
5. **Live infrastructure**: lab/relay hosts, real TLS, production keys created with the new keygen, preflight PASS on every host, DB-IP build path (`CLIENT_GEO=dbip`) not yet exercised.
6. **Front proxy.** Only `schild front` is tested (T12). If `schild front` itself fails, the TLS terminator answers 502 (no fail-open), hence way-back variant B in the runbook. nginx/Caddy directly in front of schild remain untested.
7. **Privacy**: privacy notices, record of processing, and the 7-day IP truncation checked once on the final image (runbook 11.4; still only unit-tested).
8. **M2 live tool.** No tool yet checks every sent signal live (like the test lab's egress check); the runbook uses a manual sample of 20 signals per site and week.
9. **Unchanged gaps** from section 4 items 6 and 8 (unmeasured benchmarks, visible product limits) and decisions 7, 8, 9, 10, 12 (decisions 1 and 4 were settled in D23: kill criteria frozen, hard limits keep rejecting after a per-site log check).
