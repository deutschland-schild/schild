# Development

How the code of Deutschland-Schild is built and tested. The Schild Gateway (`gateway/`, binary `schild`) is released as an alpha; lab and relay (`lab/`, `relay/`) are planned parts that run in the test lab only.

```sh
make gateway-test     # go vet and the gateway's tests
make gateway-run      # local, with TEST ONLY keys: proxy on 127.0.0.1:8080 in front of an app on 127.0.0.1:8081
make gateway-image    # image schild:dev (dev build, dashboard built in the image) with the geo test fixture, no download
make test             # contracts and every Go module, in short mode (as in CI)
cd dashboard && pnpm check   # dashboards: typecheck, lint, tests, build
cd site && npm install && npm run dev   # website on http://localhost:3000 (npm, not pnpm)
```

Installing a released gateway is described for users in [docs/gateway/00-installieren.md](docs/gateway/00-installieren.md) (German). Acceptance criteria and test scenarios (German): [docs/concept/23-verifikation.md](docs/concept/23-verifikation.md), [docs/concept/14-testkonzept.md](docs/concept/14-testkonzept.md). How the prototype got here: [History](#history-stages-of-the-prototype).

## Quickstart (local, Docker)

Needs Go 1.27 (`go.work` names `toolchain go1.27.4`; an older local `go` downloads it automatically unless `GOTOOLCHAIN=local` is set), Node >= 22 with pnpm 12, Docker and Python 3 with `jsonschema` (else `make contracts-test` creates `.venv`). Everything runs on internal Docker networks; only the gateway publishes the dashboards on `127.0.0.1`.

```sh
make contracts-test                        # contracts v0.5: Go and Python agree on every golden vector
make test                                  # contracts + go vet/test of every module + gateway/lab/relay tests, in short mode (as in CI)
make test-full                             # the same with the load and performance tests (10k burst, fan-out, floods); needs a quiet machine
(cd dashboard && pnpm install --frozen-lockfile && pnpm check && pnpm test:e2e)   # dashboards: typecheck, lint, unit, build, e2e (mock mode)
make adversaries-test                      # MVP-07 adversary suite alone (also part of make test)
make selftest                              # evaluator self-test: every planted fault must be detected
make testlab-compose-config                # compose files of t0, t1 and t0+traffic are valid
make ui                                    # build both dashboards and copy them into the Go embed dirs: for go run, make gateway-run, make build
                                           # and the schild-lab image (the schild image builds its dashboard itself)
BUILDX_BUILDER=desktop-linux make images   # schild, schild-lab, schild-relay, schild-testlab, schild-testlab-app-vm, schild-traffic, schild-adversary (:dev)
make testlab-readonly-proof                # MVP-11: schild check (root and nobody) in a disposable app VM changes nothing but its report dir
make testlab-check-install                 # D100: schild check install under systemd on six distributions, gateway as container and as service

make testlab-up PROFILE=t0                 # TEST ONLY secrets, lab users, the stack; waits until healthy
make smoke PROFILE=t0                      # gateway end-to-end proof (lab chain skipped, D72) + evaluator + browser check
make testlab-t12                           # T12 fail-open live (front proxy, schild killed / dead / hung) on the running t0
make testlab-down PROFILE=t0               # removes containers, networks and volumes

make testlab-up PROFILE=t1                 # 2 sites (observe / autoblock); 4 labs and 2 relays for the lab side,
                                           # plus the MVP-11 agent lab (gateway host check, 3 app VMs; SCHILD_AGENTS=0 leaves it out)
make smoke PROFILE=t1                      # incl. agent steps: enrolment, delivery, replay, unknown/revoked keys, gateway down, canaries
node tests/testlab/scripts/server-page-check.mjs   # MVP-11 Server page against the real backend (after the t1 smoke), tests/results/ux/spec11/real/
make testlab-down PROFILE=t1
```

- `BUILDX_BUILDER=desktop-linux`: the images must land in the local image store. If your default buildx builder is the `docker` driver, leave it out. `make images` and `make gateway-image` build `schild:dev` as a dev build (test keys and the test profile allowed, label `de.deutschland-schild.build=dev`, never published) with the TEST ONLY geo fixture (no download); `GATEWAY_GEO=dbip` downloads DB-IP Lite, `TAGS=release` makes a local release build. The gateway image builds its dashboard in a Node stage, so it needs no `make ui`. Published images and tarballs come from [.github/workflows/release.yml](.github/workflows/release.yml) only ([docs/ops/release.md](docs/ops/release.md)).
- Dashboards while a stack is up (t0): gateway `http://127.0.0.1:18788` (user admin), labs `http://127.0.0.1:18789`, `:18790`, `:18791` (users `carol`, `alice`, `bob`). t1: gateways `:28788`, `:28798`, labs `:28789` to `:28792`. TEST ONLY password: `$SMOKE_PASSWORD`, default `schild-testlab-passwort`; the gateway's first password is set by `make smoke` with the one-time setup code from the schild log.
- Preflight (D24): `schild`, `schild-lab` and `schild-relay` refuse to start with test keys, key ids starting with `test` or the test lab CA. The test lab compose files, `lab/dev`, the UI dev scripts and `make gateway-run` set `SCHILD_ALLOW_TEST_KEYS=1`; anything you start by hand against the TEST ONLY keys needs it too. Never set it in production. `schild preflight`, `schild-lab preflight` and `schild-relay preflight` only print the check.
- Server check and agents (MVP-11): `schild check` runs on the gateway host, the separate binary `schild-agent enrol|init|run` on app VMs (no proxy, WAF or dashboard; not part of the first gateway version, D60b: the gateway refuses `host_check.agents`, the image carries it only with `AGENT=1`, `make gateway-agent` builds it alone); contract [contracts/host-check.md](contracts/host-check.md), commands and rights [gateway/README.md](gateway/README.md), systemd units [docs/ops/systemd/](docs/ops/systemd/), runbook section 17. Agent results of the t1 smoke: `tests/results/runs/smoke-t1/agents.json`; read-only proof: `tests/results/runs/readonly-proof/`; summary [tests/results/MVP-11.json](tests/results/MVP-11.json).
- Ops tools: `schild logcheck` (access logs against the hard limits before installing). The lab and relay keep their own tools (`schild-lab export d2`, `schild-lab keygen`, `schild-relay keygen`).
- Reports: `tests/results/runs/smoke-<profile>/smoke.json` (every step with evidence and timings), `eval/MVP-05.json` (evaluator on the gateways' NDJSON event exports and ground truth), `browser/` (screenshots, `browser-check.json`). `tests/results/runs/` is gitignored.
- What `make smoke` checks and how the stacks are wired: [tests/testlab/README.md](tests/testlab/README.md). Co-signing protocol, peer requests and the RFC 6962 log root: [contracts/cosign.md](contracts/cosign.md).

## History: stages of the prototype

The prototype was built in stages: interfaces first, then every component as a Docker image, validated locally in the Schild test lab, then the same images live on the initiator's own projects in observe mode.

Status: stage 1 contracts frozen as `v0` and extended by the backwards-compatible addenda `v0.1`, `v0.2`, `v0.3` (server check and agent, MVP-11) and `v0.4` (behaviour across requests and rate limits, MVP-17) ([contracts/CHANGELOG.md](contracts/CHANGELOG.md)). Stage 2: the images `schild`, `schild-lab`, `schild-relay` and the test lab are built; the whole loop (traffic, local events, signals, labs, proposal, human approval, co-signed bundle, relays, clients, emergency stop) ran end to end in the test lab profiles t0 and t1. Since D72 (2026-11-06, [contracts/DECISIONS.md](contracts/DECISIONS.md)) the first gateway version has no network features: it sends no signals, takes no rule bundles or withdrawals and talks to no lab or relay. `make smoke` now proves the gateway on its own and reports the lab chain as skipped (lab later); labs and relays still run in the stacks for their own checks. The hypotheses M1–M7 were measured in stage 2 ([tests/results/REPORT.md](tests/results/REPORT.md)); after the stage-3 preparation (Go 1.25 / Coraza 3.8, contracts v0.2, preflight, keygen, D1–D3 tools; REPORT addendum) M1 and M2 are re-measured on clean pinned images before stage 3.

| Stage | Output | Gate |
| --- | --- | --- |
| 1 – Contracts | `contracts/` schemas + golden test vectors | reviewed and frozen as `v0` |
| 2 – Local build and validation | images `schild`, `schild-lab`, `schild-relay` + test lab | hypotheses M1–M7 pass (or decided) |
| 3 – Live on own projects | same image digests, observe mode, 4–6 weeks | hypotheses D1–D3 measured, no incident |
| 4 – Review | report, concept updates | go/no-go for the alpha |

Operating the gateway (German): [docs/gateway/00-installieren.md](docs/gateway/00-installieren.md) and [docs/gateway/02-betrieb.md](docs/gateway/02-betrieb.md). The runbooks of the prototype (stage 3, first own server) are not part of this repository.

## Website

`site/` is a Nuxt site, generated statically (`cd site && npm run generate`, output in `site/.output/public`). Netlify builds it on every push to `main` (`netlify.toml`): **a push to `main` is live.** With Docker instead of a local Node: `docker compose up -d` in the repository root serves the dev site on http://localhost:3000. The release shown on the site (version, date, repository URLs) lives in one file, `site/app/utils/release.ts`.

Editing copy in the browser (only under `npm run dev`): Alt+click (Mac: Option+click) on a text makes that text node editable, Enter saves, Esc cancels. The change is written to the source file the text comes from (`site/app/**/*.vue|ts` or the published Markdown in `docs/concept`, `docs/brand`, `docs/stories`). It only saves when the text occurs exactly once; markup, attributes and texts assembled at run time have to be changed in the editor. The module `site/modules/inline-edit` registers nothing outside `nuxt dev`, accepts only local POST requests and never writes outside `site/app` and those three docs folders. Switch it off with `INLINE_EDIT=0 npm run dev`.

## Specs

| Spec | Component | Ships in the prototype | Hypotheses |
| --- | --- | --- | --- |
| [MVP-01](tests/specs/MVP-01-contracts.yaml) | Contracts and test vectors | yes | all |
| [MVP-02](tests/specs/MVP-02-client.yaml) | `schild run`: proxy, WAF, local events (signals and rule updates: lab later, D72) | yes | M1 |
| [MVP-03](tests/specs/MVP-03-lab-core.yaml) | Lab core: ingest, queue, scoring, signed feed | yes | M3, M6 |
| [MVP-04](tests/specs/MVP-04-relay.yaml) | Relay: SSE stream, rule bundles, withdrawals | yes | M5, M7 |
| [MVP-05](tests/specs/MVP-05-testlab.yaml) | Test lab: sites, label stripper, ground truth, evaluator, sniffer | test only | measures all |
| [MVP-06](tests/specs/MVP-06-traffic.yaml) | Legit traffic, attack suites, botnet simulation, replay | test only | M1, M3, D2 baseline |
| [MVP-07](tests/specs/MVP-07-adversaries.yaml) | Malicious lab, Sybil clients, poisoned rules, SecLang fuzzer, red team | test only | M3, M4, M5 |
| [MVP-08](tests/specs/MVP-08-geo-dataset.yaml) | Open geo dataset (country, ASN, net class; CC0), compared with DB-IP Lite in stage 3 | no (planned) | M2, D2 |
| [MVP-09](tests/specs/MVP-09-client-dashboard.yaml) | Gateway dashboard (embedded in `schild`) | yes | M2, D1, D3 |
| [MVP-10](tests/specs/MVP-10-lab-dashboard.yaml) | Lab dashboard (embedded in `schild-lab`) | yes | M3, M5, M6 |
| [MVP-11](tests/specs/MVP-11-server-check-agent.yaml) | Server check and agent (`schild check`, `schild-agent`; contracts v0.3) | yes | D3 |
| [MVP-17](tests/specs/MVP-17-behaviour-and-rate-limits.yaml) | Behaviour across requests and rate limits in `schild run` (contracts v0.4) | draft, built | D1, D3 |
| [MVP-21](tests/specs/MVP-21-traffic-and-server-monitoring.yaml) | Traffic and server monitoring in the gateway dashboard (contracts v0.4, D33) | draft, contracts only | M2, D1, D3 |

## Layout

```text
Makefile               root targets; components add theirs in <dir>/component.mk and tests/<dir>/component.mk
go.work                Go workspace: contract gateway lab relay tests/adversaries tests/testlab
gateway/               Schild Gateway: schild (and schild-agent), MVP-02/09/11 and later specs
lab/  relay/           Schild Lab and Relay (MVP-03/04, planned parts, test lab only)
dashboard/             pnpm workspace with both dashboards (MVP-09/10), embedded by make ui (the schild image builds its own)
contracts/             stage 1: schemas, docs, golden vectors, test keys, OpenAPI
  DECISIONS.md         every decision of the contracts (E2, E3, E5, E6 details, D1 ...)
  conventions.md       ownership, images, ports, env vars, subnets, results, UI embedding
  envelope.md auth.md signal.md seclang-subset.md stream.md cosign.md
  *.schema.json        envelope, signal, feedback, ack, submission, checkpoint,
                       rule-bundle, withdrawal, stream, events, results
  config/              schild.yaml and lab.yaml schemas + examples
  api/                 client-dashboard and lab-dashboard OpenAPI 3.1 + fixtures
  vectors/             >= 5 valid and >= 10 invalid vectors per contract
  testkeys/            TEST ONLY keys (refused by release builds)
  tools/crosscheck.py  independent Python implementation of all checks
contract/              Go module: types, schema validation, DSSE, verifiers,
                       SecLang subset, stream, events, config, auth, transport
tests/                 system-level tests (unit tests stay next to the code)
  testlab/             test lab (MVP-05/06): compose stacks, evaluator, traffic
  adversaries/         red team (MVP-07)
  specs/               one YAML spec per component (MVP-01 ...)
  results/             <spec>.json and reports written by measurements
docs/ops/              runbooks (German), ops log format, systemd units
```

Commands: `make contracts-test` (stage 1 gate), `make test` (short mode), `make test-full`, `make build`, `make ui`, `make images`, `make testlab-up PROFILE=t0|t1`, `make smoke PROFILE=t0|t1`, `make testlab-down PROFILE=t0|t1`, `make eval SPEC=MVP-0x`, `make selftest`. Details: [contracts/conventions.md](contracts/conventions.md).

## Rules for agents

1. Contracts first. No component code before MVP-01 is frozen. Contract changes only via the initiator, with a new version.
2. Builders never write the measurement they are judged by. MVP-05/06/07 are built by different agents than MVP-02/03/04.
3. Red team last: gets running containers and contracts only.
4. Every measurement runs with one command, a fixed seed and pinned images; results go to `tests/results/<spec>.json` in the format from `contracts/results.schema.json`.
5. Humans decide whether a kill criterion is hit and what follows.
6. Code, identifiers, comments and payloads in English.
7. Attack tools only against own containers on internal Docker networks without a route to the outside.

## Spec format

Each spec is a YAML file with: `id`, `title`, `ships`, `hypotheses`, `refs` (IDs from the concept docs), `depends_on`, `contracts` (in/out), `must` (requirements), `measure` (done by the evaluator, not the builder), `kill_if`, `done` (one reproducible command), `out_of_scope`.
