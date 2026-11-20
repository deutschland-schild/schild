# Conventions (contracts v0.4)

Rules every agent follows. Changes only through the initiator (see [DEVELOPMENT.md](../DEVELOPMENT.md), rule 1).

## 1. Directory ownership

Each agent writes only in its own directories. Requests for changes elsewhere go into the agent's final report under "requests".

| Path | Owner | Spec |
| --- | --- | --- |
| `Makefile`, `go.work`, `DEVELOPMENT.md` | contracts agent | MVP-01 |
| `contracts/`, `contract/` (Go module) | contracts agent | MVP-01 |
| `tests/specs/` | initiator; `MVP-08`, `MVP-09`, `MVP-10` drafted by the contracts agent | all |
| `gateway/` | gateway agent (`schild run`, gateway dashboard API) | MVP-02, MVP-09 (server side) |
| `lab/` | lab agent (lab core, lab dashboard API) | MVP-03, MVP-10 (server side) |
| `relay/` | relay agent | MVP-04 |
| `tests/testlab/` except `tests/testlab/traffic/` | test lab agent | MVP-05 |
| `tests/testlab/traffic/` | traffic agent | MVP-06 |
| `tests/adversaries/` | adversaries / red team agent | MVP-07 |
| `dashboard/` | UI agent (both dashboards, pnpm workspace) | MVP-09, MVP-10 (frontend) |
| `tests/results/` | written only by evaluators and `make eval` | all |

Builders never write the measurement they are judged by: MVP-05/06/07 are built by other agents than MVP-02/03/04.

## 2. Go modules

- One workspace: `go.work` uses `contract gateway lab relay tests/adversaries tests/testlab`.
- Module paths: `github.com/deutschland-schild/schild/<name>` (`contract`, `gateway`, `lab`, `relay`, `adversaries`, `testlab`). Components import `github.com/deutschland-schild/schild/contract/...`; inside the workspace this resolves to `./contract`. **No `replace` directives in component `go.mod` files.**
- Go 1.27 (`go.work` pins `toolchain go1.27.4`; D24 chose 1.25), `CGO_ENABLED=0`, pure-Go dependencies only (e.g. `modernc.org/sqlite`, not `mattn/go-sqlite3`). Record every new dependency and its licence in your report.
- Docker builds use the repository root as build context (each Dockerfile has its own `<Dockerfile>.dockerignore` that admits only what it needs) and copy `go.work`, `go.work.sum` (if present), `contract/` and the component, plus the `go.mod` files of all other workspace modules (they are tiny). Example:

  ```dockerfile
  FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS build
  WORKDIR /src
  COPY go.work ./
  COPY contract/ contract/
  COPY gateway/ gateway/
  COPY lab/go.mod lab/go.mod
  COPY relay/go.mod relay/go.mod
  COPY tests/testlab/go.mod tests/testlab/go.mod
  COPY tests/adversaries/go.mod tests/adversaries/go.mod
  RUN cd gateway && CGO_ENABLED=0 go build -trimpath -o /out/schild ./cmd/schild

  FROM gcr.io/distroless/static-debian13:nonroot
  COPY --from=build /out/schild /usr/local/bin/schild
  ENTRYPOINT ["/usr/local/bin/schild"]
  ```

- Build tag `release`: refuses test keys and the test profile (E5, see [DECISIONS](DECISIONS.md) D05). The prototype images for stage 2 and 3 are built **without** it (stage 3 needs the test profile); alpha builds use `-tags release`.

## 3. Images

| Image | Built from | Role |
| --- | --- | --- |
| `schild` | `gateway/Dockerfile` | `schild run`: proxy, WAF, events, signals, rule updates, gateway dashboard |
| `schild-lab` | `lab/Dockerfile` | lab core and lab dashboard |
| `schild-relay` | `relay/Dockerfile` | relay stream |
| `schild-testlab-<name>` | `tests/testlab/...` | e.g. `schild-testlab-evaluator`, `-label-stripper`, `-sniffer`, `-gateway`, `-site-api` |
| `schild-traffic-<name>` | `tests/testlab/traffic/...` | legit traffic, attack suites, botnet, replay |
| `schild-adversary-<name>` | `tests/adversaries/...` | malicious lab, Sybil clients, poisoned bundles, SecLang fuzzer |

Tag `:dev` locally; every measurement records image digests in `tests/results/<spec>.json`. Base images: `golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280` for building (shared by all, saves disk; pinned by digest, D24), `gcr.io/distroless/static-debian13:nonroot` for running. Disk is tight: no large datasets in images, no `docker system prune` of anything you did not create.

## 4. Ports (inside containers)

| Component | Port | Purpose |
| --- | --- | --- |
| `schild` | 8080 | reverse proxy (HTTP; TLS terminates in front or via Caddy config) |
| `schild` | 8788 | client dashboard + `/api/v0` (localhost or login only) |
| `schild` | 9101 | Prometheus `/metrics` |
| `schild` | 8790 | v0.3, only with `host_check.agents.enabled` and an explicit `host_check.agents.listen` (no default): agent listener `POST /v0/agent/report`, `POST /v0/agent/enrol` (TLS, [host-check.md](host-check.md)); reachable from the app VMs only |
| `schild-lab` | 7443 | ingest `POST /v0/submit` (TLS) |
| `schild-lab` | 7444 | lab feed for relays: `GET /v0/stream`, `/v0/bundles/...`, `/v0/checkpoint`, `/v0/log`; for peers: `GET /v0/collecting` (signed peer requests), `POST /v0/signatures` (TLS, [cosign.md](cosign.md)) |
| `schild-lab` | 8789 | lab dashboard + `/api/v0` |
| `schild-lab` | 9102 | `/metrics` |
| `schild-relay` | 7480 | public stream `GET /v0/stream` (SSE), `/v0/bundles/...`, `/v0/checkpoint` |
| `schild-relay` | 9103 | `/metrics` |
| test lab | 9090 Prometheus, 3000 Grafana, 9200 evaluator, 9201 ground truth | observation |

Every service also answers `GET /healthz` (liveness) and `GET /readyz` (readiness) on its main port. Published host ports bind to `127.0.0.1` only and go through one gateway container (section 6).

## 5. Environment variables and paths

| Variable | Default | Used by |
| --- | --- | --- |
| `SCHILD_CONFIG` | `/etc/schild/schild.yaml` | `schild` |
| `SCHILD_DATA_DIR` | `/var/lib/schild` (events DB, geo DB, rule cache) | `schild` |
| `SCHILD_LAB_CONFIG` | `/etc/schild-lab/lab.yaml` | `schild-lab` |
| `SCHILD_LAB_DATA_DIR` | `/var/lib/schild-lab` (queue, public log, bundles) | `schild-lab` |
| `SCHILD_RELAY_ID` | hostname | `schild-relay` |
| `SCHILD_RELAY_LISTEN` | `:7480` | `schild-relay` |
| `SCHILD_RELAY_UPSTREAMS` | none (comma-separated lab feed URLs) | `schild-relay` |
| `SCHILD_RELAY_BUFFER` | `256` (events per client) | `schild-relay` |
| `SCHILD_TEST_CA` | none (PEM bundle of the test CA) | all, test lab only |
| `SCHILD_ALLOW_TEST_KEYS` | unset; only `1` counts | `schild`, `schild-lab`, `schild-relay`: test lab override of the D24 preflight (start despite test keys, `test` key ids or the test CA); test lab compose files and dev scripts only |
| `SCHILD_LOG_LEVEL` | `info` | all |
| `SCHILD_LOG_FORMAT` | `json` | all |
| `SCHILD_SEED` | `42` | test lab, traffic, adversaries |
| `SCHILD_RESULTS_DIR` | `/results` (mounted from `tests/results`) | evaluators |

Files: `/etc/schild/keys/site.key`, `/etc/schild-lab/keys/<name>.key` (mode 0600, one line `ed25519-seed:<64 hex>`), `/etc/schild-lab/tls/{cert,key}.pem`. Config formats: [config/schild.schema.json](config/schild.schema.json), [config/lab.schema.json](config/lab.schema.json), examples in [config/examples/](config/examples/). Loaders: `contract/config` (YAML 1.2, strict, schema-validated).

Logs: JSON lines on stdout (`log/slog`), fields `time`, `level`, `msg`, `component`. Metrics names: `schild_*`, `schild_lab_*`, `schild_relay_*`. Time is UTC everywhere.

## 6. Docker networks

Docker's default address pools are exhausted on the build host. **Every compose network declares an explicit subnet inside `10.66.0.0/16`** (IPv6 inside `fd66::/64` where needed). Compose project names start with `schild-`. All test networks are `internal: true` (no route out). Attack tools run only against own containers on these networks.

| Network | Profile t0 | Profile t1 | Members |
| --- | --- | --- | --- |
| `sites` | `10.66.1.0/24` | `10.66.17.0/24` | `schild` instances and the apps behind them |
| `federation` | `10.66.2.0/24` | `10.66.18.0/24` | `schild`, labs, relays, sniffer |
| `obs` | `10.66.3.0/24` | `10.66.19.0/24` | Prometheus, Grafana, evaluator, ground truth, gateway |
| `inet` | `10.66.4.0/22`, `fd66::4:0:0:0/80` | `10.66.20.0/22`, `fd66::14:0:0:0/80` | simulated internet: legit traffic, attackers, botnet, `schild` front side |
| `mgmt` | `10.66.8.0/24` | `10.66.24.0/24` | **only** the gateway container (not internal) publishing dashboards on `127.0.0.1` |

Development composes of single agents: `10.66.32.0/24` client, `10.66.33.0/24` lab, `10.66.34.0/24` relay, `10.66.35.0/24` ui, `10.66.36.0/24` adversaries, `10.66.37.0/24` testlab development; `10.66.38.0` to `10.66.47.255` reserved; `10.66.48.0/20` red team. Projects: `schild-testlab-t0`, `schild-testlab-t1`, `schild-dev-<component>`.

Egress capture (T19): the sniffer sees every packet of every `schild` container on `federation` and `inet`; labs use the test CA so payloads are readable.

## 7. Test keys

`contracts/testkeys/keys.json` holds the fixed **TEST ONLY** keys. Seeds are public (`sha256("schild/testkey/v0/" + name)`), key ids start with `test-`. Release builds (`-tags release`) refuse them everywhere (`keys.IsTestKey` checks prefix and public key). Write a key file for a container with `cd contract && go run ./cmd/testkeyfile -name lab-a > lab.key`. See [testkeys/README.md](testkeys/README.md).

## 8. Results

Every measurement writes `tests/results/<spec>.json` in the format of [results.schema.json](results.schema.json) (Go helper: `contract/results`). Raw artifacts (pcaps, logs) go to `tests/results/runs/<run_id>/` (gitignored). One command per measurement, fixed seed (`SEED`, default 42), pinned image digests.

## 9. Dashboards: UI build and embedding

- Frontends live in `dashboard/` (pnpm workspace): `dashboard/apps/client-dashboard` and `dashboard/apps/lab-dashboard` (Vue 3, TypeScript, Vite, Tailwind v4, shadcn-vue). They talk only to the APIs in [api/](api/).
- `make ui` runs `pnpm install --frozen-lockfile && pnpm -r build` in `dashboard/` and copies
  - `dashboard/apps/client-dashboard/dist` -> `gateway/internal/webui/dist`
  - `dashboard/apps/lab-dashboard/dist` -> `lab/internal/webui/dist`

  It is for local builds (`go run`, `make gateway-run`, `make build`) and the `schild-lab` image. The `schild` image does not use it: `gateway/Dockerfile` builds the gateway dashboard in a Node stage and stops without `index.html`, and its `.dockerignore` keeps the local `dist` out. `make build TAGS=release` refuses to build without a dashboard build.
- The Go side embeds with `//go:embed all:dist` and keeps a committed `dist/.gitkeep`, so it always compiles. When `dist/index.html` is missing it serves an embedded `placeholder.html` ("Dashboard noch nicht gebaut: make ui"). Unknown non-API paths fall back to `index.html` (SPA routing). API under `/api/v0/`, SSE under `/api/v0/.../stream` (client `GET /api/v0/events/stream` with local events, lab `GET /api/v0/events/stream` with topic-named live events, v0.1).
- No inline scripts and no inline styles: `index.html` loads `theme-init.js` as a file, components set styles only through CSSOM (Vue `:style`), never through `style` attributes in markup or injected `<style>` elements. Both servers send `script-src 'self'; style-src 'self'`.
- Fixtures: `contracts/api/fixtures/<client|lab>/<operationId>[.variant].json` (v0.1), validated against the operation's success response; the app-kit mock serves `<app>/<operationId>.json` for that operation.
- Security headers on every dashboard response: strict CSP (`default-src 'self'`), `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `frame-ancestors 'none'`. Session cookie `HttpOnly`, `SameSite=Strict` and `Secure` whenever the browser came over HTTPS (gateway: D76); the gateway dashboard also checks the `Host` header (`dashboard.allowed_hosts`, D76); state-changing requests need the `X-CSRF-Token` header from the session.
- UI copy is German, du-form, calm (docs/brand/01-marke.md#sprache): "Grundschutz aktiv", never "geschützt"/"sicher"; "pseudonym", never "anonym"; "Anfrage", "Ereignis", "Signal", "Regel"/"Empfehlung", "Lab".

## 10. Makefile

The root `Makefile` includes `*/component.mk` and `tests/*/component.mk`. A component file may define targets prefixed with its directory name (`gateway-...`, `lab-...`, `testlab-...`) and register them through these variables (append with `+=`, set the single-target hooks with `:=`):

| Variable | Root target that runs it |
| --- | --- |
| `TEST_TARGETS` | `make test` (short mode, `GO_TEST_FLAGS ?= -short`) and `make test-full` (with the load and performance tests) |
| `BUILD_TARGETS` | `make build` |
| `IMAGE_TARGETS` | `make images` (for images without the default `<dir>/Dockerfile` mapping) |
| `UI_TARGETS` | `make ui` |
| `EVAL_TARGETS` (`eval-MVP-0x`) | `make eval SPEC=MVP-0x` |
| `SELFTEST_TARGETS` | `make selftest` / `make testlab-selftest` |
| `TESTLAB_UP_TARGET`, `TESTLAB_DOWN_TARGET` | `make testlab-up` / `testlab-down` (`PROFILE=t0|t1`) |
| `TRAFFIC_TARGET` | `make traffic SCENARIO=... SEED=...` |
| `SMOKE_TARGET` | `make smoke PROFILE=t0\|t1` (end-to-end proof against the running test lab) |

Never redefine root targets. `make contracts-test` is the MVP-01 gate and must stay green; `make contracts-fuzz` is the differential fuzz of the contract checkers; `make contracts-vectors` regenerates vectors after a contract change (initiator only after the freeze).

## 11. Language

Code, identifiers, comments, payloads, API fields and docs of the code (`gateway/`, `lab/`, `relay/`, `dashboard/`, `contract/`, `contracts/`, `tests/`): English. User-facing UI copy: German. Exception: the operator runbooks in [docs/ops/](../docs/ops/) are German (du-form), because the initiator runs them. Documentation IP addresses only from RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and RFC 3849 (`2001:db8::/32`); ASNs from RFC 5398 (`64496-64511`) where possible; domains `*.example`, `*.test` and the RFC 2606 names `example.org`/`example.com`.
