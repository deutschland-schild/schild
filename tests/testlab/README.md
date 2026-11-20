# Schild test lab (MVP-05) and traffic (MVP-06)

The test lab runs the schild gateway against realistic sites and traffic on
isolated internal Docker networks and measures how well it works. The labs and
relays (planned parts) run in the same stacks for their own tests. Since D72
the gateway has no network features: it sends no signals, receives no rules
and talks to no lab or relay (`contracts/DECISIONS.md`, D72). The test lab is
never shipped; it uses the fixed TEST ONLY keys of `contracts/testkeys` and
exists only in the `SCHILD_TEST_CA` world.

Everything is built by a different agent than the components it measures
(conventions §1): this directory never builds `schild`, `schild-lab` or
`schild-relay`.

## Layout

```
testlab/
  cmd/
    label-stripper/   reverse proxy: strips the secret label, assigns X-Request-Id,
                      records request_id -> label into the ground-truth SQLite
    groundtruth/      read-only HTTP view of the ground-truth DB (obs, :9201)
    evaluator/        joins events with ground truth -> results/<spec>.json; -selftest
    egress-check/     scans a transparency log of signals for canary/IP/forbidden-field leaks (T19;
                      no gateway writes one since D72, kept for the signal contract)
    site-api/         a tiny, ordinary REST API used as one target site
    healthcheck/      1-shot HTTP probe so distroless services can have a healthcheck
    gateway/          the only container on mgmt: publishes the dashboards on 127.0.0.1
    smoke/            end-to-end proof of the gateway (make smoke), runs inside the stack
  internal/
    label/            signed ground-truth label header (HMAC-SHA256)
    groundtruth/      SQLite store (modernc.org/sqlite, pure Go)
    eval/             join, metrics, and the planted-fault self-test
    egress/           independent positive-list + canary/IP scanner
  compose/
    docker-compose.t0.yaml   profile t0: the REST API behind schild; 3 labs (3 operators), 2 relays
    docker-compose.t1.yaml   profile t1: 2 light sites (observe / autoblock); 4 labs (4 operators),
                             2 relays; profile `full`: WordPress, DVWA, Juice Shop; `adversary`: lab-mal
    config/t0, config/t1     schild.yaml / lab.yaml per node (validated by compose/config_test.go)
    secrets/                 generated, gitignored: TEST ONLY keys, test CA + TLS, geo fixture
  dockerfiles/testlab.Dockerfile
  scripts/                   preflight.sh, gen-secrets.sh, up.sh, smoke.sh, browser-check.mjs
  traffic/              MVP-06 (see below)
```

## Traffic (MVP-06)

`testlab/traffic/` is the deterministic traffic generator. A plan is pure data
(no network), so counts are reproducible before anything is sent — the MVP-06
kill criterion is "two runs with the same seed differ in labelled counts".

- `internal/legit` — browsing sessions, API clients, good bots (CoreDNS mock
  rDNS), and benign canary requests.
- `internal/attacks` — a small curated SQLi/XSS/traversal/cmdi set plus
  credential stuffing with a tiny test list.
- `internal/corpus` — the K3 resilience corpus (oversized, nested JSON, ReDoS,
  low-and-slow markers).
- `internal/sources` — deterministic IPv4/IPv6 source pools in the `inet`
  ranges, for botnet simulation (loud, low-and-slow, waves).
- `internal/plan` — assembles scenarios T01–T05 and counts them.
- `cmd/traffic` — builds, counts, and sends plans; `-emit-label` prints a signed
  label header for the external attack-tool containers.

Heavy external suites (nuclei with `-no-interactsh`, sqlmap with tamper scripts,
GoTestWAF, go-ftw CRS subset, nikto, ffuf) run as their own containers in
`traffic/compose/docker-compose.traffic.yaml` under the `attack` profile; each
carries a precomputed signed label header so the stripper records its ground
truth. Attacks only ever target the lab's own strippers on internal networks.

## Commands

```
make testlab-image                 # build schild-testlab:dev (all test-lab binaries)
make traffic-image                 # build schild-traffic:dev
make testlab-compose-config        # docker compose config for t0, t1, t1+agents, t0+traffic
make testlab-app-vm-image          # MVP-11: TEST ONLY app VM image (schild comes from schild:dev at runtime)
make testlab-agent-smoke           # MVP-11: agent steps against a running t1 (pending until the backend supports them)
make testlab-readonly-proof        # MVP-11: schild check changes nothing but the report dir
make testlab-readonly-proof-selftest  # MVP-11: the proof passes a clean fake and catches a writing one
make selftest                      # evaluator planted-fault self-test (MVP-05 kill criterion)
make testlab-secrets               # TEST ONLY keys, test CA, TLS, geo fixture -> compose/secrets (gitignored)
make testlab-up   PROFILE=t0|t1    # secrets, lab users, stack; waits until healthy
make smoke        PROFILE=t0|t1    # end-to-end proof + evaluator + browser check (see below)
make testlab-down PROFILE=t0|t1    # stop and remove containers, networks and volumes (incl. profile t12)
make testlab-t12                   # T12 live on a running t0: front proxy + schild kill/pause under load -> results/runs/t12/t12.json
make traffic-ftw                   # go-ftw CRS regression subset (labelled) vs the running t1 autoblock shop -> results/runs/ftw/ftw.json
make traffic SCENARIO=T0x SEED=42  # build + count a plan (deterministic), plan/canaries -> results/runs
make eval SPEC=MVP-05              # self-test + results/MVP-05.json
make eval SPEC=MVP-06 SCENARIO=T0x # reproducibility result -> results/MVP-06.json
```

A real measurement passes live inputs to the evaluator:

```
evaluator -ground-truth gt.sqlite -events events.ndjson \
          [-baseline no-schild.ndjson] \
          -spec MVP-05 -profile t0 -out results
```

`-signals transparency.ndjson -canaries C1,C2 -forbidden-ips ...` adds the
egress check of a transparency log of signals. The gateway writes none since
D72; the option stays for the signal contract (lab later).

## Data flow

```
traffic ──(X-Schild-Label)──► stripper ──(X-Request-Id)──► schild ──► site
                                 │ writes request_id→label
                                 ▼
                           ground-truth.sqlite ──► evaluator ──► results/<spec>.json
```

Nothing goes from schild to the labs or relays (D72): the gateways sit on
`sites` only, the labs and relays on `federation`.

The evaluator joins the Schild Gateway's local events to ground truth by
`X-Request-Id` and reports precision/recall per class, false-positive rate,
latency p50/p95/p99 with and without schild, bypass count, canary findings and
blocks of legitimate traffic. The egress check (optional) independently
re-enforces the signal positive list and scans every outgoing payload for
canary values and address-like tokens.

## Wiring of the stacks

- **Labs** use the deterministic test keys (`lab-d` additionally a deterministic test-lab key for ack and checkpoint, see `scripts/gen-secrets.sh`), serve TLS with the test CA, list every other lab as a co-signing peer (`peers[]`) and publish at `SCHILD_LAB_THRESHOLD=3` distinct operators. Dashboard users `carol`, `alice`, `bob` are created by `scripts/up.sh` (`schild-lab user add` while the labs are stopped; TEST ONLY password `$SMOKE_PASSWORD`, default `schild-testlab-passwort`).
- **Relays** follow every lab; `SCHILD_RELAY_MAX_PER_IP=100000` so load generators can open many streams from one address.
- **Sites**: each Schild Gateway is on `sites` only (D72: no `federation`, no site key, no test CA) and trusts exactly its label stripper (fixed address in `10.66.1.0/28` / `10.66.17.0/28`) and the load generators (fixed addresses in `10.66.4.0/28` / `10.66.20.0/28`) as proxies, so `X-Forwarded-For` carries the simulated visitor (documentation ranges) and the stripper's `X-Request-Id` becomes the event's `request_id` (join with ground truth). The geo fixture (`schild geo-fixture`: documentation ranges and `10.66.0.0/16`) is mounted and set as `geo.db_path`.
- **Evaluator input**: every gateway mirrors its local events to `events.ndjson` in a named volume (`SCHILD_EVENTS_NDJSON_DIR`, test lab only); the `evaluator` and `smoke` jobs mount it read-only.
- **Volumes** are writable by uid 65532: the images create their mount points owned by the runtime user, so fresh named volumes inherit it.
- **T12 front proxy** (t0, compose profile `t12`, not started by `testlab-up`): `stripper-t12` -> `front-api` (`schild front`, :8090) -> `schild-t12` on 127.0.0.1:8080 in the front's network namespace -> `site-api`. A dead schild process gives "connection refused" (fail-open to the app), a hung one (docker pause) a timeout (503), as on a real host. `front-api` reads schild-t12's storage read-only (`-access-dir`, D71); a front that cannot read the lock state never fails open. `scripts/t12.sh` drives the phases; `compose/config_test.go` guards the wiring.
- **Gateway** (the network gateway container, not the Schild Gateway): the only container on the non-internal `mgmt` network; it publishes the dashboards on `127.0.0.1` (t0: 18788 gateway dashboard, 18789-18791 labs; t1: 28788/28798 gateway dashboards, 28789-28792 labs).

## Smoke test (`make smoke PROFILE=t0|t1`)

`scripts/smoke.sh` reads the gateway dashboards' one-time setup codes from the logs, runs `cmd/smoke` inside the stack (inet + federation, fixed load-generator address) and then the evaluator and `scripts/browser-check.mjs`. The driver proves, step by step and against the real images: every gateway, lab and relay ready, logins, legit and attack traffic through the stripper, local events with full IP and fixture geo, `/v0/collecting` of the lab feed refusing unsigned requests, and the NDJSON event export for the evaluator. Reports: `results/runs/smoke-<profile>/smoke.json` (steps, evidence, timings; skipped steps carry `skipped` with the reason), `eval/MVP-05.json`, `browser/` (screenshots, `browser-check.json`).

D72 took the network out of the gateway, so these gateway steps of the old loop are gone: IP-free signals accepted by every lab, every client verifying and applying the co-signed bundle, the network rule in the gateway dashboard and in new attack events, the emergency stop applied on every client, the egress check of the transparency log. The lab chain stays in the driver but is reported as skipped (lab later): the pattern in every lab dashboard, a proposal with evidence whose author cannot approve it, human approval (two organisations in t1), the bundle co-signed by two other operators over the feed protocol, relays carrying it, relay coverage and the RFC 6962 log root, an emergency stop co-signed and carried by the relays. It needs signals as input and runs again once the labs have a signal source.

The browser check uses the Playwright of `dashboard/node_modules` and its bundled Chromium (`SCHILD_PLAYWRIGHT` selects another package). It logs into every dashboard through the gateway, opens the main views (the gateway dashboard has no Signale page since D72), runs the in-browser log root check on every lab, and fails on any console error, page error or CSP violation. `SKIP_BROWSER=1` skips it.

## MVP-11 agent lab (server check and agents)

An overlay on profile t1, `compose/docker-compose.t1.agents.yaml`, on by default in `make testlab-up PROFILE=t1` and `make smoke PROFILE=t1` (`SCHILD_AGENTS=0` leaves it out):

- **Gateway** `schild-api` with `config/t1/api-agents/schild.yaml` (= `config/t1/api` plus `host_check`; `compose/agents_test.go` keeps them in sync): agent listener on `:8790` with a TLS key pair from `scripts/gen-agent-secrets.sh` (agents pin its sha256), `test-agent-a` enrolled and `test-agent-c` revoked by public key, the report dir mounted read-only.
- **gw-host-check** plays the gateway host's systemd timer and path unit: `schild check` every 5 minutes into the shared report dir (`network_mode: none`), and at once when schild-api wrote the "Jetzt prüfen" request into the shared `/run/schild-check` (`SCHILD_HOST_CHECK_TRIGGER`). `SCHILD_AGENT_URL=https://schild-api:8790` puts the agents' address into the enrolment command.
- **App VMs** on `sites` only (no route to labs or outside), image `schild-testlab-app-vm:dev` (`make testlab-app-vm-image`, `dockerfiles/app-vm.Dockerfile`): Debian 13, PHP 8.1 (EOL) as php-fpm on loopback, nginx, MariaDB on `0.0.0.0:3306`, sshd with password and root login, nftables without rules, no unattended-upgrades, real pending Debian updates plus the canary package `schild-canary-pkg-q7m3x9` (1.0 installed, 1.1 in a local file repo), a WordPress-like tree with secret canaries in `wp-config.php` and `.env`, a secret canary in every process environment. The apt caches are absent on purpose (Docker's `docker-clean` removed), so an apt call as root that rewrites `/var/cache/apt/*.bin` is visible. `schild` itself comes from the `schild:dev` image as an image volume (`/opt/schild`), so the test lab never builds it and never runs a stale copy.
  - `app-vm` (hostname = canary `app-vm-canary-k4p8z2`): enrolled with a one-time code by the smoke, then runs the agent daemon;
  - `app-revoked`: enrolled with a code, delivers once, revoked in the dashboard;
  - `app-unenrolled`: TEST ONLY key `agent-b`, never enrolled.
- **CLI**: every call of `schild-agent` / `schild check` goes through `dockerfiles/app-vm/rootfs/usr/local/sbin/schild-testlab-agent`. The app VMs use the separate binary `schild-agent` (mounted from the `schild:dev` image, which carries both binaries): `schild-agent enrol --dir --gateway --gateway-name --pin --code [--keyid]`, `schild-agent init --key --keyid` (app-unenrolled's explicit key), `schild-agent once|run --dir --app [--interval 5m]`; `gw-host-check` plays the gateway host and runs `schild check -dir`. `schild-testlab-agent enrolled|reset` lets the smoke re-enrol on a re-run.
- **Canaries** (`internal/hostcanary`): hostname and package name must reach the gateway (positive control) and never any lab; the three secrets must never appear anywhere.

`scripts/agent-smoke.sh` (`make testlab-agent-smoke`, or part of `make smoke PROFILE=t1`) runs the steps through `smoke agents <phase>` (`cmd/smoke/agents.go`) with the Docker side in between and writes `results/runs/smoke-t1/agents.json`:

| Step | How |
| --- | --- |
| enrolment | dashboard `createEnrolment` (403 without the password, then with it; pin and gateway name checked), `schild-agent enrol` in app-vm, key 0600 on the VM, `confirmAgent` with a wrong fingerprint (409) and the right one |
| first report visible | `listHosts`/`getHost`; stored report passes the contract, carries no secret canary; planted facts found (password SSH, root login, public MariaDB `tcp/3306`, PHP 8.1 EOL and in the inventory, canary package pending, no finding for loopback `tcp/9000`, firewall) |
| signed deliveries | the driver signs with the TEST ONLY keys: accepted once; same envelope again is `duplicate` or `replay` and not stored twice; `expired`, `clock_skew`, `channel`, impersonation (`signature`), unknown key (`signature`), revoked key (`revoked`), `forbidden_content`, `forbidden_field`, `oversize`, `malformed`; every answer must be a valid `schild.agent_ack/0.1` (`cmd/smoke/agents_test.go` checks the expectations offline against the contract verifier) |
| unenrolled agent | real binary with key agent-b: non-zero exit, `signature`; no host and no agent listed |
| revoked agent | enrol, deliver, `revokeAgent`, deliver again: `revoked`, shown as `last_rejected` |
| gateway unreachable | app-vm cut off `sites` and restarted: retries in its log, the daemon never exits; back on the network it delivers without help |
| traffic unaffected | 120 legit requests through the stripper before and during a flood of junk, oversize and unknown-key deliveries: same statuses, Grundschutz `active` before and after |
| canaries | positive control at the gateway; `egress.ScanTree` over every lab's data volume for all canaries (D72: the gateway sends them nothing), over the gateway's data and report dir for the secrets |
| silent agent | opt-in (`SCHILD_AGENTS_SILENT=1`, about 11 minutes): app-vm stopped, host shows "meldet sich nicht", Grundschutz unchanged |

**Re-runs on the same lab** work: when the app VMs already hold an enrolment, `smoke agents retire` revokes the earlier agents of those host names at the gateway, the VMs forget key and `agent.json` (`schild-testlab-agent reset`), app-vm is restarted and both enrol again with a fresh key id (`<hostname>/agent/r<timestamp>`); every step then looks at the newest agent of a name. The signed-deliveries step compares report ids instead of the history length, so the 30-report cap does not matter. It runs from its own fixed address (`agent-smoke-deliveries`, 10.66.17.100 on sites), so the flood of the previous run does not leave it in the listener's per-address request budget (120 per 15 minutes).

Steps are `pending` when the image does not support MVP-11 (dashboard `/hosts` 404, no listener, no `schild-agent` binary); in `make smoke` pending fails the run (`SCHILD_AGENTS_REQUIRE=1` is the default there; `=0` tolerates it). `egress-check -scan-dirs DIRS -canaries C1,C2` runs the same canary scan by hand.

**Read-only proof** (`make testlab-readonly-proof`, `scripts/readonly-proof.sh`): `schild check` in a disposable app VM container without network, as root and as `nobody`; before/after sha256 of `/etc`, `/var/lib/apt`, `/var/lib/dpkg`, `/var/cache/apt`, `/var/cache/debconf`, `/var/www`, `/root`, metadata of `/etc /usr /var /root /home /opt`, every path newer than a marker, and `docker diff`; only the report dirs may change; reports must pass `cmd/hostreport-check` (contract, no secret canary, `<started_at>-<report_id>.json`) and be 0640. Result `results/runs/readonly-proof/readonly-proof.json`; `pending` (exit 0) when `schild` has no `check` command. `make testlab-readonly-proof-selftest` proves the proof: a fake check that only writes its report passes, one that runs `apt list --upgradable` as root and touches `/etc` fails.

## Graceful degradation

`make testlab-up` needs the images `schild:dev`, `schild-lab:dev`,
`schild-relay:dev` and `schild-testlab:dev` (`make images`; `preflight.sh`
reports which are missing and the script stops). `make selftest`, `make eval`,
`make traffic` and all Go tests run without any of those images.

## Disk use

Base images are shared to save space: `golang:1.27.4-alpine` (pinned by digest) builds everything;
runtime images are `gcr.io/distroless/static-debian13:nonroot`. The two images
this directory builds (`schild-testlab`, `schild-traffic`) are small static Go
binaries (tens of MB each). The heavy third-party images (WordPress + MariaDB,
DVWA, Juice Shop, and the external attack suites) are gated behind the `full`
and `attack` compose profiles so the default stack stays light on a tight disk;
pull them only when you opt in.

## Notes and decisions

- Traffic lives at `testlab/traffic/` (not a top-level `traffic/` module) to
  match conventions §1/§3 (`schild-traffic-*` is built from `testlab/traffic/`)
  and the `go.work` module list, which this agent must not change.
- The egress checker maintains its own copy of the signal positive list on
  purpose: a second implementation, so a bug in a signal sender cannot hide
  behind the same bug in the checker. Since D72 no gateway sends signals; the
  checker and its self-test stay for the signal contract (lab later).
- TLS: labs listen with the test CA so a sniffer could read payloads; the
  T19 path was the cross-check of the gateway's transparency log (no keys,
  runs in CI). The egress-check sidecar (compose profile `check`) is gone with
  D72.
```
