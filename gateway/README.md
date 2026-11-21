# Schild Gateway (`schild`)

A reverse proxy with a web application firewall in front of your website: one static binary with an embedded **Caddy v2**, **Coraza**, the **OWASP CRS**, the public CrowdSec Hub rules, and a local dashboard. Everything it records stays on your server.

Status: **alpha** (`0.1.0-alpha.1`). There is no protection mode (D89): each rule repository, scenario and limit has its own switch; by default the OWASP CRS and your own rules block from the start, four of the five behaviour scenarios block after the 14-day learning period (D92), `aggressive_crawl` and rate limits start in observe mode, and CrowdSec Hub rules start in detect mode. For a careful start set `rules.crs.state: detect`, and know the [one-minute way out](#one-minute-way-out). Commands, flags, config defaults and the dashboard may still change; the contracts in [`../contracts`](../contracts/) change only with a new version. Report vulnerabilities as described in [SECURITY.md](../SECURITY.md), never in a public issue.

Two setups:

```
as your Caddy:       visitor ── schild :80 :443 (your Caddyfile, your certificates) ── application
behind a web server: visitor ── nginx, Apache or a load balancer (TLS) ── schild :8080 ── application

both:                dashboard 127.0.0.1:8788, metrics 127.0.0.1:9101 (/metrics, /healthz, /readyz)
```

## Quick start

Both setups start with the CRS blocking and the dashboard on `127.0.0.1:8788`. All ways (Docker, systemd, Compose) with every step are in [docs/gateway/00-installieren.md](../docs/gateway/00-installieren.md); the `README.txt` in the tarball has the systemd steps and how to verify the download.

### You run Caddy: schild as your Caddy (default, D79)

schild is a Caddy distribution: Caddy with the WAF module built in. It loads your Caddyfile, listens on the same ports and starts with a copy of Caddy's certificates. With the CRS set to detect it blocks nothing, but it is your web server from the swap on: while schild is down, your sites are down.

**Linux with systemd** (Caddy from the distribution package). Download `schild_<version>_linux_<arch>.tar.gz` (`amd64` or `arm64`) from the [releases](https://github.com/deutschland-schild/schild/releases), unpack it, then:

```sh
sudo install -m 0755 schild /usr/local/bin/schild
sudo install -m 0644 schild.service /etc/systemd/system/schild.service
sudo install -d /usr/share/schild/geo && sudo install -m 0644 geo/* /usr/share/schild/geo/   # optional: countries
sudo useradd --system --home-dir /var/lib/schild --create-home --shell /usr/sbin/nologin schild
sudo systemctl daemon-reload
sudo schild init -caddyfile /etc/caddy/Caddyfile       # writes /etc/schild/schild.yaml, lists the lines the Caddyfile needs
sudo nano /etc/caddy/Caddyfile                         # add them; do not reload Caddy afterwards
sudo mkdir -p /var/lib/schild/caddy                    # copy Caddy's certificates (init names the source it found)
sudo cp -a /var/lib/caddy/.local/share/caddy/. /var/lib/schild/caddy/
sudo chown -R schild:schild /var/lib/schild/caddy
sudo -u schild schild ingress validate                 # full check as the service user, Caddy still runs
sudo systemctl disable --now caddy && sudo systemctl enable --now schild
sudo schild dashboard setup-code                       # one-time code for the first login
```

The lines in the Caddyfile: once the snippet `(schild) { schild }` (on three lines), and `import schild` in every site that reaches a backend.

**Docker** (official `caddy` image; the container name `caddy` and the volume `caddy_data` for its `/data` are examples, `docker ps` and `docker volume ls` show yours), in the folder of your Caddyfile:

```sh
curl -fsSLo schild.yaml https://raw.githubusercontent.com/deutschland-schild/schild/v0.1.0-alpha.1/gateway/deploy/quickstart/caddy/schild.yaml
docker run --rm -v "$PWD/schild.yaml:/etc/schild/schild.yaml:ro" -v "$PWD/Caddyfile:/etc/caddy/Caddyfile:ro" \
  ghcr.io/deutschland-schild/schild:0.1.0-alpha.1 ingress validate -adapt-only    # lists the lines to add
docker run --rm -v caddy_data:/from:ro -v schild-data:/to caddy:2 sh -c \
  'mkdir -p /to/caddy && cp -a /from/caddy/. /to/caddy/ && chmod 700 /to/caddy && chown -R 65532:65532 /to'
docker run --rm --read-only --cap-drop ALL -v "$PWD/schild.yaml:/etc/schild/schild.yaml:ro" -v "$PWD/Caddyfile:/etc/caddy/Caddyfile:ro" \
  -v schild-data:/var/lib/schild \
  ghcr.io/deutschland-schild/schild:0.1.0-alpha.1 ingress validate                # full check in the container schild will run in
docker stop caddy
docker run -d --name schild --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --add-host host.docker.internal:host-gateway \
  -p 80:80 -p 443:443 -p 127.0.0.1:8788:8788 \
  -v "$PWD/schild.yaml:/etc/schild/schild.yaml:ro" -v "$PWD/Caddyfile:/etc/caddy/Caddyfile:ro" \
  -v schild-data:/var/lib/schild \
  ghcr.io/deutschland-schild/schild:0.1.0-alpha.1
docker exec schild schild dashboard setup-code
```

Add `--network NAME` when the Caddyfile names other containers. With Compose: [deploy/quickstart/caddy/compose.yaml](deploy/quickstart/caddy/compose.yaml) and [deploy/quickstart/caddy/schild.yaml](deploy/quickstart/caddy/schild.yaml); its one-shot service `certificates` does the copy, at `docker compose run --rm schild ingress validate` (the full check, right before the swap); `docker compose run --rm --no-deps schild ingress validate -adapt-only` reads the Caddyfile only and copies nothing.

**The way back.** Put a `#` in front of the line `schild` inside the `(schild)` snippet (stock Caddy does not know the directive; the `import schild` lines can stay), then `sudo systemctl disable --now schild && sudo systemctl enable --now caddy`, or `docker rm -f schild && docker start caddy`. Then check that Caddy is up (`systemctl is-active caddy`, `docker ps --filter name=caddy`): `docker start` reports no error when Caddy exits at once because the `#` is missing. Caddy's own storage was never changed.

How it works and why (D79):

- **Certificates: a copy.** `ingress.storage` is `/var/lib/schild/caddy`, inside schild's own data directory or volume. Caddy's storage is only read, once, by the copy. So the way back never depends on what schild did, the systemd sandbox needs no path outside `/var/lib/schild`, and no file of the user `caddy` changes its owner. The price: private keys exist twice on the host, and a certificate schild renews is not in Caddy's storage (Caddy renews its own after the way back).
- **Ports 80 and 443.** With systemd, schild runs as the user `schild` with `CAP_NET_BIND_SERVICE` as its only capability (`AmbientCapabilities` and `CapabilityBoundingSet` in [schild.service](../docs/ops/systemd/schild.service)). In a container it runs as uid 65532 with all capabilities dropped: Docker sets `net.ipv4.ip_unprivileged_port_start=0` in a container's own network namespace, so no capability is needed (not with `--network host`).
- **Files of the user `caddy`.** `schild ingress validate` (without `-adapt-only`) checks as the current user what would break after the swap, and refuses with the reason, what it would mean and the command that fixes it (`result: REFUSE`, exit 1, everything on stdout): a data directory this user cannot write (lock and databases: schild would not start); a certificate storage that exists but that this user cannot read (schild would not start or the sites would fail) or cannot write (schild starts, but could not renew), down to every file in it and through a symbolic link (`chown -R schild:schild /var/lib/schild/caddy`; in a container the numeric `chown -R 65532:65532 /var/lib/schild` for the whole volume); and a log file of the Caddyfile this user cannot write (`chown -R … DIR`, with `mkdir -p` when the directory is missing). It warns about unix sockets (`usermod -aG www-data schild`). Run as root it cannot tell and says so (`PASS with warnings`).
- **The sandbox of the unit.** `schild.service` lets schild write to `/var/lib/schild` and `/var/log/caddy` only (`ProtectSystem=strict`). For every log file the check asks systemd (`systemctl show schild.service`): outside the unit's `ReadWritePaths` it refuses and prints the drop-in (`sudo systemctl edit schild`, then `[Service]` and `ReadWritePaths=DIR`). `StateDirectory` and `LogsDirectory` count as writable. When systemd runs but the unit cannot be read (a user without access to the system bus), a log file outside those two directories is a warning with the same drop-in and the result is `PASS with warnings`; root can always read the unit, so `sudo schild ingress validate` settles it. Without systemd (a container) there is no such sandbox.
- **Read-only containers.** The full check needs a temporary directory for Caddy's provisioning. When `/tmp` is not writable (`--read-only`), it uses the data directory and removes it again, so the check runs in the same locked-down container as schild.
- **HTTP/3.** The Docker steps publish 443/tcp only: schild still announces HTTP/3 (`alt-svc`), but the UDP port is closed and browsers stay on HTTP/2. With systemd, HTTP/3 stays as the Caddyfile says; init prints a note (it ignores the `read_body` timeout, D41).

### You run nginx, Apache or a load balancer: schild behind it

schild listens on port 8080 and passes requests on to your application. Nothing changes for visitors until your web server passes requests to port 8080.

**Docker.** Copy [deploy/quickstart/compose.yaml](deploy/quickstart/compose.yaml) and [deploy/quickstart/schild.yaml](deploy/quickstart/schild.yaml) into one folder, set `upstream.url` in `schild.yaml` to your application, then:

```sh
docker compose up -d                                   # image ghcr.io/deutschland-schild/schild:0.1.0-alpha.1
docker compose exec schild schild dashboard setup-code # one-time code for the first login
```

**Linux with systemd.** Install the files and the user as above, then:

```sh
sudo schild init -upstream http://127.0.0.1:3000       # writes /etc/schild/schild.yaml
sudo systemctl enable --now schild
sudo schild dashboard setup-code                       # one-time code for the first login
```

### `schild init`

```
schild init -caddyfile FILE [-caddy-storage DIR] [-config FILE] [-node-name NAME] [-force]
schild init [-upstream URL] [-config FILE] [-node-name NAME] [-force]
```

Writes a starter `schild.yaml` and prints the next steps. `-config` defaults to `$SCHILD_CONFIG`, else `/etc/schild/schild.yaml`, the same file `schild run` reads. `-node-name` is the name in the dashboard and logs (default: the host name). An existing file is never overwritten without `-force`. The file holds no secret and is written with mode 0644, so the service user can read it; it is checked like `schild preflight` before it is written.

- **`-caddyfile FILE`**: schild runs as your Caddy (ingress mode, `ingress.caddyfile: FILE`, `ingress.storage: /var/lib/schild/caddy`). The Caddyfile must exist and adapt, otherwise nothing is written. init lists the sites, the lines the Caddyfile still needs (it never edits the Caddyfile), where it found Caddy's certificate storage (`-caddy-storage`, else a `storage file_system` option of the Caddyfile, else the usual places) with the copy commands, notes on log directories, unix sockets and HTTP/3, the swap commands and the way back.
- **`-upstream URL`**: schild behind a web server (proxy mode on port 8080), your application as the upstream (default `http://127.0.0.1:3000`).

The two do not mix: `-caddyfile` with `-upstream` is a usage error (exit 2), as is `-caddy-storage` without `-caddyfile`.

### First login

The dashboard listens on loopback only. On the server open `http://127.0.0.1:8788`; from your own machine use a tunnel and open the same address there:

```sh
ssh -N -L 8788:127.0.0.1:8788 you@your-server
```

The first visit asks for the one-time setup code and a password. The code is in the start log (`FIRST START`, field `setup_code`) and `schild dashboard setup-code` prints it again while no password is set. Lost the password: `schild dashboard reset-password`.

Over a tunnel or an IP address nothing else is needed. If you open the dashboard under a DNS name (your own reverse proxy with TLS, a VPN name), list that name, otherwise schild answers 403 and names this key:

```yaml
dashboard:
  allowed_hosts: ["schild.intern.example"]
```

### Allow yourself

Put your own address on the allowlist first, so a rule never locks you out of your own website:

```sh
schild allow --mine                 # the address of this SSH session, for 7 days
schild allow 203.0.113.7 -ttl never -label office
```

### One-minute way out

**schild as your Caddy:** put a `#` in front of the line `schild` in the `(schild)` snippet of the Caddyfile, stop schild and start Caddy again (see [the way back](#you-run-caddy-schild-as-your-caddy-default-d79)). **schild behind a web server:** stop schild (`docker compose down` or `systemctl disable --now schild`) and point your TLS proxy back at the application. Nothing else needs to change: schild stores nothing the application depends on. With a fail-open front proxy the first step is enough; details in [Fail-open, timeouts and the way out](#fail-open-timeouts-and-the-way-out).

### Changing the configuration

`schild.yaml` is read at start: **after a change, check it with `schild preflight` and restart schild.** Only the local rules in `rules.local.dir` load without a restart (`schild rules sync local` or `SIGHUP`). Settings changed in the dashboard act at once and are kept in the data directory; they win over the file. If a later change of `schild.yaml` no longer fits them, schild starts with the file alone and says so in the dashboard, in `schild status` and in `schild preflight`, until you save the settings again.

### Upgrades

Change the image tag or replace the binary and restart. `schild run` upgrades `schild.db` at start (D75):

- Before any change it writes a copy next to the database, `schild.db.backup-v<N>` (`N` = the old schema version). This needs about as much free space as the database. Without the copy there is no upgrade and schild does not start.
- The upgrade is one transaction: it either completes or leaves the database as it was.
- One backup generation is kept. Delete it once the new version runs well.
- Going back: stop schild, put the backup back as `schild.db` (remove `schild.db-wal` and `schild.db-shm`), start the old version. An older schild refuses a database of a newer one and changes nothing.
- Only `schild run` upgrades. The other commands (`schild allow`, `schild token`, ...) refuse an older database and ask for a restart.
- Databases of builds before `0.1.0-alpha.1` cannot be upgraded: move `schild.db` (with `-wal` and `-shm`) away and start again.

Read the release notes before an upgrade while schild is alpha.

## From source

From the repository root, with Go (version in `go.work`) and GNU make; Docker only for the image:

```sh
make gateway-test                                  # go vet (dev and release tags) and the tests
python3 -m http.server 8081 --bind 127.0.0.1 &    # any app on 127.0.0.1:8081
make gateway-run                                   # schild on 127.0.0.1:8080 in the test profile, dashboard on 127.0.0.1:8788
make gateway-image                                 # image schild:dev (dev build) with TEST ONLY geo data, no download
```

`make gateway-run` uses [deploy/dev.schild.yaml](deploy/dev.schild.yaml) (test profile: nothing is blocked). Run `make ui` first (needs Node.js and pnpm), otherwise the dashboard of `go run` and `make build` is a placeholder page. The image needs no `make ui`: [Dockerfile](Dockerfile) builds the dashboard itself. A plain `docker build -f gateway/Dockerfile .` is a release build with real geo data; `make gateway-image` asks for a dev build with the geo fixture.

Other setups: schild as the ingress with TLS ([deploy/schild.standalone.yaml](deploy/schild.standalone.yaml), see [As the ingress](#as-the-ingress)), or behind a fail-open front proxy ([nginx](deploy/nginx-front.conf), [Caddy](deploy/Caddyfile.front)). Run the container locked down as in the quickstart compose file.

## Reference

Everything below is the dense description of what the code does, for operators who want the details and for contributors. Ids like `MVP-19` name the spec in [`../tests/specs`](../tests/specs/), `D31` the decision in [`../contracts/DECISIONS.md`](../contracts/DECISIONS.md).

This module builds two binaries:

- **`schild`, the Schild Gateway** (`cmd/schild`): runs on the reverse proxy. Proxy with WAF, dashboard and the server check of its own host (`schild check`). One static Go binary (`CGO_ENABLED=0`), local events in SQLite (pure Go), the dashboard API and UI embedded.
- **`schild-agent`, the Schild Agent** (`cmd/schild-agent`): for internal app VMs behind the gateway. Only the server check and the agent that delivers signed reports to the gateway; no Caddy, no Coraza, no WAF, no dashboard, no listener. About 8 MB instead of about 63 MB (linux/arm64, stripped; linux/amd64 8.2 vs 66.8 MB). `cmd/schild-agent/main_test.go` fails when `go list -deps` shows Caddy, Coraza, the WAF, the dashboard, the gateway's agent listener or SQLite (`make gateway-agent-deps`). **Not part of the first gateway version (D60b):** `schild` refuses `host_check.agents` (enabled or keys) at start and in `schild preflight`; development builds accept it with `SCHILD_HOST_AGENTS=1` (TEST ONLY: test lab, tests), release builds ignore that variable (D77). The `schild` image carries `schild-agent` only with `--build-arg AGENT=1` (`make gateway-image AGENT=1`); `make gateway-agent` builds `bin/schild-agent` alone. The server check of the gateway host (`schild check`) stays.

The first gateway version has no labs features (D72): no labs, relays, signals or network rules; it decides alone with the CRS, the CrowdSec Hub rules, local rules and behaviour.

## Commands

| Command | What it does |
| --- | --- |
| `schild init -caddyfile FILE [-caddy-storage DIR] [-config FILE] [-node-name NAME] [-force]` | writes a starter `schild.yaml` for schild as your Caddy and prints the steps of the swap, see [`schild init`](#schild-init) (D79) |
| `schild init [-upstream URL] [-config FILE] [-node-name NAME] [-force]` | writes a starter `schild.yaml` for schild behind a web server, see [`schild init`](#schild-init) (D78) |
| `schild run [-config FILE] [-data DIR] [-check]` | upgrades `schild.db` when it comes from an older release (D75, see [Upgrades](#upgrades)); proxy, dashboard, metrics, background loops; runs the D24 preflight first (`-check`: preflight only); holds `<data>/gateway.lock` (one gateway per data directory) and serves the local control path `<data>/control/schild.sock` |
| `schild preflight [-config FILE]` | D24 preflight without starting: refuses any key from `contracts/testkeys`, key ids starting with `test` (`host_check.agents.keys`) and the test lab CA among the trusted CAs (`SCHILD_TEST_CA`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, system bundle); notes data dir, geo database and listen addresses; in ingress mode also adapts and checks the Caddyfile; checks the D38 disk budget of `storage.path`; exit 1 when schild would refuse to start |
| `schild ingress validate [-config FILE] [-adapt-only]` | MVP-19: checks `schild.yaml` and the Caddyfile of `ingress.caddyfile` without starting: stock Caddyfile adapter, `schild` directive on every site that reaches a backend, with the lines to add on a missing `schild` (D79). Then, as the current user: the data directory writable (or creatable), `ingress.storage` readable and writable when it exists (a symbolic link is followed) and the number of certificates in it, Caddy provisioning with a throwaway storage (in the temp directory, else in the data directory; Caddy's own log shows errors only), write access to the log files of the Caddyfile and, under systemd, the `ReadWritePaths` of `schild.service`. It ends with one result line: `result: PASS`, `result: PASS with warnings (N, …)` or `result: REFUSE (…)` and exit 1; the report is on stdout only. `-adapt-only` stops after the Caddyfile (`result: PASS (Caddyfile)`) and looks at nothing else: no data directory, no storage, no certificate count, no provisioning, no file access (for machines without the server's files) |
| `schild allow IP\|CIDR\|HOST [-ttl 24h\|7d\|30d\|never] [-label ..] [-level no_block\|bypass_waf]` | add a local allowlist entry (a running schild picks it up within 2 s) |
| `schild allow --mine [-ttl ..] [-label ..]` | allow the client address of the current SSH session (`SSH_CONNECTION`/`SSH_CLIENT`; in a container pass it with `docker exec -e SSH_CONNECTION=...`) |
| `schild allow list` / `schild allow rm ID` | show / remove stored entries |
| `schild token add --scope SCOPE --expires 1d..365d [--label ..] \| list \| revoke ID \| log [ID] [-n 50]` | host only: bearer tokens of the agent API, shown once and stored as SHA-256 (see [Agent API](#agent-api-internalagentapi)) |
| `schild status` | profile, a warning for an old `mode` line, backend, allowlist, health of the listeners; a `WARNING:` line when dashboard settings no longer fit `schild.yaml` and were left out (D78) |
| `schild rules sync local\|crowdsec [-config FILE] [-data DIR]` | D46, D73, host only, through the control path: `local` loads `rules.local.dir` again without a restart (the new set compiles in full next to the running one; a file that does not build or a rule id in the range of another repository leaves the running rules in place and the command fails with the reason; `SIGHUP` does the same, with the result in the log); `crowdsec` checks the CrowdSec Hub now |
| `schild rules reset crowdsec [-config FILE] [-data DIR]` | D43, D73, host only: back to the crowdsec rules of the image: drops the stored set, through the running gateway's control path, or directly in the store while schild is stopped. The dashboard and the agent API offer the same. The state of the repository stays. |
| `schild dashboard setup-code [-config FILE] [-data DIR]` | host only, through the control path of the running gateway: prints the one-time setup code again while no password is set (D78); exit 1 when a password exists or schild is not running |
| `schild dashboard reset-password [-config FILE] [-data DIR]` | MVP-09 addendum (D38), host only, no API: removes every dashboard user and session and requires the first-run setup again with a new one-time setup code, printed once to stdout (schild keeps only its SHA-256, also across a restart). While schild runs it goes through the gateway's local control path `<data>/control/schild.sock` (dir 0700, socket 0600; old sessions end at once); while schild is stopped it writes the store directly. If schild holds `<data>/gateway.lock` but the control path does not answer, it refuses and changes nothing. Writes the event `schild.dashboard.access_reset.v1` (`via` host_cli or control_path, counts, host account from `SUDO_USER`/`USER`); events, settings and blocks stay. Exit 0 done, 1 error or refused, 2 usage |
| `schild firewall run [-api URL] [-token-file FILE] \| status \| off` | D87, the first step of MVP-15, with `CAP_NET_ADMIN` in the gateway's network (a second container of the same image with `network: host` or `network_mode: service:schild`, or `docs/ops/systemd/schild-firewall.service`): keeps the nftables table `inet schild` (over netlink, no `nft` binary) holding the address blocks that run, each with its remaining time as the kernel timeout; drops TCP and UDP to 80 and 443 from them on prerouting (priority -150). Gets the blocks from `syncAgentFirewall`, a long poll on the agent API with a token of scope `firewall:sync` (`$SCHILD_FIREWALL_TOKEN`); a block or lift arrives within a second. Builds the table at start, removes it on SIGTERM; `status` lists the elements, `off` removes the table |
| `schild cluster init \| invite \| join ADDRESS CODE \| status \| remove NODE` | D103, the first version of MVP-27, experimental: a group of gateways that shares its address blocks from node to node over a mesh of TLS 1.3 connections between the node keys (`cluster.listen`, a private address), with no store beside them. `init` on the first node, `invite` there prints a join code (one use, one hour), `join` on every other node, then restart schild. Key and records lie in `<storage.path>/cluster`. A block or a release on one node acts on every node within about a second; a node decides again with its own allowlist. Contract: [contracts/cluster.md](../contracts/cluster.md) |
| `schild version` | version, the embedded Caddy version (`caddy v2.x.y (embedded)`) and the versions of Coraza, CRS, SQLite, maxminddb |
| `schild front -listen ADDR -schild URL -app URL [-timeout 30s] [-access-dir /var/lib/schild] [-no-access-lock]` | reference front proxy: fail-open only on connection refused, 503 on timeout; no fail-open while an access lock is in force (D56) or while the front cannot read schild's lock file below `-access-dir` (D71); `-no-access-lock` only for gateways that never lock |
| `schild lock on WEBSITE [...] \| off WEBSITE \| status` | access lock (D56, MVP-14 step 1): the whole website (maintenance page, 503 for everyone else) or only some paths; conditions: shared password, addresses, own networks, every one given must hold (D58: password and address), on until `lock off`; through the control path of the running gateway |
| `schild health [-url ...]` | container health check (distroless has no curl) |
| `schild geo-fixture -out FILE` | TEST ONLY geo database of the documentation ranges |
| `schild logcheck [-format ...] [-json] [-show-ips] [SITE=]FILE ...` | before installing: which requests in the access logs the hard limits would reject, per site, with suggested limits |
| `schild check [-dir DIR] [-keep N] [-json] [-app PATH]... [-cert GLOB]... [-caddyfile FILE] [-fail-on SEVERITY] [-privileges]` | MVP-11: read-only server check of this host, writes a host report (see [Server check and agents](#server-check-and-agents)) |
| `schild check install [-mode auto\|container\|service] [-gid N] [-app PATH]... [-cert GLOB]... [-caddyfile FILE] [-no-start] [-dry-run] \| uninstall` | D100, as root on the host: sets up the daily check and "Jetzt prüfen" as systemd units from the binary and runs the first check; `uninstall` removes the units, reports and binary stay |

Environment: `SCHILD_CONFIG` (default `/etc/schild/schild.yaml`), `SCHILD_DATA_DIR` (default `storage.path`), `SCHILD_LOG_LEVEL`, `SCHILD_LOG_FORMAT` (`json`/`text`), `SCHILD_CADDY_LOG_LEVEL`, `SCHILD_GEO_TOKEN`. Test lab only, ignored by release builds (D77): `SCHILD_ALLOW_TEST_KEYS` (`1` = start despite test keys or the test CA, with a warning), `SCHILD_HOST_AGENTS`, `SCHILD_EVENTS_NDJSON_DIR` (mirrors every local event to `events.ndjson` in that directory for the evaluator; full IPs, outside retention, capped at 256 MiB), `SCHILD_CROWDSEC_HUB_URL`, `SCHILD_WAF_MAX_EVALS` and `SCHILD_WAF_QUEUE_WAIT_MS` (override `waf.max_concurrent_evals`, default `GOMAXPROCS` and at least 2, and `waf.queue_wait_ms`, default 100).

Make targets (from the repository root): `make gateway-test`, `make gateway-race`, `make gateway-bench`, `make gateway-coraza`, `make gateway-run`, `make gateway-image [GATEWAY_GEO=fixture|dbip] [TAGS=release]` (default `fixture`: no download), `make images`, `make build`. `make eval SPEC=MVP-02` dispatches to the test lab's evaluator (builders do not write their own measurement).

## As the ingress

MVP-19, D31. One switch in `schild.yaml` (contracts v0.4, [contracts/config/examples/schild.standalone.yaml](../contracts/config/examples/schild.standalone.yaml), deploy example [deploy/schild.standalone.yaml](deploy/schild.standalone.yaml)):

- **`ingress.caddyfile`**: `schild run` adapts the operator's Caddyfile with Caddy's stock adapter and loads it into the embedded Caddy instead of the single proxy route (`listen.proxy` and `upstream` are absent). The standard modules of the stock `caddy` binary are compiled in (`modules/standard`): TLS and ACME issuers, `log`, `encode`, `file_server`, `header`, `rewrite`, `handle_errors`, `reverse_proxy`, `php_fastcgi` behave as in stock Caddy of the pinned version. The admin API stays disabled (changes need a restart); the storage root is `ingress.storage` (else the Caddyfile's `storage`, else `<data>/caddy`), so an existing Caddy data directory with certificates is reused. Automatic HTTPS and the storage checks are left as the Caddyfile says.
- **Caddyfile directive `schild`** (`http.handlers.schild`, no arguments, optional matcher): ordered before `redir`, so it runs before `rewrite`, `try_files`, `basic_auth`, `handle`, `route`, `respond`, `reverse_proxy`, `php_fastcgi` and `file_server` and sees the request as sent. The pattern is a snippet `(schild) { schild }` and `import schild` per site; the stock-Caddy rollback file defines the snippet empty. `schild run`, `schild preflight` and `schild ingress validate` refuse a Caddyfile in which a site reaches `reverse_proxy` or `php_fastcgi` (also in `handle_errors` and named routes) without an unconditional `schild` in front, unless all its hosts are in `ingress.unprotected_sites`; `file_server` without `schild` is a warning. The check reads the adapted JSON, not the text, and refuses when it is unsure (after the MVP-19 measurement): route lists nested anywhere in a handler (`handle_response` of `intercept` and `reverse_proxy`) are checked too; mutually exclusive `handle` blocks count as conditional, so `schild` must be in every branch or before all of them; `handle_errors` belongs to the server (listener), not to the site block it is written in, and Caddy hands it errors of every site on that server (a `file_server` 404 of a static site, a `basic_auth` 401, `error`), so a `handle_errors` that reaches a backend is accepted only when `schild` runs inside it (after the MVP-19 re-measurement; a request that the site's `schild` already passed is not evaluated a second time there); `invoke` of a named route that starts with an unconditional `schild` guards what follows; `schild /*` is not unconditional (the request target `*` of `OPTIONS *` does not match `/*`) and stays refused; unknown handlers without `schild` are refused. Errors of later handlers go back to Caddy, so `handle_errors` works as in stock Caddy.
- **One gate per process**: `caddymod.Bind` binds the gate once; every handler of every config load uses it, and a different gate cannot be bound meanwhile, so a second load keeps one learning state, one event store and the counters. A panic below the handler answers that request with 503 and `Retry-After` and never stops the server; WAF timeouts stay 503. There is no fail-open in this setup (schild is the ingress); the way back is the stock Caddy image.

Operating it (German): [docs/gateway/02-betrieb.md](../docs/gateway/02-betrieb.md).

## Request path (internal/gate)

1. Client attribution (G5): TCP peer, or `X-Forwarded-For`/`Forwarded`/... only when the peer is in `ingress.trusted_proxies` (rightmost untrusted address wins). Without `client_ip_headers` a trusted peer's `X-Forwarded-For` is used. Too broad trusted ranges (< /8 IPv4, < /32 IPv6): forwarding headers are ignored, every client counts as its TCP peer, and the dashboard shows `trusted_proxies_too_broad` (D40).
2. Allowlist (own IPs, ranges, DynDNS names, expiry; config + dashboard + CLI). `bypass_waf` skips everything, `no_block` inspects and logs but never blocks.
3. Hard limits, rejected **always**, whatever the switches say (a request that cannot be inspected never reaches the backend): declared or streamed body above `waf.request_body_limit_bytes` → 413, and above a Caddy `request_body max_size` in front of `schild` → 413 as in stock Caddy (`body_too_large`, schild's block page, MVP-19 fix round 3); compressed request bodies (`Content-Encoding` other than identity) → 415; more than 1000 arguments in the query, form, JSON or multipart parts → 400; JSON deeper than 64 or syntactically broken → 400 (Coraza's JSON processor accepts broken JSON silently, so Schild checks it); body parse errors (`REQBODY_ERROR`, `MULTIPART_STRICT_ERROR`) → 400.
4. Coraza in `DetectionOnly` with the rules of the three repositories (D73): CRS (paranoia level and anomaly threshold from `rules.crs`), then local rules, then the crowdsec rules. Phase 1 and phase 2 run in goroutines with a shared budget of `waf.eval_timeout_ms`; when it is exceeded the answer is **503 with an incident number, never a pass**. A panic in the WAF also fails closed (503). The body is read outside that budget (bounded by the size limit and the server read timeout); an over-limit body is rejected while it streams in, before phase 2. **Bounded work** (ingress and proxy mode, after the MVP-19 measurement and re-measurement): each phase runs on one of `waf.max_concurrent_evals` evaluation slots (default GOMAXPROCS, at least 2; the test lab's `SCHILD_WAF_MAX_EVALS` wins). Each phase is classified by its estimated cost: more than 64 arguments (query, body and cookies), a request target (path and query) plus Host over 4 KiB or more than 32 KiB of body the rules read as text (urlencoded, JSON, XML, text; multipart file content does not count) is expensive. Expensive phases use at most half of the slots (`config.ExpensiveEvalSlots`: 1 of 2, 1 of 3, half from 4 on; also with `SCHILD_WAF_MAX_EVALS`, which counts as at least 2), so cheap ordinary requests always keep the other slots; one client (IPv4 address or IPv6 /64) holds at most 2 expensive evaluations at once (cgnat and mobile addresses 4 times as many); all expensive evaluations together stay within a memory budget (estimated about 96 KiB per argument, half of the Go memory limit). Without a free slot within `waf.queue_wait_ms` (default 100; `SCHILD_WAF_QUEUE_WAIT_MS` wins) the answer is 503 + `Retry-After` (hard limit `waf_busy`). **Waiting page (D37, MVP-23 step 1, `waiting_page.enabled`, default on):** a `waf_busy` or `waf_timeout` 503 for a document navigation (Fetch Metadata, else `Accept` preferring HTML over JSON; GET, HEAD, POST) is the calm waiting page (`internal/waitpage`, illustration A, German or English by `Accept-Language`, the website name, meta refresh and CSS countdown equal to `Retry-After` 5 to 8 s, none for POST) without an incident number; every other request with these reasons gets problem details (code `waiting`) with the same jittered `Retry-After`. Both carry the marker `Schild-Waiting: 1`; the gateway strips that header from backend responses (and the fail-open front from bypass answers), so an app cannot fake it. The page is pre-rendered at start; serving it runs no WAF, writes no incident and samples its event like an unremarkable request. Rules: `contracts/waiting-page.md`. An evaluation over its budget is cancelled: Coraza stops at the next rule or argument (checked through a per-transaction debug logger, `internal/waf/cancel.go`) and the slot and memory share are freed only once it has stopped, so abandoned evaluations never pile up beyond the limits. The transaction is closed before forwarding (the body is kept for the backend: up to 128 KiB in memory, the rest in a temporary file below the data directory), so Coraza's cache of transformed values does not stay alive while the backend answers. Text bodies get 4 ms per KiB on top of `eval_timeout_ms`, at most 10 s. Responses are not inspected: phases 3 and 4 do not run, so the CRS response rules (95x) never match. **Memory limit:** `schild run` sets the Go memory limit from the cgroup limit (v2, else v1) or the machine's memory: 80 % of it, but always at least 256 MiB below it (min(0.8 x total, total - 256 MiB); below 512 MiB half of it, `memlimit.Of`, MVP-19 fix round 3); `GOMEMLIMIT` wins; limit, source, total, rule and headroom are logged at start (`go memory limit`). **Request-shape limits** before any rule (400, always): query over 32 KiB (`query_too_long`), request target (path and query) over 40 KiB (414 `uri_too_long`), more than 100 header values (`too_many_headers`) or 64 KiB of headers with Host (`headers_too_large`), more than 150 cookies (`too_many_cookies`), besides 1000 arguments and JSON depth 64.
5. Decision (`contract/rules` per repository and rule, merged by `internal/decide`, exhaustively unit tested): CRS score is recomputed from CRS detection rules only (no other rule can push CRS over its threshold). A repository in `detect` logs its matches and never blocks, `off` is not built.
   - A repository in `block` blocks: rules of the image (CRS, the crowdsec snapshot) and local rules at once, crowdsec rules received from the hub after `settling_s` (status `settling` until then, they only detect). There is no protection mode and no approval (D89).
   - Profile `test`: nothing is blocked by rules (`would_block`, reason `gateway_observe`), and neither scenarios, limits nor blocks by hand or by agents block.
   - An old `mode` line in `schild.yaml` is ignored with a warning at the start; `mode: observe` sets the repositories that `rules` leaves open to `detect`.
6. Block answer: calm German HTML page with incident number (`XXXX-XXXX`), or RFC 9457 problem details for API clients (`Accept: application/json`). Header `X-Schild-Incident`.
7. Bookkeeping, never blocking the request: local event (full IP and geo, E7; secrets redacted; bodies never stored), incident, counters (non-blocking channel sends).

Every rule change builds a new Coraza instance in the background (CRS ~60 ms) and swaps an atomic pointer; requests in flight keep their instance. `TestAtomicSwapUnderLoad` swaps continuously while 16 clients send requests: 0 failures.

## Fail-open, timeouts and the way out

The rule is **fail-open only when schild refuses the connection** (process down), **503 on timeout, never pass**. Inside schild there is nothing to fail open: the WAF runs in-process; its own timeout is answered with 503. The front proxy implements the rest:

- nginx: [deploy/nginx-front.conf](deploy/nginx-front.conf) (`error_page 502 = @schild_down` to the application, `error_page 504 = @schild_timeout` → 503, `proxy_next_upstream off`).
- Caddy: [deploy/Caddyfile.front](deploy/Caddyfile.front) (`handle_errors 502` → application, `handle_errors 504` → 503).
- `schild front`: reference implementation with strict classification (`ECONNREFUSED` only); tested in `internal/failopen` (refused → application with the body intact, timeout → 503 and the application never sees the request).
- **Access lock (D56):** while a website or some of its paths are locked (`schild lock`, dashboard "Passwortschutz"), schild keeps `<storage>/access/active` and writes `<storage>/access/active.json`. Then there is no fail-open: `schild front -access-dir <storage>` answers 503, and both snippets above check the marker in their fail-open branch. A lock state the front cannot read counts as a lock (D71): schild writes `active.json` at every start, so while the front does not see it (storage not mounted, wrong path, file broken) it answers 503 too. Adjust `/var/lib/schild` to your storage path and give the front proxy read access (in Compose: schild's volume read-only in the front service). In ingress mode nothing is needed: schild is the web server.

**One-minute way out** (take schild out of the path):

1. Stop schild (`docker stop schild` or `systemctl stop schild`). The front proxy gets "connection refused" and serves the application directly (fail-open). Done.
2. Permanently: point the front proxy's `proxy_pass`/`reverse_proxy` at the application (`127.0.0.1:8081`) and reload (`nginx -s reload` / `caddy reload`).
3. Without a front proxy (schild on :80/:443 itself): change the application's or the load balancer's port mapping back.

Nothing else needs to change: schild stores nothing the application depends on. Tested: `TestFailOpenOnlyOnRefused`.

## Dashboard (internal/dashboard, internal/webui)

- API exactly as `contracts/api/client-dashboard.openapi.yaml` under `/api/v0`, UI from `internal/webui/dist` (`make ui` for local builds, the Node stage of the Dockerfile for the image) with an embedded placeholder when it is not built. SPA fallback for unknown non-API paths; the UI uses `#/` routes.
- Process model (documented fallback): the dashboard runs **in the same process** on its own listener, bound to `127.0.0.1:8788` by default. A separate least-privilege process would need its own IPC for live state (rules, SSE) and is left for a later version.
- No password again: every change needs session and CSRF only (D74).
- Auth: first password needs the one-time setup code printed to the log at start (after `schild dashboard reset-password`: the code that command printed, never logged), from everywhere, also through an SSH tunnel (D40); argon2id (m=19 MiB, t=2, p=1); session cookie `schild_session` HttpOnly, SameSite=Strict, Secure over HTTPS (also behind a proxy that sets `X-Forwarded-Proto: https`), not Secure on loopback or when the browser itself loaded the page over plain HTTP (D76); requests under a host name that is neither `localhost`, an IP address, the listen host nor in `dashboard.allowed_hosts` get 403 (DNS rebinding, D76); `X-CSRF-Token` on every change plus an Origin check; 5 failed logins per address and 15 minutes.
- Headers: strict CSP (`default-src 'self'`, `script-src 'self'`, `style-src 'self'`; the built `index.html` has no inline script, the hashes of any inline script would be added automatically), `nosniff`, `no-referrer`, `frame-ancestors 'none'`, COOP/CORP.
- Overview (contracts v0.1): `series_24h` with 24 hourly buckets (requests, blocked, would_block) for the sparklines, from the same in-memory counters as `counters_24h`.
- Settings changed in the dashboard are written to an overlay in the data directory (`schild.yaml` is usually read-only) and validated together with the file by the contract config validator; `schild.yaml` stays the base.
- Incident export (`POST /incidents/{incident}/export`, D51): incident, events and context as a download; every download writes `schild.incident.exported.v1`.
- Privacy: search, export (all stored events) and delete by IP (events, sessions, incidents unless `keep_incidents`, exceptions and allowlist entries). Retention: raw IPs truncated after `raw_ip_days` (IPv4 /24, IPv6 /48, also inside the stored event JSON and incidents), events deleted after `events_days`, size cap `max_size_mb` (oldest events first), the pinned context of an incident in the ring after `min(events_days, raw_ip_days)` days (D51), hourly summaries without IPs kept `summaries_days`.

## Server check and agents

Spec MVP-11. Contract: [contracts/host-check.md](../contracts/host-check.md) (v0.3, D25), spec [MVP-11](../tests/specs/MVP-11-server-check-agent.yaml). Code: `internal/hostcheck` (checks, EOL table, report files), `internal/hostagent` (the agent of `schild-agent`), `internal/hostcli` (command line of `schild check` and `schild-agent`, shared; links no proxy code), `internal/hosts` (gateway: report directory, agent listener, storage, dashboard operations), `internal/dashboard/hosts.go` (API). Deployment: [docs/ops/systemd/](../docs/ops/systemd/) (check service, timer, path unit for "Jetzt prüfen", agent unit, tmpfiles) and [docs/ops/host-check-compose.yaml](../docs/ops/host-check-compose.yaml); the systemd units with their install notes are in [docs/ops/systemd](../docs/ops/systemd/).

**Read only.** Every check is a function over an `Env` (files plus a fixed list of read-only commands with fixed argv; `OSEnv` refuses anything else and runs commands with `PATH` and `LC_ALL=C` only, 60 s timeout). Never `apt update`, `dnf`, `yum`, `needs-restarting`, installs, writes outside the report directory, scans of other hosts or any network access from the check. Package data comes from the existing cache (`apt list --upgradable`, `apt-get -s`; on RHEL-like hosts a fixed hawkey script reads dnf's metadata cache and the rpm database with every cache/log write switched off, see `internal/hostcheck/dnfscript.go`); a stale cache can under-report, the finding text says so. Run as root, the package database queries and runtime version probes run as `nobody` (65534), so the kernel refuses any write they try; without `CAP_SETUID`/`CAP_SETGID` they report `unreadable` (`needs: CAP_SETUID`) instead of running as root. Java's version comes from `<java home>/release` (no JVM start). What cannot be read safely becomes `status: unreadable` with `reason` and `needs`, never a failed run. Evidence is typed facts only; before a report is written or sent it passes the contract check (`verify.Document(host-report)`: forbidden fields and content, schema), a report that fails is a bug and is not written (exit 4). The fixtures contain `wp-config.php`, a Laravel `.env` and a key file next to a certificate as canaries (`TestNoSecretsInReports`).

**Checks and ids:** `distribution.eol`, `distribution.kernel_outdated`, `updates.security_pending`, `updates.pending`, `updates.automatic`, `updates.reboot_required`, `ports.public_service` (subject `tcp/<port>`), `ports.docker_api`, `ports.admin_panel`, `firewall.active`, `firewall.default_incoming`, `firewall.docker_bypass`, `ssh.password_authentication`, `ssh.permit_root_login`, `ssh.port`, `ssh.failed_logins` (count only, 24 h), `tls.certificate_expiry` (gateway only, subject = site, from certificate files; no TLS handshake), `software.runtime_eol`, `software.server_eol`, `software.database_eol` (subject `<name>-<cycle>`), `software.app_outdated` (subject `path:<dir>`), since v0.5 (D38, addendum Log-Hygiene) `logs.docker_unbounded`, `logs.journald_size`, `logs.logrotate_missing`, `logs.logrotate_stale`, `logs.logrotate_config` (subject = config file or log path; cross-checks the `output file` blocks of schild's Caddyfile: `roll_disabled` needs a rule with `copytruncate`, a rule on a file Caddy rolls itself is double rotation), `logs.large_file` (subject = path; growth per day against the newest kept report, in `schild-agent run` the previous report of the process). Logs fixes that are config files come as `fix_config {path, content}`, rendered only from `hc.FixTemplates` and checked with `hc.FixConfigKnown` before the report is written. Inventory: relevant packages from `dpkg-query`/`rpm -qa` (runtimes, servers, databases, openssl, openssh, kernels, ...; not the whole package list), runtimes from `--version` when not packaged, and apps only under `--app` paths (WordPress core from `wp-includes/version.php` and plugins from their header `Version:`, TYPO3 `ext_emconf.php`, Laravel `composer.lock`, Nextcloud `version.php`; only the version line is parsed).

**EOL table:** `internal/hostcheck/eol.json`, embedded, dated (`run.eol_table`) with its sources; no lookup at runtime. Compiled from the vendors' lifecycle pages for the table date; entries marked `approx` were announced, not final. Re-check it before relying on a date and bump `date` with every change. Runtime EOL from distribution packages counts `low` while the distribution itself is supported (backports), `high` otherwise.

**Rights per check** (`schild check -privileges` prints the same):

| Check | Reads | Without extra rights | Needs for the rest |
| --- | --- | --- | --- |
| distribution | `/etc/os-release`, `uname -r/-m`, `/boot/vmlinuz-*` | everything | root where `/boot` is 0700 |
| updates (apt) | `apt -o Dir::Cache::pkgcache= -o Dir::Cache::srcpkgcache= list --upgradable`, `apt-get -s -o Debug::NoLocking=1 (same cache options) dist-upgrade`, `/etc/apt/apt.conf.d`, `/var/run/reboot-required` (the empty cache options keep apt's binary cache in memory, so a run as root never rewrites `/var/cache/apt/*.bin`) | everything | – |
| updates (dnf) | dnf metadata cache + rpm database via the hawkey script (as nobody), rpm install times vs. `/proc/stat` btime (reboot rule of needs-restarting), timer links | everything | as root: `CAP_SETUID`/`CAP_SETGID` for the drop to nobody; yum hosts: pending updates not readable |
| ports | `ss -tlnp`, else `/proc/net/tcp{,6}` | addresses and ports | `CAP_SYS_PTRACE` or root for process names |
| firewall | `nft list ruleset`, else `iptables-save` and `ip6tables-save`; `/proc/net/if_inet6`; `/etc/ufw/ufw.conf`, `/etc/default/ufw`, firewalld unit link | ufw/firewalld on/off and default policy | `CAP_NET_ADMIN` for the ruleset (Docker chains) |
| ssh settings | `sshd -T`, else `sshd_config` + `Include`d files (first value wins, stops at `Match`) | world-readable `sshd_config` (Debian, Ubuntu) | root for `sshd -T` and on RHEL-like systems |
| ssh.failed_logins | `journalctl _COMM=sshd --since=-24h`, else `/var/log/auth.log` / `/var/log/secure` | – | group `systemd-journal` (or `adm`); root for `/var/log/secure` |
| tls (gateway) | certificate files of `-cert` globs (default Let's Encrypt `live/*/cert.pem`, Caddy stores); key files are never opened | readable stores | root for `/etc/letsencrypt/live` |
| logs | `/etc/docker/daemon.json`, `/var/lib/docker/containers/*/hostconfig.json` (`LogConfig` only; never `config.v2.json`, which holds the environment) and the size of `*-json.log` by stat; `journald.conf` and drop-ins, size of `/var/log/journal`; logrotate binary, timer link or `/etc/cron.daily/logrotate`, mtime of the status file, `/etc/logrotate.conf` and `logrotate.d/*`; schild's Caddyfile (`-caddyfile`, default `ingress.caddyfile`); a stat walk of `/var/log` (depth 4, 5000 entries, 200 ms) and the usual log files under `-app` paths. Never runs `logrotate` or `docker`, never the Docker socket, never reads a log file | everything but Docker containers | root for `/var/lib/docker/containers` and root-only log directories |
| software | `dpkg-query -W` / `rpm -qa` (as nobody), `<java home>/release`, `node/php/python3 --version` (as nobody; `java -XX:-UsePerfData -version` only without a release file), version files under `-app` paths | world-readable files | read access to the app directories |

**`schild check install`** (D100, `internal/hostsetup`) sets the check up on a host with systemd: `docker cp <container>:/usr/local/bin/schild /tmp/schild && sudo /tmp/schild check install` for a gateway in a container, `sudo schild check install` next to a `schild.service`. It writes `schild-check.service`, `.timer`, `.path` and the tmpfiles entry from the copies embedded in the binary (`internal/hostsetup/units`, kept equal to [docs/ops/systemd](../docs/ops/systemd/) by a test), runs `systemd-tmpfiles --create`, `systemctl daemon-reload`, `enable --now` of timer and path unit and one `systemctl start schild-check.service`, then prints what is left (`host_check: {}` in `schild.yaml`; for a container the two mounts and `SCHILD_HOST_CHECK_TRIGGER`). Mode `container` (default without an installed `schild.service`): the reports get group 65532, and a binary outside `/usr/bin` and `/usr/local/bin` is copied to `/usr/local/bin/schild`. Mode `service`: the reports get the group `schild`, and the drop-in `schild.service.d/50-host-check.conf` gives the service the request directory and `SCHILD_HOST_CHECK_TRIGGER`; schild is never restarted by the command. `-app` and `-cert` go into `ExecStart` (absolute paths without spaces, quotes, `%` or `$`). `-dry-run` prints files and commands. It is the only part of the server check that writes outside the report directory, and `internal/hostcheck` never imports it.

**`schild check`** runs on the host (not in the container; `schild check install` puts the binary there). Config: `-config`/`$SCHILD_CONFIG`/`/etc/schild/schild.yaml` when it exists, for `host_check.report_dir` (default `/var/lib/schild/host-check`) and `keep_reports` (default 30); flags win. Writes `<started_at>-<report_id>.json` atomically (temp file, fsync, rename, mode 0640, directory 0750) and keeps the newest N. `-json` prints instead of writing. `-trigger-file` (default `$SCHILD_HOST_CHECK_TRIGGER`) is removed first of all, before the config is read, so a run that fails never leaves the request behind for `schild-check.path`. Exit codes: **0** report written or printed (findings do not change it), **1** error (config, write), **2** usage, **3** `-fail-on SEVERITY` hit, **4** the report failed the contract (bug in a check; nothing written).

**`schild-agent`** (app VMs; not part of the first version): `check` is `schild check` with the same flags, report and exit codes (local report, nothing delivered; `host.role` stays `gateway` in that local report, the contract's value for a report not delivered by an agent). `version` and `help` as usual. `enrol --gateway https://GW:8790 --gateway-name NODE_NAME --pin sha256:HEX --code XXXX-XXXX-XXXX-XXXX [-dir /etc/schild-agent] [-keyid ID] [-hostname H]` (also `enroll`) creates the Ed25519 key (`agent.key`, 0600, never overwritten, refused inside a source checkout; default key id `<host>/agent/<yyyy-mm>`), prints its fingerprint, sends the self-signed enrolment request and writes `agent.json` (URL, gateway name, pin, key id; no secret). A rejected enrolment removes the key. `run [-app PATH]... [-interval 24h]` checks on the interval (up to +10 % jitter and a random start delay of up to 1 min), signs every attempt anew (nonce, `issued_at`) and retries with exponential backoff (30 s doubling, ±20 % jitter, capped at 1 h and at the next regular run; `retry_after_s` respected); `rejected` is never resent. `once` does one run, `status` shows the enrolment. `init --gateway URL --gateway-name NODE_NAME --pin sha256:HEX [--key FILE --keyid ID]` sets up an agent enrolled by public key in the gateway's `schild.yaml` (`host_check.agents.keys`) instead of a code: it creates (or uses) the key, writes `agent.json`, prints the `schild.yaml` entry and contacts nobody. TLS: only the pinned certificate (sha256 of the DER) is accepted, no proxy, no redirects; the ack is verified against `agent-ack.schema.json` and only `status`, `error`, `retry_after_s` are used. The gateway name is `Enrolment.gateway_name` (contracts v0.3), and the dashboard's command carries it as `--gateway-name`.

**Gateway (`schild run` with `host_check`)**: reads the report directory (read-only mount) at start, every minute and at most every 5 s on dashboard reads; files that fail the contract are skipped and logged once. With `host_check.agents.enabled` a separate TLS listener (`agents.listen`, no default: without an address it does not start; `tls_cert`/`tls_key` or a self-signed certificate created once in `<data>/agent-tls/`, key 0600) serves only `POST /v0/agent/report`, `POST /v0/agent/enrol` and `GET /healthz`. Reports are verified with `verify.Signed(agent-report)` against enrolled and revoked agent keys (pending keys are not trusted: `signature`; revoked: `revoked`), `Gateway` = `node_name`, nonce store in SQLite (`agent_nonces`, kept for the 7 min window); the same bytes again answer `duplicate`, the same nonce with other bytes `replay`. Connections: at most 512 open and 8 per address (IPv6: per /64); excess connections from one address are closed at accept. At the global cap the oldest connection that is still waiting for its request headers (TLS handshake, slow headers, idle keep-alive) and older than 500 ms is closed for the new one; a request whose headers are complete is never evicted. So slow headers from many addresses (distributed slowloris) cannot lock enrolled agents out. Headers within 5 s, body at 64 KiB/s or faster. At most 4 verifications in parallel (else `retry`, 503), 120 requests per 15 min per address (429); enrolment: 10 failures per 15 min per address. Enrolment: code stored only as a hash, valid `enrolment_code_minutes`, once; key ids or public keys of known agents are rejected without consuming the code. Storage: tables `host_agents`, `host_enrolments`, `host_reports` (last `keep_reports` per host, report bytes unchanged), `host_rejects` (newest rejection after the signature check per agent) in `schild.db`. Agents from `host_check.agents.keys` are synced at start (`revoked: true` revokes; source `config`, revoke there). Silent: no accepted report within 2× `interval_minutes` (counted from confirmation while there is none). A failing agent listener or host store only logs: request handling and Grundschutz never depend on it.

**Dashboard API (v0.3):** `GET /hosts`, `GET /hosts/{id}`, `POST /hosts/local/check`, `GET /agents`, `POST /agents/enrolments`, `POST /agents/{id}/confirm`, `POST /agents/{id}/revoke`, `Overview.servers`. Without `host_check` the lists are empty, the other operations answer 404 and `servers` is absent. "Jetzt prüfen": in-process when `SCHILD_HOST_CHECK_INPROCESS=1` (schild runs on the host itself, not in a container), else via `SCHILD_HOST_CHECK_TRIGGER=<file>` and [schild-check.path](../docs/ops/systemd/schild-check.path) (202 `queued`, 409 `check_running` while a request is open), else 503 `check_unavailable` with the `systemctl start schild-check.service` hint. Enrolment URL: `SCHILD_AGENT_URL`, else the listener address, the dashboard's host name or `node_name`. No password re-authentication here: creating a code, confirming and revoking an agent need session and CSRF only (D40, D74).

**Accepted findings (D102, `internal/hosts/accept.go`):** `POST /hosts/{id}/findings/accept` and `.../findings/reopen`. Table `host_accepted` (host, check id, subject, severity at acceptance, note, time; at most 200 per host). Applied when counting the newest report: a finding with the same id and subject at the accepted severity or lower is left out of `counts`, the status and `Overview.servers` and counted in `accepted`; a higher severity is open again. Reports stay as stored; the check and agents know nothing of it.

**Isolation:** host reports stay on the gateway; nothing sends them anywhere.

Tests: `internal/hostsetup` (rendered units per mode, refused arguments, dry run, uninstall, embedded units equal to docs/ops/systemd), `internal/hostcheck` (fixtures of Debian 9/11/12, Ubuntu 22.04/24.04, Rocky 9, Alma 9, CentOS 7 in `testdata/hosts/` with an expectation for every result; area logs in `logs_test.go` on fixture roots of Debian 12, Ubuntu 24.04 and Alma 9 default installs (no finding above info) and every seeded fault, the bounded walk with 10 000 files, and a read-only proof (no command, only the listed config files opened, fixture tree unchanged); parsers; read-only command list; privilege downgrade; atomic write and pruning; concurrent runs), `internal/hosts` (all agent-report and agent-enrolment golden vectors through the gateway, enrolment over pinned TLS, replay, unknown and revoked keys, pending agents, one-time codes, gateway down with backoff, retention, silent, config agents, local reports and "Jetzt prüfen", concurrent ingest under `-race`), `internal/hostagent` (pinning, no redirects, URL checks), `internal/dashboard` (API against the OpenAPI schemas, re-authentication, egress).

## Behaviour and rate limits (internal/behaviour)

Spec MVP-17. Contracts v0.4 (DECISIONS D29): `behaviour` in `schild.yaml`, local events `schild.behaviour.triggered.v1` and `schild.ratelimit.exceeded.v1`, dashboard section "Verhalten & Limits". Everything stays on the server.

- **Order in the gate:** client attribution and allowlist → running behaviour block of the client key (403, calm page "Kurze Pause" with the block's incident number, end time and `Retry-After`) → rate limits of the route (429, `Retry-After`, problem details `rate_limited` for API clients) → hard limits and WAF → app. After the answer the scenarios are fed with status, `Location` and the names of cookies the app set.
- **Client key:** IPv4 address (/32, never coarser than /24), IPv6 /64.
- **Scenarios** (fixed in Go; defaults adapted from CrowdSec hub scenarios, MIT, see [NOTICE](NOTICE)): `login_bruteforce` 5 failed logins in 1 min or 30 in 1 h; `credential_stuffing` 10 distinct user names in 10 min per client, and 50 across the whole site (observed only, `scope: site`); `path_probing` 20 distinct 404/403 paths in 1 min, known scanner paths (`.env`, `.git/`, `wp-config.php.bak`, `phpmyadmin`, `/vendor/phpunit`, ...) count 5, static files never; `aggressive_crawl` 120 non-static GET/HEAD per minute and 10 times the site's per-client baseline; `waf_repeat` 2 distinct WAF rules with blocking intent over at least 2 requests in 1 min. Counting is a sliding window (two fixed windows); after a hit a scenario only counts for 5 min per key.
- **Login presets** (`behaviour.presets`, default all): WordPress `/wp-login.php` (failure = form shown again, 200/401/403; `xmlrpc.php` always answers 200 and is covered by its rate limit; lost password, registration and the other actions are no login attempts when the query names them and the body names no other action, anything else is a login, as in WordPress), Joomla `/administrator/index.php` and `task=user.login` (303 without the `joomla_user_state` cookie), Drupal `/user/login` (200), Nextcloud `/index.php/login` and `/login`, Laravel and generic `/login`, `/signin`, `/api/login`, `/auth/login` (401/403/422/429 or a redirect back to `/login`), TYPO3 `/typo3/login` (200). A plain 200 at `/login` is not a failure (single-page apps). Passwords and bodies are never read or stored; only the user name field is hashed (per-process random key) into a HyperLogLog sketch, and neither name nor hash is kept.
- **Preset rate limits** (D95: each has its own mode in `behaviour.preset_limit_modes`, by id; left open it takes its recommendation, `block` for login, password reset and `xmlrpc.php`, `observe` for search, contact forms and API writes; `behaviour.preset_limits` sets one mode for all without an own entry): login 10/min, password reset 3/10 min, `xmlrpc.php` 10/min, search 30/min, contact forms 5/10 min, API writes 60/min (burst 120), per preset; a route several presets name (`/login`, `/api/**`) is listed once as `preset-generic-<kind>` and belongs to none of them. Own limits in `behaviour.rate_limits` or the dashboard (`*` within a segment, `**` across; a route of wildcards only needs `confirm_site_wide: true`). Dashboard limits are kept in the data directory and validated together with `schild.yaml`.
- **Defaults (D92):** a scenario that `schild.yaml` leaves open takes its recommended mode: `block` for `login_bruteforce`, `credential_stuffing`, `path_probing` and `waf_repeat`, `observe` for `aggressive_crawl`. Scenarios act only after the learning period; limits act from the first day. The dashboard marks the recommendation on every switch and can apply it, or block or observe every scenario, in one settings change.
- **Ladder:** `observe` (hit with `would_action`), `block` (15 min, 1 h, 4 h, 24 h for repeat offenders within a day; cap 24 h; every block expires). Blocks are kept in memory: a restart ends them early, never late. A gateway in the test profile blocks and limits nobody: every scenario and limit only counts ("hätte gesperrt"). Releasing (dashboard "Freigeben"), an exception (`behaviour:<scenario>` / `ratelimit:<id>`, or the existing incident unblock) or an allowlist entry lets the client through; WAF rules still run.
- **Never blocked by behaviour or limits:** `net_class` `cgnat`, `mobile` and `tor` (initiator 2026-10-28) (reason `net_class`), allowlisted senders (`allowlisted`), a trusted proxy itself when a request is attributed to it because its forwarding header names no client (also `allowlisted`: a block would hit everyone behind it), released senders (`released`). Search engine user agents are counted by `aggressive_crawl` but not acted on (`unverified_bot`), unless the address is proven not to be that bot's: with fresh published ranges of the bot that do not contain it, the scenario acts as for any client.
- **Memory:** sharded fixed-capacity tables with random eviction: 65536 client keys, 65536 rate-limit buckets, 16384 blocks, 256 sites; idle entries are swept every minute. A flood of one million distinct addresses grows the heap by about 30 MiB and keeps clean requests fast (`TestFloodBoundedMemory`).
- **Dry run** (`POST /behaviour/rate-limits/dry-run`): replays the stored request events of the last 24 h; unremarkable requests are stored as a sample, so the counts are a lower bound (`sampled: true`).

## Distributed attacks (internal/behaviour)

Spec MVP-18. Contracts v0.4 extended (DECISIONS D30): `behaviour.distributed`, events `schild.distributed.detected.v1` / `.ended.v1`, dashboard tab "Wellen" under "Regeln › Szenarien und Limits". Attacks through residential proxies rotate IP and user agent, so they are counted by target, request shape and client fingerprint and answered per route or account, never by address. Wave events carry no address, user name or account key.

- **Detectors** (default `observe`; thresholds conservative, to be tuned in the testlab; mode and thresholds are set in the dashboard under "Regeln › Szenarien und Limits › Wellen", D97): `route_wave` at least 30 failed logins per minute on a route and 5 times its own learned baseline, with a failure share or a share of first-seen senders of at least 70 % (first-seen: two-generation bloom filter, rotated daily), from at least 3 senders in the window, so that one client alone cannot tighten a route for everyone; `account_wave` 10 failures on one account (user name hashed with the per-process key) from at least 3 senders in 10 min; `shape_wave` the same request_sig with blocking-intent WAF rules from 20 senders in 1 min; `fingerprint_cluster` 20 senders and at least 3 different user agents with one fingerprint among failed logins in 5 min; `inconsistency` 20 failed logins with contradicting headers (stage 0 of concept 24 §10) making up at least half of the failures in 5 min, from at least 3 senders. Routes: the login routes of the enabled presets plus `distributed.routes`.
- **Fingerprint:** JA4 only from `distributed.fingerprint.ja4_header` sent by a trusted proxy (schild itself computes no JA4: behind a web server it sees no ClientHello, and as the Caddy distribution it does not read the one Caddy sees yet). Otherwise a low-entropy header set (header names present, Accept, Accept-Encoding, number of languages, Sec-Fetch, client-hint presence, protocol); header order is not available behind Go's net/http. Either way only a 12-hex local id (per-process key) is kept, for the window.
- **Responses** (time-boxed, only after the learning period of at least 14 days from the first start, never in the test profile): `route_tighten` 20 min (extended while the wave lasts, at most `max_minutes`, 2 h): POST and other unsafe methods on the route without a session cookie share a strict limit of 10 per minute (429, Retry-After, problem details); a request with a session cookie passes unless it carries a JA4 of the cluster; the form (GET) stays reachable. `account_slowdown`: attempts without a session cookie on an attacked account wait 5 s, doubling up to `max_s` (default 60 s, hard cap 5 min); attempts with a session cookie are never slowed, a successful login with one resets the account, so nobody can lock the real user out. `shape_block`: a request shape with blocking-intent WAF rules seen from many senders is answered with 403 for any sender (one incident number per wave, no address). Session cookie = a cookie whose name the app set on this site (learned from `Set-Cookie` names, at most 64 per site).
- **No address actions:** cgnat, mobile and tor senders are treated like everyone else by the route and account responses; no response is an address ban. Allowlisted senders pass.
- **Memory:** fixed tables (1024 routes, 65536 accounts, 16384 fingerprints, 16384 shapes, 256 waves) and sketches; one million rotating senders and fingerprints stay within them (`TestDistributedFloodBounded`).

## Geo data

`make images` bakes the TEST ONLY geo fixture into the image by default (`GATEWAY_GEO=fixture`, no download; the test lab also mounts it via `geo.db_path`). With `GATEWAY_GEO=dbip`: DB-IP Lite country + ASN (CC BY 4.0, "IP Geolocation by DB-IP", <https://db-ip.com>), downloaded at image build time, pinned to one month and checked by sha256 (`GEO_MONTH`, `GEO_COUNTRY_SHA256`, `GEO_ASN_SHA256` in the Dockerfile; `make gateway-geo-pin GEO_MONTH=YYYY-MM` prints new values). This is the default of a plain `docker build` and of the published image, shipped in `/usr/share/schild/geo/` with `ATTRIBUTION.txt` and `SHA256SUMS`. `geo.db_path` (default `/var/lib/schild/geo/geo.mmdb`) wins when present; the image directory is the fallback. The files are re-read hourly when they change. Net class: DB-IP Lite has none; a coarse heuristic from the AS organisation (`hosting`, `education`, ...), otherwise `unknown`. Signing the geo data and shipping it with rule updates is open (contracts open point 3).

Own provider (MVP-22, D35): with `geo.provider: ipinfo` or `maxmind` schild downloads that provider's database every `geo.refresh_hours` (default 24) with your own token (`geo.token_file`, mode 0600, or `SCHILD_GEO_TOKEN`; never in `schild.yaml`, never logged) from the provider's fixed host, checks size, format and sample lookups and swaps it in; on any failure the last good database stays. It is the only outbound connection of the geo section. No visitor address is sent; lookups stay local. The project does not redistribute these databases, so their licence and attribution terms are between you and the provider.

## Traffic and server monitoring (internal/monitoring)

Spec MVP-21. Every request that reaches the schild handler is counted at `gate.finish` (exact classes, status classes, upstream errors, body bytes, latency histograms total/upstream/overhead, breakdowns; top lists for path, ASN, referrer and rule; HyperLogLog and 7-day in-memory Bloom filters for clients, so "new" means new since the last restart at most). Host values come from /proc and /sys every 10 s (on macOS only traffic and process numbers). Buckets of 10 s, 1 min and 10 min go to `<storage.path>/metrics.db` (fixed-size rings, aggregates only; delete the file to reset monitoring). Served under the dashboard tag `monitoring` and the agent API; `monitoring.enabled: false` answers 409 `monitoring_off` (the dashboard then stops asking and shows that monitoring is off). Without MVP-16 sites the gateway has one implicit site `default`. Hint thresholds are fixed (contract `HealthHintCode`).

- **Estimates.** Unique and new clients are a Näherungswert: the HyperLogLog sketch (precision 10) has a standard error of about 3.3 %, so a value is usually within ±3 % and sometimes a bit further off; values of different buckets cannot be added. Top lists (path, ASN, referrer, rule; K = 64 per bucket) carry `error`, the maximum overcount: the true count lies between `requests - error` and `requests`, also when a breakdown merges many buckets (a key missing from a full bucket list counts that list's smallest value as possible overcount). Every rule id of a detection is counted. `would_rate_limit` counts forwarded requests over a rate limit that was only observed (mode `observe`, gateway mode observe, allowlist, release).
- **Bounded memory.** The path template and referrer caches are bounded in entries, bytes and key length (keys above 256 bytes are never stored; paths above 1 KiB are templated from their first bytes); the user agent classification is one pass over the first 512 bytes with a fixed 4096-slot cache (32 KiB) keyed by a hash. A flood of distinct long paths, user agents or referrers costs CPU, not memory (`TestMemoryFlatWithDistinctLongInputs`).
- **Sampler.** TCP states come from `/proc/net/tcp{,6}` only up to 5000 sockets (per `sockstat`) and only while the measured cost per socket predicts at most 10 ms per scan (the kernel formats every line, about 1.7-2.5 µs per socket; 19 800 sockets cost about 0.35 % of a core at one sample per 10 s, D36 measurement); otherwise the totals of `/proc/net/sockstat{,6}` (established = in use, so listening sockets are not split out). In a container, tunnel stubs (`gre0`, `sit0`, ...) are ignored; an interface whose `iflink` differs from its `ifindex` (veth, macvlan) means schild has its own network namespace, and then the connection table is `container_hidden`.
- **metrics.db layout 3** (D36 fix round 2). Each ring row holds the gateway `core` (compact binary, flate); part rows hold each gateway top list and each website (its counters, latency, estimates and its top lists, each section compressed on its own). A gateway breakdown reads the core and one list per bucket; a breakdown, series or KPI row of one website reads that website's part only (with 32 websites a 14-day breakdown of one website read the whole bucket, about 1 s; 0.17-0.28 s after the change, measured by the builder on files with every slot holding the worst-case bucket for 0, 1, 8 and 32 websites, on a shared M2 Max). A ring of another layout starts over, and a bucket of an older codec version is skipped (D74: no readers of older formats). The API answers (MetricBucket JSON) are unchanged.
- **Size of metrics.db.** The file stops growing once every slot of the three rings was written (default 2160 + 2880 + 2016 slots); after that it does not grow with traffic or cardinality, only with the number of tracked websites `W` (at most 32 plus `_other`). Top list keys and labels (paths, referrers, AS names) are cut at 64 bytes and end with `…` (`MaxTopKeyBytes`, 128 before D36 fix round 2; the contract allows up to 512, so cut keys stay valid; two keys with the same first 61 bytes count as one). **Documented bound** (`monitoring.MetricsBoundBytes`): `gateway × 1.40 + W × website × 1.15` with `gateway = slots_10s × 6 KiB + slots_1m × 20 KiB + slots_10m × 22 KiB` and `website = slots_10s × 192 B + slots_1m × 384 B + slots_10m × 5 KiB`. The bucket sizes come from the adversarial input of the independent re-measurement (`testlab/measure/monitoring/d36n`: three 64-character path segments the path template keeps, 63-character referrer labels, random AS names, every list full, a host with 17 mounts, 17 devices and 16 interfaces): gateway 5 215 B / 17 558 B / 19 469 B, per website 160 B / 310 B / 4 225 B (10 s / 1 min / 10 min), each rounded up by 15-25 %. The factors are SQLite pages, page fill and indexes with every slot holding the worst-case bucket (measured 0.83-0.88 of the bound for W = 0, 1, 8 and 32 with that host). With the default rings the bound is about **157 MiB** for a gateway without websites, **170 MiB** with one, **209 MiB** with 4 and **573 MiB** with 32 websites. Real traffic stays far below (measured 17 MiB with one site, about 1.5 KiB per website and 10 min bucket). `monitoring.keep` scales each ring linearly (30 days at 10 min roughly double the 10 min part).
- **Disk budget (D38, `internal/diskbudget`).** budget = `retention.max_size_mb` + 10 % + 2 × 64 MiB WAL + `MetricsBoundBytes` for the configured rings and the number of websites (0 with monitoring off) + `monitoring.requests.max_size_mb` (0 with the request ring off), compared with statfs of `storage.path` (its nearest existing parent before the first start; total = f_blocks × f_frsize, available = f_bavail × f_frsize; f_bsize on macOS) and the bytes the bounded files use now (`schild.db`, `metrics.db` and their WALs; the MVP-22 request ring segments join once the ring exists). `schild preflight` prints the figures; budget > total: `schild preflight` and `schild run` refuse with contract code `config`, pointer `/retention/max_size_mb`. The running gateway checks at start and every hour (`App.StorageBudget`) and raises `storage_budget` (notice, object = `storage.path`, value = what would stay available once the bounds filled, threshold = the reserve max(1 GiB, min(5 % of the file system, 20 GiB)), `storage.Reserve`); a verdict change is logged once.
- **disk_fill_projection (D38).** From the 10 min ring only (no new sampling): per mount the minimum of `server.disk_used` (bucket min) per complete UTC day over the last 7 days, the number of buckets as the day's points, `storage.Projection` with the current used and size of the mount from the latest sample. Recomputed at most once an hour in the sampler goroutine; complete days (15 min after midnight UTC) are cached, so a refresh reads at most the days not cached yet (a full 7-day read of 1008 small buckets took 5.5 ms on an M2 Max, `BenchmarkProjectionRefresh`). Hint value = days left, threshold = 14; it reaches every website like `disk_full_soon`. The rate per day of the German text has no field in `HealthHint` (open point).

Builder benchmarks (Apple M2 Max, `go test -run - -bench . ./internal/monitoring`; the independent measurement decides): `BenchmarkRecordCommon` about 0.55 µs per request, 0 allocations; `BenchmarkClassifyUAMiss` about 0.5 µs per new user agent; `BenchmarkQuerySeries16x1000` about 40 ms and one 14-day breakdown about 60 ms on rings filled with worst-case buckets (`BenchmarkQueryBreakdown14d` runs two).

## Agent API (internal/agentapi)

Spec MVP-21. Off by default. With `agent_api.enabled: true` a second listener on `agent_api.listen` (loopback only, default `127.0.0.1:8789`) serves `/agent/v0` with bearer tokens only. It describes itself: `GET /agent/v0/openapi.json` is the whole OpenAPI document with a short guide for agents at the top (D61; bundled from `contracts/api/gateway-agent.openapi.yaml` by `make contracts-sync`). No MCP: an agent with a shell needs nothing but `curl` and this document.

```sh
schild token add --scope exceptions:write --expires 90d --label "coding-agent"     # token shown once
schild token list | schild token revoke tok_<id> | schild token log
ssh -N -L 8789:127.0.0.1:8789 agent@gateway                                         # on the operator's machine
curl -s -H "Authorization: Bearer sat1_..." http://127.0.0.1:8789/agent/v0/openapi.json   # give this to the agent
```

Read only except the write scopes, each with `--label`: `rules:write` sets the state of a rule repository, syncs and resets it and disables single rules, `blocks:write` sets and lifts single blocks (D42), `exceptions:write` sets and removes rule exceptions (D54), `crawlers:write` changes the crawler policy (D57). Every token may test a sample request against the rules (D55). Events, incidents and requests carry the client address as stored, next to the pseudonym `p1-…` and the /24 or /48, and can be filtered by it (D99); a block is still named by event, incident or pseudonym. Visitor text is escaped and marked untrusted. With a cloud model the data read leaves your own network. The call log (`schild token log`) is bounded on its own: refused calls (429) are one row per token and minute with their count (`CALLS`), the log keeps at most the newest 50 000 rows within `agent_api.log_days`, and when `schild.db` is over `retention.max_size_mb` the call log is cleared before any event is deleted, so agent traffic never pushes out events or incidents. The request ring operations answer 409 `requests_off` while `monitoring.requests` is off.

## Rule repositories (D73)

Three repositories, each with one state `off` (not built, nothing fetched), `detect` (matches logged, never a block) or `block`, set in `schild.yaml`, on the Regeln page or through the agent API; a value set there wins over `schild.yaml` until `reset_state`. No restart, no password. `off` against the others rebuilds the WAF, `detect` against `block` changes only the decision.

```yaml
rules:
  crs:                     # OWASP CRS, built into the binary
    state: block           # off | detect | block (default)
    paranoia_level: 1
    inbound_anomaly_threshold: 5
    livewire_exception: true
    disabled_rules: []     # CRS ids, e.g. "942100" (SecRuleRemoveById at build)
  crowdsec:                # CrowdSec Hub virtual patches: image snapshot plus updates
    state: detect          # off | detect (default, nothing blocks) | block
    auto_update: true      # false: no outgoing request, the running set stays
    interval_s: 3600       # with +-10 % jitter
    # pin: <40 hex>        # a hub commit: fetched once, auto_update has no effect
    settling_s: 86400      # a rule received from the hub only detects this long, then blocks
    disabled_rules: []     # hub names, e.g. crowdsecurity/vpatch-CVE-2026-1207
  local:                   # the operator's SecLang files
    state: block
    dir: /etc/schild/rules.d   # *.conf in name order
    disabled_rules: []     # local ids (SecRuleRemoveById at build)
```

- **One vocabulary** (`contract/rules`, `internal/ruleset`): a rule is `{repository, id}` with origin (`release`, `update`, `operator`), status (`active`, `settling`, `disabled`) and effect (`off`, `detect`, `would_block`, `block`). Both APIs: `/rule-repositories[/{repository}[/sync|/reset]]`, `/rules[/{repository}/{rule}]`.
- **Id ranges**, checked at every build: crs 900000–999999 and the engine's 200000–200099, crowdsec 60000000–99999999, agent exceptions 1900000–1999999, 7700000–7799999 reserved; local takes everything else. A local rule in another range is refused: at a sync the running rules stay, at a start the gateway does not come up.
- **Disabling one rule** works in every repository: `disabled_rules` in `schild.yaml` (cannot be enabled elsewhere, 409 `config_limit`) or the APIs (table `rule_decisions` in `schild.db`, with who, when and a note). CRS and local rules leave the WAF at once (rebuild), a crowdsec rule stops at once.
- **crowdsec:** no account, no Central API, no IP lists, no CrowdSec engine, and nothing goes to CrowdSec beyond one `GET` of the public `.index.json` on `raw.githubusercontent.com`. Rules: [contracts/crowdsec-hub.md](../contracts/crowdsec-hub.md). Which set loads: a pinned set first, else the newer of the stored last good set and the image snapshot (`make crowdsec-snapshot`, `internal/hub/snapshot.json`), else none; a start never fails because of it. Updates run in the background (`internal/hub`): `CheckIndex`, cost check, compile, swap, store; a failed, slow or hostile update changes nothing and writes one `schild.rule.repository_updated.v1` per change of the reason. Rules of the image snapshot are `release`; a rule (name and version) the hub brought later is `update` and settles for `settling_s` before it blocks.
- **local:** `schild rules sync local`, `SIGHUP` or the APIs load `rules.local.dir` again; a set that does not build changes nothing (`schild.rule.repository_updated.v1`, outcome `refused`). Operator rules cannot switch the rule engine or the request body off (D80): `SecRuleEngine`, `SecRequestBodyAccess`, the `SecRequestBodyLimit` directives `ctl:ruleEngine`, `ctl:requestBodyAccess`, `ctl:requestBodyLimit` and `Include` do not build. To leave a path out of the CRS use `ctl:ruleRemoveByTag=OWASP_CRS`.
- **Agents** need `--scope rules:write --label ...` to change repositories and rules; every change is an event with the token label and in the call log.
- **Known limits:** 201 of the 206 selected hub rules load on the hub of 2026-10-30; the five skipped ones are listed in the status. `vpatch-CVE-2026-109618` (php2shell) is refused because it brings raw SecLang. Rules that read `RAW_BODY` see urlencoded and JSON bodies only (note `raw_body_partial`). The hub signs nothing: HTTPS, its digests, the bounds, `shrink`, approval and settling are the protection.

## Metrics

`schild_incident_hits_dropped_total` (hits of aggregated incidents lost while the store stalls, D40), `schild_http_requests_total{class}`, `schild_http_bytes_total{direction}`, `schild_http_latency_seconds{part}`, `schild_http_waiting_page_shown_total` (MVP-21 totals and the D37 overlay, kept by the monitor, no request path cost), `schild_requests_total{outcome}` (`client_gone` for a client that left or stalled, D46), `schild_connections_open`, `schild_connections_refused_total{scope}`, `schild_connections_evicted_total{scope}`, `schild_local_rules_reloads_total{result}` (D46), `schild_waf_seconds` (histogram), `schild_hard_limit_rejects_total{code}`, `schild_events_written_total`, `schild_events_dropped_total`, `schild_rule_swaps_total`, `schild_rule_swap_build_seconds`, `schild_baseline_protection_active`, plus Go/process metrics. No label carries visitor data.

## Measured on the build machine (Apple M2 Max, not the test lab)

| What | Result |
| --- | --- |
| CRS instance build | ~60 ms (B07 lower bound; 50 rules add little) |
| Clean GET through the gate (CRS blocking), single request CPU | ~0.4 ms; form POST ~0.7 ms (`BenchmarkCRSCleanGET`, `BenchmarkCRSFormPOST`) |
| Full path through embedded Caddy, 12 parallel clients | 34 µs/op without schild, 69 µs/op with schild (`BenchmarkCaddyPath`) |
| Large urlencoded fields | CRS costs ~3-9 ms per KiB of form, JSON or text body in Coraza; multipart file content is cheap (1 MiB: ~4 ms). Text bodies get 4 ms per KiB on top of `eval_timeout_ms` (at most 10 s, MVP-19 re-measurement); what does not finish within that gets 503. |

These are builder numbers. B01/B02/B07/K3/T19 are measured by the test lab (MVP-05).

## Dependencies (all pure Go) and licences

| Module | Version | Licence |
| --- | --- | --- |
| github.com/caddyserver/caddy/v2 | v2.11.9 | Apache-2.0 |
| github.com/corazawaf/coraza/v3 | v3.8.1 | Apache-2.0 |
| github.com/corazawaf/coraza-caddy/v2 | v2.6.2 (stock `http.handlers.waf` compiled in for custom routes) | Apache-2.0 |
| github.com/corazawaf/coraza-coreruleset/crs/v4 | v4.30.0 (OWASP CRS 4.30) | Apache-2.0 (CRS itself Apache-2.0) |
| modernc.org/sqlite | v1.61.0 | BSD-3-Clause |
| github.com/oschwald/maxminddb-golang/v2 | v2.8.0 | ISC |
| github.com/maxmind/mmdbwriter | v1.2.0 (test fixture writer) | Apache-2.0 / MIT |
| github.com/prometheus/client_golang | v1.25.0 (via Caddy) | Apache-2.0 |
| golang.org/x/crypto (argon2) | v0.58.0 | BSD-3-Clause |
| github.com/santhosh-tekuri/jsonschema/v6 | v6.0.3 (API contract tests) | Apache-2.0 |
| DB-IP Lite data | monthly | CC BY 4.0 (attribution in the image) |

Toolchain (DECISIONS D24, closes D21's toolchain point and open point 7; the versions moved on since): Go 1.27 with **Coraza v3.8.1, coraza-caddy v2.6.2, Caddy v2.11.9** and CRS 4.30 (`coraza-coreruleset/crs/v4` v4.30.0). The module `coraza-coreruleset/v4` is frozen at CRS 4.25.0 and replaced by `crs/v4` and `lts/v4`. coraza-caddy still requires the frozen module, so `load_owasp_crs` on the stock `http.handlers.waf` of a custom route gets CRS 4.25.0, not the CRS of the gate.

Behaviour changes that matter for the gateway (checked when upgrading from Coraza 3.3.3, coraza-caddy 2.1.0, Caddy 2.10.0):

- **Argument limit (Coraza 3.8).** `SecArgumentsLimit` now also applies to urlencoded and JSON bodies; arguments beyond it are dropped and only `ARGUMENTS_LIMIT_REACHED` is set. Without a rule on that flag the tail of a JSON array with more than 1000 elements was never inspected (a SQL injection in element 1001 passed with anomaly score 0). The WAF now carries rules 200004/200005 (and 200009 for `URI_PARSE_ERROR`) from `coraza.conf-recommended`; the gate answers them with 400 `too_many_args` in every mode (`TestArgumentsLimitReached`, `TestArgumentsLimitInEveryMode`).
- **Pattern cache (Coraza 3.5).** Compiled patterns live in a process-wide memoize cache with one owner per WAF. `Engine.Swap` closes the previous instance (`experimental.WAFCloser`) so rule swaps do not accumulate owners; requests in flight keep working.
- **Stricter body parsing (Coraza 3.8.x).** Malformed or duplicate multipart part headers and `filename*N` continuations set `MULTIPART_STRICT_ERROR`; JSON bodies whose flattened form exceeds 8x the body size set `REQBODY_ERROR`. Both are answered with 400 (`body_unparseable`), as before for other parse errors. The first `Content-Type` header now selects the body processor.
- **Caddy 2.11.4** drops request header fields whose names contain `_` before any handler runs (neither the WAF nor the upstream sees them) and answers HTTP/1.1 requests without `Host` with 400.
- **Caddy 2.11.6 and 2.11.7** (checked when upgrading from 2.11.4; the adapted config of every `ingress-order` vector is unchanged):
  - Request header fields with a `.` in the name are dropped as well, before any handler runs.
  - Ingress: request headers are limited to 16 KiB unless the Caddyfile sets `max_header_size`. Caddy answers 431 itself, so the gate sees nothing and writes no event; above that size the gate's own `headers_too_large` no longer applies. The proxy listener sets `max_header_bytes` to 1 MiB and keeps the gate's limit.
  - A request body or response write that stalls for 1 minute is aborted (`read_body_idle`, `write_idle`), also when `read_body` allows more. A slow upload that keeps moving is not affected.
  - Caddy's body reader sets its own read deadline on every read, which replaces a deadline set once. The gate therefore ends the drain of a refused request with a timer (D41, `TestDrainIsBoundedBehindCaddy`).
  - A client that disconnects while the request is proxied is recorded as 499 (class 4xx). Before, nothing was written and the gate recorded 200.
- **Caddy 2.11.8 and 2.11.9** (checked when upgrading from 2.11.7 on 2026-11-05; `make gateway-test`, every `ingress-order` vector, `TestDrainIsBoundedBehindCaddy`):
  - Security fixes in FastCGI, which matter when schild is the ingress with `php_fastcgi`: `env` values win over request headers (`HTTP_*`), a request whose escaped and decoded path would run different scripts gets 400, and over HTTP/2 a `host` field next to `:authority` no longer changes the host the app sees. `go-jose` is at v4.1.6 (GHSA-mgcc-cww5-fp2q).
  - `php_fastcgi` redirects a directory without trailing slash to a relative, escaped location: the adapted config has `./{http.request.orig_uri.path.file_escaped}/...` instead of `{http.request.orig_uri.path}/...`. Only `ingress-order` vector 007 changed with it; where `schild` sits did not change.
  - Deadlines set by handlers act as a ceiling and are no longer overridden by the idle timeouts; per-route `timeouts` win over `read_body_idle`/`write_idle`. The drain timer of a refused request (D41) is unchanged and still bounded.
  - A Caddyfile in which two site blocks set different `client_auth` for the same host is refused by the adapter now (it used to keep the first one silently).
- **CRS 4.30** (checked when upgrading from 4.25.0, 112 evaluations at PL1 and PL2 side by side). New detections: XML attribute values, the URL path in the 932 RCE rules, uppercase `CHARSET=` (920480), several `_charset_` values (922100), uploads ending in `/` (933110), template injection (934200). Gone false positives: `application/*+json` and `x-amz-json` types (920420), a JSON key `profiledata`, `vega` inside a user agent (913100). New false positives come from the path inspection: `/api/v1/users/whoami` scores 5 at PL1 (932260), which meets the default threshold; `/wiki/Python_(programming_language)` and `/docs/python/print-function` score 5 at PL2 (932236). Rule ids 950010 to 956010 are gone (950020 and 950022 replace them), `@crs-setup.conf.example` now sets `SecDefaultAction` for phases 3 to 5.
- Unchanged: the 1 s evaluation timeout and the fail-closed 503 path (`TestTimeoutNeverPasses`, `TestPanicFailsClosed`), the hard limits (`TestHardLimitsInEveryMode`) and the anomaly scoring (recomputed from CRS rule severities, `TestCRSLoadsAndScores`).
- The Coraza semantics the SecLang subset relies on (argument trimming, `@pm` splitting, macro expansion in operators, empty-value `@within`, operator case rules) are pinned in `internal/waf/coraza_semantics_test.go` and hold on v3.8.1 (`make gateway-coraza`).

## Known limits (alpha)

- **No upgrades from pre-release builds (D74, D75).** Releases from `0.1.0-alpha.1` on upgrade `schild.db` at start (see [Upgrades](#upgrades)). A database of a build before that is refused at start with an error that names the file: stop schild, move `schild.db` (with `schild.db-wal` and `schild.db-shm`) away and start again with a fresh database. `metrics.db` and the request ring start over when their layout changes.
- The browser check ("Kurze Prüfung", MVP-12 v1_cut, [contracts/human-check.md](../contracts/human-check.md)) covers page views only: API calls, POSTs and assets are never challenged, so it does not protect forms. It is a setting per website, not a scenario mode: the mode `challenge` is gone (D92): an old value in `schild.yaml` loads as `observe` with a warning, the APIs refuse it.
- Behaviour blocks, counters and 24 h counts live in memory (reset on restart); the `waf_repeat` counter is not yet shared with a network-level ban helper (MVP-15 is not built).
- The daily XFF self-test of G5 is not implemented beyond the static check of `trusted_proxies`; `ja4` is never sent (schild does not terminate TLS).
- `origin.protected` (G6 protection list) is always `false`: there is no signed protection list yet.
- Hit counts and latency quantiles are in memory (reset on restart); `p95_overhead_ms` covers the last hour.
- The dashboard runs in-process (see above). Roles: admin only.
- Upstream URLs with a path prefix are not supported (put the prefix into the application or the front proxy).
