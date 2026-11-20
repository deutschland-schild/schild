# Server check and agent (contracts v0.3, MVP-11)

Contract for `schild check` (read-only host findings) and `schild-agent` (the same checks on every app VM behind one gateway; until 2026-10-27 the subcommand `schild agent`, now a separate binary without proxy, WAF or dashboard; nothing on the wire changed), decided in [DECISIONS](DECISIONS.md) D25, specified in [specs/MVP-11](../tests/specs/MVP-11-server-check-agent.yaml). Background (German): concept 13, sections "Server-Check" and "Mehrere Server hinter einem Gateway", and concept 24 (Datenschutz).

| Contract | Schema | Go | Vectors |
| --- | --- | --- | --- |
| Host report `schild.host_report/0.1` | [host-report.schema.json](host-report.schema.json) | `contract/hostcheck`, `verify.Document(verify.DocHostReport, …)` | `vectors/host-report` |
| Agent delivery (DSSE, kind `agent-report`) | [agent-report.schema.json](agent-report.schema.json) | `verify.Signed(contract.KindAgentReport, …)` | `vectors/agent-report` |
| Enrolment request (DSSE, self-signed) | [agent-enrolment.schema.json](agent-enrolment.schema.json) | `verify.AgentEnrolment` | `vectors/agent-enrolment` |
| Gateway answer `schild.agent_ack/0.1` | [agent-ack.schema.json](agent-ack.schema.json) | `verify.Document(verify.DocAgentAck, …)` | `vectors/agent-ack` |
| `schild.yaml` section `host_check` | [config/schild.schema.json](config/schild.schema.json) | `contract/config` (`Site.HostCheck`, `Site.AgentTrust`) | `vectors/config-schild` (006, 007, 018–022) |
| Dashboard API (hosts, agents) | [api/client-dashboard.openapi.yaml](api/client-dashboard.openapi.yaml) | `contract/apispec` (checks) | fixtures `api/fixtures/client/{listHosts,getHost*,runLocalCheck*,listAgents,createEnrolment,confirmAgent*,revokeAgent}.json` |

## 1. Roles and data flow

```text
app VM: schild-agent ──signed agent report (TLS, :8790)──▶ gateway: schild ◀── report dir (read-only mount) ◀── schild check (host, systemd timer)
                     ◀──────────── ack only ────────────
```

- **`schild check`** runs on the host (not in the container), reads only and writes one report per run as a JSON file (mode 0640) into `host_check.report_dir` (default `/var/lib/schild/host-check`, file name `<started_at>-<report_id>.json`). The schild container mounts that directory read-only and shows the newest report as host `local`.
- **`schild-agent`** (Schild Agent) runs on an app VM, runs the same checks and pushes the report, signed with its own key, to the gateway. It never talks to labs and accepts no commands.
- **The gateway** accepts reports only from enrolled, not revoked agent keys and answers with an ack (section 6), never with instructions.
- **Host reports stay in the operator network.** They are no signals, no lab ever receives them, and nothing derived from them goes into a signal or feedback (the M2 egress check covers this). They never affect request handling or the Grundschutz state.

## 2. Host report `schild.host_report/0.1`

Schema: [host-report.schema.json](host-report.schema.json). One object per host and run:

| Field | Content |
| --- | --- |
| `schema`, `report_id` | `"schild.host_report/0.1"`, random UUID v4 |
| `host` | `hostname` (lower case), `role` (`gateway` \| `agent`), `agent_key_id` (the agent's key id; `null` on the gateway), `os` (`id`, `version_id`, `name` from `/etc/os-release`, `kernel` from `uname -r`, `arch` from `uname -m`, `eol` and `extended_support_until` from the bundled EOL table or `null`) |
| `run` | `started_at`, `duration_ms`, `schild_version`, `eol_table` (date of the bundled, dated EOL table: no lookup at runtime), `as_root` |
| `findings[]` | `id` (stable check id, e.g. `ssh.password_authentication`), `area` (`distribution`, `updates`, `ports`, `firewall`, `ssh`, `tls`, `software`, since v0.5 `logs`), optional `subject` (`tcp/3306`, a site name, a runtime), `severity` (`info`, `low`, `medium`, `high`, `critical`), `status` (`ok`, `finding`, `unreadable`), German `title` and `explanation`, `fix_command` (one copyable line or `null`), since v0.5 optional `fix_config` (section 2, fix_config), `evidence`, and for `unreadable` the `unreadable` object |
| `inventory[]` | `kind` (`os_package`, `runtime`, `server`, `database`, `app`), `name`, `version`, `eol` (date or `null`), `source` (`dpkg`, `rpm`, `apk`, `binary`, `app_path`), apps: `path` (configured path only) and `parent` (plugins: `wordpress`, …) |

Rules the schema and the checks enforce:

- `(id, subject)` is unique within a report (`schema`). A check that yields several results (one per port, site or runtime) sets `subject`.
- `status: ok` and `status: unreadable` always have `severity: info`. Every check reports a result: `ok` when nothing is wrong, so the dashboard can show what was checked.
- **"nicht lesbar":** a check that lacks rights or tools reports `status: unreadable` with `unreadable.reason` (`permission_denied`, `not_installed`, `not_supported`, `not_configured`, `timeout`, `parse_error`) and, when it helps, `unreadable.needs` (`root`, `CAP_NET_ADMIN`, `group:adm`, `group:systemd-journal`). It never fails the run and never tries harder (no sudo, no refresh of package indexes).
- **Evidence is typed facts only:** `source` (where the fact was read: `os_release`, `apt`, `dnf`, `ss`, `nft`, `sshd_t`, `journal`, `cert_store`, …), `path` (path only, never content), `setting`/`value`/`expected` (single tokens without spaces or `=`), `port`, `protocol`, `address` (local listen address), `process`, `package`, `installed_version`, `candidate_version`, `count`, `packages` (at most 50 names), `date`, `not_after`, `days_left`, `enabled`, `policy`, `window_hours`. No free text, no command output, no file excerpts.
- Text (`title`, `explanation`, `fix_command`, `os.name`) is one line without control characters. Copy is German, du-form, calm (what it means, why it matters, the command); never promises such as "sicher" or "geschützt".
- **Size limits:** report (file, and agent payload) at most 512 KiB, at most 500 findings and 2000 inventory items, strings as in the schema.

### Forbidden content

A report (and every agent report and enrolment request) never contains:

- **environment variables** of any process (`/proc/*/environ`, `env`, systemd `Environment=`, `.env` files),
- **file bodies** (configuration files, logs, `sshd_config`, `wp-config.php`, …): only paths and single parsed settings,
- **private keys, certificates in PEM, passwords, tokens, API keys, session ids**, nor values of settings that hold secrets (`requirepass`, `DB_PASSWORD`, …: report that the setting exists, never its value),
- **visitor data** (IP addresses of visitors, request contents) – the server check is about the host, not about traffic.

Hostnames and local listen addresses are allowed: the report stays local.

Detectable violations are rejected before the schema, in two passes (so the code does not depend on map order):

1. `forbidden_field`: an object key at any depth whose name, after ASCII lower-casing and removing `-`, `_` and `.`, is one of: `env`, `envs`, `environ`, `environment`, `env_vars`, `environment_variables`, `password`, `passwd`, `passphrase`, `secret`, `secrets`, `secret_key`, `private_key`, `privkey`, `api_key`, `apikey`, `token`, `tokens`, `access_token`, `auth_token`, `bearer`, `credential`, `credentials`, `cookie`, `cookies`, `session`, `authorization`, `content`, `contents`, `file_content`, `file_contents`, `file_body`, `body`, `raw`, `raw_output`, `output`, `stdout`, `stderr`, `cmdline`, `command_line`, `argv`, `config_file`, `shadow`.
2. `forbidden_content`: any object key or string value (at any depth) that
   - after ASCII lower-casing contains `-----begin `, `-----end `, `private key-----` or `putty-user-key-file` (PEM armour, key files), or
   - after ASCII lower-casing matches `(password|passwd|secret|token|api_?key|access_?key|private_?key|credentials?)[a-z0-9_]*=[!-~]` (a secret assignment such as `DB_PASSWORD=…` or `--password=…`), or
   - contains three or more matches of `(^|[ ;\t\n\x00])[A-Z_][A-Z0-9_]{1,63}=` (an environment dump; two assignments as in `DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=a apt-get …` are fine).

The detectors are a net, not the protection: the protection is that checks only ever emit typed fields. A finding the detectors would reject is a bug in the check.

### fix_config (v0.5, D38)

Some fixes are config files, not commands (area `logs`). A finding with `status: finding` may carry `fix_config {path, content}`: an absolute path and the full file content (LF line ends, no other control characters, at most 4 KiB). The text never comes from the host: path and content must be a rendering of a **gateway-side template** of the finding id (`hostcheck.FixTemplates`, the same table in `crosscheck.py`) whose only variable parts are

| Variable | Rule |
| --- | --- |
| `${slug}` | `[a-z0-9][a-z0-9-]{0,47}`; logrotate fixes only write `/etc/logrotate.d/schild-${slug}`, never a vendor file |
| `${file}` | absolute path, at most 8 segments, no segment starting with `.` (so no `..`), below `/var/log/`, `/srv/`, `/opt/` or `/var/www/`; outside `/var/log/` the name ends in `.log` (copytruncate never reaches a system or config file) |
| `${max_size_mb}`, `${max_files}`, `${max_use_mb}`, `${keep_free_mb}`, `${rotate}` | decimal without leading zero, within 1..10240, 1..20, 64..65536, 64..1048576, 1..365 |

Templates (v0.5): `logs.docker_unbounded` → `/etc/docker/daemon.json` `{"log-driver": "local", "log-opts": {"max-size": "${max_size_mb}m", "max-file": "${max_files}"}}`; `logs.journald_size` → `/etc/systemd/journald.conf.d/50-schild-size.conf` `[Journal]` `SystemMaxUse=${max_use_mb}M` `SystemKeepFree=${keep_free_mb}M` `MaxRetentionSec=1month`; `logs.logrotate_config` and `logs.large_file` → `/etc/logrotate.d/schild-${slug}` with `${file} { daily, rotate ${rotate}, maxsize ${max_size_mb}M, missingok, notifempty, compress, delaycompress, copytruncate }`. A fix_config that is no such rendering (another finding id's template, an added line, a path with `..`, a file outside the roots) is rejected with `schema` (pointer `/findings/<i>/fix_config`), in host reports and agent reports alike: an agent can never get arbitrary file content shown as a fix. The key `content` stays a forbidden field everywhere else; directly inside `fix_config` of a finding it is exempt from the key pass (the template check is stricter), the content detectors still run on it.

The dashboard shows path and content with a copy button and says which command applies it (`sudo systemctl restart systemd-journald`, a redeploy for Docker); a `daemon.json` template is only offered when the file is missing or holds nothing but log keys (otherwise the explanation names the two keys to add and `fix_config` is absent).

### Recommended check ids

Stable ids the first implementation uses (new ids may be added, an id never changes meaning):

| Area | Ids |
| --- | --- |
| distribution | `distribution.eol`, `distribution.kernel_outdated` |
| updates | `updates.security_pending`, `updates.pending`, `updates.automatic`, `updates.reboot_required` |
| ports | `ports.public_service` (subject `tcp/<port>`), `ports.docker_api`, `ports.admin_panel` |
| firewall | `firewall.active`, `firewall.default_incoming`, `firewall.docker_bypass` |
| ssh | `ssh.password_authentication`, `ssh.permit_root_login`, `ssh.port`, `ssh.failed_logins` |
| tls | `tls.certificate_expiry` (subject = site), gateway only |
| software | `software.runtime_eol` (subject = runtime), `software.app_outdated` (subject = app), `software.server_eol`, `software.database_eol` |
| logs (v0.5, D38) | `logs.docker_unbounded`, `logs.journald_size`, `logs.logrotate_missing`, `logs.logrotate_stale`, `logs.logrotate_config` (subject = config file or log path), `logs.large_file` (subject = path); detection, rights, false-positive rules, severities and texts in [specs/MVP-11](../tests/specs/MVP-11-server-check-agent.yaml) (addendum Log-Hygiene). Evidence (v0.5): `size_bytes` (from st_blocks), `growth_bytes_per_day` (against the previous kept report), `fs_percent`, `mount`; sources `docker_daemon`, `docker_container`, `journald_conf`, `logrotate_conf`, `logrotate_status`, `stat`, `caddyfile` |

## 3. Agent delivery (signed envelope)

A DSSE envelope ([envelope.md](envelope.md)) with:

| | |
| --- | --- |
| payloadType | `application/vnd.schild.agent-report.v0+json` (own domain: a signal, enrolment or any other signature never counts) |
| signature | exactly one, by the agent's own Ed25519 key, key purpose `agent`, key id per agent (recommended `<hostname>/agent/<yyyy-mm>`) |
| payload | [agent-report.schema.json](agent-report.schema.json): `schema` `schild.agent_report/0.1`, `gateway` (the gateway's `node_name`), `issued_at`, `nonce` (16 random bytes, lower-case hex, new for every attempt), `report` (a host report with `role: agent`) |
| limits | envelope 768 KiB, payload 512 KiB |
| window | `issued_at` in [now − 5 min, now + 120 s]; the gateway remembers every accepted nonce at least until `issued_at` + 5 min + 120 s. The same envelope bytes again (a lost ack, the agent resends) are answered with ack `duplicate` and not stored twice; the same nonce with other bytes is rejected with `replay` |
| binding | `report.host.agent_key_id` equals the key id of the valid signature (`signature` otherwise): an agent can only report as itself |

Transport: `POST /v0/agent/report` on the gateway's agent listener (`host_check.agents.listen`, TLS with `tls_cert`/`tls_key`), body = envelope bytes, `Content-Type: application/json`, with a `Content-Length` (section 6.1). `host_check.agents.listen` has no default: without an explicit address the listener does not start; bind it to the interface the app VMs reach and firewall it from everything else. The agent sends its key id in the request header `Schild-Agent-Key` (a hint for the gateway's limits, never trusted; the signature decides). The agent pins the gateway certificate (`--pin sha256:<hex of the DER certificate>` from enrolment) and needs no other outgoing access. It runs on its interval (`host_check.agents.interval_minutes`, default daily) and, when the gateway is unreachable or answers `retry`, re-signs (new nonce and `issued_at`) and retries with exponential backoff (30 s doubling, capped at 1 h and at the next regular run). Agent failures never affect the gateway's request handling.

### Verification order (agent-report)

The signed-message order of [vectors/README.md](vectors/README.md) with these steps:

1. `oversize` envelope > 768 KiB
2. `malformed`
3. `envelope` (schema, canonical base64, exactly one signature)
4. `oversize` payload > 512 KiB
5. `payload_type`
6. `signature`: no valid signature by a trusted key with purpose `agent` (unknown key, site or lab key, wrong key id); `revoked`: the only valid signature is by a revoked agent key
7. `malformed` payload
8. `forbidden_field`, then `forbidden_content` (section 2)
9. `schema`, then duplicate `(id, subject)` (`schema`)
10. `signature` (report names another agent key), `clock_skew`, `expired`, `channel` (`gateway` differs from this gateway's name), `replay` (nonce already accepted)

## 4. Rights per check

The check runs without root where possible; what it cannot read becomes `unreadable` with `needs`.

| Check | Reads | Without root |
| --- | --- | --- |
| Distribution, kernel | `/etc/os-release`, `uname` | yes |
| Updates (apt) | `apt list --upgradable` / `apt-get -s upgrade` on the existing cache (never `apt update`), `/var/run/reboot-required`, unattended-upgrades config | yes |
| Updates (dnf) | dnf's existing metadata cache (`/var/cache/dnf/*/repodata`, enabled repos of `/etc/yum.repos.d`) and the rpm database through libdnf's hawkey bindings, with every cache and log write switched off and as `nobody`; reboot rule of `needs-restarting -r` from rpm install times vs. boot time; dnf-automatic timer. **dnf, yum and needs-restarting are never run** (even with `-C` they write logs, solv caches and per-user caches). yum hosts (RHEL 7 family): pending updates `unreadable`/`not_supported` | yes |
| Listening ports | `ss -tlnupH` or `/proc/net/{tcp,tcp6,udp,udp6}` | addresses and ports yes; process names need `CAP_SYS_PTRACE` or root (else no `process`) |
| Firewall | `nft -j list ruleset`, `iptables-save`, `ip6tables-save`, `ufw status`, `firewall-cmd --state` | needs `CAP_NET_ADMIN` (nft/iptables); ufw/firewalld state partly |
| SSH | `sshd -T` (needs root), else parse `/etc/ssh/sshd_config` and `sshd_config.d/*.conf` | partly |
| Failed logins | journal (`_COMM=sshd`, 24 h) or `/var/log/auth.log`, count only | `group:systemd-journal` or `group:adm` |
| TLS (gateway) | local certificate storage of schild/Caddy or a TLS handshake to localhost | yes (cert storage readable by the schild user) |
| Inventory | `dpkg-query`/`rpm -qa` (filtered to relevant packages), `<java home>/release`, `--version` of node/php/python3 (java only without a release file, with `-XX:-UsePerfData`), app files under configured paths only | yes |
| Logs (v0.5, D38) | `/etc/docker/daemon.json`, `/var/lib/docker/containers/*/hostconfig.json` (`LogConfig`) and the size of `*-json.log` by stat; `journald.conf` and `journald.conf.d/*.conf`, size of `/var/log/journal`; `/usr/sbin/logrotate`, the `logrotate.timer` link or `/etc/cron.daily/logrotate`, mtime of `/var/lib/logrotate/status` (RHEL `logrotate.status`), `/etc/logrotate.conf` and `logrotate.d/*`; a walk of `/var/log` by stat (depth 4, 5000 entries, 200 ms); optionally the fixed argv `systemctl show logrotate.service -p Result -p ExecMainStatus -p ExecMainExitTimestamp` | yes, except Docker containers (`needs: root`) and root-only log directories ("nicht lesbar"). Never runs `logrotate`, `docker` or the Docker socket, never reads log contents |

Never: `apt update`, `dnf`/`yum`/`needs-restarting`, package installs, writes outside the report directory, scans of other hosts, outgoing connections other than the agent's delivery.

Run as root, the check starts the package database queries (rpm, dpkg-query, the dnf metadata reader) and the runtime version probes as `nobody` (uid/gid 65534, no supplementary groups), so the kernel refuses any write they attempt (rpm's sqlite `-shm`, JVM perf data). Without `CAP_SETUID`/`CAP_SETGID` they are not run and report `unreadable` with `needs: CAP_SETUID`; they are never run as root instead.

## 5. Enrolment and revocation

Two ways to enrol an agent:

1. **One-time code (dashboard).** The admin creates a code (`POST /api/v0/agents/enrolments`, valid `enrolment_code_minutes`, default 30, once). The dashboard shows one line for the app VM: `sudo schild-agent enrol --gateway https://<gateway>:8790 --gateway-name <node_name> --pin sha256:<cert> --code XXXX-XXXX-XXXX-XXXX`. `--gateway-name` is the gateway's `node_name` (`Enrolment.gateway_name`), which every enrolment request and report must name; the URL host is not enough behind NAT or a proxy. The agent creates its key locally (mode 0600, never leaves the VM), prints its fingerprint and sends an enrolment request to `POST /v0/agent/enrol`:
   - DSSE envelope, payloadType `application/vnd.schild.agent-enrolment.v0+json`, exactly one signature **by the new key itself** (proof of possession): the signature's key id equals the payload's `keyid` and verifies with the payload's `public_key`.
   - Payload [agent-enrolment.schema.json](agent-enrolment.schema.json): `gateway`, `code`, `keyid`, `public_key`, `hostname`, `issued_at`, `nonce`; limits 16 KiB / 4 KiB; same time window and nonce rule as reports.
   - The gateway then checks the code (exists, unused, not expired; else ack `rejected` with `enrolment_code`), marks it used, and stores the agent as `pending` (ack `pending`). A public key or key id already known is rejected (`enrolment_code` is not consumed).
   - The admin compares the fingerprint (sha256 of the 32 public key bytes) shown in the dashboard with the one the agent printed and confirms (`POST /api/v0/agents/{id}/confirm`). Only `enrolled` agents' reports are accepted; a pending agent's report is answered with `signature`.
   - Verification order: `oversize`, `malformed`, `envelope`, `oversize` (payload), `payload_type`, `malformed` (payload), `forbidden_field`, `forbidden_content`, `schema`, `signature`, `test_key` (release builds), `clock_skew`, `expired`, `channel`, `replay`.
2. **Explicit public key (config).** `host_check.agents.keys[]` in `schild.yaml` lists `keyid`, `public_key`, optional `hostname`. These agents are enrolled without code and confirmation. Agent key ids and public keys share one namespace with the lab keys of `schild.yaml` (`config` on duplicates).

**Revocation list.** Revoking (`POST /api/v0/agents/{id}/revoke`, or `revoked: true` in `schild.yaml`) keeps the key in the gateway's store with status `revoked`, so a later report with a valid signature is answered with `revoked` instead of `signature` and the dashboard can say why. Revocation is immediate and permanent for that key; re-enrolling the host creates a new key. Kept reports stay visible until retention removes them. Release builds refuse test keys as agent keys like any other key ([testkeys/README.md](testkeys/README.md)).

## 6. Gateway answer (ack)

[agent-ack.schema.json](agent-ack.schema.json), unsigned JSON (the agent authenticates the gateway by the pinned TLS certificate), at most 4 KiB:

```json
{"schema":"schild.agent_ack/0.1","status":"accepted","nonce":"<request nonce>","received_at":"2026-10-26T12:00:00Z","error":null}
```

- `status`: `accepted`, `duplicate` (nonce already stored; agents treat it like accepted), `pending` (enrolment waits for confirmation), `rejected` (`error` is the contract code; do not resend the same message), `retry` (`retry_after_s` 1–86400, gateway busy).
- HTTP status: 200 for accepted/duplicate/pending, 400/401/403/409/411/413 for rejected, 429/503 for retry.
- There is no field for commands, intervals or configuration (`additionalProperties: false`), and agents ignore everything but `status`, `error` and `retry_after_s`. **The gateway never sends instructions to an agent.**

### 6.1 Listener limits (v0.3 amendment, MVP-11 review)

The agent listener must not be able to affect request handling, whatever the number of senders. The reference gateway bounds it like this (values are the defaults of `gateway/internal/hosts.DefaultLimits`):

- Connections: at most 512 open, 8 per address (IPv6: per /64); excess connections are closed at accept, before the TLS handshake. TLS handshake and headers within 5 s, idle keep-alive connections closed after 30 s.
- Bodies: `Content-Length` is required (411 `malformed` otherwise, also for chunked bodies) and checked before a single body byte is read (413 `oversize` above 768 KiB for reports, the enrolment limit for enrolments). The declared length must fit into the in-flight body budget (4 MiB shared, 2 MiB reserved for enrolled agents), else 503 `retry`. The body must arrive at 64 KiB/s or faster (deadline 2 s + length / rate).
- Verification: at most 4 at once, else 503 `retry`.
- Requests: 120 per 15 minutes per address (prefix); enrolled agents (by `Schild-Agent-Key` naming an enrolled key, or after verification) are counted on their own budget of 120 per 15 minutes instead, so a flood from other addresses does not keep them in retry. A header the signature does not back is charged to the address as well. 503 answers (the gateway's state, not the sender's doing) are not counted. Enrolment: 120 requests and 10 rejected requests per 15 minutes per address. The rate table is a bounded LRU: a flood of new addresses evicts the least recently used entries one by one and never resets the others.
- Rejection details (`last_rejected.detail`, gateway and agent logs) are value-free: the contract code and, when known, the JSON pointer of the offending place (array indices and contract field names only), never a value from the rejected message.

## 7. Gateway storage and dashboard

- Keep the last `host_check.keep_reports` reports per host (default 30); the dashboard shows the newest and the history.
- Agent free text (v0.3 amendment, MVP-11 review): `title`, `explanation` and `fix_command` of an agent report are written by the agent's binary; a compromised app VM controls them. `GET /hosts/{host_id}` adds `annotations` for agent hosts: per finding the gateway's own catalogue title and explanation (by finding id) and `fix_verified` (the fix command is one the gateway's own check produces for that id). The dashboard shows the catalogue text, marks the agent's text as "vom Agent gemeldet" and offers a copy button only for verified commands; other commands are shown with a warning and without copy.
- An agent that has not delivered an accepted report within twice its interval is **silent** ("meldet sich nicht"). Silent agents and failed checks never change the Grundschutz state and never touch request handling.
- Dashboard API (client, OpenAPI 0.3.0): `GET /hosts` (cursor list: status, silent flag, last report, open findings per severity, unreadable count), `GET /hosts/{host_id}` (newest report with findings and inventory, history, last rejected delivery), `POST /hosts/local/check` ("Jetzt prüfen" for the gateway only, 202), `GET /agents`, `POST /agents/enrolments`, `POST /agents/{agent_id}/confirm`, `POST /agents/{agent_id}/revoke`, optional `Overview.servers` for the Server card. `GET /hosts` and `GET /agents` return an empty page when `host_check` is not configured. Creating a code, confirming and revoking need session and CSRF, no password (D40). Problem codes besides the general ones: `check_running`, `check_unavailable`, `enrolment_code`, `fingerprint_mismatch`, `config_agent`.
