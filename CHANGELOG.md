# Changelog

Notable changes per release. Contract changes are in [contracts/CHANGELOG.md](contracts/CHANGELOG.md).

The section of a version becomes the text of its GitHub release, so its heading stays `## <version>`. The date of a release is the one GitHub shows.

## 0.1.0-alpha.5

### Rules

- Strictness (paranoia level) and blocking threshold of the OWASP CRS are set in the dashboard (D101): "Strenge und Schwelle anpassen" on the page of the CRS. A change holds at once, without a restart, and wins over `schild.yaml`; "Werte aus schild.yaml einsetzen" gives both back to the file. A threshold above 5 points is named on the page, because a request with a single critical hit then passes.

### Agent API

- The agent API is on by default (D103). Without a token it answers every call with 401, and tokens are still created on the server only (`schild token add`). After the update an existing gateway listens on `127.0.0.1:8789`; `agent_api: {enabled: false}` in `schild.yaml` keeps it off, and the dashboard cannot switch it on against that. If the port is taken, only this listener does not start, requests are not affected.
- The dashboard has a card "Agent-API" under Einstellungen: a switch that opens and closes the listener without a restart, the address, and the tokens with scope, expiry and last use. A value set there holds until "Wert aus schild.yaml einsetzen".
- `schild token add` needs no flags: without them the token reads only and holds 90 days. `--expires` takes 1d to 365d as before.
- Docker: the agent API can be reached from the host. `agent_api.listen` also takes `0.0.0.0:8789`, and the quickstart files publish the port on `127.0.0.1` of the host. Outside a container schild does not open a listener on every interface. An existing installation adds `agent_api: {listen: "0.0.0.0:8789"}` to `schild.yaml` and `"127.0.0.1:8789:8789"` to the ports in `compose.yaml`.
- The docs describe the setup step by step under "Agent-API einrichten", and the features page says what an agent does with it.

### Server check

- `schild check install` sets the server check up with one command (D100): as root on the host it writes the systemd units from the binary, enables the daily run and "Jetzt prüfen" and runs the first check. For a gateway in Docker: `docker cp <container>:/usr/local/bin/schild /tmp/schild && sudo /tmp/schild check install`. `schild check uninstall` removes the units. The docs describe it under "Server-Check einrichten".
- "Jetzt prüfen" no longer gets stuck when `schild.yaml` does not load: the check removes the request before it reads the config.
- A server without any firewall rule and without iptables is reported as "Keine Firewall auf dem Server aktiv" instead of "nicht lesbar".
- The dashboard names the install command where the server check is not set up yet, and the overview shows the Server card only once a report exists.
- Findings can be marked as accepted in the dashboard, with a note (D102): for example an open port that a firewall in front of the server closes. An accepted finding no longer counts as open, stays listed and can be opened again; it is open by itself when the check reports it with a higher severity.
- `schild init` and the quickstart files turn the Server section on (`host_check: {}`); the compose templates carry the mounts of the server check as comments.
- A report written in the same second as the one before is no longer skipped by the gateway.
- Findings about open ports say what the check can know: a service listens on a public interface and "könnte von außen erreichbar sein". Whether a firewall on the server or at the hoster closes the port, the check cannot see from inside; the text says so and points to accepting the finding. "Keine Firewall auf dem Server aktiv" names the firewall of the hoster the same way.
- The results of the server check are one list in the dashboard: one line per check with level, title, area and the main fact, the detail opens on click. The list can be searched (title, explanation, port, package, path) and filtered by state (open, not readable, accepted, in order) and area. The installed software has its own section.

### Upgrade

- From 0.1.0-alpha.4: change the image tag, run `sudo apt update && sudo apt install schild` and `sudo systemctl restart schild`, or replace the binary and restart. `schild.yaml` and `schild.db` need no change.
- After the update the agent API listens on `127.0.0.1:8789` and answers 401 without a token. `agent_api: {enabled: false}` in `schild.yaml` keeps it off.
- The server check is new to set up: `sudo schild check install` on the host. With Docker, copy the binary out of the container first and add the two mounts and the variable the command prints; the docs describe it under "Server-Check einrichten". With the check set up by hand before, run the command once as well: it replaces the units.

## 0.1.0-alpha.4

### Release

- `checksums.txt` is signed with cosign (keyless). The release carries the signature as `checksums.txt.sigstore.json`; it covers every archive and package the file lists. The command to check it stands in the release notes and in `SECURITY.md`.
- The build provenance is attached to the release as a file, `provenance.sigstore.json`, for checks without access to the GitHub API. `gh attestation verify` works as before.
- From this release on the release tag is signed by the maintainer who sets it. The tags of 0.1.0-alpha.1 to 0.1.0-alpha.3 are annotated and not signed.
- The base images of the build are pinned by digest, and the build gets pnpm through corepack.

### Docs

- The installation docs describe the package for Debian and Ubuntu: installing with the installer script or by hand, both cases (schild as your Caddy, schild behind your web server), updating through apt, removing. README and start page name the package as one of the ways to install.

### Upgrade

- From 0.1.0-alpha.3: change the image tag, run `sudo apt update && sudo apt install schild` and `sudo systemctl restart schild`, or replace the binary and restart. `schild.yaml` and `schild.db` need no change. The gateway itself is the one of 0.1.0-alpha.2.

## 0.1.0-alpha.3

### Packages

- Debian and Ubuntu packages (MVP-31): every release carries `schild_<version>_linux_amd64.deb` and `schild_<version>_linux_arm64.deb`, listed in `checksums.txt` and covered by the build provenance. One package serves Debian 12 and 13 and Ubuntu 22.04 and 24.04. It installs `/usr/bin/schild`, both systemd units and the geo data, creates the user `schild`, and starts nothing. An upgrade replaces the files and never restarts the service; it names `sudo systemctl restart schild`. `apt purge` deletes `/etc/schild` and `/var/lib/schild`.
- From this release on the release workflow publishes a signed apt repository with the channels `alpha` and `stable` and an installer script under `https://pkg.deutschland-schild.de`. The installation docs name it once it is checked against this release.

### Upgrade

- From 0.1.0-alpha.2: change the image tag (or replace the binary) and restart. `schild.yaml` and `schild.db` need no change. The gateway itself is the one of 0.1.0-alpha.2; this release adds the packages.
- A server installed from the tarball stays as it is. The package puts the binary to `/usr/bin/schild` and the units to `/usr/lib/systemd/system`; moving an existing tarball installation to the package is not described yet.

## 0.1.0-alpha.2

### Gateway

- A second `Content-Type` header no longer gets a JSON body past the depth and syntax check: the body is checked for every value that picks a parser, not only for the first. Values the rules read as JSON but Go does not (`application/json x`, `application/a+json-seq`) are checked as JSON too.
- Bodies of an `application/…+xml` type (`application/atom+xml`, `application/vnd.x+xml`) go through the XML parser like `application/xml`.
- A `;`, a bad escape or a parameter sent twice no longer hides a login from the scenarios and limits: `/wp-login.php?action=lostpassword&action=login` counts as a login attempt, a preset limit on `task=reset.request` holds with other parameters around it, and of a user name field sent twice the last one counts, as in PHP.
- On `/wp-login.php` the action is read as WordPress reads it: from the body over the query, and a value WordPress does not know is a login. `?action=register` with `action=login` in the body, or `?action=anything`, no longer keeps login attempts out of `login_bruteforce`, `credential_stuffing` and `account_wave`. Lost password, registration and the other actions stay no login attempts in the form WordPress sends them; a body schild cannot read as a form (multipart) counts as a login attempt.
- A trusted proxy is never blocked or limited itself. When its forwarding header names no client, the request is attributed to the proxy, and a block there would have hit every visitor behind it. Trusted is loopback only unless `ingress.trusted_proxies` names more: a proxy or load balancer on another host or in a Docker network belongs there.
- `route_wave` and `inconsistency` need at least 3 senders in the window: one client alone can no longer tighten a login route for everyone.
- A client that names a search engine in its User-Agent but comes from outside that bot's published ranges is treated by `aggressive_crawl` like any other client. Without fresh ranges for the bot nothing changes: counted, not acted on.
- Requests with a `Host` no website has no longer push the crawl baselines and learned session cookies of real websites out of the tables.
- `schild firewall run` builds its table again only when the table is gone. Before, any error while writing the blocks rebuilt it, which emptied a table that was intact.
- The firewall gets no block that shares an address with Eigene IPs, a trusted proxy or the server itself, also when only one address of a blocked IPv6 /64 is yours: the firewall drops before schild could let it through.
- IPv6 blocks go into the firewall sorted and without overlaps. /64 blocks side by side become one interval, and `schild firewall status` and "Sperren" still list and count each of them.
- Bot range lists are refused when they redirect to another host, name a private, loopback or link-local range, or a range wider than /16 (IPv4) or /32 (IPv6). The ranges fetched before stay in use.
- The agent API names the client address (D99): `ip` on events, incidents and requests for as long as the gateway keeps the address (`retention.raw_ip_days`), next to pseudonym and /24, and an `ip` filter on `listAgentEvents` and `queryRequests`. A block is still named by event, incident or pseudonym, never by address. The API document is shorter and matches the code: the `filter` parameter, the error codes `busy`, `no_snapshot` and `filter_unavailable`, "profile" instead of "mode" in `getAgentStatus`.
- At a full connection limit the search for an idle connection to close looks at 64 connections instead of 16.
- The live numbers of one website (`/monitoring/now?site=…` and the website list) are over 60 seconds from the website's first request on. In its first minute after a start they named a window of 10 to 50 seconds, which the API document does not allow, and rates up to six times too high.
- A start that `schild run` refuses (a Caddyfile it does not accept, a port in use) ends like a run: background work stopped, events written, stores closed. Before, it returned while that work was still writing into the data directory.

### Upgrade

- From 0.1.0-alpha.1: change the image tag (or replace the binary) and restart. `schild.yaml` and `schild.db` need no change.
- With `schild firewall run`: update it together with the gateway, both come from the same image.
- An agent that reads the agent API now gets client addresses. With a cloud model, everything the agent reads leaves the server; `retention.raw_ip_days` sets how long the gateway keeps an address.
- On a WordPress site more requests count as login attempts than before: a POST to `/wp-login.php` with a body schild cannot read as a form, or with an action WordPress does not know.

## 0.1.0-alpha.1

First public alpha of the Schild Gateway.

### Gateway

- The first gateway version has no labs features (D72): no signals or feedback, no network rules, bundles, withdrawals or relay stream, no review queue of network recommendations. The config keys `network`, `channel`, `labs`, `min_independent_operators`, `test_profile`, `relays`, `remote_rules`, `signals`, `site_key` and `behaviour.distributed.wave_hint` are refused as unknown keys; delete them (also `network: {enabled: false}`) from `schild.yaml`. The dashboard pages Verbund, Freigaben and Signale are gone. `schild-lab` and `schild-relay` stay planned parts.
- The default way in is the Caddy swap (D79): `schild init -caddyfile FILE [-caddy-storage DIR]` writes a starter `schild.yaml` with which schild runs as your Caddy: schild is a Caddy distribution with the WAF module built in. It loads the same Caddyfile and starts with a copy of Caddy's certificates in `/var/lib/schild/caddy`, so nothing is issued again and Caddy's own storage is never changed. init lists the sites, the lines the Caddyfile still needs (the snippet `(schild)` and `import schild` per site with a backend), the copy commands, the swap and the way back. It never edits the Caddyfile. `-caddyfile` and `-upstream` exclude each other.
- `schild ingress validate` prints the lines to add when a site lacks `schild` and then checks, as the current user, what would break after a swap (D79). It refuses (`result: REFUSE`, exit 1) a data directory this user cannot write, where the lock and the databases go; a certificate storage that exists but that this user cannot read or write, also behind a symbolic link, with the `chown` command (in a container one numeric `chown` for the whole data volume) and the consequence in plain words (cannot read: no start or failing sites; cannot write: no renewal); a log file of the Caddyfile this user cannot write; and, under systemd, a log file outside the `ReadWritePaths` of `schild.service`, with the drop-in to add. When systemd runs but the unit cannot be read or is not installed, such a log file is a warning that says which of the two, and the result is `PASS with warnings`. The full check ends with one result line and keeps Caddy's provisioning log lines off the terminal. The full check also runs in a container with a read-only root file system (its temporary directory falls back to the data directory). `-adapt-only` reads the Caddyfile only: no data directory, no certificate storage, no provisioning, no file access. The whole report is on stdout; a refusal is no longer repeated on stderr.
- `schild init [-config FILE] [-upstream URL] [-node-name NAME] [-force]` writes a starter `schild.yaml` for schild behind a web server (D78). It never overwrites an existing file without `-force` and does not write through a symlink.
- `schild dashboard setup-code` prints the one-time code for the first login again while no password is set (D78). The start log keeps the field `setup_code` and adds `dashboard_url`.
- The store migrates itself (D75): `schild run` brings `schild.db` to the schema of the binary in one transaction and writes the copy `schild.db.backup-v<N>` first. A database of a newer schild or of a build before this release is refused with a message that names the file; nothing is written. Other commands never migrate and ask for a restart.
- The dashboard checks the `Host` header against DNS rebinding (D76). It answers under `localhost`, any IP address, the host of `listen.dashboard` and the names in the new config key `dashboard.allowed_hosts`; any other name gets 403 with the line to add.
- The session cookie works over plain HTTP in a tunnel or VPN (D76): `Secure` whenever the request came over HTTPS, not on loopback, and not when the browser itself states it loaded the dashboard over plain HTTP.
- Test-lab switches do nothing in release builds (D77): `SCHILD_HOST_AGENTS`, `SCHILD_WAF_MAX_EVALS`, `SCHILD_WAF_QUEUE_WAIT_MS`, `SCHILD_EVENTS_NDJSON_DIR`, `SCHILD_CROWDSEC_HUB_URL` and `SCHILD_ALLOW_TEST_KEYS` are ignored.
- Operator rules cannot switch the rule engine or the request body off (D80). `SecRuleEngine`, `SecRequestBodyAccess`, `SecRequestBodyLimit`, `SecRequestBodyNoFilesLimit`, `SecRequestBodyInMemoryLimit`, `SecRequestBodyLimitAction` the actions `ctl:ruleEngine`, `ctl:requestBodyAccess`, `ctl:requestBodyLimit` and `Include` in `rules.d` are refused at start and at a sync, with the reason. Before, such a rule made schild pass an empty request body to the backend. To leave a path out of the CRS use `ctl:ruleRemoveByTag=OWASP_CRS`.
- The server check judges the firewall for IPv6 too (D81). When the host has a public IPv6 address and only IPv4 is filtered, `firewall.active` and `firewall.default_incoming` are findings instead of ok. With iptables the check also reads `ip6tables-save`.
- The event list of all websites names the website of every row.
- An address without a known country (127.0.0.1, private ranges) shows a globe icon instead of the letters ZZ as a broken flag.
- Less is redacted (D85). The User-Agent is stored as sent: an app name with a build number no longer reads `[redacted]`. In paths, query values and rule messages only values that look random count as tokens (32 characters or more, digits and letters mixed), so long slugs and file names stay readable. Parameter names like `zipcode`, `country_code` or `monkey` no longer count as secret. Passwords, tokens, JWTs and e-mail addresses are redacted as before.
- The page "Server" no longer shows the container image ("Distroless") as the operating system. In a container without a host report it shows the kernel's name (Linux); with a host report it shows the server's distribution as before.
- Rule exceptions are set and removed in the dashboard (D84), no longer only through the agent API: "Ausnahme anlegen" under "Eigene Regeln und Ausnahmen", in the detail of an event next to the rule that hit, and on a possible false positive, where the form opens filled. The page "Eigene Regeln" is now "Eigene Regeln und Ausnahmen", with two tabs, "Eigene Regeln" first and "Ausnahmen" behind the second, which also lists the possible false positives of all websites; the overview of the rules counts the exceptions. The page "Ausnahmen" of a website is gone, its address leads to that tab. Exceptions for the same field are one entry in the list, however many parts an agent had to set: the rules together, grouped by what they look for, removed with one click.
- Single rules come out of a rule exception (D86): an × next to each rule number in the dashboard, `rules` in the body of `removeAgentException` for agents. The exception stays for the other rules with its reason and author; the last rule out removes it.
- The dashboard says that the mode is about single requests and that only the scenarios block an address for a while: a line under "Modus" with how many scenarios block and a link to them, a note on "Szenarien" while none blocks. "Automatisch sperren" and "Freigeben" say that the rules block requests, not addresses.
- The sidebar of a website or a server lists only its own pages. Schutz (Regeln, Verhalten & Limits, Eigene IPs) and Einstellungen hold for all websites and stand under "Alle Websites"; their pages no longer keep the last website in the switcher.
- The password page of an access lock has no line above the password field; the line stays where a page holds its own text above a second part "Mit Passwort weiter".
- A maintenance switch on the page "Zugriffsschutz" of a website: everyone gets the maintenance page "Wir sind gleich wieder da." with 503, only Eigene IPs get through, with an optional text. It is a whole-website access lock with Eigene IPs as the way in; while another protection is set, the switch stays off and says so.
- The website cards on "Alle Websites" show the last 24 hours (requests, share stopped, response time) instead of the last minute, which is empty most of the time on a small website. "p95" is gone from the visible copy: "Antwortzeit" with "95 von 100 Anfragen waren schneller", and the latency chart names its lines that way.
- Every blocked address in one list (D87): the new page "Sperren" shows each address schild blocks now, with reason, duration, incident and a button to lift it, and the stopped requests of all websites with the search for an incident number. "Szenarien und Limits" moved below "Regeln"; "Verhalten & Limits" and the page "Vorfälle" are gone, their old addresses lead to the new pages.
- Blocks go into the server's firewall when you want (D87): `schild firewall run`, the same image as its own small container with `NET_ADMIN` (or a systemd service), asks the agent API for the running blocks (new scope `firewall:sync`, a long poll) and keeps its own nftables table `inet schild`, which drops the traffic of blocked addresses to the ports 80 and 443 until each block ends. A block or a lift reaches the firewall within a second; "Sperren" shows per address whether the firewall holds it. `schild firewall status` and `off`; a Compose service and a Kamal example are in the docs.
- Unblocking an incident in the dashboard ends its timed block, not only for this client's requests: the address leaves the list of blocks and, within a second, the firewall. "Freigeben" on "Sperren" opens the same unblock (false positive or not, the address as an own IP if wanted).
- Addresses are blocked by hand in the dashboard (D88): "Adresse sperren" on "Sperren", on an event and on an incident, for 1 hour, 24 hours or 7 days with a reason. The block reaches the firewall within a second like any other. Own IPs, the server and private addresses are refused; mobile, CGNAT and Tor addresses need a confirmation.
- One click blocks the address of an event, an incident or a row of "Ereignisse" and "Zugriffe": data-centre addresses for 7 days, every other address for 24 hours, with the event as reason and "Rückgängig" in the notice. Another duration and "Zu Eigene IPs hinzufügen" sit in the "…" menu beside it; rows of addresses already blocked or on Eigene IPs offer no block.
- A request a rule stopped no longer reads "Gesperrt": its incident is "Anfrage gestoppt", "Durchlassen" lets the person pass those rules for 24 hours, and the address can still be blocked. A blocked address has "Sperre aufheben"; the dialog says that it ends on every website of the server and that the rules let the address pass for 24 hours. Adding the address to Eigene IPs is off by default there.
- The page "Schutzstatus" is part of "Einstellungen › Allgemein": the 24-hour numbers, what blocks, the top patterns and the version. A box at the top appears only when the Grundschutz is degraded or off.
- The login page names the right command for a forgotten password (`schild dashboard reset-password`), the setup page `schild dashboard setup-code`.
- No protection mode any more (D89): each rule source (OWASP CRS, CrowdSec Hub, own rules), each scenario and each limit has its own switch, and nothing sits above them. The dashboard drops the mode from the header, the overview, the settings and the setup; "Einstellungen" shows where each source stands. Rule updates from the CrowdSec Hub are no longer approved one by one: they only detect for the settling time and then block on their own while the hub is set to block. Only the test profile blocks nothing. A `mode` line in an older `schild.yaml` is ignored with a warning; `mode: observe` sets the rule sources it leaves open to "erkennen". New installations start with the CRS blocking; set `rules.crs.state: detect` for a careful start.
- A rule source on "Erkennen" shows its matches as "Erkannt" in the dashboard, with the reason "Regelquelle steht auf Erkennen" (D90). Before they read "Notiert", and the filter "Erkannt" showed nothing for them. A CrowdSec update that still settles says "Update wartet noch".
- The dashboard says when a proxy in front is not trusted (D91): "Schild sieht nur die Adresse deines Proxys". Behind nginx on the Docker host every visitor counted as the Docker bridge address and no scenario could block anyone. The Docker quickstart now publishes port 8080 on 127.0.0.1 only and trusts the Docker networks; the docs explain `ingress.trusted_proxies` for Docker, load balancers and Cloudflare and show the nginx and Apache lines.
- `schild init -upstream` writes `listen.proxy: "127.0.0.1:8080"`: only the web server on the same machine reaches schild. Before, port 8080 listened on every interface.
- The quickstarts and the release README no longer say that schild starts in observe mode and blocks nothing: the OWASP CRS and your own rules block from the start.
- Scenario defaults (D92): four of the five scenarios (`login_bruteforce`, `credential_stuffing`, `path_probing`, `waf_repeat`) default to `block` and act after the 14-day learning period; `aggressive_crawl` defaults to `observe`. The dashboard marks the recommendation on each switch and can apply it in one click.
- Browser check and Under Attack per website (MVP-12): "Kurze Prüfung", a short proof-of-work page served by the gateway itself, with a button for browsers without JavaScript, no third party and no tracking. Off by default; "Bei Auffälligkeiten", "Immer" or, for at most 24 hours, Under Attack for the admin and login pages or the whole website. Only page views are checked: APIs, POSTs, assets, verified good bots and your own addresses always pass. Dashboard: the website's "Zugriffsschutz".
- Scenario thresholds are set in the dashboard (D93): "Schwelle anpassen" at every scenario, with the built-in value next to it. They were configurable in `schild.yaml` only.
- "Szenarien und Limits" shows one status on the page "Regeln" (D94), and says "Würde sperren" during the learning period instead of counting scenarios as blocking.
- Preset rate limits are switched one by one (D95, `behaviour.preset_limit_modes`). Left open, the limits for login, password reset and `xmlrpc.php` limit from the first day; search, contact forms and API writes only count. A route several systems share (`/login`, `/api/**`) is listed once under a neutral name.
- The maintenance mode works together with an access protection (D98). It is a switch of its own: it closes the whole website for everyone outside your own IPs, also when single paths are protected by a password, and that protection stays as it is. Before, the protection had to be removed first. A protection that was the old maintenance switch becomes the maintenance mode at the next start.
- The event list shows a blocked address as what it is: "IP gesperrt" with the address, where it comes from, the incident and the result "Gesperrt". The same for a scenario hit and an exceeded limit. Before, such a row read "Hinweis, Ereignis" with every other column empty. Every event type has its German name.
- "Alle Websites" shows the stored 24-hour numbers of every website right after a restart. Before, a card stayed empty until the website's first request since the start, and a quiet website read "unbekannt"; it now reads as quiet once the gateway has run for five minutes.
- The detectors of distributed attacks ("Wellen") are set under "Regeln › Szenarien und Limits › Wellen" (D97), each with its switch and "Schwelle anpassen". The waves they found are listed in the same tab. Both stood under "Sperren", and the thresholds were configurable in `schild.yaml` only.
- The list of limits shows what is requested on this server (D96): every limit counts the requests that fall under it, and preset limits on their recommendation without a request in 24 hours are folded away until asked for.
- The dashboard shows the running version at the foot of the sidebar, a test build marked short.
- The dashboard lists the rule exceptions in force (D83): under "Eigene Regeln", on the repository they belong to and under "Ausnahmen" of the website, with field, reason and the rules left out. Until now only the agent API showed them.
- The detail of a CRS rule shows the rule as written, with its chained rules and the CRS file it comes from (D82), in the dashboard and the agent API. The dashboard shows the rule text of every repository open, with copy and download.
- Dashboard: a behaviour hit of a scenario that only counted says why nothing was blocked (the scenario has its own switch, independent of the gateway mode) and can set the scenario to block from there. Detail panels are wider on large screens and step to the previous and next entry with buttons or the keys K and J.
- Dashboard settings that no longer fit a changed `schild.yaml` are reported (baseline reason `dashboard_settings_dropped`, `schild status`, `schild preflight`) instead of being dropped silently (D78).

### Packaging and release

- Container image `ghcr.io/deutschland-schild/schild:<version>` for linux/amd64 and linux/arm64, published by the release workflow on a tag `v<version>`. There is no `latest` tag for pre-releases. The image is signed with cosign (keyless) and carries an SBOM and build provenance.
- Release tarballs `schild_<version>_linux_amd64.tar.gz` and `schild_<version>_linux_arm64.tar.gz` with `checksums.txt` (sha256) and a GitHub build attestation. Each holds the static binary `schild` (the one in the image), the hardened systemd units `schild.service` and `schild-firewall.service`, the geo data, `LICENSE`, `NOTICE`, `THIRD_PARTY_LICENSES` and `README.txt`.
- Docker quickstart in `gateway/deploy/quickstart` (`compose.yaml`, `schild.yaml`): one locked-down container in front of your application, the dashboard on the host's `127.0.0.1:8788` only.
- Docker quickstart for the Caddy swap in `gateway/deploy/quickstart/caddy` (`compose.yaml`, `schild.yaml`): the same locked-down container on ports 80 and 443 with your Caddyfile; a one-shot service copies Caddy's certificates into schild's volume.
- systemd unit `docs/ops/systemd/schild.service`: runs `schild run -config /etc/schild/schild.yaml` as the user `schild`, writable only below `/var/lib/schild` and, for the log files of a Caddyfile, `/var/log/caddy` when it exists. One unit for both setups; ports 80 and 443 through `CAP_NET_BIND_SERVICE` only.
- Every published artifact is a release build (test keys and the test profile are refused) with the dashboard built in. The image build makes the dashboard itself and stops without it. A plain `docker build -f gateway/Dockerfile .` is a release build too; dev images (`make gateway-image`, `make images`) are labelled `de.deutschland-schild.build=dev` and never published.
- The image build needs only `contract/`, `gateway/` and `dashboard/`, no lab or relay sources.
- The DB-IP Lite geo data in the image is pinned to one month and checked by sha256 in every build.

### Upgrade

- First release, nothing to upgrade from. A `schild.db` of a build before this release is refused at start: move the file away, schild creates a new one and shows a new setup code.
- A dashboard opened under a DNS name (own reverse proxy, VPN name) needs that name in `dashboard.allowed_hosts`.
