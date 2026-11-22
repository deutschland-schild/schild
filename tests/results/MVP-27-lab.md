# MVP-27 group of gateways on real VMs: independent lab measurement

Measured 2026-11-22 by a measuring agent, not by the builder. Black box: the gateway was driven through its binary, `schild.yaml`, the Caddyfile, its listeners, its command line and the documented dashboard API, as [contracts/cluster.md](../../contracts/cluster.md), the operator guide [docs/gateway/03-cluster.md](../../docs/gateway/03-cluster.md), the OpenAPI files and `schild -h` describe them. No source of the gateway was read.

- Harness: [tests/testlab/measure/group-lab](../testlab/measure/group-lab/README.md), rerun with `SCHILD_LAB_HOST=<alias> tests/testlab/measure/group-lab/run.sh` (about 40 minutes).
- Build: development build of `e0349dc` for linux/arm64 (a test binary, never a release). Machine-readable: [MVP-27-lab.json](MVP-27-lab.json). Seed 27.
- 165 checks: 114 PASS, 19 FAIL, 32 numbers without a pass mark. Scenario 1 (pair behind HAProxy) 39: 4 FAIL. Scenario 2 (network faults) 41: 0 FAIL. Scenario 3 (clocks) 40: 8 FAIL. Scenario 4 (edge) 20: 0 FAIL. Scenario 5 (sixteen gateways) 15: 1 FAIL. Scenario 7 (certificates) 10: 6 FAIL. Scenario 6 (mixed versions) was not measurable, see below.
- The loopback measurement of the same day ([MVP-27-group-measurement.md](MVP-27-group-measurement.md)) covers what is not repeated here: hostile records, join codes, pause, erasure, rate limits.

## What this is and what it is not

Nineteen Linux VMs on one lab host (10 cores and 24 GB of memory; each VM has its own kernel 6.18, its own address and its own packet filter): sixteen gateways, each `schild run` as the web server (ingress mode) with the files of the guide, one balancer VM with HAProxy 3.0 in TCP mode (health check `GET /.schild/readyz`, PROXY protocol v2), one application VM, one client VM. Visitors come from 203.0.113.0/24 with real packets from those source addresses. Groups are set up by configuration (`cluster.secret_file`, `cluster.peers`), the same files on every node.

It is not the testlab of the spec (profiles `pair` and `fleet`): no keepalived, one balancer VM instead of two, all VMs on one host and one virtual switch (0.5 ms round trip; delay and loss are injected), a Python load client of a few hundred requests a second. Blocks are set by hand in the dashboard API (7 days); scenarios, limits and waves need 14 days of learning before they block. The verdict in the JSON cannot be `pass`; it is `fail` because of the checks below. What a hit kill criterion means is for people to decide.

Three things of the lab host differ from what the task assumed, none of them a matter of schild:

- **No netem.** The kernel of the VMs has `CONFIG_NET_SCH_NETEM` not set (`tc qdisc add ... netem`: "Specified qdisc kind is unknown"). Delay is done by a small tool of the harness that holds each IP packet a node sends to its peers (TUN device, raw socket; `ping` between two nodes shows 101 ms at 50 ms each way and 402 ms at 200 ms). Loss, partition and the one-way cut are nftables rules.
- **The clock of a VM does not stay where it is put.** The hypervisor sets it right again about every 30 s. The harness keeps a shifted clock in place (checked every 2 ms); a shifted clock is therefore right for a few milliseconds every 30 s. Two earlier runs of scenario 3 without this were thrown away.
- **Network and builder.** The builtin container network of the host carried no packets (no carrier in the VMs, no bridge on the host) and VMs have no route to the internet, so the image is built on the developer machine with Docker and loaded on the host, and the VMs are on a network of the harness (192.168.65.0/24, MTU 1280).

## Failures

### F1. The guide's "only `listen` differs" gives every node the same name (FAIL, 1.05; 3 of 3 runs)

Guide, "Einrichten mit einer Konfigurationsdatei": "Nur `listen` unterscheidet sich von Server zu Server." The guide never names `node_name`. A `schild.yaml` without it is refused (`missing property 'node_name'`, 1.01), so a deployment that writes the same file to every node gives all of them one name. Measured with `node_name: web` on both nodes of the pair:

- `schild cluster status` lists two rows `web`, told apart by address and id only.
- `schild cluster remove web`, the form the guide shows (`schild cluster remove web-3`): `schild: cluster: 2 members are named "web", use the node id`, exit 1 (1.35).
- The block list of the other node names the deciding node as `"node": "web"`, which is its own name too (1.14), so "welcher Server sie entschieden hat" cannot be read from it.

Everything else worked with equal names. All other scenarios give each node its own `node_name`.

### F2. "Freigeben" on another node answers 404 while that node already lists the block (FAIL, 1.12b)

Block on one node of the pair, then on the other node: wait until `GET /api/v0/blocks` lists the block, read its incident number, `POST /api/v0/incidents/<incident>/unblock` at once.

- Final run: 404 in 25 of 30 tries; the same call answers 200 between 68 ms and 790 ms later (median 538 ms).
- Run before: 404 in 23 of 30 (200 after 235 to 776 ms). First run, with a pause of 0.2 to 1.2 s between block and lift: 404 in 5 of 30.

The block itself is on the other node after 196 ms at p50 (1.11). A person who clicks "Freigeben" on the dashboard of another node within the first second gets "not found" for a block the page shows. The loopback report noted the same as a surprise (0.08 to 1.16 s). Reproduce: `run.sh s1`.

### F3. A planned stop cuts requests on kept-alive connections at the end of the delay (FAIL, 1.30, 1.33, 5.13; in 6 of 6 stops of a pair and in the rolling restart of sixteen)

Guide: "So schickt der Balancer neue Verbindungen woanders hin, bevor eine einzige abgewiesen wird." Spec, `must`: "a rolling update of every node under load fails no request". For new connections this held everywhere: 0 of 4 887 and 0 of 4 844 requests failed during `schild cluster drain` and SIGTERM of one node of the pair (1.29, 1.32), 0 of 69 470 during the rolling restart of sixteen (5.12), requests of 1.5 s in flight included.

Connections a client keeps open through the balancer (HTTP keep-alive, 10 connections at 5 requests a second each; HAProxy in TCP mode keeps such a connection on its node whatever the health check says) are closed by the node when the delay ends, between requests and without a word before:

| Stop | Requests on kept connections | Closed without an answer | When, after the stop began |
| --- | --- | --- | --- |
| `schild cluster drain`, pair, three runs | 1 222, 1 224, 1 232 | 7, 6, 3 | 15.10 to 15.28 s |
| SIGTERM, pair, three runs | 1 220, 1 217, 1 221 | 5, 5, 3 | 15.02 to 15.18 s |
| rolling restart of sixteen (`delay_s` 5) | 13 906 | 17 | at each node's stop |

Each of them was answered 200 when the client sent it again on a new connection. An answer during the 15 s of delay carries no `Connection: close` (probe on a kept connection: no such header), so a client has no way to leave in time. Whether that counts as a failed request is a matter of the client: a browser sends an idempotent request again, an API client with a POST may not. Reproduce: `run.sh s1`, `run.sh s5`.

### F4. Clocks: no hint anywhere, and a node whose clock is 90 s behind reports ready and active while it takes nothing from the group (FAIL, 3.16, 3.26, 3.36, 3.46, 3.50; 3.23, 3.43 and 3.62 are what the 60 s rule does)

The guide does not mention clocks. The contract (section 4, check 4) refuses a record whose time is more than 60 s ahead of the receiver; the spec says "`schild cluster status` reports a skew over 5 s". Measured with n3 of three nodes shifted, each step on a fresh group:

| n3 | Blocks set on n3 act on n1, n2 | Blocks set on n1 act on n3 | Lifts across | Logins across | Dashboard and readiness of both |
| --- | --- | --- | --- | --- | --- |
| 30 s ahead | yes, p95 251 ms | yes, p95 44 ms | all lifted | valid within 0.5 s | active, ready |
| 30 s behind | yes, p95 258 ms | yes, p95 44 ms | all lifted | valid within 0.5 s | active, ready |
| 90 s ahead | none within 4 s; each acts 30.4 to 31.2 s after it was set | yes, p95 251 ms | a lift made on n3 does not act on n1 and n2 within 8 s | a login on n3 is not valid on n1 within 6 s | active, ready |
| 90 s behind | yes, p95 221 ms | none: n3 serves all five addresses, n2 refuses them | a lift made on n1 does not act on n3 | a login on n1 is not valid on n3 | active, ready |

- **The 60 s rule holds as written.** At 30 s nothing is refused. At 90 s ahead every block of n3 is taken by n1 exactly when its time comes within 60 s of n1's clock (30.4 to 31.2 s after it was set, five blocks set 4.5 s apart). At 90 s behind n3 puts off everything the others write, for as long as its clock is behind.
- **Nothing tells the operator (3.16, 3.26, 3.36, 3.46).** In all four cases both dashboards say `active` with every member `ok`, `/.schild/readyz` answers 200, and `schild cluster status` has no line about a clock. The one trace is a counter: "Since the start: 15 records taken, 0 refused, 232 put off (clock or unknown origin)", on the node that puts off. The log of that node has no line about it either (`grep -E 'clock|ahead'` on its log: nothing).
- **A node that starts with its clock 90 s behind answers ready without the state of the group (3.50).** n3 was killed, an address was blocked on n1, n3 started: `/.schild/readyz` answers 200 after 1.2 s and n3 serves the blocked address, at that moment and 3 s later. Contract section 10: 503 "until the node took the records of the group from a member once". When the clock is set right, n3 holds the same blocks as n1 after 0.63 s (3.51).
- **A node that was 90 s ahead and is set right, then falls 90 s behind (3.60 to 3.62, same processes):** after the correction it takes a block of n1 after 0.3 s; 30 s behind it takes blocks within 1 s; 90 s behind it takes none.

Consequence for a balancer without stickiness: behind a node whose clock is more than a minute off, a block or a lift made on one dashboard is missing on a part of the nodes, and a login is valid on a part of them, while every dashboard shows the sync as active. Reproduce: `run.sh s3`.

### F5. A TLS site: port 80 does not take the PROXY protocol, and the readiness answer there is a redirect (FAIL, 7.02; every run)

Guide: "Lass den Balancer `/.schild/readyz` auf den Web-Ports abfragen", and for the client address the block `servers { listener_wrappers { proxy_protocol { allow ... } tls } }`. With a site that has a certificate from a CA (`cert.sg27.test { import schild ... }`, the usual case: "TLS endet auf den Gateways") and exactly that block:

- Port 80 is a listener of its own (log: `server running, name schild_redirects`). A balancer that sends a PROXY header there gets `400 Bad Request` (in one run the connection was closed). Without the header `/.schild/readyz` answers `308` to `https://cert.sg27.test/.schild/readyz`, never 200 or 503.
- The readiness answer exists on port 443 only, over TLS. Before the node has its first certificate the handshake fails (`tlsv1 alert internal error`), so a balancer that checks readiness there keeps a new node out, and the CA cannot reach it on port 443 (`Failed to connect to <balancer>:443 for the tls-alpn-01 challenge`).

What worked, and what the harness therefore uses in scenario 7: port 80 without the PROXY protocol and with a TCP check, port 443 with PROXY v2 and `check-ssl`, `check-sni`. The guide says none of this. Scenarios 1 to 5 use a plain HTTP site on port 80, where the block of the guide works as written.

### F6. Certificates: a node asks the CA before it asks the group, and the CA's check is not answered by the other node (FAIL, 7.04, 7.05, 7.08, 7.09, 7.10)

ACME test server pebble 2.8.0 on the application VM; it checks `cert.sg27.test` through the balancer (round robin over the nodes that are up). Guide: "Eine Bestellung pro Zertifikat. Die Prüfung der Zertifizierungsstelle klappt, egal auf welchem Server sie landet." Contract section 5: "At its first sync a node hands over what its storage holds and the group does not: certificates from before go with it, none is ordered again."

- **One node alone works (7.03).** n1 with n2 down: certificate 6.8 s after its start, one issued, and from then on ready on port 443.
- **A node that enters a group which holds the certificate asks the CA at once (7.04, 3 of 3 runs).** n2 started with an empty storage while n1 held and served the certificate: `lock acquired` and `obtaining certificate` in the same millisecond, the CA got its first order from n2 0.21 s after the start of n2 (orders at the CA 2 before, 4 after), its first sync with n1 came about a second later. The order failed, because the CA's check landed on n1: "The key authorization file from the server did not match this challenge ... != "ok xff=192.168.65.6"". n1 redirected the check to HTTPS and handed it to the application.
- **It shows the group's certificate a minute late (7.05, 3 of 3 runs).** The certificate file was on the disk of n2 within seconds, TLS on n2 failed for 61.6, 61.7 and 61.8 s, until its second try. No second certificate was issued. A restart of n2 alone afterwards serves the certificate after 0.3 s without an order (7.07).
- **The CA's check on the other node (7.08, 3 of 3 runs, and 3 of 3 in the run before).** The CA down at first, n1 started, n2 started 20 s later, the CA up at 30 s; n1 tries again at 60 s, when both nodes have been in step for 40 s and both are behind the balancer on port 80. Each time the CA made 3 checks on port 80, n1 answered 1 or 2 of them itself, n2 answered none (`served key authentication` on n2: 0), the order failed: `Get "https://cert.sg27.test/.well-known/acme-challenge/...": EOF`. The check that landed on n2 was redirected to HTTPS, where no node was ready. No certificate on either node within 150 s (7.09).
- **Two nodes started together both ask (7.10, 3 of 3 runs).** Both log `lock acquired` within 2 ms of each other, the CA has 4 orders after 8 s, none issued.

So a second certificate was never issued in these runs, and only because the orders failed. With a CA that can reach the ordering node directly (DNS-01, or a balancer that sends the check to the right node) the same orders would succeed. Reproduce: `run.sh s7`.

## Surprises without a pass mark

- **A killed node behind HAProxy without `option redispatch` (1.21, 1.23).** Pair, 200 new connections a second, health check every 2 s, two failures to take a node out: 30 of 1 899 requests failed (37 and 22 in the runs before), the last one 3.2 s after the kill (HAProxy tries a refused connection again for up to 3 s before it gives up); HAProxy marked the node down after 3.4 s (4.0, 2.3). Of the requests of 1.5 s, 3 that were in flight on the killed node failed and 5 that HAProxy still sent there afterwards. None failed after the node was marked down. With sixteen nodes and a check every second: 25 failed in 0.54 s when five were killed at once (5.08). This is the balancer's part; the guide has no HAProxy example to copy it from.
- **`allow 0.0.0.0/0` in the PROXY wrapper is accepted (1.19).** `schild ingress validate`: `PASS with warnings`, and the warning is about file access. Without an allow list and with `fallback_policy use` schild refuses to start, with the reason spelled out (1.18, 1.20).
- **A PROXY header of a sender outside the allow list (1.15, 1.15b).** The header is not believed: the application sees the sender's own address and a claimed blocked address is not refused. The connection is not refused either; the request is served as the sender's (200). The spec's `measure` says "is refused".
- **Idle cost of the mesh at sixteen nodes (5.05).** Per node 201 MiB resident (max 208) and 12.6 % of one core (max 15.3 %) with no visitor at all; 257 MiB and 33 % at 19 requests a second per node (5.07). Sixteen VMs share ten cores here.
- **A restart after a drain is ready after 5.2 s, after a kill after 1.2 to 1.3 s** (5.12 against 5.10 and 1.26).
- **The edge drops a new block after 0.94 s at p50 (4.06)**, max 0.97 s (1.2 s in the run before); a lift after 0.29 s.
- **Loss.** The 10 % row loses a packet with 10 % when it leaves a node and again when it arrives, about 19 % per direction (`ping`: 45 % of 20). A block still reached both other nodes within 418 ms.

## Per check

### Scenario 1: a pair behind HAProxy, set up as the guide says

39 checks: 28 PASS, 4 FAIL, 7 numbers without a pass mark.

| # | Check | Result | Numbers |
| --- | --- | --- | --- |
| 1.01 | a schild.yaml with the guide's cluster block and no node_name: what schild says | number | exit 1 |
| 1.01b | the same files with one node_name for both nodes are accepted | PASS |  |
| 1.02 | the HAProxy configuration of the balancer is valid (TCP mode, httpchk on /.schild/readyz, send-proxy-v2) | PASS |  |
| 1.03 | both nodes start from the same files, in any order, and answer ready | PASS | n1 1.21; n2 1.21 |
| 1.04 | schild cluster status on n1 lists two gateways | PASS |  |
| 1.05 | the two members can be told apart by name in schild cluster status (guide: remove NODE by name) | **FAIL** | names [web, web] |
| 1.06 | HAProxy marks both gateways UP by /.schild/readyz over the PROXY protocol | PASS | seconds 0.8 |
| 1.07 | through the balancer the application gets the visitor's address (PROXY protocol v2) | PASS | codes [200, 200, 200, 200] |
| 1.08 | the first password set on n1: its session is valid on the dashboard of n2 | PASS | setup 200 |
| 1.09 | the password set on n1 signs in on n2 | PASS | status 200 |
| 1.10 | a login on n2 is valid on n1 | PASS |  |
| 1.11 | a block set on one node of the pair refuses the address on the other within 1 s at p95 (n = 30) | PASS | n 30, p50 196.5, p95 213.5, max 218.6 |
| 1.12 | a lift on the other node serves the address again on the first ("etwa eine Sekunde") | PASS | n 30, p50 139.0, p95 257.7, max 260.3 |
| 1.12b | "Freigeben" on the other node at the moment that node lists the block is answered 200 (n = 30) | **FAIL** | answered 404 25; of 30; ms until 200 [508.6, 506.2, 247.9, 541.8, 785.1, 768.6, 561.2, 764.6, 511.7, 751.2, 509.9, 538.3, 552.6, 508.9, 542.0, 557.9, 306.4, 68.1, 304.2, 504.2, 790.1, 558.0, 774.8, 533.1, 521.6] |
| 1.13 | a blocked address is refused through the balancer whichever node it lands on, others pass | PASS | blocked [403, 403, 403, 403, 403, 403, 403, 403, 403, 403]; other [200, 200, 200, 200] |
| 1.14 | the block list of n2 names the node that decided | PASS |  |
| 1.15 | a PROXY header from a sender outside the allow list is not believed: the claimed (blocked) address is not the client | PASS | status 200; client seen by app 192.168.65.6 |
| 1.15b | what such a sender gets (spec, measure: 'a PROXY header from a sender outside the allow list is refused') | number | status 200; client seen by app 192.168.65.6 |
| 1.16 | an X-Forwarded-For header of a sender that is no trusted proxy is not believed either | PASS |  |
| 1.17 | a visitor behind the balancer who sends X-Forwarded-For with a blocked address is served as itself | PASS |  |
| 1.18 | in a cluster schild refuses to start with a proxy_protocol wrapper: no allow list | PASS | refused yes |
| 1.19 | in a cluster schild refuses to start with a proxy_protocol wrapper: allow 0.0.0.0/0 | number | refused no |
| 1.20 | in a cluster schild refuses to start with a proxy_protocol wrapper: allow list with fallback_policy use | PASS | refused yes |
| 1.21 | one node of the pair killed (SIGKILL) under 200 new connections a second through the balancer: failed requests | number | requests 1899; failed or not 200 30; codes (0 30, 200 1869); latency ms of served requests 4s after kill n 58, p50 7.4, p95 18.8, max 29.7; first failure s after kill 0.01; last failure s after kill 3.24; haproxy marks down after s 3.36 |
| 1.22 | after the balancer marked the node down no request fails any more | PASS | failures after down 0 |
| 1.23 | requests in flight (1.5 s each) at the kill: only those on the killed node fail | number | requests 60; failed 8; failed started before kill 3; failed started after kill 5 |
| 1.24 | with n1 gone, n2 still holds the block and the login | PASS | blocked [403, 403, 403, 403] |
| 1.25 | the dashboard of n2 says the sync is interrupted and n1 unreachable | PASS | state interrupted; member [unreachable, self] |
| 1.26 | n1 returns: readiness is 503 first and at its first 200 the node holds what it missed (new block refused, lifted block served) | PASS | ready after s 1.17; polls 503 44; new block at ready 403; lifted block at ready 200 |
| 1.27 | no request through the balancer fails while n1 returns | PASS | requests 2020; codes (200 2020); haproxy up after s 2.8 |
| 1.28 | n1 holds the allowlist entry set while it was away and the session is valid on it again | PASS | allowlist [203.0.113.41]; status of the add on n2 201 |
| 1.29 | schild cluster drain under load: no request on a new connection fails | PASS | requests 4887; codes (200 4887); slow requests 101; slow codes (200 101) |
| 1.30 | schild cluster drain: kept-alive connections through the balancer lose no request | **FAIL** | requests 1232; codes (200 1232); cut without answer and sent again 3; cut at s after stop began [15.12, 15.18, 15.24]; connection header of an answer during the delay - |
| 1.31 | schild cluster drain: readiness 503 at once, the node serves 15 s more, then stops | PASS | readyz 503 after s 0.09; haproxy down after s 3.9; process gone after s 17.36 |
| 1.32 | SIGTERM (systemctl stop) under load: no request on a new connection fails | PASS | requests 4844; codes (200 4844); slow requests 100; slow codes (200 100) |
| 1.33 | SIGTERM (systemctl stop): kept-alive connections through the balancer lose no request | **FAIL** | requests 1221; codes (200 1221); cut without answer and sent again 3; cut at s after stop began [15.04, 15.11, 15.18]; connection header of an answer during the delay - |
| 1.34 | SIGTERM (systemctl stop): readiness 503 at once, the node serves 15 s more, then stops | PASS | readyz 503 after s 0.0; haproxy down after s 2.94; process gone after s 17.15 |
| 1.35 | schild cluster remove NODE by the name both nodes carry: what the command does | number | exit 1 |
| 1.36 | state of the pair after that command | number |  |

### Scenario 2: network faults between the node VMs (three nodes)

41 checks: 28 PASS, 0 FAIL, 13 numbers without a pass mark.

| # | Check | Result | Numbers |
| --- | --- | --- | --- |
| 2.01 | three nodes on three VMs form a group from the same files | PASS | ready s (n1 1.22, n2 1.22, n3 1.22) |
| 2.02 | baseline without a fault: 100 requests a second on each node for 15 s | PASS | n1 (requests 1504, not 200 0, retried 0, p50 4.31, p99 9.99, max 23.81); n2 (requests 1507, not 200 0, retried 0, p50 4.23, p99 7.5, max 14.13); n3 (requests 1511, not 200 0, retried 0, p50 4.24, p99 6.37, max 19.32) |
| 2.03 | round trip between two node VMs without a fault | number |  |
| 2.10 | delay 50 ms each way between the node VMs: the fault is on the wire (ping n1 to n2) | number |  |
| 2.11 | delay 50 ms each way: a block set on n1 refuses the address on n2 and n3 within 1 s at p95 | PASS | n 20, p50 146.3, p95 160.6, max 160.6, not within 8s 0 |
| 2.12 | delay 50 ms each way: no request fails or waits (max under 500 ms) | PASS | n1 (requests 1533, not 200 0, retried 0, p50 4.38, p99 7.9, max 12.37); n2 (requests 1536, not 200 0, retried 0, p50 4.31, p99 8.28, max 9.2); n3 (requests 1539, not 200 0, retried 0, p50 4.27, p99 7.44, max 13.08); baseline p99 ms 9.99 |
| 2.13 | delay 50 ms each way: what the dashboard of n1 says | number | state active; members [ok, ok, self] |
| 2.20 | delay 200 ms each way between the node VMs: the fault is on the wire (ping n1 to n2) | number |  |
| 2.21 | delay 200 ms each way: a block set on n1 refuses the address on n2 and n3 within 1 s at p95 | PASS | n 20, p50 389.6, p95 409.0, max 409.0, not within 8s 0 |
| 2.22 | delay 200 ms each way: no request fails or waits (max under 500 ms) | PASS | n1 (requests 1801, not 200 0, retried 0, p50 4.49, p99 7.2, max 18.86); n2 (requests 1804, not 200 0, retried 0, p50 4.39, p99 7.21, max 19.96); n3 (requests 1807, not 200 0, retried 0, p50 4.33, p99 6.49, max 15.15); baseline p99 ms 9.99 |
| 2.23 | delay 200 ms each way: what the dashboard of n1 says | number | state active; members [ok, ok, self] |
| 2.30 | loss 1 % each way between the node VMs: the fault is on the wire (ping n1 to n2) | number |  |
| 2.31 | loss 1 % each way: a block set on n1 refuses the address on n2 and n3 within 1 s at p95 | PASS | n 20, p50 143.7, p95 164.9, max 164.9, not within 8s 0 |
| 2.32 | loss 1 % each way: no request fails or waits (max under 500 ms) | PASS | n1 (requests 1414, not 200 0, retried 0, p50 4.38, p99 8.6, max 16.96); n2 (requests 1417, not 200 0, retried 0, p50 4.36, p99 7.32, max 18.03); n3 (requests 1420, not 200 0, retried 0, p50 4.3, p99 7.61, max 15.28); baseline p99 ms 9.99 |
| 2.33 | loss 1 % each way: what the dashboard of n1 says | number | state active; members [ok, ok, self] |
| 2.40 | loss 10 % each way between the node VMs: the fault is on the wire (ping n1 to n2) | number |  |
| 2.41 | loss 10 % each way: a block set on n1 refuses the address on n2 and n3 within 1 s at p95 | PASS | n 20, p50 139.6, p95 418.0, max 418.0, not within 8s 0 |
| 2.42 | loss 10 % each way: no request fails or waits (max under 500 ms) | PASS | n1 (requests 1469, not 200 0, retried 0, p50 4.37, p99 6.95, max 20.64); n2 (requests 1472, not 200 0, retried 0, p50 4.24, p99 6.92, max 13.28); n3 (requests 1475, not 200 0, retried 0, p50 4.25, p99 7.59, max 13.94); baseline p99 ms 9.99 |
| 2.43 | loss 10 % each way: what the dashboard of n1 says | number | state active; members [ok, ok, self] |
| 2.50 | full partition (n3 cut from n1 and n2, packets dropped both ways): n1 shows n3 as not reachable (guide: at once for a failure, about three seconds for a hanging server) | PASS | seconds 2.93; state of n1 degraded; n3 unreachable |
| 2.51 | full partition (n3 cut from n1 and n2, packets dropped both ways): the nodes that reach each other keep sharing (block n1 to n2 within 1 s) | PASS | block on n1 reaches n2 ms 163.0; status 200; block on n3 200; allow on n1 201; allow on n3 201; lift on n3 200; login on n3 200; readyz n3 200; state n3 interrupted; n3 serves 200; n3 refuses own block 403 |
| 2.52 | full partition (n3 cut from n1 and n2, packets dropped both ways): no request on any serving node fails or waits (max under 500 ms), from 2 s before the fault to 10 s into it | PASS | n1 (requests 1327, not 200 0, retried 0, p50 4.25, p99 7.39, max 10.94); n2 (requests 1331, not 200 0, retried 0, p50 4.23, p99 7.17, max 17.82); n3 (requests 1335, not 200 0, retried 0, p50 4.21, p99 6.72, max 13.69); baseline p99 ms 9.99 |
| 2.53 | full partition (n3 cut from n1 and n2, packets dropped both ways) healed: the three nodes hold the same blocks and allowlist | PASS | seconds 0.62 |
| 2.54 | full partition (n3 cut from n1 and n2, packets dropped both ways) healed: nothing set on either side is lost (blocks, allowlist entries, the lift, the login of both sides) | PASS | block n1 side yes; block n3 side yes; allow n1 side on n1 yes; allow n3 side on n1 yes; allow n1 side on n3 yes; allow n3 side on n3 yes; lifted block gone on n1 yes; lifted block gone on n3 yes; login of n3 valid on n1 yes |
| 2.55 | full partition (n3 cut from n1 and n2, packets dropped both ways) healed: seconds until n1 and n3 both show 'active' with every member reachable | number | seconds 0.66 |
| 2.60 | one-way cut (n3 hears nothing of n1 and n2, its own packets arrive): n1 shows n3 as not reachable (guide: at once for a failure, about three seconds for a hanging server) | PASS | seconds 2.2; state of n1 degraded; n3 unreachable |
| 2.61 | one-way cut (n3 hears nothing of n1 and n2, its own packets arrive): the nodes that reach each other keep sharing (block n1 to n2 within 1 s) | PASS | block on n1 reaches n2 ms 106.2; status 200; block on n3 200; allow on n1 201; allow on n3 201; lift on n3 200; login on n3 200; readyz n3 200; state n3 degraded; n3 serves 200; n3 refuses own block 403 |
| 2.62 | one-way cut (n3 hears nothing of n1 and n2, its own packets arrive): no request on any serving node fails or waits (max under 500 ms), from 2 s before the fault to 10 s into it | PASS | n1 (requests 1249, not 200 0, retried 0, p50 4.43, p99 7.83, max 17.0); n2 (requests 1253, not 200 0, retried 0, p50 4.37, p99 7.77, max 10.1); n3 (requests 1257, not 200 0, retried 0, p50 4.35, p99 7.89, max 14.52); baseline p99 ms 9.99 |
| 2.63 | one-way cut (n3 hears nothing of n1 and n2, its own packets arrive) healed: the three nodes hold the same blocks and allowlist | PASS | seconds 0.84 |
| 2.64 | one-way cut (n3 hears nothing of n1 and n2, its own packets arrive) healed: nothing set on either side is lost (blocks, allowlist entries, the lift, the login of both sides) | PASS | block n1 side yes; block n3 side yes; allow n1 side on n1 yes; allow n3 side on n1 yes; allow n1 side on n3 yes; allow n3 side on n3 yes; lifted block gone on n1 yes; lifted block gone on n3 yes; login of n3 valid on n1 yes |
| 2.65 | one-way cut (n3 hears nothing of n1 and n2, its own packets arrive) healed: seconds until n1 and n3 both show 'active' with every member reachable | number | seconds 0.88 |
| 2.70 | n3 hangs (process stopped with SIGSTOP, the kernel still answers): n1 shows n3 as not reachable (guide: at once for a failure, about three seconds for a hanging server) | PASS | seconds 3.0; state of n1 degraded; n3 unreachable |
| 2.71 | n3 hangs (process stopped with SIGSTOP, the kernel still answers): the nodes that reach each other keep sharing (block n1 to n2 within 1 s) | PASS | block on n1 reaches n2 ms 84.2; status 200 |
| 2.72 | n3 hangs (process stopped with SIGSTOP, the kernel still answers): no request on any serving node fails or waits (max under 500 ms), from 2 s before the fault to 10 s into it | PASS | n1 (requests 1319, not 200 0, retried 0, p50 3.87, p99 5.72, max 12.02); n2 (requests 1322, not 200 0, retried 0, p50 3.84, p99 5.53, max 9.02); baseline p99 ms 9.99 |
| 2.73 | n3 hangs (process stopped with SIGSTOP, the kernel still answers), n3 back: n1 shows the group active again and n3 refuses the address blocked meanwhile | PASS | active after s 4.12; block on n3 after s 0.0 |
| 2.75 | n3 hangs (process stopped with SIGSTOP, the kernel still answers) healed: seconds until n1 and n3 both show 'active' with every member reachable | number | seconds 4.13 |
| 2.80 | n3 killed (SIGKILL, connections refused): n1 shows n3 as not reachable (guide: at once for a failure, about three seconds for a hanging server) | PASS | seconds 0.07; state of n1 degraded; n3 unreachable |
| 2.81 | n3 killed (SIGKILL, connections refused): the nodes that reach each other keep sharing (block n1 to n2 within 1 s) | PASS | block on n1 reaches n2 ms 138.5; status 200 |
| 2.82 | n3 killed (SIGKILL, connections refused): no request on any serving node fails or waits (max under 500 ms), from 2 s before the fault to 10 s into it | PASS | n1 (requests 1032, not 200 0, retried 0, p50 3.92, p99 6.33, max 16.42); n2 (requests 1035, not 200 0, retried 0, p50 3.86, p99 6.58, max 10.62); baseline p99 ms 9.99 |
| 2.83 | n3 killed (SIGKILL, connections refused), n3 back: n1 shows the group active again and n3 refuses the address blocked meanwhile | PASS | active after s 8.45; block on n3 after s 0.0 |
| 2.85 | n3 killed (SIGKILL, connections refused) healed: seconds until n1 and n3 both show 'active' with every member reachable | number | seconds 8.46 |

### Scenario 3: clocks (three nodes, n3 shifted)

40 checks: 24 PASS, 8 FAIL, 8 numbers without a pass mark.

| # | Check | Result | Numbers |
| --- | --- | --- | --- |
| 3.01 | clocks of the three node VMs against the client VM before the test (seconds) | number | n1 -0.0; n2 -0.0; n3 -0.0 |
| 3.10 | n3 30 s ahead: the clock of the VM is where the test put it | PASS | offset s 30.0 |
| 3.11 | n3 30 s ahead: blocks set on n3 act on n1 and n2 within 1 s at p95 (5 blocks) | PASS | n 10, p50 33.5, p95 250.5, max 250.5, not within 4s 0, counters n1 (taken 15, refused 0, deferred 0, unread 0) |
| 3.12 | n3 30 s ahead: blocks set on n1 act on n2 and n3 within 1 s at p95 (5 blocks) | PASS | n 10, p50 35.3, p95 44.4, max 44.4, not within 4s 0, counters n3 (taken 18, refused 0, deferred 0, unread 0) |
| 3.13 | n3 30 s ahead: a lift on one side of the clock difference lifts the block on all three nodes | PASS | set on n3, lifted on n1 (unblock status 200, lifted everywhere after s 0.13, still refused on []); set on n1, lifted on n3 (unblock status 200, lifted everywhere after s 0.24, still refused on []); set on n1 before the clock moved, lifted on n3 (unblock status 200, lifted everywhere after s 0.26, still refused on []) |
| 3.14 | n3 30 s ahead: a login on n3 is valid on n1, and one on n1 valid on n3, within 6 s (a balancer without stickiness sends the next click elsewhere) | PASS | login on n3 valid on n1 after s 0.32; login on n1 valid on n3 after s 0.44 |
| 3.15 | n3 30 s ahead: what the operator sees on n1 and on n3 | number | n1 (state active, members [ok, ok, self], counters (taken 20, refused 0, deferred 0, unread 0), status lines that name a clock [], status counter line [Since the start: 15 records taken, 0 refused, 0 put off (clock or unknown origin), 0 of a newer version unread], readyz 200); n3 (state active, members [ok, ok, self], counter... |
| 3.17 | n3 30 s ahead: the clock stayed there to the end of the step | PASS | offset s at the end 30.0; times the holder put the clock back 1 |
| 3.16 | n3 30 s ahead: schild cluster status names the clock difference (spec, merge: 'schild cluster status reports a skew over 5 s') | **FAIL** | n1 []; n3 [] |
| 3.20 | n3 90 s ahead: the clock of the VM is where the test put it | PASS | offset s 90.0 |
| 3.21 | n3 90 s ahead: blocks set on n3 are not taken by n1 and n2 while their time is more than 60 s ahead (contract section 4, check 4) | PASS | n 0; not within 4s 10; of 10; counters n1 (taken 10, refused 0, deferred 69, unread 0) |
| 3.21b | n3 90 s ahead: n1 takes each such block when its time is within 60 s of n1's clock, about 30 s after it was set, not earlier | PASS | seconds after each was set [30.4, 31.0, 30.6, 31.2, 30.7]; set at s after the first [0.0, 4.5, 8.9, 13.4, 17.9]; counters n1 (taken 15, refused 0, deferred 159, unread 0) |
| 3.22 | n3 90 s ahead: blocks set on n1 act on n2 and n3 within 1 s at p95 (5 blocks) | PASS | n 10, p50 67.5, p95 250.6, max 250.6, not within 4s 0, counters n3 (taken 17, refused 0, deferred 0, unread 0) |
| 3.23 | n3 90 s ahead: a lift on one side of the clock difference lifts the block on all three nodes | **FAIL** | set on n3, lifted on n1 (unblock status 200, lifted everywhere after s 0.13, still refused on []); set on n1, lifted on n3 (unblock status 200, lifted everywhere after s none, still refused on [n1, n2]); set on n1 before the clock moved, lifted on n3 (unblock status 200, lifted everywhere after s none, still refused on [n1, n2]) |
| 3.24 | n3 90 s ahead: a login on n3 is valid on n1, and one on n1 valid on n3, within 6 s (a balancer without stickiness sends the next click elsewhere) | number | login on n3 valid on n1 after s none; login on n1 valid on n3 after s 0.44 |
| 3.25 | n3 90 s ahead: what the operator sees on n1 and on n3 | number | n1 (state active, members [ok, ok, self], counters (taken 15, refused 0, deferred 237, unread 0), status lines that name a clock [], status counter line [Since the start: 15 records taken, 0 refused, 232 put off (clock or unknown origin), 0 of a newer version unread], readyz 200); n3 (state active, members [ok, ok, self], cou... |
| 3.27 | n3 90 s ahead: the clock stayed there to the end of the step | PASS | offset s at the end 90.0; times the holder put the clock back 2 |
| 3.26 | n3 90 s ahead: schild cluster status names the clock difference (spec, merge: 'schild cluster status reports a skew over 5 s') | **FAIL** | n1 []; n3 [] |
| 3.60 | the clock of n3 is set right after it was 90 s ahead: seconds until n3 takes a block set on n1 at that moment | number | seconds 0.3; n2 took it yes; counters n3 (taken 21, refused 0, deferred 0, unread 0) |
| 3.61 | n3 was 90 s ahead, was set right and is now 30 s behind (same processes): blocks set on n1 act on n3 within 1 s | PASS | offset s -30.0; n3 answers 6 s after each block [403, 403, 403]; not within 6s 0; ms n 6, p50 169.8, p95 272.3, max 272.3; login on n1 valid on n3 after s 0.33; counters n3 (taken 25, refused 0, deferred 0, unread 0); times the holder put the clock back 1 |
| 3.62 | n3 was 90 s ahead, was set right and is now 90 s behind (same processes): blocks set on n1 act on n3 within 1 s | **FAIL** | offset s -90.0; n3 answers 6 s after each block [200, 200, 200]; not within 6s 3; ms n 3, p50 98.9, p95 1016.4, max 1016.4; login on n1 valid on n3 after s none; counters n3 (taken 25, refused 0, deferred 127, unread 0); times the holder put the clock back 0 |
| 3.30 | n3 30 s behind: the clock of the VM is where the test put it | PASS | offset s -30.0 |
| 3.31 | n3 30 s behind: blocks set on n3 act on n1 and n2 within 1 s at p95 (5 blocks) | PASS | n 10, p50 38.5, p95 257.9, max 257.9, not within 4s 0, counters n1 (taken 15, refused 0, deferred 0, unread 0) |
| 3.32 | n3 30 s behind: blocks set on n1 act on n2 and n3 within 1 s at p95 (5 blocks) | PASS | n 10, p50 35.5, p95 43.9, max 43.9, not within 4s 0, counters n3 (taken 10, refused 0, deferred 0, unread 0) |
| 3.33 | n3 30 s behind: a lift on one side of the clock difference lifts the block on all three nodes | PASS | set on n3, lifted on n1 (unblock status 200, lifted everywhere after s 0.14, still refused on []); set on n1, lifted on n3 (unblock status 200, lifted everywhere after s 0.24, still refused on []); set on n1 before the clock moved, lifted on n3 (unblock status 200, lifted everywhere after s 0.26, still refused on []) |
| 3.34 | n3 30 s behind: a login on n3 is valid on n1, and one on n1 valid on n3, within 6 s (a balancer without stickiness sends the next click elsewhere) | PASS | login on n3 valid on n1 after s 0.33; login on n1 valid on n3 after s 0.43 |
| 3.35 | n3 30 s behind: what the operator sees on n1 and on n3 | number | n1 (state active, members [ok, ok, self], counters (taken 20, refused 0, deferred 0, unread 0), status lines that name a clock [], status counter line [Since the start: 15 records taken, 0 refused, 0 put off (clock or unknown origin), 0 of a newer version unread], readyz 200); n3 (state active, members [ok, ok, self], counter... |
| 3.37 | n3 30 s behind: the clock stayed there to the end of the step | PASS | offset s at the end -30.0; times the holder put the clock back 0 |
| 3.36 | n3 30 s behind: schild cluster status names the clock difference (spec, merge: 'schild cluster status reports a skew over 5 s') | **FAIL** | n1 []; n3 [] |
| 3.40 | n3 90 s behind: the clock of the VM is where the test put it | PASS | offset s -90.0 |
| 3.41 | n3 90 s behind: blocks set on n3 act on n1 and n2 within 1 s at p95 (5 blocks) | PASS | n 10, p50 37.8, p95 221.2, max 221.2, not within 4s 0, counters n1 (taken 10, refused 0, deferred 0, unread 0) |
| 3.42 | n3 90 s behind: blocks set on n1 are not taken by n3, for which their time lies more than 60 s ahead; n2 takes them | PASS | n3 answers [200, 200, 200, 200, 200]; n2 answers [403, 403, 403, 403, 403]; counters n3 (taken 13, refused 0, deferred 138, unread 0) |
| 3.43 | n3 90 s behind: a lift on one side of the clock difference lifts the block on all three nodes | **FAIL** | set on n3, lifted on n1 (unblock status 200, lifted everywhere after s none, still refused on [n3]); set on n1, lifted on n3 (unblock status 200, lifted everywhere after s 0.12, still refused on []); set on n1 before the clock moved, lifted on n3 (unblock status 200, lifted everywhere after s 1.0, still refused on []) |
| 3.44 | n3 90 s behind: a login on n3 is valid on n1, and one on n1 valid on n3, within 6 s (a balancer without stickiness sends the next click elsewhere) | number | login on n3 valid on n1 after s 0.43; login on n1 valid on n3 after s none |
| 3.45 | n3 90 s behind: what the operator sees on n1 and on n3 | number | n1 (state active, members [ok, ok, self], counters (taken 15, refused 0, deferred 0, unread 0), status lines that name a clock [], status counter line [Since the start: 15 records taken, 0 refused, 0 put off (clock or unknown origin), 0 of a newer version unread], readyz 200); n3 (state active, members [ok, ok, self], counter... |
| 3.47 | n3 90 s behind: the clock stayed there to the end of the step | PASS | offset s at the end -90.0; times the holder put the clock back 2 |
| 3.46 | n3 90 s behind: schild cluster status names the clock difference (spec, merge: 'schild cluster status reports a skew over 5 s') | **FAIL** | n1 []; n3 [] |
| 3.50 | n3 restarted while its clock is 90 s behind: at its first ready answer it refuses the address the group blocked while it was down | **FAIL** | ready after s 1.2; blocked address at ready 200; 3 s later 200; offset s -90.0 |
| 3.51 | clock of n3 corrected: n3 takes what it had put off and holds the same blocks as n1 | PASS | seconds 0.63; counters n3 (taken 6, refused 0, deferred 49, unread 0) |
| 3.52 | clocks at the end (seconds against the client VM) | PASS | n1 -0.0; n2 -0.0; n3 -0.0 |

### Scenario 4: the edge on the balancer VM, real nftables

20 checks: 18 PASS, 0 FAIL, 2 numbers without a pass mark.

| # | Check | Result | Numbers |
| --- | --- | --- | --- |
| 4.01 | schild cluster invite -role edge on a gateway prints a code | PASS | exit 0 |
| 4.02 | schild cluster join ADDRESS CODE -edge -name lb-1 -data DIR on the balancer VM, as the guide writes it | PASS | exit 0 |
| 4.03 | the same code a second time is refused (one use) | PASS | exit 1 |
| 4.04 | schild firewall run -group -data DIR creates the nftables table inet schild on the balancer VM | PASS | seconds 0.11 |
| 4.05 | the dashboard API of a gateway lists the balancer VM as an edge, apart from the gateways | PASS | edges [(name lb-1, state ok, address none, last in 2026-11-22T11:27:40Z, blocks held 0)]; gateways 3 |
| 4.06 | a block set on any gateway drops the packets of the address on the balancer VM within 2 s at p95 (n = 12) | PASS | n 12, p50 939.2, p95 974.3, max 974.3 |
| 4.07 | a lift serves the address through the balancer VM again within 2 s at p95 (n = 12) | PASS | n 12, p50 285.5, p95 295.9, max 295.9 |
| 4.08 | the element of a 7 day block carries its end as the kernel timeout | PASS |  |
| 4.09 | only the ports 80 and 443 are dropped: the blocked address still reaches another port of the VM | PASS | status on another port 200 |
| 4.10 | schild firewall status on the balancer VM names the table and the blocked address | PASS | exit 0 |
| 4.11 | an address put on the allowlist after its block leaves the firewall of the balancer VM | PASS | allow status 201; seconds 0.63; status through balancer 200; still in set no |
| 4.12 | an erased address (Art. 17) with a running block leaves the firewall of the balancer VM within 30 s | PASS | status 200; seconds 0.01; nodes (reached [n1, n2, n3], open []) |
| 4.13 | the data directory and the log of the edge hold no login, no setting, no visitor that is not blocked, no secret of the group | PASS | found in (session cookie [], csrf token [], allowlisted address [], address of a visitor that is not blocked [], the word password [], an event type [], the group secret []) |
| 4.14 | with the key of the edge: sync answers member records only, ask answers the firewall list only, every other mesh call 403 | PASS | sync (status 200, bytes 2951, classes [members], names a visitor not blocked no); ask firewall (status 200, bytes 100, classes [], names a visitor not blocked no); ask events (status 403, bytes 16, classes [], names a visitor not blocked no); ask incidents (status 403, bytes 16, classes [], names a visitor not blocked no); as... |
| 4.15 | the firewall list the edge gets names blocked clients and their end, not the incident, the source or a visitor that is not blocked | number |  |
| 4.16 | the balancer VM reaches no gateway: the blocks it holds stay dropped, a new block is refused by the gateways behind it (block page) | PASS | held block 0; new block 403; edge as n1 sees it [(name lb-1, state ok, last in 2026-11-22T11:28:09Z, blocks held 1)] |
| 4.17 | the balancer VM reaches the gateways again: the new block is dropped there | PASS | seconds 0.66 |
| 4.18 | the gateway the edge joined at is killed: a block set on another gateway is dropped on the balancer VM within 2 s | PASS | seconds 0.13 |
| 4.19 | a clean stop (SIGTERM) of schild firewall run removes the table | PASS | seconds 0.02 |
| 4.20 | files of the edge below its data directory | number |  |

### Scenario 5: sixteen gateways

15 checks: 12 PASS, 1 FAIL, 2 numbers without a pass mark.

| # | Check | Result | Numbers |
| --- | --- | --- | --- |
| 5.01 | sixteen gateways started together from the same files: every node answers ready | PASS | seconds to ready n 16, p50 2.14, p95 2.21, max 2.21; not ready []; start calls took s 0.03 |
| 5.02 | every one of the sixteen dashboards shows sixteen gateways, all reachable, state active | PASS | seconds since start 5.8 |
| 5.03 | the login made on n1 is valid on all sixteen | PASS | valid on 16 |
| 5.04 | HAProxy has all sixteen UP | PASS |  |
| 5.05 | idle group of sixteen, per node: resident memory (MiB) and CPU (percent of one core, over 60 s) | number | rss mib n 16, p50 201.5, p95 207.9, max 207.9; cpu percent of one core n 16, p50 12.58, p95 15.32, max 15.32 |
| 5.06 | a block set on one of sixteen refuses the address on the fifteen others within 1 s at p95 (20 blocks, 300 pairs) | PASS | n 300, p50 162.3, p95 642.1, max 666.4, not within 8s 0 |
| 5.07 | 300 requests a second through the balancer over sixteen nodes (about 19 a node): no failure; per node memory and CPU | PASS | requests 12202; codes (200 12202); latency ms n 12202, p50 6.79, p95 33.8, max 126.86; rss mib n 16, p50 257.1, p95 265.7, max 265.7; cpu percent of one core n 16, p50 33.39, p95 37.77, max 37.77 |
| 5.08 | five of sixteen killed at once under load: failed requests, and none after the balancer marked them down | PASS | failed 25; last failure s after kill 0.54; haproxy all down after s 1.36; n1 shows five unreachable after s 0.0; state n1 degraded |
| 5.09 | with five gone, a block set on one of the eleven refuses the address on the ten others within 1 s at p95 | PASS | n 60, p50 232.4, p95 952.5, max 962.1, not within 8s 0 |
| 5.10 | the five return together: each refuses the address blocked meanwhile at its first ready answer; all sixteen dashboards active again | PASS | ready s (n12 1.31, n13 1.31, n14 1.29, n15 1.3, n16 1.3); blocked at ready (n12 403, n13 403, n14 403, n15 403, n16 403); all active after s 9.0 |
| 5.11 | from the moment the balancer had the five down until they were back: no failed request | PASS | requests 6707; codes (200 6707) |
| 5.12 | rolling restart of all sixteen (schild cluster drain, start, wait for ready and the balancer; delay_s 5, check every 1 s, fall 2) under load: no request on a new connection fails | PASS | requests 69470; codes (200 69470); seconds for all 225.5; ready after start s n 16, p50 5.22, p95 5.31, max 5.31 |
| 5.13 | rolling restart: kept connections through the balancer lose no request | **FAIL** | requests 13906; codes (200 13906); cut without answer and sent again 17 |
| 5.14 | after the rolling restart: all sixteen active, the same blocks on every node, the login still valid everywhere | PASS | blocks per node [26]; login valid on 16 |
| 5.15 | after all of it, per node: resident memory (MiB) | number | rss mib n 16, p50 259.3, p95 268.4, max 268.4 |

### Scenario 7: certificates with an ACME test server

10 checks: 4 PASS, 6 FAIL, 0 numbers without a pass mark.

| # | Check | Result | Numbers |
| --- | --- | --- | --- |
| 7.01 | the Caddyfile with a TLS site and the ACME test server is accepted in a cluster | PASS |  |
| 7.02 | a TLS site with the listener_wrappers of the guide: /.schild/readyz on port 80, asked by a balancer that speaks the PROXY protocol, answers 200 or 503 (guide: 'auf den Web-Ports') | **FAIL** | port 80 with proxy header 400; port 80 without proxy header 308; location https://cert.sg27.test/.schild/readyz |
| 7.03 | n1 alone obtains the certificate through the balancer and is then ready on port 443 (readiness asked over TLS and PROXY) | PASS | seconds from start to certificate 6.8; orders placed 2; issued by the ca 1; haproxy 443 (n1 UP, n2 DOWN) |
| 7.04 | n2 starts later with an empty storage while n1 holds the certificate: n2 asks the CA for no order of its own (guide: 'Eine Bestellung pro Zertifikat') | **FAIL** | orders placed before 2; orders placed after 4; first order of n2 s after its start 0.21; issued by the ca 1 |
| 7.05 | n2 shows the certificate n1 obtained within 10 s of its start | **FAIL** | seconds 61.6; same certificate yes; issued by the ca 1; certificate files on n2 1 |
| 7.06 | through the balancer every TLS connection gets one and the same certificate | PASS | codes [200, 200, 200, 200, 200, 200]; certificates [1112dd816a7c199d]; issued by the ca 1 |
| 7.07 | n2 restarted with n1 down: it serves a certificate from its own copy at once, no new order | PASS | seconds 0.3; issued by the ca before 1; after 1 |
| 7.08 | one node asks the CA while both are behind the round-robin balancer and in step, 3 runs: its first try with the CA up gets the certificate (guide: the CA's check works on whichever server it lands) | **FAIL** | runs [(second try of n1 ended at s 63.0, issued by the ca then 0, orders placed then 2, challenge answers of n1 2, challenge answers of n2 0, ca checks on port 80 3, both serve s after n1 started none, same certificate no, orders placed 5, issued by the ca 0), (second try of n1 ended at s 62.9, issued by the ca then 0, orders... |
| 7.09 | the same 3 runs: one certificate issued per run in the end, and both nodes show it (guide: 'Eine Bestellung pro Zertifikat') | **FAIL** | issued [0, 0, 0]; orders placed [5, 5, 5]; both serve s after n1 started [none, none, none] |
| 7.10 | both nodes started fresh at the same moment with the CA reachable: one of them asks the CA, the other waits (first 8 s) | **FAIL** | orders placed in 8 s 4; n1 started obtaining 1; n2 started obtaining 1; issued by the ca 0 |

## Kill criteria

| Clause | State | Seen |
| --- | --- | --- |
| any request waits for a peer or fails because of one (ACME challenge lookups aside) | not hit | 2.12 to 2.82: 100 requests a second on every node while the peers were delayed by 50 and 200 ms, lossy, cut off both ways and one way, hanging and killed: 0 failed, slowest request 23.8 ms without a fault and 20.6 ms with one. 5.11: 0 of 6 707 failed with five of sixteen gone |
| a lost, empty or returning member deletes or weakens access state on another | not hit | 1.24 to 1.28, 2.54, 2.64, 5.10, 5.14: blocks, lifts, allowlist entries and logins made on both sides of a cut are all there after it heals (the loopback report's F3 does not show any more); a killed node, five killed nodes and sixteen restarted nodes lose nothing |
| a record that fails signature, schema or caps is applied | not measured here | see the loopback report |
| an edge or a removed member reads events, requests, settings, logins or keys | not hit for the edge | 4.13, 4.14: the data directory of the edge holds its key and the member list; with its key, sync answers member records only, `ask firewall` the block list (`client`, `until`), seven other calls 403. A removed member was not measured here |
| an erased address returns | not measured here | only 4.12: an erased address leaves the firewall of the edge |
| an address outside the proxy allow list can get another address blocked | not hit | 1.15 to 1.20: a PROXY header and an `X-Forwarded-For` of senders outside the allow list are not believed; schild refuses to start in a cluster without an allow list or with `fallback_policy use`. It accepts `allow 0.0.0.0/0` |
| a partial answer is shown as complete | not measurable | group queries with partial answers are not built |
| a copy outlives its origin's retention | not measured | needs days of retention |
| certificates are lost or issued again by the move into the group | not hit in these runs, see F6 | no certificate was lost (7.06, 7.07) and the CA issued none twice. A node that enters a group which holds the certificate does ask the CA for its own (7.04), and two nodes started together both ask (7.10); the orders failed because the CA's check was not answered (7.08). People have to decide whether an order that fails for another reason counts |

The spec has no kill criterion about clocks. F4 (a node 90 s behind takes no block and no lift and reports ready and active) is listed here because it is the one failure of this run where protection differs between nodes without any sign.

## Statements that did not hold

| Where | Statement | Measured |
| --- | --- | --- |
| Guide, "Einrichten mit einer Konfigurationsdatei" | "Nur `listen` unterscheidet sich von Server zu Server." | `node_name` is required and has to differ too, or `schild cluster remove NAME` fails and no list tells the nodes apart (F1) |
| Guide, "Was der Cluster teilt" | "„Freigeben“ hebt sie überall auf." | on another node the call answers 404 for 0.07 to 0.8 s after that node lists the block (F2) |
| Guide, "Einen Server geplant anhalten"; spec `must` | "bevor eine einzige abgewiesen wird"; "a rolling update of every node under load fails no request" | true for new connections; 3 to 7 requests per stop on kept-alive connections are cut without an answer (F3) |
| Spec, `merge` | "`schild cluster status` reports a skew over 5 s" | no line at 30 s and at 90 s, ahead or behind (F4) |
| Contract section 10; guide, "Was der Loadbalancer braucht" | 503 "until the node took the records of the group from a member once" | a node that starts with its clock 90 s behind answers 200 after 1.2 s and holds none of the group's blocks (F4) |
| Guide, table "Anzeige" | "Abgleich aktiv: Der Server erreicht alle anderen Gateways." | shown while a node takes nothing from the others, or the others nothing from it, because of its clock (F4). True as worded, and no other display covers the case |
| Guide, "Was der Loadbalancer braucht" | "Lass den Balancer `/.schild/readyz` auf den Web-Ports abfragen", with the `listener_wrappers` block for every server | with a TLS site port 80 answers a PROXY header with 400 and the readiness path with a redirect; readiness exists on port 443 over TLS only, and not before the first certificate (F5) |
| Guide, "Was der Cluster teilt"; contract section 5 | "Eine Bestellung pro Zertifikat"; "none is ordered again" | a node that starts asks the CA 0.2 s after its start, before its first sync; two nodes started together both ask (F6) |
| Guide, "Was der Cluster teilt" | "Die Prüfung der Zertifizierungsstelle klappt, egal auf welchem Server sie landet." | the HTTP-01 check that lands on the other node is redirected to HTTPS and not answered with the token: 0 of 3 orders succeeded with two nodes behind the balancer, 1 of 1 with one (F6) |
| Guide, "Wenn ein Server ausfällt" | "Die anderen Server bemerken einen Ausfall sofort, einen hängenden Server nach etwa drei Sekunden." | held: 0.07 s for a killed node, 3.0 s for a hanging one, 2.9 s and 2.2 s for a cut both ways and one way |
| Guide, "Sperren schon vor den Gateways" | the three commands for an edge | held as written, flags after the address and the code included (4.01 to 4.04) |

Missing in the guide, found while following it: `node_name`; clocks (nothing about NTP or the 60 s); an HAProxy example (the spec's `not_built_here` says the runbook carries one), in particular that a health check has to speak the PROXY protocol where traffic does, and what to do on port 80 of a TLS site; that `delay_s` does nothing for connections a client keeps open.

## Not measured

- **Scenario 6, mixed versions.** [contracts/CHANGELOG.md](../../contracts/CHANGELOG.md) names no earlier commit of this branch whose nodes have to work with the current ones. Its two newest entries about the group say "not compatible between nodes of the earlier draft" (the Ask kind `requests`, the config key `cluster.share_data`); the additive ones ("a node of an earlier build sends none and ignores them") name no build. Without a named pair of versions there is nothing to hold a result against. The rolling restart of sixteen nodes of one version is 5.12 to 5.14.
- **Setting up by hand** (`init`, `invite`, `join` for gateways), `pause` and `resume`, `remove` of a running member, erasure across nodes, rate limits and scenarios over several nodes, hostile records: in the loopback measurement, not repeated on VMs. Only the edge joined by a code here.
- **Blocks by a scenario, a limit or a wave**: every block here is set by hand for 7 days.
- **TLS session resumption across nodes, the browser check and the access lock across nodes, `seed`, 2 000 certificates, renewal, a cut across a renewal window.**
- **Two balancer VMs, keepalived, a floating address, hashing by client address.** One HAProxy with round robin.
- **Events and requests of a failed node on the others** (the spec's 5 s), group queries, charts.
- **Throughput and latency under real load.** The load client is Python; latency numbers show whether a request waited, not how fast schild is.
- **An hour of mixed load, a real WAN.** Every run is minutes long, on one host.

## Notes on the method

- Propagation of a block is timed from sending the API call to the first refused request of that address on each other node, polled every 4 ms on a kept connection that speaks the PROXY protocol. On the edge it is timed to the first connection attempt of that source address that gets no answer within 0.25 s, minus those 0.25 s.
- "No request waits" is judged on kept connections straight to every node, 100 requests a second each, from 2 s before a fault to at least 10 s into it: no failed request, none sent twice, the slowest under 500 ms. The slowest of all was 23.8 ms, without a fault.
- Errors of the harness that were found and fixed before the numbers above were taken: an allowlist call without `level` (answered 400, first run of scenario 1); a test application that answered in two TCP segments (40 ms per request, first run of scenario 2); a cut of the edge that dropped one direction only; clock steps that were measured after the hypervisor had set the clock right again (two runs of scenario 3); a TLS health check of HAProxy without `check-sni` (two runs of scenario 7). Scenario 1 ran three times, 3 and 7 four times, 4 twice, 2 and 5 once; the tables show the last run of each.
- Checks marked "number" have no pass mark: they report what was seen.
- Documents read: the two contract texts, the guide, the spec, `contracts/api/client-dashboard.openapi.yaml`, `contracts/config/schild.schema.json`, `docs/gateway/00-installieren.md` (the lines for the Caddyfile), `schild -h`, and the loopback harness of the measuring side (`tests/testlab/measure/group`), whose mesh client is reused for the edge.
