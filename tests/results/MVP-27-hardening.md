# MVP-27 group of gateways: hardening measurement

Measured 2026-11-22 by the measuring agent, not by the builder. Black box: the gateway was driven through its binary, `schild.yaml`, its HTTP listeners, its command line and the dashboard API, as [contracts/cluster.md](../../contracts/cluster.md), [docs/gateway/03-cluster.md](../../docs/gateway/03-cluster.md), the spec [MVP-27](../specs/MVP-27-ha-group.yaml), the OpenAPI files and `schild -h` describe them. No source of the gateway was read.

- Harness: [tests/testlab/measure/group/hardening](../testlab/measure/group/hardening/README.md), rerun with `tests/testlab/measure/group/hardening/run.sh` (about 50 minutes; `--only s1,s5` for single scenarios).
- Numbers below: run `hardening-20261122T111656Z`, development build of `e0349dc` (gateway tree clean), seed 27. Machine-readable in [MVP-27-hardening.json](MVP-27-hardening.json); every check with its evidence and the raw numbers in [MVP-27-hardening-checks.json](MVP-27-hardening-checks.json). The first measurement ([MVP-27-group-measurement.md](MVP-27-group-measurement.md), `MVP-27.json`) is untouched.
- 259 checks: 223 PASS, 13 FAIL, 23 numbers without a pass mark.

This extends the first measurement (three gateways, no faults, no load, 92 of 92 judged checks) by what it left out: faults between the nodes, hard crashes, load, sixteen gateways and a pair, a long absence, clock differences, mixed versions.

## What this is and what it is not

Real `schild run` processes on 127.0.0.1 of one machine (macOS, arm64, 12 cores, 64 GiB), groups set up by `cluster.secret_file` and `cluster.peers`, one application that answers 200. Faults between nodes come from a userspace TCP proxy in front of every mesh listener (`cluster.advertise` names the proxy): it holds the bytes of one direction between two nodes (a cut: the connection stays open, nothing arrives), refuses connections or delays bytes. Load comes from an open-loop client that spreads requests round robin and, where said, follows `/.schild/readyz` every 200 ms as a balancer does.

It is not a real network: no balancer, no PROXY protocol, no ACME, no nftables, no packet loss, no latency but the delay the proxy adds. A cut by the proxy holds bytes instead of dropping packets. The builder worked on the same machine meanwhile; single latency values carry that noise. The verdict in the JSON can therefore not be `pass`; it is `fail` because of the checks below. What a failure means is for people to decide.

## Failures

### H1. A node that never reached the group answers ready after 10 s and serves without the group's state (FAIL, s1 `t.fresh`, `p.fresh`, s4 `w.bound`)

Contract section 10: "A node that was set up by configuration and reached none of its named peers yet is not in step."

- A fresh node (empty data directory) whose peers accept the connection and never answer: `/.schild/readyz` is 503 from 0.21 s and 200 at 10.1 s. From then on a request of an address the group blocks is answered 200 by it (403 by the group) and the group's login is not valid on it. 6 of 6 (three gateways and a pair, three runs each). Once the peers answer it takes the blocks within 0.2 s.
- A 17th gateway with the group secret: the group refuses it (16 gateways in the member list, as section 13 says), the process runs on, answers ready (200) after 14 s and lets a blocked address through. 2 of 2 runs. Its log names no line with the bound.

A node that was a member before behaves as documented: restarted while cut off, 503 for 10.1 s, then 200 with the blocks, allowlist and login it had.

Reproduce: `run.sh --only s1` (checks `t.fresh`, `p.fresh`), `run.sh --only s4` (`w.bound`).

### H2. A gateway killed under load keeps none of the requests it served in its last seconds (FAIL, s2 `c.kill9`, 4 of 4 rounds, 12 of 12 over three runs)

300 requests a second over three nodes, `kill -9` of c3 after 1.9 to 3.4 s, restart. Afterwards c3 holds 284, 324, 303 and 284 single requests fewer than c1 and c2, in rounds where it had answered 279, 290, 340 and 189 requests before the kill: about everything it served in that round. The two others hold them (they had asked for them); c3 does not get its own requests back from them, so the difference stays (counted for 25 s after the restart, and it adds up over the rounds: 11 977, 11 978 and 10 783 after four). The log of c3 says nothing about it.

Contract section 9: "Each node stores what the whole group records ... every node has to hold the same to judge by it." The documents name the last second before a failure for events on the *other* nodes; nothing says the failed node itself loses seconds of its own requests for good. Not measured: how many seconds at most (the kill came at most 3.4 s after the load began).

Killed with nothing in flight (three rounds, all three nodes at once), no stored request was lost. In an earlier run of this scenario one node logged `request ring: unreadable segment removed ... reqring: corrupt record` after such a kill (1 of 11 all-at-once rounds over four runs; that run did not count requests yet, so the loss is not quantified).

Reproduce: `run.sh --only s2`.

### H3. At 9 000 requests a second asked the nodes no longer hold the same requests (FAIL, s3 `l.ladder`)

| Asked a second | Achieved | Answered | Held by g1, g2, g3 | Lacking | Client p50 / p99 ms |
| --- | --- | --- | --- | --- | --- |
| 300 | 300 | 9 000 | 9 000 each | 0 | 0.80 / 15.3 |
| 1 000 | 1 000 | 30 000 | 30 000 each | 0 | 1.25 / 26.8 |
| 2 000 | 2 000 | 60 000 | 60 000 each | 0 | 0.70 / 59.0 |
| 3 000 | 3 000 | 90 000 | 90 000 each | 0 | 0.57 / 10.3 |
| 6 000 | 5 988 | 180 000 | 180 000 each | 0 | 0.62 / 36.2 |
| 9 000 | 7 531 | 270 000 (202 of them 503) | 259 641 / 262 001 / 258 303 | 10 359 / 7 999 / 11 697 (3.0 to 4.3 %) | 4.99 / 170 |

30 s per step, an address stays on one node, `monitoring.requests.max_size_mb: 4096`. Up to 6 000 a second every node held every request. At the last step the machine was saturated (12 cores for three gateways, the client and the application; the gateways answered 202 requests with 503), the nodes lacked 3 to 4 % each and differed from each other by up to 3 698 requests; the request store reported sample rate 1. The contract names requests "dropped by a full writer queue" as not handed over; whether that is what happened here cannot be told from outside. On this machine the divergence begins between 6 000 and 7 500 requests a second over three nodes.

### H4. With a clock 120 s off, a node misses the group's newest blocks at ready, an erasure takes 60 s, and requests are lost for the others (FAIL, s6, 2 of 2 runs; the requests were compared in the second run only)

One of three gateways got another wall clock (a library that shifts `CLOCK_REALTIME` for that process).

- **30 s ahead** (inside the 60 s of contract section 4): blocks act both ways (0.98 s and 0.24 s), a block of the fast node lifted on another 2 s later stays lifted, the same setting changed on the fast node and 2 s later on another ends with the later change. PASS.
- **`schild cluster status` names no clock difference** (FAIL against the spec, `merge`: "`schild cluster status` reports a skew over 5 s"). With 120 s the counter "put off" rises (0 to 113), which is the only sign.
- **120 s ahead:** a block set on that node acts on the others after 60.3 s (documented: put off, asked for again; never lost, PASS). An address erased on it is gone on the two reachable others after 60.3 s; the answer names both as `open`. FAIL against the spec (`must`: gone from every reachable member within 30 s).
- **120 s ahead, requests:** the others store none of the requests that node serves (contract section 9 says so: not more than a minute ahead). They do not come later either: 125 s on, k1 and k2 hold 5 019 and 5 018 requests fewer than k3. FAIL against "every node holds what every node wrote".
- **120 s behind, restart:** the node answers ready after 1.25 s; a block set on another node while it was down acts on it 59.0 s later. Until then it serves the blocked address. FAIL against section 10 (ready only after it took the records of the group).
- No client request waited or failed on the nodes with the right clock (slowest 25.7 ms).

Reproduce: `run.sh --only s6` (macOS, needs `cc`).

### H5. A returning node answers ready 0.2 s before the logins are in step (FAIL, minor, s5 `a.return`, 2 of 2 runs)

After 70 s away: at the first 200 of `/.schild/readyz` the blocks and lifts of the absence act and nothing of the erased address is there, but a login ended meanwhile is still accepted and a login made meanwhile is refused. 0.23 s later both are right. Contract section 10 counts logins among what a node took before it is ready.

### Seen once, not reproduced

In the first of two runs of s5 a block set on a2 and lifted on a1 half a second later (the unblock call was repeated until a1 knew the incident) was still in force on all three nodes at the end. That run did not record the answer of the unblock call; the second run, which did, answered 200 and the lift held. 1 of 2.

## Surprises without a pass mark

- **A node that lost its cluster directory comes back as a second member.** With an empty `<storage.path>/cluster` (new key, same name and address) c3 is ready after 1.7 s with the group's state, nothing changes on the others, the login stays. But the former identity stays in the member list as `unreachable` and the group says `degraded` until someone runs `schild cluster remove <former id>` (then `active`). No document says so. Not measured: whether the former identity counts against the bound of 16.
- **A restart shortly after a stop takes 5.2 s to ready**, a first start or a return after 20 s or more 1.2 to 1.7 s. Seen in every scenario (5.19 to 5.77 s, n > 60). A rolling restart of 16 nodes with `delay_s` 2 took 168 s, 9.7 s per node.
- **An erasure names running nodes as open.** With 5 of 16 killed, `PrivacyDeleteResult.nodes.open` named the 5 and, in the first run, 4 gateways that were up (reached 7 of 11), in the final run 2 that were up (reached 9 of 11). Documented ("away, paused or slow"); the address was gone on every survivor at once.
- **A read-only data directory stops a start** (`gateway.lock: permission denied`, exit 1). Made read-only while running (chmod, so only new files fail) the node serves on, takes and stores changes, and logs `request ring: cannot write the number of the served log`.
- **A full volume** (6 GB disk image filled up): the node serves on (0 of 1 000 requests failed), a block of another node acts on it, changes made on it reach the others, the log says `request ring: flush failed`. A volume smaller than the storage budget (5 016 MiB by default) is refused at start by preflight.
- **Latency with the cluster off and on** (3 000 a second over three gateways, 45 s a round, in turn): off p50 2.90 / 1.31 / 0.57 ms, on 0.61 / 0.60 / 0.54 ms; off p99 259 / 190 / 13.3 ms, on 35.1 / 19.6 / 9.8 ms. The first two rounds without cluster were disturbed by other work on the machine; the quiet third round shows no cost of the cluster within noise (0.57 against 0.54 ms, 13.3 against 9.8 ms). 0 failed in 810 000 requests.
- **Pair, one direction cut:** nothing crosses either way until it ends (with three nodes a block reaches the far node through the third in 0.13 to 1.0 s).

## Per scenario

| | Scenario | Checks | Failed |
| --- | --- | --- | --- |
| s1 | Faults between nodes, three gateways and a pair | 76 PASS, 2 FAIL, 5 numbers | H1 (both sizes) |
| s2 | Crashes and restarts | 40 PASS, 4 FAIL, 4 numbers | H2 (4 rounds) |
| s3 | Load | 17 PASS, 1 FAIL, 4 numbers | H3 |
| s4 | Sixteen gateways and a pair | 43 PASS, 1 FAIL, 6 numbers | H1 (17th gateway) |
| s5 | Long absence | 12 PASS, 1 FAIL | H5 |
| s6 | Clock differences | 17 PASS, 4 FAIL, 1 number | H4 |
| s7 | Mixed versions | 18 PASS, 0 FAIL, 3 numbers | none |

### s1 Faults (three gateways t1 to t3, pair p1 and p2)

| Fault | Result | Numbers (three / pair) |
| --- | --- | --- |
| 300 ms delay on every byte between nodes | PASS | no client request failed, slowest 16.3 / 6.4 ms; a block acts after 0.40 / 0.34 s; `POST /blocks` answers in 0.8 / 0.7 ms |
| Cut into two sides (connections open, no byte): noticed | PASS | `GET /group` no longer lists the other side as ok after 2.05 s and 0.22 s / 3.0 s and 0.0 s (documented: about 3 s) |
| During the cut | PASS | readyz 200 on both sides; state `degraded` and `interrupted` as documented; every write answers in under 2 ms (erasure 35 / 38 ms, names the other side as open); blocks act on their own side only; 0 client requests failed, slowest 14.5 / 13.3 ms |
| After the cut | PASS | same state on every node after 0.43 / 0.42 s; both sides keep their block, allowlist entry, rate limit, setting and login; the same setting changed on both sides: the later one stands; the address erased on one side is gone everywhere after 0.5 s and stays gone |
| One direction only | PASS | noticed after 2.6 s; with three nodes blocks reach the far node through the third |
| Links break and return ten times in 10 s while every node sets blocks | PASS | all ten on every node, same state after 0.2 / 0.0 s (4.2 s in an earlier run), 0 client requests failed |
| Restart while cut off | PASS | 503 for 10.1 s, then 200 with the state it had; the missed block acts 0.02 s after the cut ends |
| Restart with peers 300 ms away | PASS | ready after 2.4 s, the block set while it was down acts at the first 200 |
| Fresh node, peers never answer | FAIL | H1 |

The proxy attributed every connection to its node (0 of 207 and 289 unknown).

### s2 Crashes (c1 to c3)

| Item | Result | Numbers |
| --- | --- | --- |
| kill -9 while the node takes writes (4 rounds) | PASS | 310 to 1 496 writes answered per round, the last 2 to 4 ms before the kill: none missing on any node; ready after 5.2 to 5.3 s; nothing about a damaged store in the log; the two others: 0 failed, slowest 58.4 ms |
| Requests of the killed node | FAIL | H2 |
| Every node stopped (SIGTERM) and started in turn, 300 a second following readyz | PASS | 0 of 11 400 failed, state as before |
| Every node killed (kill -9) and started in turn | PASS | ready after 5.2 s each, state as before |
| All three killed at once and started together (3 rounds) | PASS | ready after 5.2 s, state as before, login valid, no stored request lost |
| Empty cluster directory | PASS, see surprises | ready after 1.7 s, block set meanwhile acts at ready, others unchanged |
| Read-only data directory, full volume | PASS for the other nodes and for serving; see surprises | others: 0 failed, slowest 25.9 ms; same state within 0.03 s once writable |

### s3 Load (three gateways, 3 000 requests a second for 180 s on a fresh group)

| Item | Result | Numbers |
| --- | --- | --- |
| No request fails | PASS | 540 000 sent, 0 failed; p50 0.55 ms, p99 16.3 ms, p99.9 58.1 ms, max 112 ms |
| A block set on one node acts on the others under load | PASS | 24 samples: p50 0.15 s, p95 0.59 s, max 0.59 s |
| Rate limit 60 a minute for a client at 20 a second, under load | PASS | one node 74 of 300 pass, spread over three 75 of 300 (bound 74 + 20) |
| What every node holds afterwards | PASS | 541 022 on each of the three, none lacking; 45 sampled client addresses: every node holds exactly what the client was answered; 2 700 refused attacks, 2 700 blocked events on each node |
| Memory, CPU, connections per node | number | idle 149 to 173 MiB, 0.3 to 0.6 % CPU, 12 connections; under load 358 to 366 MiB, 75 % of a core, 141 to 144 connections |
| By rate | FAIL at the top step | H3 |

A stored request takes about 81 bytes. Inferred from the config text and not observed (the store reported sample rate 1 throughout): a 10 min segment may use `max_size_mb / 288`, so with the default of 512 the next segment would keep a sample only above about 38 requests a second for the whole cluster, since every node stores the requests of all.

### s4 Sixteen gateways (w01 to w16) and a pair (q01, q02)

| Item | Result | Sixteen | Pair |
| --- | --- | --- | --- |
| Start | PASS | ready after 1.6 to 1.7 s, every node lists every other as ok 4.0 s after the start | 1.3 s, 2.7 s |
| A block set on one acts on all | PASS | 180 samples: p50 0.23 s, p95 0.96 s, max 0.96 s; lift max 0.42 s | p50 0.23 s, p95 1.00 s |
| Setting, allowlist entry and limit made on three nodes | PASS | on all after 0.9 s | 1.1 s |
| Limit 60 a minute, one client at 20 a second over every node | PASS | 78 of 300 pass (one node: 74) | 75 |
| 100 requests a second per node, 40 s | PASS | 0 of 64 000 failed, p50 1.5 ms, p99 93 ms; every node holds all of them and all 640 blocked events | 0 of 8 000, p50 1.3 ms, p99 3.9 ms |
| Several nodes killed at once under load | PASS | 5 killed: 0 requests to survivors failed (27 to the killed ones); noticed after 0.06 to 0.16 s; survivors `degraded`, state kept, a block acts on all 11 in 0.18 s | 1 killed: 0 failed, `interrupted` |
| They return | PASS | ready after 1.5 s, the block set meanwhile acts at ready, the erased address is not on them, all `active` after 6.4 s | same |
| Rolling restart under load following readyz | PASS | 0 of 160 000 failed, 168 s | 0 of 3 200, 18 s |
| 17th gateway | not taken (PASS), but ready (FAIL) | H1 | |
| Per node idle | number | 171 to 194 MiB, 0.7 to 1.4 % CPU, 90 connections | 152 to 178 MiB, 0.4 %, 6 |
| Per node at 100 requests a second each | number | 318 to 355 MiB, 16 to 36 % of a core, 104 to 107 connections | 252 to 255 MiB, 9 to 10 % |

The connections at the end of the scenario (165 to 172 per node of sixteen, 96 to 143 of the pair) include those of the load client just before.

### s5 Long absence (a3 away for 70 s)

Meanwhile on a1 and a2: three blocks set, two lifted, two settings, a rate limit, an allowlist entry added and one removed, a login made and one ended, an address erased (12 refused attacks, 33 events, 30 requests on every node before), 100 000 requests served (50 000 per node, more than the 32 768 of the log in memory), a1 stopped and started in between.

| Item | Result | Numbers |
| --- | --- | --- |
| At the first ready answer | FAIL for the logins (H5), rest as expected | ready after 1.23 s; blocks act, lifts hold, 0 events of the erased address |
| State | PASS | same on the three after 0.2 s; the removed allowlist entry stays removed |
| Requests | PASS | a3 holds all 100 000 after 9 s, counts equal (100 041 each); 40 sampled addresses exact; 900 blocked events on each |
| Erased address | PASS | 0 events and 0 requests by that address on every node, also 8 s later |

### s7 Mixed versions (f396f0e, the commit before, upgraded in turn to e0349dc)

[contracts/CHANGELOG.md](../../contracts/CHANGELOG.md) calls the Ask kind `requests` of this step "not compatible between nodes of the earlier draft". Measured: 0 of 21 000 requests failed during the upgrade of three nodes in turn; at every mixed stage a block set on each node acts on the two others (0.09 to 0.99 s) and a login is valid on all; no WARN or ERROR line in any log; while mixed the nodes hold different numbers of requests (6 442 / 6 464 / 6 464, then 10 870 / 10 988 / 10 892), and after the last upgrade all hold the same (23 032). One node put back on the older build starts on the data the newer one wrote (ready after 5.2 s) with the same state. One step of versions only; no hour under load as the spec asks.

## Kill criteria

| Clause | State | Seen |
| --- | --- | --- |
| any request waits for a peer or fails because of one (ACME challenge lookups aside) | not hit | 31 checks: delay, cut, one direction, flapping links, crashes, a full or read-only disk on a peer, 16 nodes with 5 lost, clocks, mixed versions. Slowest client request on a healthy node during a fault between nodes or a crash of a peer 58.4 ms; writes during a cut under 2 ms |
| a lost, empty or returning member deletes or weakens access state on another | not hit | 47 checks. H1, H4 and H5 are a node that serves with less than the group's state itself; nothing was weakened on another node |
| a record that fails signature, schema or caps is applied | not measured here | first measurement, item 9 |
| an edge or a removed member reads events, requests, settings, logins or keys | not measured here | first measurement, items 9b and 9c |
| an erased address returns | not hit | 11 checks: across a cut, with 5 of 16 away, after 70 s away with 100 000 requests in between. With a clock 120 s ahead the erasure was 60 s late (H4), nothing returned |
| an address outside the proxy allow list can get another address blocked | not measured | needs the ingress mode with a PROXY protocol listener |
| a partial answer is shown as complete | not measurable | group queries with partial answers are not built |
| a copy outlives its origin's retention | not measured | needs days of retention |
| certificates are lost or issued again by the move into the group | not measured | no ACME server here |

## Statements that did not hold

| Where | Statement | Measured |
| --- | --- | --- |
| contract section 10 | a node set up by configuration that reached none of its named peers is not in step | ready after 10.1 s (H1) |
| contract section 10 | ready only after the node took blocks, settings, access, logins, erasures | logins 0.2 s late (H5); with its clock 120 s behind, a block 59 s late (H4) |
| contract section 9, docs "Daten und Datenschutz" | every node holds what every node wrote | not after a kill -9 (H2), not above about 6 000 requests a second here (H3), not for a node whose clock is over a minute ahead (H4; the rule itself is in section 9, that the requests never come is not) |
| spec `must` | an erased address is gone from every reachable member within 30 s | 60.3 s when the erasing node's clock is 120 s ahead (H4) |
| spec `merge` | `schild cluster status` reports a skew over 5 s | it names none |
| contract section 9, docs "Grenzen" | `requests.keep_hours`, `requests.max_size_mb` | the keys are `monitoring.requests.keep_hours` and `monitoring.requests.max_size_mb` |
| contract section 7 against OpenAPI `GroupMember.state` | reachable: answered at most 10 s ago / ok: reached within the last 15 s | two numbers for one thing; a silent peer left `ok` after 2.0 to 3.0 s |
| `schild cluster -h` | "A group shares the address blocks of every node (MVP-27, first version)" | it shares what contract section 5 lists |
| docs "Grenzen" | proven in operation with two and three gateways only | sixteen ran here on one machine (s4) |

Unclear in the documents: what happens to the former identity of a node that returns with an empty cluster directory, and why a quick restart takes 5 s to ready.

## Not measured

- **Docker testlab profiles** `pair` and `fleet` of the spec: Docker is available on this machine, the profiles are not built.
- A real balancer, keepalived, the PROXY protocol and spoofing; certificates, ACME, TLS resumption; the browser check and the access lock across nodes; edges and their firewall; hostile records (first measurement).
- Real packet loss and reordering, a partition longer than 15 s, a node away longer than minutes (tombstones of 30 days, erasures of 31 days, retention).
- A full disk on every node at once; a data directory that is read-only for open files too (needs another mount, hence root).
- Load on real hardware with a core budget per gateway; more than three minutes; the default request store (512 MB) across a 10 min segment under load, so the sampling the config describes was never seen.
- Sixteen gateways under faults between nodes, a cut of a fleet into halves, 10 nodes with hashing by address.
- Clock differences between 30 s and 120 s, clocks that jump while a node runs, a difference on more than one node.
- Mixed versions beyond one commit back, and for an hour under load; no released version of the cluster exists to upgrade from.
- The maximum of what a killed node loses of its own requests (H2), and the corrupt segment seen once.

## Notes on the method

- Single requests a node holds are counted through `queryRequests` with a filter that matches nothing: the sum of `scanned` over the cursor. It counts whole 10 min segments, so counts are compared before and after with one span.
- Three failures of the first runs were the harness and are fixed, not counted: the allowlist read with one page of 500, a count taken while the last requests were still on their way (differences of 1 to 3), a count that included earlier steps.
- Timing: every failure above was seen in every run made (the number of runs is given), except the one listed under "seen once". No failure rests on a single latency value.
- Checks first tagged with a kill clause and then untagged, because the clause speaks of state "on another" node or of an address that "returns": the fresh node and the 17th gateway (H1), the late erasure (H4), the logins at ready (H5). They stay failures of the statements named.
- Documents read besides those named in the task: `contracts/config/schild.schema.json`, `contracts/results.schema.json`, `contracts/CHANGELOG.md`, the first harness.

## Second run after the fixes (2026-11-22)

Not by the measuring agent: the builder ran the unchanged harness (`run.sh`, every scenario, one continuous run) on `e54c040`, with `e0349dc` as the older build of scenario 7. The JSON files next to this report hold this run; the text above describes the first run on `e0349dc`.

236 judged checks: 229 pass, 7 fail (first run: 223 and 13).

- **Gone:** H1 (a node that never reached the group no longer answers ready; the refused 17th gateway stays out of traffic), H5 (ready only when logins are in step), the divergence at 9 000 requests a second asked (8 999 achieved this time, one node lacked 39 of 270 000), the clock line of `schild cluster status`.
- **Still failing, 4 checks:** H2. A gateway killed with `kill -9` under load lacks the requests of its last second (287, 211, 143 and 287 in four rounds); the others hold them. Not fixed; the guide names it as a limit.
- **Still failing, 2 checks:** a node 120 s ahead. Its erasure reaches the others after 60.3 s, and they do not store the requests it serves. Not fixed; the guide names it as a limit and the dashboard, the command line and the log name the clock.
- **Still marked as failing, 1 check:** a node that restarts 120 s behind. It now never answers ready while it cannot take what the others wrote (`ready after None s`), which is what the fix intends; the check waits for a first ready answer and has none to judge. Asked directly, past the balancer, the node still serves the blocked address until it holds the block (20.3 s here).
- Scenario 7: an upgrade in turn from `e0349dc` to `e54c040` under load passed all 18 checks.

An independent second run on real VMs is under way separately (`MVP-27-lab-run2`).

## Third run on the tree with every change of 2026-11-22 (same day)

Not by the measuring agent: the builder ran the unchanged harness (`run.sh`, every scenario, one continuous run, then scenario 3 once more alone) on `3971e35`, with `e54c040` as the older build of scenario 7. The JSON files next to this report hold this run, with scenario 3 from its repetition. The machine did other work during both runs (a build for another measurement, test suites), so the load numbers are indications.

236 judged checks: 225 pass, 11 fail in the continuous run.

- **Pass now:** sixteen gateways and the pair (44 of 44), the long absence (13 of 13; the returning node is in step at its first ready answer), the upgrade in turn from `e54c040` under load (18 of 18), which crosses the new form of the request exchange.
- **Still failing, 7 checks, named as limits in the guide:** the requests of the last second of a gateway killed with `kill -9` (4), a node 120 s ahead (2), a node that restarts 120 s behind and therefore never answers ready (1, see the second run).
- **New, 3 checks, about the harness's fault proxy:** it could not name the calling node of 1 of 182 and 1 of 252 connections. Not looked into; for the measuring agent.
- **Load ladder, 1 check, not judged as a failure of schild:** in the continuous run the rung of 6 000 requests a second lost 1 355 and 924 of 180 000 on two nodes while 47 requests were answered 503 and the client's p99 was 159 ms; the rung of 9 000 held everything. In the repetition 6 000 held everything and 9 000 (8 553 achieved, 101 answers of 503) lost 2 727 of 270 000 on one node. Each loss came with 503 answers on a saturated machine, on one node only, while the others held every request: a node whose own writer cannot keep up drops requests it served itself, and they are not brought back to it (the same gap as after `kill -9`).
