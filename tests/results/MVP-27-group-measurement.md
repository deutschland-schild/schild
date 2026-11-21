# MVP-27 group of gateways: independent measurement

Measured 2026-11-21 by the measuring agent, not by the builder. Black box: the gateway was driven through its binary, `schild.yaml`, its HTTP listeners and its command line, as [contracts/cluster.md](../../contracts/cluster.md), [docs/gateway/03-gruppe.md](../../docs/gateway/03-gruppe.md), the OpenAPI files and `schild -h` describe them. No source of the gateway was read.

- Harness: [tests/testlab/measure/group](../testlab/measure/group/README.md), rerun with `tests/testlab/measure/group/run.sh` (about 15 minutes).
- Numbers below: run `group-20261121T224241Z`, development build of `32c642e` (tree dirty in files outside the gateway), machine-readable in [MVP-27.json](MVP-27.json). Seed 27.
- 97 checks: 84 PASS, 8 FAIL, 5 numbers without a pass mark.

## What this is and what it is not

Real `schild run` processes on 127.0.0.1 of one machine (macOS, arm64, 12 cores): one single gateway without `cluster`, group A of three gateways by `cluster.secret_file` and `cluster.peers` (n1 to n3), group B of three gateways by `schild cluster init`, `invite`, `join` (m1 to m3), one application that answers 200. The load client does the round robin. Client addresses come from `X-Forwarded-For` out of the documentation ranges.

It is not the testlab of the spec: no profiles `pair` and `fleet`, no balancer, no keepalived, no PROXY protocol, no ACME server, no nftables, three gateways instead of ten, no network between the nodes (loopback, no latency, no loss). Every time below is a lower bound for a real network. The verdict in the JSON can therefore not be `pass`; it is `fail` because of the checks below. What a hit kill criterion means is for people to decide.

## Failures and surprises

### F1. A fresh node answers ready before its first sync, and what is set on it in that moment is thrown away (FAIL, items 14 and 03r)

Contract section 10: `/.schild/readyz` answers 503 until the node took the state of the group, or reached no member for 10 s.

Measured:

- Three fresh nodes of a group by configuration, started together: `/.schild/readyz` answers 200 after 1.26 s on each. The first sync runs about 0.8 s later (log line `this node takes the group's value at its first sync`).
- A fresh node whose two peers are TCP listeners that accept and never answer: 200 at 0.20 s, the first moment the port is open. No 503 at all.
- A node that was a member before behaves as the contract says: restarted with the others up, 503 from 0.21 s to 1.22 s and the state is correct at the first 200; restarted with nobody reachable, 503 from 0.21 s to 10.1 s (items 04 and 12).

Consequence, measured: the first-run password set on c1 right after its ready answer (`POST /api/v0/auth/setup` answers 200, session valid) is gone 1 to 1.5 s later. In the final run the session was replaced (`"thing":"logins/sessions"` in the log, all three nodes answer `authenticated: false, first_run: true`, the password itself still signed in). In two earlier runs of the same steps `logins/users` was replaced too and the password no longer signed in (`401`), the group was back at the first-run setup.

Reproduce: `run.sh --only 14` (and `--only 03` for the black hole). By hand: start three nodes with the same `cluster.secret_file` and `cluster.peers` at once, poll `/.schild/readyz` of one, at the first 200 call `POST /api/v0/auth/setup` with its setup code, then `GET /api/v0/auth/session` with the cookie for 5 s.

### F2. Two changes of the same list on two nodes within a second: the first is silently lost (FAIL, item 07)

Ten times: `POST /api/v0/allowlist` on n1, right after it another address on n2 (same session, as one person behind a balancer without stickiness does it), 2.5 s pause. Every call answered 201. Afterwards 10 of the 20 entries are missing on every node: each time the one added on n1. The lists are equal on the three nodes.

This is what contract section 5 says ("the later one stands, the other is not merged in"), because the allowlist is one value. It is a failure against the spec: its `must` and `kill_if` treat an allowlist entry as access state that is not lost, and the caller got 201 for an entry that does not exist a second later. Inferred, not measured: the same holds for every thing that is one value (rate limits of the dashboard, rule exceptions, IP exceptions, sessions, agent tokens).

Reproduce: `run.sh --only 07`.

### F3. After a cut, one side's allowlist entry and one side's login are gone (FAIL, item 11, kill criterion 2)

The cut is `schild cluster pause` on m3; m1 and m2 stay together; both sides are writable.

- m1 adds 203.0.113.53 to the allowlist, 1.2 s later m3 adds 203.0.113.54. After `resume`: every node holds 203.0.113.54 and not 203.0.113.53. The returning node removed an allowlist entry on the two others. Spec, `split`: "an allowlist entry set on either side holds".
- A login on m1, 1.2 s later a login on m3 (both 200). After `resume` the session of m1 is not valid any more (`authenticated: false`), the one of m3 is.
- Settings (number, no pass mark): `events_days` 11 on m1, then 22 on m3, `summaries_days` 100 on m3, then 200 on m1. After healing every node has 11 and 200: the overlay is one value and the last write of all (m1) stands as a whole, so the later change of `events_days` on m3 is gone. This follows the contract.

Reproduce: `run.sh --only 11`.

The rest of the cut behaved as the rules say: a block set on the cut-off side holds everywhere, a lift there holds, an erasure there holds, an allowlist entry of one side beats the block of the other when only one side touched the allowlist, and the state was the same on all three nodes 1.5 s after `resume`.

### F4. A block by hand of 1 hour or 24 hours ends at the next full minute of the process, on a single gateway too (FAIL, item 02b)

`POST /api/v0/blocks` with `duration_s` 3600 or 86400 answers 200 with `until` an hour or a day later. The address is refused (403) until the process of the node that set it reaches its next full minute of running time, then the block is gone: not in `GET /api/v0/blocks`, requests pass. A block of 604800 s (7 days) stays.

- Final run: set at process age 100.5 s, ended 21.2 s later (poll every 2.5 s), on the group and on the single gateway without `cluster` alike.
- Probe on a single gateway, polled every second: blocks set at 0.2 s and at 70.8 s of process age ended at 60.7 s and 120.7 s.
- In the group the node that set the block publishes a tombstone at that moment (seen on the wire: `class blocks`, `deleted: true`, origin the setting node), so the block ends on every node.

This is not a defect of the group: the single gateway does the same. It is listed because the group spreads it, and because it decides how every block measurement here had to be built: all other items use 7 day blocks. Not measured: whether blocks set by a scenario or by an agent end the same way (scenarios act only after 14 days of learning).

Reproduce: `run.sh --only 02b`, or on one gateway: block an address for one hour by hand, request from it once a second, note the process age when 403 turns to 200.

### F5. Readiness turns 200 about 0.1 s before the block of an erased address is dropped (FAIL, minor, item 08t)

n3 killed, then an address with a running block erased on n1 (`POST /api/v0/privacy/delete`), n3 started again. At the first 200 of `/.schild/readyz` on n3 a request from the erased address is still answered 403; 0.11 s later 200. Three of three runs. The block does not return on n1 or n2, and nothing else of the address was on n3 at ready.

Reproduce: `run.sh --only 08`.

### Surprises without a pass mark

- **A limit is stricter in a group than on one node once a client keeps asking.** Limit 60 per minute, burst 60, one client at 4 requests a second for 60 s: 119 of 240 pass on one node, 81 of 240 pass when the same client is spread round robin over three nodes. At 5 a second for 30 s: 89 against 75. Inferred: the nodes tell each other the requests that matched the limit, the refused ones included, so the buckets of the others stay empty; a single gateway does not count a refused request against the bucket. Within the bound of the spec (it is an upper bound), but a client above the rate gets about a third of what the limit says.
- **A burst passes n per node.** 300 requests as fast as the client can (0.13 s): 60 pass on one node, 180 on three. The contract says so ("n plus what the nodes take in the second a count travels").
- **Events of the others arrive after ready, not before.** After the restart of n3 the 20 events n1 wrote meanwhile were on n3 8.1 s after its ready answer (1.0 s in another run). docs/gateway/03-gruppe.md says the node catches up events and incidents and reports ready only afterwards.
- **`unblock` on another node answers 404 until that node asked for the incident**: found on n2 between 0.08 s and 1.16 s after the block call on n1 (n = 20). The harness waits for it; a person who clicks "Freigeben" on another node within the first second gets 404. On the node that set the block the same call answered 404 in 4 of 12 tries when it followed the block within about 10 ms (probe outside the harness; not tried on a single gateway). One block of item 3 stayed for that reason; it changes no number.
- **Restart after a drain: ready after 5.2 s**, after a kill 1.2 s.
- **Outbound calls by default.** A `schild.yaml` without `rules.crowdsec.state: off` and `bots.ranges_fetch: false` fetches the CrowdSec Hub index from GitHub about 20 to 45 s after the start. This happened once in the first exploratory run of three nodes, before the harness switched both off.

## Per item

| # | Item | Result | Numbers |
| --- | --- | --- | --- |
| 1 | Single gateway without `cluster.enabled` | PASS | listens on its 4 configured ports only (lsof), no `cluster` directory, no cluster line in the log. A node of a group has one listener more (`cluster.listen`) |
| 2 | Block set on n1 until n2 and n3 refuse (40 blocks of 7 days, 80 samples, from sending the API call) | PASS | p50 238 ms, p95 823 ms, max 837 ms; none unseen. Group B: p50 28 ms, p95 732 ms (20 samples) |
| 2 | Lift (half on the setting node, half on another) until the other nodes pass | PASS | p50 94 ms, p95 332 ms, max 633 ms (80 samples) |
| 2b | Blocks of 1 h and 24 h hold | FAIL | F4 |
| 2d | A node's own `schild.yaml` allowlist beats a received block | PASS | blocked on n1 and n2, passes on n3 |
| 3 | Latency through one gateway, 3000 sequential requests per round | PASS for "no request waits or fails"; off against on: see below | off p50 0.60 / 0.59 / 0.65 ms, on 0.62 / 0.60 / 0.64 ms; off p95 0.76 / 0.80 / 0.79, on 1.02 / 1.17 / 0.78; off p99 1.6 / 2.4 / 2.1, on 1.9 / 3.5 / 1.1 |
| 3 | Peers killed (kill -9) | PASS | p50 0.58, p95 0.72, p99 1.83 ms; during the kill 12 837 requests, p99 1.22, max 7.9 ms; 0 failed |
| 3 | Peers frozen (SIGSTOP: sockets accept, nothing answers) | PASS | p50 0.62, p95 0.73, p99 0.85 ms; during 12 s of freeze 18 487 requests, p99 1.16, max 38.7 ms; 0 failed |
| 3 | Peers are listeners that never answer | PASS for latency, FAIL for readiness (F1) | p50 0.64, p95 0.86, p99 1.34 ms; 0 failed |
| 3 | A write with peers stopped or frozen | PASS | `POST /blocks` 0.6 ms and 0.7 ms, acts locally at once; reaches the thawed peers after 0.07 s |
| 4 | kill -9 of n3 under load (150 requests a second round robin) | PASS | 0 of 1 322 requests on n1 and n2 failed, their p99 4.8 ms before and 7.6 ms after; all 358 requests the client still sent to n3 failed (no balancer here) |
| 4 | Events of the killed node on the others | PASS | n3 answered 245 attacks with 403 before the kill; missing on n1 5, on n2 45; the oldest missing one was answered 1.13 s before the kill (0.23 s in another run). Contract: all but the last second; spec: 5 s |
| 4 | Blocks kept, restart, readiness | PASS | 5 blocks still act on n1 and n2; restarted n3: 503 from 0.21 s, 200 at 1.22 s; at the first 200 the block set meanwhile acts, the lift made meanwhile holds, the allowlist entry is there; blocks and allowlist equal on all three |
| 5 | `schild cluster drain` (n2, n1) and SIGTERM (n3) under load, `delay_s` 4, `grace_s` 5 | PASS | readyz 503 after 0.11 s (drain) and 0.01 s (SIGTERM); served on for 3.97 s (152 to 158 probe requests answered 200 while 503, 0 failed); process gone after 5.3 to 6.2 s. Load that follows readyz every 200 ms: 0 of 7 458 requests failed over the three stops and starts |
| 6 | Rate limit 60 per minute over 3 nodes | PASS against the bound | 20 a second: 74 pass on one node, 69 over three (bound 74 + 20). 5 a second: 89 and 75. Burst and sustained: see surprises |
| 7 | Settings and logins | PASS, except F2 | session of n1 valid on n2 and n3 after 0.11 s; password of n1 signs in on n2; setting on n2 and n3 after 0.97 s; allowlist entry of n2 on n1 and n3 after 1.0 s and effective (`own_address`); agent token made on n1 accepted on n3 after 0.6 s; logout on n1 ends the session on n2 within 1 s; limit made on n1 limits on n3 |
| 8 | Erasure on n1 with n3 down | PASS, except F5 | 33 events, 30 ring records: 0 on n1 and n2 after 0.06 s, block of an erased address ends at once; n3 back: 0 events at ready, 0 everywhere 8 s later (privacy search, event list by address, request ring by address) |
| 9 | Records at the protocol level | PASS | see below |
| 9b | Edge | PASS | see below |
| 9c | Member removed while it runs | PASS | see below |
| 10 | `pause` and `resume` | PASS | paused m2: block of m1 acts on m1 and m3 only, block of m2 on m2 only, m2 serves; both act everywhere 3.7 s after the resume command |
| 11 | Cut and heal | FAIL in two points (F3), rest PASS | same state on all nodes 1.5 s after resume; a node frozen for 8 s takes a missed block 0.02 s after SIGCONT |
| 12 | Every node stopped, one started alone | PASS | 6 blocks, allowlist, settings and the session kept; 503 for 10.1 s, then 200 |
| 13 | A member that lost its data directory returns empty | PASS | blocks, allowlist, limit, setting and session unchanged on n1 and n2; the empty node takes them |
| 14 | First-run setup on a fresh group | FAIL | F1 |

**Off against on (item 3).** Median equal within 0.02 ms in every round. p95 was 0.25 to 0.4 ms higher with the group on in two of three rounds and equal in the third; with the peers stopped or frozen it was at the level of off. On one machine the peers compete for the same cores, so this setup cannot tell the cost of the mesh from the cost of two more processes. Not decided here.

### Item 9: hostility

The adversary (`hostile/main.go`) speaks the mesh from the text of the contract. To hand records to honest nodes it has to be called by them, so a fourth node n4 joined group A with the group secret, was killed, and the adversary took its key and its address. Controls: a correctly signed block of n4 served by the adversary acts on n1, n2 and n3 (403), before and after the refused ones; `ask events` with a gateway key answers 200 with rows. Without these the refusals would prove nothing.

| Case | Applied anywhere? |
| --- | --- |
| Records of n4 changed after signing: id, data and id, hlc, one bit of the signature | no (6 addresses, 200 on all nodes) |
| Signed by a key that is no member: its own member record without admission, a block under its own id, a block under n4's id | no; not in the member list |
| Correctly signed by n4: clock a day ahead, another group id, `v` 2, an unknown field in the data, data over 256 KiB | no |
| Replay: block, then its lift, then the first record handed over again on every call for 4 s | block acted, lift after 0.6 s, stays lifted |
| Counted: `schild cluster status` of n1 | refused 0 to 54, put off 0 to 86 |
| `schild cluster remove n4`, then a correctly signed new block of n4 | no; sync, ask and tell with n4's key answer 410 |
| TLS client with a random key: sync, ask events, ask firewall, tell, lock, join with a wrong code, hello | 403 (hello with garbage 400); nothing readable |
| TLS client without a certificate | handshake refused (`certificate required`) |
| Edge (joined with `invite -role edge`, `join -edge`): sync | 200, records of class `members` only; a gateway key gets access, blocks, erasure, logins, members, settings |
| Edge: ask firewall | 200: `revision` and per block `client` and `until`, nothing else |
| Edge: ask events, incidents, requests, settings, counts; tell counts, tell requests; lock, unlock | 403 each |
| Edge: hello with its own member record as role gateway | 403, still listed as edge |
| m3 removed while it runs | a block, 5 events and a setting written on m1 afterwards do not reach m3; a block m3 sets is not taken by m1 and m2; calls with m3's key answer 410; m3 logs that it was removed and serves on |

Not tried: a removed member that signs a record with a clock before its removal. The contract lets such a record stand; no member calls a removed node, so it has no path to hand it over. Inferred from the text, not measured.

## Kill criteria

| Clause | State | Seen |
| --- | --- | --- |
| any request waits for a peer or fails because of one (ACME challenge lookups aside) | not hit | 0 failed, slowest request 38.7 ms with peers killed, frozen or black-holed. Peers at 2 s per answer and ACME not measured |
| a lost, empty or returning member deletes or weakens access state on another | **hit** | F3: after a cut the returning node's allowlist replaces the other side's, one entry gone on two nodes; one side's login gone. Lost (kill -9), empty (data directory lost) and restarted members weakened nothing |
| a record that fails signature, schema or caps is applied | not hit | item 9. Caps measured: data over 256 KiB only; 200 blocks a second and 20 000 running blocks not measured |
| an edge or a removed member reads events, requests, settings, logins or keys | not hit | items 9b and 9c, at the mesh. The edge's own files were not inspected |
| an erased address returns | not hit | item 8, also on the node that was down, and item 11 across a cut. F5 is a window of 0.1 s for the block, nothing returns |
| an address outside the proxy allow list can get another address blocked | not measured | needs the ingress mode with a PROXY protocol listener |
| a partial answer is shown as complete | not measurable | group queries with partial answers are not built (contract section 13) |
| a copy outlives its origin's retention | not measured | needs days of retention |
| certificates are lost or issued again by the move into the group | not measured | no ACME server here |

## Not measured

Of `must` and `measure` in the spec, outside this setup: the profiles pair and fleet with a real balancer, keepalived and ten gateways; the PROXY protocol and spoofing; certificates, ACME challenges on any node, session ticket keys and TLS resumption, `seed`; the browser check and the access lock across nodes; peers that answer after 2 s; versions N and N-1 mixed and a rolling update with a new binary (stop and start of every node in turn with the same binary: item 5); floods of blocks and hot keys, the caps of 200 blocks a second, 20 000 running blocks, 2 000 counts, memory; a credential stuffing run over the nodes (scenarios act after 14 days of learning); an edge's firewall and its 2 s (no nftables); the bounds of 16 gateways and 8 edges; `share_data: false`; clock skew between nodes; data copies, their disk budget and catch-up after an hour; limits over 10 nodes and with hashing by address.

Not built according to contract section 13, so not counted as failures: where each block holds, copies on some nodes and queries from node to node, counters of the overview and server charts across nodes, counts of the distributed detectors, a hint when the configuration differs, the nodes an erasure reached in `PrivacyDeleteResult`, events and dashboard operations of the group. Also named in the spec and absent from the command line of this build: `cluster leave`, `seed`, `healthcheck`.

## Notes on the method

- Propagation is timed by polling the other nodes with requests from the blocked address every 2 ms on keep-alive connections, from the moment the API call is sent. The API call itself took 2.1 ms at p50.
- Latency is one keep-alive connection, sequential, from a Python client: the absolute values carry its overhead, the comparison between modes does not.
- The drain load closes its connections to a node whose readiness is not 200, as a balancer does. A first version kept them and counted 12 failed requests on the stale connections after each restart; that was the client, not the gateway.
- Data directories lie below `/tmp/sg27-*` because the control socket lies below the data directory and a unix socket path on macOS is short. With a long data path `schild cluster status`, `drain`, `pause` are not available (the gateway logs `control path not available`).
- Documents read besides the ones named in the task: `gateway/deploy/dev.schild.yaml` for the keys of `schild.yaml`. The mesh request and answer bodies were learned from the contract and from one sync call with a member key.
