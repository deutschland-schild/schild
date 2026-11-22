# Group of gateways: hardening measurement (MVP-27)

Black-box measurement of what the first measurement ([../README.md](../README.md), three gateways, no faults, no load) left out: faults between the nodes, hard crashes, load, sixteen gateways and a pair, a long absence, clock differences and mixed versions. Written by the measuring agent, not by the builder. Result: [tests/results/MVP-27-hardening.md](../../../../results/MVP-27-hardening.md), [MVP-27-hardening.json](../../../../results/MVP-27-hardening.json) and every check with its evidence in [MVP-27-hardening-checks.json](../../../../results/MVP-27-hardening-checks.json). The first measurement and its results file `MVP-27.json` are untouched.

## Rerun

```sh
tests/testlab/measure/group/hardening/run.sh                 # every scenario, about 50 minutes
tests/testlab/measure/group/hardening/run.sh --only s1,s5    # single scenarios
```

Needs Go, Python 3 and, for scenario 6, `cc` on macOS. It builds into a temporary directory: a development `schild`, the helper `tool`, the clock shim and `schild` of the commit before HEAD (`OLD_REV=COMMIT` picks another; from `git archive`, the checkout is not touched). Real `schild run` processes on 127.0.0.1, ports 19190 to 19500 (`--port0 N` moves them). Per scenario a file `$OUT/<scenario>.json` (default `/tmp/sg27h-out`); the results file is written from every scenario file found there, so a single scenario can be run again without losing the others. `--keep` keeps the data directories (`/tmp/sg27h-*`), `--quick` shortens load and rounds for work on the harness. Seed 27: client addresses of the load, the nodes that are killed, the moments of a kill.

No call leaves the machine: the CrowdSec Hub and the crawler ranges are off in every `schild.yaml`.

## Scenarios

| | File | What |
| --- | --- | --- |
| s1 | `s1_faults.py` | three gateways and a pair behind the fault proxy: delay, a cut into two sides (connections open, no byte), one direction only, links that break and return, readiness of a node that restarts cut off or slow, a fresh node whose peers never answer |
| s2 | `s2_crashes.py` | kill -9 while a node takes writes and serves, every node restarted in turn (SIGTERM and kill -9), all killed at once, an empty cluster directory, a read-only data directory, a full volume (disk image by `hdiutil`, no root) |
| s3 | `s3_load.py` | 300 to 9 000 requests a second over three nodes and what every node holds afterwards; latency with the cluster off and on; 3 000 a second for three minutes with blocks, a rate limit, per-address samples and events |
| s4 | `s4_sizes.py` | sixteen gateways and a pair: start, time to converge, blocks, a limit, moderate load, several nodes killed at once, their return, a rolling restart, a 17th gateway, memory, CPU and connections per node |
| s5 | `s5_absence.py` | one node away while the others change everything, erase an address and serve more than 32 768 requests each |
| s6 | `s6_clocks.py` | one node with its clock 30 s ahead, 120 s ahead, 120 s behind |
| s7 | `s7_versions.py` | three nodes of the commit before HEAD upgraded in turn under load, then one back |

## Tools

- `tool/main.go` (Go, standard library only, imports nothing of schild): `backend` answers 200 to everything; `load` is an open-loop client with latency per request, round robin over the nodes, a client address per request in `X-Forwarded-For`, and with `-health` the behaviour of a balancer that follows `/.schild/readyz`; `proxy` is the fault proxy.
- **The fault proxy.** Every node's `cluster.advertise` and every entry of `cluster.peers` name a port of the proxy, which forwards to the node's real mesh listener. A rule names two nodes and acts on the bytes that travel from one to the other, whoever opened the connection: `block` holds them and lets new connections wait (a cut: nothing arrives, nothing is lost, the connection stays open, like packets dropped and sent again later), `refuse` closes connections, `delay_ms` makes them late. The proxy learns which node opened a connection from the pid at the other end of the loopback connection (`netstat -anv`, no root). It counts connections it could not attribute; every run so far had none.
- `clockshim/shim.c`: TEST ONLY. Loaded into one `schild` process with `DYLD_INSERT_LIBRARIES`, it shifts `CLOCK_REALTIME` by `SG27H_CLOCK_OFFSET_MS`. macOS only.
- `hard.py`: processes, the dashboard API, counting. Single requests a node holds are counted with `queryRequests` and a filter that matches nothing: the sum of `scanned` over the cursor (the API has no count). Client addresses of the load are private addresses (10.x), blocked addresses come from the documentation ranges.

## Limits of this setup

One machine (macOS, loopback): no real network, no balancer, no PROXY protocol, no ACME, no nftables. The builder worked on the same machine while this ran, so single latency values carry noise; a failing timing check was run again before it was called a failure, and the report says how often. A cut by the proxy holds bytes instead of dropping packets: a TCP connection that would time out in a real network may here go on after the cut.
