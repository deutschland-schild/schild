# Group of gateways on real VMs: lab measurement (MVP-27)

Black-box measurement of [MVP-27](../../../specs/MVP-27-ha-group.yaml) on real Linux VMs with a real network between them, against [contracts/cluster.md](../../../../contracts/cluster.md) and the operator guide [docs/gateway/03-cluster.md](../../../../docs/gateway/03-cluster.md). Written by a measuring agent, not by the builder. Results: the first run on commit `e0349dc` is [tests/results/MVP-27-lab.md](../../../results/MVP-27-lab.md) and [MVP-27-lab.json](../../../results/MVP-27-lab.json); the second run, after the builder answered its findings, is [tests/results/MVP-27-lab-run2.md](../../../results/MVP-27-lab-run2.md) and [MVP-27-lab-run2.json](../../../results/MVP-27-lab-run2.json). The harness as it is now is the one of the second run: where the documented behaviour changed, the checks follow the documents of the second run (listed in its report).

The loopback harness next to it ([../group](../group/README.md)) runs every node on 127.0.0.1 of one machine. This one puts every node into a VM of its own, with its own kernel, clock, packet filter and address, a balancer VM with HAProxy in front and a client VM that sends the traffic.

## Rerun

```sh
SCHILD_LAB_HOST=<ssh alias of the lab host> tests/testlab/measure/group-lab/run.sh            # everything, about two hours
SCHILD_LAB_HOST=<ssh alias of the lab host> tests/testlab/measure/group-lab/run.sh s2 s3      # single scenarios
```

Needs on this machine: Go, Docker (the image is built here), `rsync`, `ssh` to the lab host without a password. Needs on the lab host: an arm64 machine with the `container` command line that `host.sh` calls (one Linux VM per container) and `python3`. The name of the lab host is read from `SCHILD_LAB_HOST` only; no file of this directory and no result names it.

`run.sh` builds a development `schild` for linux/arm64 (a test binary, never a release), the mesh client of the loopback harness (`../group/hostile`) and the ACME test server pebble, builds the image `sg27-node:dev`, copies it to the lab host, creates 19 VMs there, runs the scenarios in the client VM, writes `tests/results/MVP-27-lab-run2.json` (`RESULTS=<file>` names another file; the first run's file is never written again) and removes every container, the network, the image and the work directory from the lab host again. `KEEP=1` leaves the VMs up; `ssh <lab host> 'bash ~/sg27-work/lab/host.sh down'` removes them later. `WORK=<directory>` keeps the build between runs; keep it short (the ssh control socket lies in it). Next to the results, `$OUT/tables.md` holds the checks as Markdown tables for the report.

Everything on the lab host is named `sg27-*` (containers, the network `sg27-net`, the image, `~/sg27-work`). The harness touches nothing else there.

## Setup

| VM | What runs there |
| --- | --- |
| `sg27-n1` ... `sg27-n16` | one `schild run` each, as the web server (ingress mode): `schild.yaml`, Caddyfile and `cluster.secret` as the guide says, the same on every node but `cluster.listen` (and `node_name`) |
| `sg27-lb` | HAProxy 3.0 in TCP mode: health check `GET /.schild/readyz`, PROXY protocol v2 to the gateways; in scenario 4 also the edge (`schild firewall run -group`) with real nftables |
| `sg27-app` | the application behind the gateways (`app.py`, answers 200); in scenario 7 the ACME test server pebble |
| `sg27-client` | the driver (`run.py`) and the load client. Visitors come from 203.0.113.0/24 (documentation range): the client VM holds these addresses and the other VMs route them back to it, so the balancer and the edge see real packets from those sources |

Every VM runs `ctl.py`, a small agent the driver uses to start and kill schild, set packet filters, move the clock and read logs. It is a root shell over HTTP on the host-only test network. TEST ONLY.

The client VM is in the PROXY allow list of the gateways next to the balancer VM: to time one single node it speaks the PROXY protocol itself, as a second balancer would. The spoofing checks come from the application VM, which is not in the list.

## Scenarios

| | What | VMs |
| --- | --- | --- |
| `s1` | a pair behind HAProxy, set up as the guide says (one `schild.yaml` with `name_from_host`, the guide's HAProxy example): names, failover, planned stop with clients that honour and that ignore `Connection: close`, blocks and logins across nodes, spoofed addresses | n1, n2 |
| `s2` | network faults between node VMs: delay 50 and 200 ms, loss, full partition, one-way cut, a hanging node, a killed node | n1 to n3 |
| `s3` | clocks: one node 30 s and 90 s ahead, 30 s and 90 s behind, a start 90 s behind, and 3, 7 and 12 s for the hints (`clock_skew_ms`, `schild cluster status`, the overview, the log) | n1 to n3 |
| `s4` | the edge role on the balancer VM with real nftables | n1 to n3, lb |
| `s5` | sixteen gateways: start, convergence, ten minutes of load with memory and disk per node, five lost at once, rolling restart | n1 to n16 |
| `s7` | certificates with pebble: one order per certificate, a joining node, the CA's check on either node, a planned stop over HTTP/2 | n1, n2 |
| `s8` | readiness of a node that reaches no member: a fresh one (503 for good) and one that was in step once (about 10 s) | n1, n2 |
| `s9` | a new group secret, server by server as the guide says, with a TLS site, an edge and a light load: what survives, whether a certificate is ordered again, what the edge needs | n1 to n3, lb |
| `s10` | the page data of the group (`GET /api/v0/group`: names, vitals, clock difference) and the counters across nodes (`node` on the monitoring calls, a killed node as partial) | n1 to n3 |
| `s11` | a block set on one node and lifted on another 0.2 to 1 s later, 200 times, two rounds | n1 to n3 |

There is no `s6` (mixed versions): [contracts/CHANGELOG.md](../../../../contracts/CHANGELOG.md) names no earlier commit whose nodes have to work with the current ones.

## Faults

- **Delay.** The kernel of the lab VMs has no netem qdisc (`CONFIG_NET_SCH_NETEM is not set`), so `tc netem` does not work there. `netdelay.py` does the same for the packets a node sends to its peers: a route sends them into a TUN device, the tool holds each IP packet for the delay and sends it out of `eth0` unchanged. TCP stays end to end between the nodes. Each run checks the delay with `ping`.
- **Loss, partition, one-way cut.** nftables rules in a table of the harness (`inet sg27fault`), by peer address. A loss of p drops a packet with probability p when it leaves a node and again when it arrives at the other, so a direction loses about 2p.
- **Hanging and killed node.** `SIGSTOP` and `SIGKILL` of the schild process.
- **Clock.** Every VM has its own kernel and clock, but the hypervisor of the lab host sets the clock of a VM right again about every 30 s. `clockhold.py` puts the clock a fixed number of seconds off and puts it back there within 2 ms whenever it was moved; it logs each time, and the checks report the count. So a shifted clock is right for a few milliseconds every 30 s.

## Files

| File | What |
| --- | --- |
| `run.sh` | everything from this machine: build, image, VMs, scenarios, results, cleanup |
| `host.sh` | runs on the lab host: creates and removes the `sg27-*` VMs |
| `run.py` | the scenarios `s1` to `s7`, one function each |
| `run_more.py` | the scenarios `s8` to `s11`, added for the second run |
| `lab.py` | VMs, gateway nodes, the dashboard API, the load client, faults |
| `ctl.py` | the control agent in every VM |
| `app.py` | the application behind the gateways |
| `netdelay.py` | delay, jitter and loss per packet without netem |
| `clockhold.py` | keeps the clock of a VM a fixed number of seconds off |
| `report.py` | raw results of the scenarios to the results file, and the tables of the report |
| `Dockerfile` | the test image: Debian trixie, the development `schild`, HAProxy, nftables, Python |

## Limits of this setup

- All VMs are on one host and one virtual switch: the network is real (own kernels, own stacks, real packets, MTU 1280) and fast (0.5 ms round trip). Delay and loss are injected.
- The builtin network `default` of the lab host carried no packets when this was written, and its VMs have no route to the internet; the harness creates its own network `sg27-net` and builds the image on the developer machine.
- HTTP on port 80 in every scenario but `s7` and `s9`; TLS on the gateways only there. There the balancer runs the guide's example for a TLS site: port 80 without the PROXY protocol and with a TCP check, port 443 with PROXY v2 and the readiness check over TLS (checks 7.02, 7.02b).
- The balancer configurations are the two examples of the guide line by line; the harness adds a section `global` with the stats socket it reads the state of the servers from.
- The load client is Python: a few hundred requests a second. This is a measurement of behaviour under faults, not of throughput.
- One site, one application, dashboard blocks only: scenarios, limits and waves need 14 days of learning before they block and are not driven here.
