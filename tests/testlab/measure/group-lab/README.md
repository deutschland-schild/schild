# Group of gateways on real VMs: lab measurement (MVP-27)

Black-box measurement of [MVP-27](../../../specs/MVP-27-ha-group.yaml) on real Linux VMs with a real network between them, against [contracts/cluster.md](../../../../contracts/cluster.md) and the operator guide [docs/gateway/03-cluster.md](../../../../docs/gateway/03-cluster.md). Written by a measuring agent, not by the builder. Result: [tests/results/MVP-27-lab.md](../../../results/MVP-27-lab.md) and [tests/results/MVP-27-lab.json](../../../results/MVP-27-lab.json).

The loopback harness next to it ([../group](../group/README.md)) runs every node on 127.0.0.1 of one machine. This one puts every node into a VM of its own, with its own kernel, clock, packet filter and address, a balancer VM with HAProxy in front and a client VM that sends the traffic.

## Rerun

```sh
SCHILD_LAB_HOST=<ssh alias of the lab host> tests/testlab/measure/group-lab/run.sh            # everything, about 40 minutes
SCHILD_LAB_HOST=<ssh alias of the lab host> tests/testlab/measure/group-lab/run.sh s2 s3      # single scenarios
```

Needs on this machine: Go, Docker (the image is built here), `rsync`, `ssh` to the lab host without a password. Needs on the lab host: macOS on arm64 with Apple's `container` CLI (1.5.0 was used) and `python3`. The name of the lab host is read from `SCHILD_LAB_HOST` only; no file of this directory and no result names it.

`run.sh` builds a development `schild` for linux/arm64 (a test binary, never a release), the mesh client of the loopback harness (`../group/hostile`) and the ACME test server pebble, builds the image `sg27-node:dev`, copies it to the lab host, creates 19 VMs there, runs the scenarios in the client VM, writes `tests/results/MVP-27-lab.json` and removes every container, the network, the image and the work directory from the lab host again. `KEEP=1` leaves the VMs up; `ssh <lab host> 'bash ~/sg27-work/lab/host.sh down'` removes them later.

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
| `s1` | a pair behind HAProxy, set up as the guide says: failover, planned stop, blocks and logins across nodes, spoofed addresses | n1, n2 |
| `s2` | network faults between node VMs: delay 50 and 200 ms, loss, full partition, one-way cut, a hanging node, a killed node | n1 to n3 |
| `s3` | clocks: one node 30 s and 90 s ahead, 30 s and 90 s behind | n1 to n3 |
| `s4` | the edge role on the balancer VM with real nftables | n1 to n3, lb |
| `s5` | sixteen gateways: start, convergence, five lost at once, rolling restart, memory and CPU | n1 to n16 |
| `s7` | certificates with pebble: one order per certificate, the CA's check on either node | n1, n2 |

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
| `run.py` | the scenarios, one function each |
| `lab.py` | VMs, gateway nodes, the dashboard API, the load client, faults |
| `ctl.py` | the control agent in every VM |
| `app.py` | the application behind the gateways |
| `netdelay.py` | delay, jitter and loss per packet without netem |
| `clockhold.py` | keeps the clock of a VM a fixed number of seconds off |
| `report.py` | raw results of the scenarios to `tests/results/MVP-27-lab.json` |
| `Dockerfile` | the test image: Debian trixie, the development `schild`, HAProxy, nftables, Python |

## Limits of this setup

- All VMs are on one host and one virtual switch: the network is real (own kernels, own stacks, real packets, MTU 1280) and fast (0.5 ms round trip). Delay and loss are injected.
- The builtin network `default` of the lab host carried no packets when this was written, and its VMs have no route to the internet; the harness creates its own network `sg27-net` and builds the image on the developer machine.
- HTTP on port 80 in every scenario but `s7`; TLS on the gateways only there. In `s7` the balancer sends port 80 without the PROXY protocol and with a TCP check, port 443 with PROXY v2 and the readiness check over TLS: port 80 of a TLS site is the redirect listener and does not take a PROXY header (check 7.02).
- The load client is Python: a few hundred requests a second. This is a measurement of behaviour under faults, not of throughput.
- One site, one application, dashboard blocks only: scenarios, limits and waves need 14 days of learning before they block and are not driven here.
