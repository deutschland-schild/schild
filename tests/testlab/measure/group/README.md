# Group of gateways: measurement (MVP-27)

Black-box measurement of [MVP-27](../../../specs/MVP-27-ha-group.yaml) against [contracts/cluster.md](../../../../contracts/cluster.md), written by the measuring agent, not by the builder. Result: [tests/results/MVP-27-group-measurement.md](../../../results/MVP-27-group-measurement.md) and [tests/results/MVP-27.json](../../../results/MVP-27.json).

## Rerun

```sh
tests/testlab/measure/group/run.sh
```

About 15 minutes. Needs Go and Python 3, nothing else. It builds a development `schild` and the adversary tool into a temporary directory, starts real `schild run` processes on 127.0.0.1 (ports 18090 to 18199, `--port0 N` moves them), writes `tests/results/MVP-27.json` and the raw numbers to `/tmp/sg27-out/raw.json` (`OUT=DIR` moves them), then stops every process and removes its data directories. `--only 02,09` runs single items while working on the harness (no results file then), `--keep` keeps the data directories.

No call leaves the machine: the CrowdSec Hub and the crawler ranges are switched off in every `schild.yaml` the harness writes.

## Files

| File | What |
| --- | --- |
| `run.py` | the items, one function each, and the results file |
| `lib.py` | gateway processes, HTTP, the dashboard API, the load client |
| `backend.py` | the application behind the gateways: 200 to everything |
| `hostile/main.go` | the adversary at the mesh: TLS 1.3 and HTTP/2 with a node key, signs records, serves them as a member would, or answers every call 410 with a group id (`gone`). Written from the text of the contract, imports nothing of schild, standard library only |

## Setup

- A single gateway without `cluster` (s0), the baseline.
- Group A by configuration: n1 to n3 with `cluster.secret_file` and `cluster.peers`.
- Group B: m1 to m3 with a secret file of their own (joining by code was removed in 5b12c2c; item 10 stops and starts a node instead of `cluster pause`, items 09b (edges) and 11 (a cut by `cluster pause`) are not run; the cut is measured by the fault proxy of [hardening](hardening/README.md) s1).
- The load client spreads requests round robin; there is no balancer. Client addresses come from `X-Forwarded-For` (loopback is a trusted proxy by default), from the documentation ranges of the TEST ONLY geo fixture.
- Random choices use seed 27.

## Limits of this setup

One machine, macOS, loopback: no network latency, no balancer, no keepalived, no ACME server, no nftables, three gateways instead of ten. The testlab profiles `pair` and `fleet` of the spec are not built here. What that leaves unmeasured is listed in the report.

The data directories lie below `/tmp/sg27-*`: the control socket of schild lies below the data directory, and a unix socket path on macOS is at most 104 bytes.
