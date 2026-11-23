# MVP-27 group of gateways on real VMs: fourth run (partial)

Measured 2026-11-22/23 by a measuring agent, not by the builder, on the lab host (one host with 10 cores and 24 GB of memory running Linux VMs) against a development build of `1cb7c3a` (branch `feat/cluster`), never a release. The agent's session stopped after two of five scenarios because the model API did not answer; it wrote no report. This file was written by the builder from the agent's raw results, which lie unchanged in [MVP-27-lab-run4/](MVP-27-lab-run4/) (`raw-s26.json`, `raw-s27.json`). The harness changes of the run (`run4.py`) were not reviewed and are not committed. The lab host was cleaned afterwards: no container, image, network or directory of the run is left.

## What was measured

**s26, the state comparison under a stream of changes (third run: 15.02, 15.22, 24.01 failed).** Three nodes; `shared_state` of every member asked on every node once a second; the overview looked at every five seconds; repair lines counted in the logs.

| Row | Load | Member views | `differs` | Overview `cluster_state_differs` | Repairs | `unknown` |
| --- | --- | --- | --- | --- | --- | --- |
| 26.00 | idle, 60 s | 364 | 0 | 0 of 37 | 0 | 0 |
| 26.01 | a block, its lift on the next node and a setting change every 0.6 s, 300 s | 1 896 | 0 | 0 of 192 | 0 | 50 (2.6 %), in 3 runs of 10 to 20 s |
| 26.02 | the same every 2 s | 1 896 | 0 | 0 | 0 | 0 |

After each stream every node read every other as `same` (26.01b, 26.02b). The third run had 20 % `differs` at 0.6 s and the overview hint in 17 of 24 looks.

**s27, first starts (third run: 15.30 failed in 2 of 30 starts).** 30 first starts of three wiped nodes together from the same files.

- All 30 ended with the same keys of the browser check on the three nodes; no view of class `settings` read `differs`; no node logged a repair.
- In 29 of 30 starts the node with the lowest id handed the keys over; in one start two nodes did and the cluster still ended with one set.
- Time to ready of each node from its start: 1.42 to 1.49 s over 90 node starts.
- The stored keys agreed 4.9 to 6.0 s after the start; every `settings` view read `same` after 6.1 s (p50) to 11.2 s (max). Until then the view reads `unknown` (30 of 30 starts).

## Not measured in this run

The session stopped before: the stream on sixteen nodes, time to ready of a node that joins or returns while the group is idle and under light writes, a rotation of the browser-check keys with a takeover, and the rerun of the earlier scenarios. They stay as measured in the third run ([MVP-27-lab-run3.md](MVP-27-lab-run3.md)).
