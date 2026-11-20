# Tests

System-level tests of Deutschland-Schild. Unit tests stay next to the code they test (`*_test.go` in the Go modules, Vitest and Playwright in `dashboard/`).

| Path | Content |
| --- | --- |
| [`testlab/`](testlab/README.md) | Test lab (MVP-05, MVP-06): compose stacks t0/t1, evaluator, label stripper, traffic generators |
| `adversaries/` | Red team (MVP-07): malicious lab, Sybil clients, poisoned bundles, SecLang fuzzer |
| `specs/` | One YAML spec per component with requirements, measurement and kill criteria (MVP-01 ...) |
| `results/` | Measurements and reports (`<spec>.json`, `REPORT.md`); raw runs in `results/runs/` (gitignored) |

Builders never write the measurement they are judged by ([DEVELOPMENT.md](../DEVELOPMENT.md#rules-for-agents), rule 2). Commands: `make test`, `make testlab-up PROFILE=t0|t1`, `make smoke`, `make eval SPEC=MVP-0x` (see [DEVELOPMENT.md](../DEVELOPMENT.md)).
