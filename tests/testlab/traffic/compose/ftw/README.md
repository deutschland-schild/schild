# go-ftw CRS regression subset

A small, curated regression corpus in go-ftw format, written for this test lab
(not copied from the CRS repository). `tests/<rule_id>.yaml` holds attack
requests that CRS paranoia level 1 (anomaly threshold 5) must block with 403
through a schild client in `autoblock` mode; `tests/negative.yaml` holds
ordinary shop requests that must pass (200/201).

| file | what |
| --- | --- |
| `ftw.yaml` | go-ftw config: overrides every test's target to `stripper-shop:8080` (t1, autoblock) |
| `tests/942100.yaml` | SQL injection (libinjection): query and urlencoded body |
| `tests/941100.yaml` | XSS (libinjection) |
| `tests/930100.yaml`, `930120.yaml` | path traversal, OS file access |
| `tests/932160.yaml` | Unix shell command injection |
| `tests/913100.yaml` | scanner user agents (Nikto, sqlmap) |
| `tests/944150.yaml` | Log4Shell JNDI lookup |
| `tests/negative.yaml` | rule 949110 (anomaly block) must not fire on ordinary requests (home, list, umlauts, apostrophe in a name, JSON create) |

Run (t1 up; go-ftw only talks to the test lab's own stripper on the internal
`inet` network; the go-ftw image is pinned by digest in
`docker-compose.traffic.yaml`):

```sh
make testlab-up PROFILE=t1
make traffic-ftw                    # -> results/runs/ftw/ftw.json
```

Cloud mode: go-ftw judges by status code only, because the schild client's WAF
log is not a file go-ftw can tail. `make traffic-ftw` first renders a copy of
the corpus to `results/runs/ftw/corpus` (`traffic -ftw-render`) with the signed
ground-truth label on every request (malicious, technique `crs-<rule_id>`, for
the attack files; benign for `negative.yaml`), and mounts that copy. Without
the label the stripper records the requests as unlabelled and the evaluator
counts every blocked one as a blocked legitimate request (seen in the first
live run: `legit_blocks=22`, `unlabelled=43` in the t1 smoke evaluator).
`docker compose run attack-ftw` without `FTW_CORPUS` runs the unlabelled
source corpus.

`traffic/internal/ftwcorpus` renders the labelled copy; its tests check that the
corpus is not empty, that every file parses with a rule id (go-ftw skips files
without one), that every stage asserts a status, that the compose service runs
the corpus, and that every rendered request carries a valid label.
