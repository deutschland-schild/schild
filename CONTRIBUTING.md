# Contributing

Thanks for helping. Deutschland-Schild is an alpha, so large changes can overlap with work in progress. Open an issue before you start on one.

By taking part you accept the [Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities as described in [SECURITY.md](SECURITY.md), never in a public issue.

## Repository

| Path | Content |
| --- | --- |
| `gateway/` | Schild Gateway (`schild`) |
| `lab/`, `relay/` | Schild Lab and Relay (planned, test lab only) |
| `dashboard/` | Gateway and lab dashboards (Vue, pnpm) |
| `contract/`, `contracts/` | Contracts: Go library; schemas, vectors, decisions |
| `tests/` | System-level tests: test lab, adversaries, specs, results (unit tests stay next to the code) |
| `docs/` | Gateway docs, concept, brand, personas (German) |
| `site/` | Website (Nuxt), renders `docs/` |
| `skills/` | Agent skills |

[AGENTS.md](AGENTS.md) holds the binding rules for humans and agents. Folder rules are in [docs/AGENTS.md](docs/AGENTS.md) and [DEVELOPMENT.md](DEVELOPMENT.md#rules-for-agents).

## Set up and test

You need Go (see `go.work`), Node.js, pnpm, Python 3 and GNU make.

```bash
make contracts-test        # Go and Python agree on every contract vector
make test                  # all Go modules and contract tests
cd dashboard && pnpm install && pnpm check   # dashboards

cd ../site && npm ci && npm run generate   # website
```

The hooks in `.githooks` run a leak check before each commit:

```bash
git config core.hooksPath .githooks
```

## Rules for changes

- **Contracts first.** Contract changes go through the initiator with a new version.
- **Builders do not measure their own work.** Keep evaluators and the code they judge apart.
- **Language.** Code, identifiers, comments, commands, flags and config keys are English. UI, website and `docs/` are German in du-form.
- **Public copy.** Apply [skills/humanizer](skills/humanizer/SCHILD.md) and the wording rules in `AGENTS.md`. Claims need a demo or a measurement behind them.
- **Attack tools** run only against your own containers on internal Docker networks.
- **No secrets** and no personal data in commits, fixtures, issues or logs.
- **AI assistance is welcome.** You stay responsible for every line you submit, and you must understand it.

## Pull requests

Keep a pull request to one topic, describe the why, and link the issue. Tests must pass.

Every commit needs a sign-off under the [Developer Certificate of Origin](https://developercertificate.org/). It states that you may submit the change under this project's license:

```bash
git commit -s -m "Short description"
```

With `git config core.hooksPath .githooks` the hook `commit-msg` refuses a commit without it, so a missing sign-off shows before the pull request does.

## License

Contributions to code and documentation are accepted under the [MIT License](LICENSE).
