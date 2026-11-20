# GitHub settings

Repository settings live in this folder as files. `scripts/github-settings.sh OWNER/REPO` shows the calls, `--apply` sends them. The script does not change visibility and never touches a Netlify connection.

| File | Content |
| --- | --- |
| `repository-settings.json` | Merge methods, features, sign-off on web commits |
| `rulesets/main.json` | Pull requests and required checks for the default branch |
| `rulesets/tags.json` | Release tags cannot be moved or deleted |

The script also sets a read-only default token, an action allowlist with SHA pinning, approval for all outside contributors' workflow runs, Dependabot alerts and, on public repositories only, private vulnerability reporting, secret scanning and push protection.

`main.json` lets repository admins merge without a review, because a single maintainer cannot approve their own pull request. Remove that bypass as soon as there is a second maintainer.

## Set by hand

- Require two-factor authentication
- Base permission: none or read
- At least two owners
- Disable member-created public repositories
- Actions: only selected actions, no self-hosted runners for public repositories
- Discussions on the repository, because the REST settings call does not cover them
- Immutable releases, on the repository or organization, before the first release
