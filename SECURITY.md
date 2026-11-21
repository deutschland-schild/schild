# Security policy

Deutschland-Schild is in alpha. The OWASP Core Rule Set and your own rules block known attacks from the start (set `rules.crs.state: detect` to detect only first); four of the five behaviour scenarios block after a 14-day learning period, while `aggressive_crawl` and rate limits start in observe mode and CrowdSec Hub rules start in detect mode. Treat it as early software and know the way out before you put it in front of production traffic.

## Reporting a vulnerability

Please do not open a public issue, pull request or discussion for a suspected vulnerability.

1. Use **Report a vulnerability** on the repository's Security tab: <https://github.com/deutschland-schild/schild/security/advisories/new> (GitHub private vulnerability reporting).
2. If that is not available, write to info@deutschland-schild.de.

Include the affected component and version or commit, the steps to reproduce, and the impact you expect. Test only against systems you own or may test. Do not access other people's data and do not run denial-of-service tests against third parties.

## What happens next

- We aim to confirm receipt within 7 days.
- We work with you on a fix and agree on a disclosure date, by default at most 90 days after your report.
- With your consent we credit you in the advisory.

This is a volunteer project without a bug bounty, so these are goals and not guarantees.

## Scope

In scope: the gateway `schild`, `schild-agent`, `schild-lab`, `schild-relay`, the dashboards, the contracts, rule signing, the container images, the deployment examples (`gateway/deploy`, `docs/ops/systemd`), the release process and this repository's workflows.

Out of scope: test keys marked TEST ONLY, deliberately vulnerable fixtures under `tests/testlab` and `tests/adversaries`, and findings in third-party software that are not caused by how we use it. Report those to the upstream project.

## Supported versions

| Version | Supported |
| --- | --- |
| latest `0.1.0-alpha.N` release | yes |
| `main` | yes, reports against the latest commit are accepted |
| older alpha releases | no, update to the latest alpha |
| prototype images built before the first release (`schild:dev`) | no |

During the alpha, fixes go into the next release; there are no patch releases for older ones. Releases are listed at <https://github.com/deutschland-schild/schild/releases>.

## Verifying a release

Images and tarballs are built only by the release workflow of this repository ([.github/workflows/release.yml](.github/workflows/release.yml)). The version below is an example. Releases from 0.1.0-alpha.4 on also carry `checksums.txt.sigstore.json`, the cosign signature of `checksums.txt`; for older releases skip the first command.

```sh
cosign verify-blob --bundle checksums.txt.sigstore.json \
  --certificate-identity https://github.com/deutschland-schild/schild/.github/workflows/release.yml@refs/tags/v0.1.0-alpha.5 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com checksums.txt
sha256sum -c --ignore-missing checksums.txt
gh attestation verify schild_0.1.0-alpha.5_linux_amd64.tar.gz --repo deutschland-schild/schild
gh attestation verify oci://ghcr.io/deutschland-schild/schild:0.1.0-alpha.5 --repo deutschland-schild/schild
cosign verify ghcr.io/deutschland-schild/schild:0.1.0-alpha.5 \
  --certificate-identity https://github.com/deutschland-schild/schild/.github/workflows/release.yml@refs/tags/v0.1.0-alpha.5 \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```
