# Releasing the Schild Gateway

Checklist for maintainers. A tag `v<version>` on `main` starts [.github/workflows/release.yml](../../.github/workflows/release.yml), which publishes:

- `ghcr.io/deutschland-schild/schild:<version>` (linux/amd64, linux/arm64; `latest` only without a pre-release suffix), signed with cosign, with SBOM and provenance
- a GitHub release with `schild_<version>_linux_amd64.tar.gz`, `schild_<version>_linux_arm64.tar.gz`, the Debian packages `schild_<version>_linux_amd64.deb` and `schild_<version>_linux_arm64.deb`, `checksums.txt` with its cosign signature `checksums.txt.sigstore.json` (keyless), and the build provenance as a Sigstore bundle `provenance.intoto.jsonl` (marked pre-release for `-alpha.N`, `-beta.N`, `-rc.N`)
- the apt repository on GitHub Pages, once it is set up ([below](#once-for-the-apt-repository)); until then the jobs `repository` and `pages` are skipped

Nothing else publishes: local builds are test images.

## Once, before the first tag

Repository `deutschland-schild/schild` (the workflow refuses to run under any other name):

1. Apply the settings in [.github/](../../.github/SETTINGS.md): `scripts/github-settings.sh deutschland-schild/schild --apply`. This imports the rulesets (`main.json`: pull requests and the required checks `go`, `go-race`, `go-fuzz`, `image`, `go-vulnerabilities`, `dashboards`, `website`, `dco`, `secrets`, `workflows`; `tags.json`: release tags cannot be moved or deleted) and the action allowlist. The release workflow uses GitHub-owned actions only, so the allowlist needs no new entry.
2. Do the items under "Set by hand" in SETTINGS.md, above all **immutable releases**.
3. Organization → Settings → Actions → General: workflow permissions stay read-only (the jobs ask for what they need). Organization → Settings → Packages: allow public container packages.
4. Runners: the arm64 build needs the hosted runner `ubuntu-24.04-arm` (free for public repositories). The repository has to be public before the first tag.
5. Netlify: connect the site to the new repository (base `site`, see `netlify.toml`). A push to `main` deploys the website when it changes `site/`, `docs/`, the agent API document or `netlify.toml` (`site/scripts/netlify-ignore.sh`), so the site should name a version only once its release exists. Switch Deploy Previews off in Netlify: the CI job `website` builds the site for every pull request.
6. Push `main` and wait for a green CI run; the required checks only exist after their first run.

After the first release (the package does not exist earlier):

7. `https://github.com/orgs/deutschland-schild/packages/container/schild/settings`: set the visibility to **public** and check that the repository `schild` has write access under "Manage Actions access". Until then `docker pull` needs a login and the quickstart fails for everybody else.

## Once per maintainer: signing tags

A release tag is signed by the maintainer who sets it (`git tag -s`). With an SSH key:

```sh
git config gpg.format ssh
git config user.signingkey ~/.ssh/<key>.pub
```

Add the same public key on GitHub under Settings → SSH and GPG keys → New SSH key, key type **Signing key**; only then GitHub shows the tag as verified. `git tag -v <tag>` checks a signature locally once `gpg.ssh.allowedSignersFile` names the key.

The tags `v0.1.0-alpha.1` to `v0.1.0-alpha.3` are annotated and not signed, and stay so: a tag cannot be moved (ruleset). What a user verifies is not the tag: the image signature, the build provenance and the signature of the apt repository come from the release run.

## Once, for the apt repository

The spec is [MVP-31](../../tests/specs/MVP-31-debian-packages.yaml). The repository is rebuilt from the packages of the releases on every release run, so nothing here holds state except the key.

1. **The signing key.** On a machine that is not a server, create a primary key that only certifies and a signing subkey with an expiry of at most two years. The primary key stays offline. Nothing of the secret key ever enters this repository.

   ```sh
   gpg --quick-gen-key "Deutschland-Schild package signing <info@deutschland-schild.de>" ed25519 cert never
   gpg --quick-add-key <fingerprint> ed25519 sign 2y
   gpg --export --armor <fingerprint> > gateway/deploy/release/apt/archive-key.asc     # public, goes into a pull request
   gpg --export-secret-subkeys --armor <fingerprint>                                   # the secret APT_SIGNING_KEY
   ```

   The export holds the signing subkey only, still locked with the passphrase of the key. The passphrase is the second secret, `APT_SIGNING_PASSPHRASE`. `gateway/deploy/release/repo.sh` refuses a key whose name says TEST ONLY.
2. **Environment `packages`:** Settings → Environments → new environment `packages`, required reviewer: the maintainer, deployment tags `v*` only, secrets `APT_SIGNING_KEY` and `APT_SIGNING_PASSPHRASE`.
3. **GitHub Pages:** Settings → Pages → source "GitHub Actions", custom domain `pkg.deutschland-schild.de`, enforce HTTPS. DNS: a `CNAME` of that name to `deutschland-schild.github.io`. The environment `github-pages` has to allow tags `v*`: the release run deploys from the tag.
4. **Switch it on:** repository variable `PACKAGES_ENABLED` = `true`. Without it a release publishes the package files on the release only.

The first run after this publishes every package the newest releases carry. Check from a fresh `debian:13` container with the commands of the installation docs.

**Rotating the key:** extend or replace the subkey before it expires, put the new public key into `archive-key.asc` with a pull request, update the secret, then run a release. Servers that installed before the rotation fetch the new `key.asc` by running the installer again; say so in the changelog of that release.

## Every release

1. `main` is green, including `image` (the quickstart smoke test) and `go-race`.
2. One pull request with the version in every place that names it:
   - `CHANGELOG.md`: heading `## <version>` (the workflow refuses a missing or an empty section; the section becomes the release text), with the Upgrade notes filled in
   - `gateway/deploy/quickstart/compose.yaml` and `gateway/deploy/quickstart/caddy/compose.yaml`: the image tag (the workflow refuses a mismatch)
   - `site/app/utils/release.ts`: `RELEASE_VERSION`
   - `README.md` and `docs/gateway/00-installieren.md`: the tag in the download addresses
   - `SECURITY.md`: supported versions, if the line changes
3. Geo data: if `GEO_MONTH` in `gateway/Dockerfile` is older than two months, run `make gateway-geo-pin GEO_MONTH=YYYY-MM` and put the three lines into the Dockerfile. DB-IP removes old months; the build then stops at the download.
4. Tag the merged commit on `main` with a signed tag ([above](#once-per-maintainer-signing-tags)) and push the tag. Each push needs the maintainer's go:

   ```sh
   git switch main && git pull --ff-only
   git tag -s v0.1.0-alpha.1 -m "Schild Gateway 0.1.0-alpha.1"
   git push origin v0.1.0-alpha.1
   ```

5. Watch the run: `gh run watch --repo deutschland-schild/schild`. The order is check, test, build (per architecture: build, smoke test, tarball, Debian package with its test, push by digest), publish (manifest, signature, attestation), release, then repository and pages when the apt repository is set up. The job `repository` waits for your approval: it holds the signing key.
6. Check the result from a machine that is not logged in to ghcr.io:

   ```sh
   docker run --rm ghcr.io/deutschland-schild/schild:0.1.0-alpha.1 version   # schild 0.1.0-alpha.1 (release)
   gh attestation verify oci://ghcr.io/deutschland-schild/schild:0.1.0-alpha.1 --repo deutschland-schild/schild
   ```

   Then walk through the quickstart on the website once, as written there. With the apt repository: in a fresh `debian:13` container the installer has to end with this version.

## When a release run fails

- Before the `publish` job: nothing is visible. Fix on `main`, then tag the next version. A tag cannot be moved (ruleset), and a version is never published twice.
- In or after `publish`: the image tag exists. Re-run the failed jobs first (`gh run rerun --failed`). If that does not help, release the next version and say in its changelog what happened; delete nothing.

## Try it locally (no push)

```sh
make gateway-image TAGS=release GATEWAY_GEO=dbip TAG=0.1.0-alpha.1   # release build, real geo data
make gateway-smoke TAG=0.1.0-alpha.1                                 # quickstart smoke test (ports 8080, 8788)
make gateway-tarball VERSION=0.1.0-alpha.1 GATEWAY_GEO=dbip          # tarball of this machine's architecture in bin/
make gateway-deb VERSION=0.1.0-alpha.1                               # Debian package of that tarball in bin/
make gateway-pkgtest VERSION=0.1.0-alpha.1                           # package, repository (TEST ONLY key) and installer in four distributions
```
