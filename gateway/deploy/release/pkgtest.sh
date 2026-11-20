#!/usr/bin/env bash
# Test of the Debian package, the apt repository and the installer, in plain
# containers of every supported release. From one release tarball it builds
# three package versions (0.9.0-alpha.1, 0.9.0-alpha.2, 0.9.0), signs two
# repositories with a fresh TEST ONLY key, serves them on an internal Docker
# network and walks through: install, upgrade, a changed signature, channel
# switch, remove and purge (steps in pkgtest/steps.sh).
#
#   gateway/deploy/release/pkgtest.sh bin/schild_0.1.0-alpha.1_linux_arm64.tar.gz
#   PKGTEST_IMAGES="debian:13" gateway/deploy/release/pkgtest.sh TARBALL
#
# The tarball has to match the architecture of the Docker host. The containers
# have no systemd: starting the service and an upgrade under a running service
# are measured in the test lab, not here. Needs network for the package
# mirrors of the distributions. Everything it starts is removed.
set -euo pipefail

tarball=${1:?usage: pkgtest.sh TARBALL}
here=$(cd "$(dirname "$0")" && pwd)
images=${PKGTEST_IMAGES:-debian:12 debian:13 ubuntu:22.04 ubuntu:24.04}
builder_image=${PKGTEST_BUILDER_IMAGE:-debian:13-slim}
server_image=${PKGTEST_SERVER_IMAGE:-caddy:2}
arch=$(docker version -f '{{.Server.Arch}}')
case "$arch" in aarch64) arch=arm64 ;; x86_64) arch=amd64 ;; esac

# The work directory is bind-mounted, so Docker must be able to see it
# (Docker Desktop: a path below your home, e.g. PKGTEST_TMPDIR=$PWD/bin).
base=${PKGTEST_TMPDIR:-${TMPDIR:-/tmp}}
mkdir -p "$base"
work=$(mktemp -d "${base%/}/schild-pkgtest.XXXXXX")
id=schild-pkgtest-$$
net=$id
server=$id-repo

cleanup() {
  docker rm -f "$server" >/dev/null 2>&1 || true
  docker ps -aq --filter "label=schild-pkgtest=$id" | xargs -r docker rm -f >/dev/null 2>&1 || true
  docker network rm "$net" >/dev/null 2>&1 || true
  rm -rf "$work" || true
}
trap cleanup EXIT

mkdir "$work/debs" "$work/serve"
for v in 0.9.0-alpha.1 0.9.0-alpha.2 0.9.0; do
  "$here/deb.sh" "$v" "$arch" "$tarball" "$work/debs" >/dev/null
done

# Two repositories, signed with a key made for this run.
docker run --rm -e "OWNER=$(id -u):$(id -g)" -v "$here:/release:ro" -v "$work:/work" "$builder_image" bash -euc '
  export DEBIAN_FRONTEND=noninteractive GNUPGHOME=/tmp/gnupg
  apt-get update -qq && apt-get install -y -qq apt-utils gnupg >/dev/null
  mkdir -m 0700 "$GNUPGHOME"
  gpg --batch --quiet --passphrase "" --quick-gen-key "Schild repository TEST ONLY <test@schild.invalid>" ed25519 sign never
  key=$(gpg --batch --list-secret-keys --with-colons | awk -F: "\$1 == \"fpr\" { print \$10; exit }")
  if SCHILD_REPO_KEY=$key /release/repo.sh /work/refused /work/debs/*.deb 2>/dev/null; then
    echo "pkgtest: FAIL: repo.sh signed with a TEST ONLY key without SCHILD_REPO_TEST=1" >&2
    exit 1
  fi
  export SCHILD_REPO_KEY=$key SCHILD_REPO_TEST=1
  /release/repo.sh /work/repo1 /work/debs/schild_0.9.0-alpha.1_linux_*.deb
  /release/repo.sh /work/repo2 /work/debs/*.deb
  # The host user copies and removes these files.
  chown -R "$OWNER" /work
  chmod -R u+rwX,go+rX /work/repo1 /work/repo2
'

serve() {
  rm -rf "${work:?}/serve"/*
  cp -R "$work/$1/." "$work/serve/"
}

docker network create "$net" >/dev/null
serve repo1
docker run -d --name "$server" --network "$net" --network-alias repo -v "$work/serve:/srv:ro" \
  "$server_image" caddy file-server --root /srv --listen :80 >/dev/null

for image in $images; do
  echo "pkgtest: == $image"
  c=$id-$(tr -c 'a-z0-9\n' '-' <<<"$image")
  docker run -d --name "$c" --label "schild-pkgtest=$id" --network "$net" -v "$here/pkgtest:/pkgtest:ro" "$image" sleep 3600 >/dev/null
  step() { docker exec "$c" sh /pkgtest/steps.sh "$1"; }

  serve repo1
  step prepare
  step install
  serve repo2
  step upgrade
  # One changed byte in the signed index: apt has to refuse it.
  sed -i.bak 's/^Suite: alpha$/Suite: alphb/' "$work/serve/apt/dists/alpha/InRelease"
  rm -f "$work/serve/apt/dists/alpha/InRelease.bak"
  step tampered
  serve repo2
  step channel
  step remove
  docker rm -f "$c" >/dev/null
done

echo "pkgtest: PASS ($images)"
