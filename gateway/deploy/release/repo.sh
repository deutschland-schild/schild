#!/usr/bin/env bash
# Builds the signed apt repository of the Schild Gateway as static files:
#
#   OUTDIR/install.sh                      the installer (deploy/release/install.sh)
#   OUTDIR/key.asc                         the public key the repository is signed with
#   OUTDIR/apt/pool/main/s/schild/*.deb    the packages
#   OUTDIR/apt/dists/alpha/                every version
#   OUTDIR/apt/dists/stable/               versions without a pre-release suffix (may be empty)
#
#   SCHILD_REPO_KEY=<fingerprint> gateway/deploy/release/repo.sh OUTDIR DEB...
#
# The repository is a function of the packages given: nothing is kept between
# runs, so the release workflow rebuilds it from the release assets each time.
# The secret key SCHILD_REPO_KEY has to be in the current GnuPG home. A key
# whose name says TEST ONLY is refused unless SCHILD_REPO_TEST=1 is set. A key
# with a passphrase gets it from the variable SCHILD_REPO_PASSPHRASE.
#
# Needs apt-ftparchive (apt-utils), dpkg-deb and gpg.
set -euo pipefail

usage="usage: SCHILD_REPO_KEY=<fingerprint> repo.sh OUTDIR DEB..."
out=${1:?$usage}
shift
[ "$#" -ge 1 ] || { echo "$usage" >&2; exit 1; }
key=${SCHILD_REPO_KEY:?$usage}
here=$(cd "$(dirname "$0")" && pwd)

for tool in apt-ftparchive dpkg-deb gpg; do
  command -v "$tool" >/dev/null 2>&1 || { echo "repo: $tool is missing" >&2; exit 1; }
done

uids=$(gpg --batch --list-secret-keys --with-colons "$key" | awk -F: '$1 == "uid" { print $10 }')
[ -n "$uids" ] || { echo "repo: no secret key $key in the GnuPG home" >&2; exit 1; }
if grep -q 'TEST ONLY' <<<"$uids" && [ "${SCHILD_REPO_TEST:-0}" != 1 ]; then
  echo "repo: $key is a TEST ONLY key; it never signs a published repository" >&2
  exit 1
fi

if [ -e "$out" ] && [ -n "$(ls -A "$out")" ]; then
  echo "repo: $out is not empty" >&2
  exit 1
fi
mkdir -p "$out/apt/pool/main/s/schild"
out=$(cd "$out" && pwd)
root=$out/apt
archs="amd64 arm64"

sign() {
  if [ -n "${SCHILD_REPO_PASSPHRASE:-}" ]; then
    gpg --batch --yes --pinentry-mode loopback --passphrase-fd 3 --local-user "$key" --digest-algo SHA512 "$@" 3<<<"$SCHILD_REPO_PASSPHRASE"
  else
    gpg --batch --yes --local-user "$key" --digest-algo SHA512 "$@"
  fi
}

for deb in "$@"; do
  name=$(dpkg-deb -f "$deb" Package)
  [ "$name" = schild ] || { echo "repo: $deb is the package \"$name\", not schild" >&2; exit 1; }
  install -m 0644 "$deb" "$root/pool/main/s/schild/"
done

cd "$root"
for suite in alpha stable; do
  for arch in $archs; do
    dir=dists/$suite/main/binary-$arch
    mkdir -p "$dir"
    apt-ftparchive --arch "$arch" packages pool/main > "$dir/Packages.all"
    if [ "$suite" = stable ]; then
      # A pre-release carries a "~" in its version (0.1.0~alpha.1).
      awk 'BEGIN { RS = ""; ORS = "\n\n" } !/(^|\n)Version: [^\n]*~/' "$dir/Packages.all" > "$dir/Packages"
    else
      cp "$dir/Packages.all" "$dir/Packages"
    fi
    rm "$dir/Packages.all"
    gzip -n -9 -k "$dir/Packages"
  done
  apt-ftparchive \
    -o APT::FTPArchive::Release::Origin="Deutschland-Schild" \
    -o APT::FTPArchive::Release::Label="schild" \
    -o APT::FTPArchive::Release::Suite="$suite" \
    -o APT::FTPArchive::Release::Codename="$suite" \
    -o APT::FTPArchive::Release::Architectures="$archs" \
    -o APT::FTPArchive::Release::Components="main" \
    -o APT::FTPArchive::Release::Description="Schild Gateway ($suite)" \
    release "dists/$suite" > "$root/Release.tmp"
  mv "$root/Release.tmp" "dists/$suite/Release"
  sign --clearsign -o "dists/$suite/InRelease" "dists/$suite/Release"
  sign --armor --detach-sign -o "dists/$suite/Release.gpg" "dists/$suite/Release"
done

gpg --batch --export --armor "$key" > "$out/key.asc"
install -m 0644 "$here/install.sh" "$out/install.sh"

echo "repo: $(find "$root/pool" -name '*.deb' | wc -l | tr -d ' ') package file(s), signed by $key"
for suite in alpha stable; do
  for arch in $archs; do
    echo "repo: $suite/$arch: $(grep -c '^Package: ' "dists/$suite/main/binary-$arch/Packages" || true) version(s)"
  done
done
