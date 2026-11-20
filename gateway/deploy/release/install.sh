#!/bin/sh
# Installs the Schild Gateway from its apt repository on Debian and Ubuntu.
#
#   curl -fsSL https://pkg.deutschland-schild.de/install.sh | sudo sh -s -- alpha
#
# The argument is the channel: "stable" (the default) or "alpha".
#
# What it does, and nothing else:
#   1. writes the repository key to /etc/apt/keyrings/schild.asc
#   2. writes /etc/apt/sources.list.d/schild.sources
#   3. runs apt-get update and apt-get install schild
#
# It starts nothing and changes no configuration of your web server. Run it
# again to switch the channel. Later updates: sudo apt update && sudo apt install schild
#
# By hand, the same three steps: https://deutschland-schild.de/doku
set -eu

channel=${1:-stable}
# SCHILD_REPO_URL points the test of this script at a local repository.
repo=${SCHILD_REPO_URL:-https://pkg.deutschland-schild.de}
keyring=/etc/apt/keyrings/schild.asc
sources=/etc/apt/sources.list.d/schild.sources

fail() {
	echo "schild install: $*" >&2
	exit 1
}

case "$channel" in
stable | alpha) ;;
*) fail "unknown channel \"$channel\" (stable or alpha)" ;;
esac
[ "$(id -u)" = 0 ] || fail "run as root, for example with sudo"
command -v apt-get >/dev/null 2>&1 || fail "no apt-get here: this script is for Debian and Ubuntu, other systems use the tarball or the container image"
arch=$(dpkg --print-architecture)
case "$arch" in
amd64 | arm64) ;;
*) fail "no package for the architecture \"$arch\" (amd64 and arm64 only)" ;;
esac

fetch() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -qO- "$1"
	else
		fail "neither curl nor wget is installed"
	fi
}

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
fetch "$repo/key.asc" > "$tmp" || fail "could not load $repo/key.asc"
grep -q 'BEGIN PGP PUBLIC KEY BLOCK' "$tmp" || fail "$repo/key.asc is not a public key"

install -d -m 0755 /etc/apt/keyrings
install -m 0644 "$tmp" "$keyring"
cat > "$sources" <<EOF
Types: deb
URIs: $repo/apt
Suites: $channel
Components: main
Architectures: $arch
Signed-By: $keyring
EOF
chmod 0644 "$sources"

echo "schild install: repository $repo/apt, channel $channel"
apt-get update
if ! apt-cache show schild >/dev/null 2>&1; then
	if [ "$channel" = stable ]; then
		fail "the channel \"stable\" has no version yet; for a pre-release run this script with the argument \"alpha\""
	fi
	fail "the channel \"$channel\" has no package for $arch"
fi
DEBIAN_FRONTEND=noninteractive apt-get install -y schild

# sed reads all of the output: schild fails on a closed stdout.
echo "schild install: $(schild version | sed -n 1p)"
