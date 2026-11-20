#!/usr/bin/env bash
# Builds the Debian package of the Schild Gateway from a release tarball:
# the same binary, units, geo data and license texts, laid out for apt. One
# package per architecture serves every Debian and Ubuntu release, because
# the binary is static. Used by the release workflow; locally:
#
#   gateway/deploy/release/deb.sh 0.1.0-alpha.1 arm64 bin/schild_0.1.0-alpha.1_linux_arm64.tar.gz bin
#
# Writes OUTDIR/schild_<version>_linux_<arch>.deb. The file keeps the version
# as the tag writes it; inside the package a pre-release is 0.1.0~alpha.1, so
# apt sorts it before 0.1.0.
#
# Needs dpkg-deb. Without it (macOS) the script runs itself in a Debian
# container (DEB_IMAGE, default debian:13-slim).
set -euo pipefail

usage="usage: deb.sh VERSION ARCH TARBALL OUTDIR"
version=${1:?$usage}
arch=${2:?$usage}
tarball=${3:?$usage}
out=${4:?$usage}
here=$(cd "$(dirname "$0")" && pwd)

case "$arch" in amd64 | arm64) ;; *) echo "deb: unknown architecture: $arch" >&2; exit 1 ;; esac
if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[0-9]+)?$ ]]; then
  echo "deb: unexpected version: $version" >&2
  exit 1
fi
test -s "$tarball" || { echo "deb: no tarball at $tarball" >&2; exit 1; }
mkdir -p "$out"
out=$(cd "$out" && pwd)
tarball=$(cd "$(dirname "$tarball")" && pwd)/$(basename "$tarball")

if ! command -v dpkg-deb >/dev/null 2>&1; then
  exec docker run --rm \
    -e "SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH:-0}" \
    -v "$here:/release:ro" -v "$tarball:/in/$(basename "$tarball"):ro" -v "$out:/out" \
    "${DEB_IMAGE:-debian:13-slim}" \
    /release/deb.sh "$version" "$arch" "/in/$(basename "$tarball")" /out
fi

deb_version=${version/-/\~}
epoch=${SOURCE_DATE_EPOCH:-0}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
src=$work/src
pkg=$work/pkg
mkdir "$src" "$pkg"
tar -xzf "$tarball" -C "$src"

install -d "$pkg/DEBIAN" "$pkg/usr/bin" "$pkg/usr/lib/systemd/system" "$pkg/usr/share/schild/geo" "$pkg/usr/share/doc/schild"
install -m 0755 "$src/schild" "$pkg/usr/bin/schild"
install -m 0644 "$src"/geo/* "$pkg/usr/share/schild/geo/"
install -m 0644 "$src/NOTICE" "$src/THIRD_PARTY_LICENSES" "$pkg/usr/share/doc/schild/"
install -m 0644 "$src/LICENSE" "$pkg/usr/share/doc/schild/copyright"

# The units of the tarball name /usr/local/bin; a package installs to /usr/bin.
for unit in schild.service schild-firewall.service; do
  sed 's|/usr/local/bin/schild|/usr/bin/schild|g' "$src/$unit" > "$pkg/usr/lib/systemd/system/$unit"
  chmod 0644 "$pkg/usr/lib/systemd/system/$unit"
  if ! grep -q '^ExecStart=/usr/bin/schild ' "$pkg/usr/lib/systemd/system/$unit"; then
    echo "deb: $unit does not start /usr/bin/schild" >&2
    exit 1
  fi
done

for script in postinst prerm postrm; do
  install -m 0755 "$here/deb/$script" "$pkg/DEBIAN/$script"
done

size=$(du -sk --exclude=DEBIAN "$pkg" | cut -f1)
cat > "$pkg/DEBIAN/control" <<EOF
Package: schild
Version: $deb_version
Architecture: $arch
Maintainer: Deutschland-Schild <info@deutschland-schild.de>
Installed-Size: $size
Depends: passwd
Section: httpd
Priority: optional
Homepage: https://deutschland-schild.de
Description: Schild Gateway, a reverse proxy with a web application firewall
 schild is a Caddy distribution with a web application firewall built in
 (Coraza, OWASP CRS) and a local dashboard. It runs as your Caddy with your
 Caddyfile, or as a proxy behind nginx, Apache or a load balancer.
 .
 The package installs the binary, the systemd units and the geo data. It
 starts nothing: "schild init" writes the configuration, and you enable the
 service when you are ready. An upgrade never restarts the service.
EOF

find "$pkg" -exec touch -h -d "@$epoch" {} +
name=schild_${version}_linux_${arch}.deb
SOURCE_DATE_EPOCH=$epoch dpkg-deb --root-owner-group -Zxz --build "$pkg" "$out/$name" >/dev/null

got=$(dpkg-deb -f "$out/$name" Version)
if [ "$got" != "$deb_version" ]; then
  echo "deb: the package reports version \"$got\", want \"$deb_version\"" >&2
  exit 1
fi
ls -l "$out/$name"
