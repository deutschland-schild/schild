#!/usr/bin/env bash
# Builds the release tarball schild_<version>_linux_<arch>.tar.gz from the
# `dist` target of gateway/Dockerfile: the same binary as in the image, built
# for the platform of the builder. Used by the release workflow; locally:
#
#   gateway/deploy/release/tarball.sh 0.1.0-alpha.1 arm64 /tmp/out
#
# Extra arguments go to docker buildx build (e.g. --build-arg GEO=fixture for
# a local try without the download; never for a release).
set -euo pipefail

version=${1:?usage: tarball.sh VERSION ARCH OUTDIR [docker build args]}
arch=${2:?usage: tarball.sh VERSION ARCH OUTDIR [docker build args]}
out=${3:?usage: tarball.sh VERSION ARCH OUTDIR [docker build args]}
shift 3
root=$(cd "$(dirname "$0")/../../.." && pwd)
name=schild_${version}_linux_${arch}
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

docker buildx build -f "$root/gateway/Dockerfile" --target dist \
  --platform "linux/$arch" \
  --build-arg TAGS=release --build-arg "VERSION=$version" "$@" \
  --provenance=false --sbom=false \
  --output "type=local,dest=$stage" "$root"

want=(LICENSE NOTICE README.txt THIRD_PARTY_LICENSES geo schild schild-firewall.service schild.service)
got=$(find "$stage" -mindepth 1 -maxdepth 1 -exec basename {} \; | LC_ALL=C sort | tr '\n' ' ' | sed 's/ $//')
if [ "$got" != "${want[*]}" ]; then
  echo "tarball: unexpected content: $got (want: ${want[*]})" >&2
  exit 1
fi
chmod 0755 "$stage/schild" "$stage/geo"
chmod 0644 "$stage"/LICENSE "$stage"/NOTICE "$stage"/README.txt "$stage"/THIRD_PARTY_LICENSES "$stage"/schild-firewall.service "$stage"/schild.service "$stage"/geo/*

mkdir -p "$out"
out=$(cd "$out" && pwd)
# Reproducible archive with GNU tar (the release runners); plain tar elsewhere.
if tar --version 2>/dev/null | grep -q 'GNU tar'; then
  tar -C "$stage" --sort=name --owner=0 --group=0 --numeric-owner \
    --mtime="@${SOURCE_DATE_EPOCH:-0}" -cf - "${want[@]}" | gzip -n -9 > "$out/$name.tar.gz"
else
  # COPYFILE_DISABLE keeps macOS tar from adding ._* files.
  COPYFILE_DISABLE=1 tar -C "$stage" -czf "$out/$name.tar.gz" "${want[@]}"
fi
ls -l "$out/$name.tar.gz"
