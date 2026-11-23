#!/bin/bash
# MVP-27 lab measurement: a group of schild gateways on real Linux VMs of the lab host.
#
#   SCHILD_LAB_HOST=<ssh alias of the lab host> tests/testlab/measure/group-lab/run.sh [s1 s2 ...]
#
# Builds a development schild for linux/arm64 and the test image on this machine, copies both to the lab host,
# creates the VMs there (all named sg27-*), runs the scenarios inside the client VM, writes
# tests/results/MVP-27-lab-run3.json (RESULTS=<file> names another one) and removes everything from the lab host again (KEEP=1 keeps the VMs).
# REUSE=1 with the WORK of an earlier KEEP=1 call builds nothing and creates nothing: it copies the scripts again and runs the
# scenarios on the VMs that are up, so a run can be made in parts. CM_DIR names a short directory for the ssh control socket
# when WORK is a long path. OLD_REV is the commit of the earlier build the mixed-version checks put next to the current one.
# The name of the lab host is read from SCHILD_LAB_HOST and written nowhere.
set -euo pipefail
: "${SCHILD_LAB_HOST:?set SCHILD_LAB_HOST to the ssh alias of the lab host}"
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../../.." && pwd)"
WORK="${WORK:-$(mktemp -d /tmp/sg27-lab.XXXXXX)}"
OUT="${OUT:-$WORK/out}"
# the earlier runs (MVP-27-lab.json on e0349dc, MVP-27-lab-run2.json on e54c040) are not written again
RESULTS="${RESULTS:-$ROOT/tests/results/MVP-27-lab-run3.json}"
OLD_REV="${OLD_REV:-e54c040}"
CM_DIR="${CM_DIR:-$WORK}"
SCENARIOS=("$@")
[ ${#SCENARIOS[@]} -gt 0 ] || SCENARIOS=(s1 s2 s3 s4 s5 s7 s8 s9 s10 s11 s12 s13 s14 s15 s16 s17 s18 s19 s20 s21 s22 s23 s24 s25)
SSH=(ssh -o BatchMode=yes -o ControlMaster=auto -o "ControlPath=$CM_DIR/cm-%C" -o ControlPersist=600)
lab() { "${SSH[@]}" "$SCHILD_LAB_HOST" "$@"; }
push() { rsync -a -e "${SSH[*]}" "$@"; }

cleanup() {
  if [ "${KEEP:-0}" != 1 ]; then
    lab 'bash ~/sg27-work/lab/host.sh down' || echo "the lab host could not be cleaned: remove sg27-* there by hand" >&2
  fi
}
trap cleanup EXIT

mkdir -p "$WORK/img" "$WORK/extra" "$OUT" "$CM_DIR"
if [ "${REUSE:-0}" = 1 ]; then
  echo "== reuse: the VMs of an earlier call, scripts copied again"
  push --exclude __pycache__ --exclude loadgen "$HERE/" "${SCHILD_LAB_HOST}:sg27-work/lab/"
  lab 'cd ~/sg27-work && for f in lab/*.py lab/inventory.json; do container cp $f sg27-client:/opt/sg27/$(basename $f) >/dev/null; done'
else
  echo "== build (test binaries, never a release)"
  (cd "$ROOT/gateway" && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o "$WORK/img/schild" ./cmd/schild)
  (cd "$ROOT/gateway" && go run ./cmd/schild geo-fixture -out "$WORK/img/geo.mmdb")
  (cd "$HERE/../group/hostile" && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o "$WORK/extra/hostile" .)
  # the load client of the throughput scenario (the Python client makes a few hundred requests a second)
  (cd "$HERE/loadgen" && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o "$WORK/extra/loadgen" .)
  # the earlier build for the mixed-version checks: the tree of OLD_REV, built the same way, in the image as schild-old
  rm -rf "$WORK/old-src" && mkdir -p "$WORK/old-src"
  git -C "$ROOT" archive "$OLD_REV" go.work go.work.sum contract gateway lab relay tests/adversaries tests/testlab | tar -x -C "$WORK/old-src"
  (cd "$WORK/old-src/gateway" && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -o "$WORK/img/schild-old" ./cmd/schild)
  git -C "$ROOT" rev-parse "$OLD_REV" > "$OUT/git-rev-old"
  # the ACME test server of scenario 7; without it the scenario reports "not measured"
  if (cd "$WORK" && GOPATH="$WORK/gopath" GOFLAGS=-modcacherw GOOS=linux GOARCH=arm64 CGO_ENABLED=0 \
      go install github.com/letsencrypt/pebble/v2/cmd/pebble@v2.8.0) 2>/dev/null; then
    P="$WORK/gopath/pkg/mod/github.com/letsencrypt/pebble/v2@v2.8.0/test/certs"
    # install, not cp: the files of the module cache are read-only, and a second run with the same WORK writes over them
    install -m 0755 "$WORK/gopath/bin/linux_arm64/pebble" "$WORK/extra/pebble"
    install -m 0644 "$P/pebble.minica.pem" "$WORK/extra/pebble.minica.pem"
    install -m 0644 "$P/localhost/cert.pem" "$WORK/extra/pebble-cert.pem"
    install -m 0644 "$P/localhost/key.pem" "$WORK/extra/pebble-key.pem"
  fi
  cp "$HERE/Dockerfile" "$WORK/img/Dockerfile"
  # the image is built here: the builder of the lab host had no network when this was written
  docker build --platform linux/arm64 -t sg27-node:dev "$WORK/img" >/dev/null
  docker save sg27-node:dev -o "$WORK/sg27-node.tar"
  docker image inspect sg27-node:dev --format '{{.Id}}' > "$OUT/image-id"
  git -C "$ROOT" rev-parse HEAD > "$OUT/git-rev"

  echo "== lab host: image and VMs"
  lab 'mkdir -p ~/sg27-work/lab ~/sg27-work/extra ~/sg27-work/out'
  push "$WORK/sg27-node.tar" "${SCHILD_LAB_HOST}:sg27-work/sg27-node.tar"
  push --exclude __pycache__ "$HERE/" "${SCHILD_LAB_HOST}:sg27-work/lab/"
  push "$WORK/extra/" "${SCHILD_LAB_HOST}:sg27-work/extra/"
  lab 'container image load -i ~/sg27-work/sg27-node.tar >/dev/null && rm ~/sg27-work/sg27-node.tar'
  VMS="client:1G:4 app:512M:2 lb:512M:2 n1:768M:2 n2:768M:2"
  for i in $(seq 3 16); do VMS="$VMS n$i:512M:2"; done
  lab "bash ~/sg27-work/lab/host.sh up $VMS > ~/sg27-work/lab/inventory.json"
  lab 'cd ~/sg27-work && sysctl -n hw.ncpu > out/host-cpus; sysctl -n hw.memsize > out/host-mem
    for f in lab/*.py lab/inventory.json; do container cp $f sg27-client:/opt/sg27/$(basename $f) >/dev/null; done
    [ -f extra/pebble ] && for f in pebble pebble.minica.pem pebble-cert.pem pebble-key.pem; do container cp extra/$f sg27-app:/opt/sg27/$f >/dev/null; done
    container cp extra/hostile sg27-lb:/opt/sg27/hostile >/dev/null
    container cp extra/loadgen sg27-client:/opt/sg27/loadgen >/dev/null; container exec sg27-client chmod +x /opt/sg27/loadgen
    container exec sg27-app sh -c "chmod +x /opt/sg27/pebble 2>/dev/null; true"; container exec sg27-lb chmod +x /opt/sg27/hostile'
fi

for s in "${SCENARIOS[@]}"; do
  echo "== $s"
  [ -f "$OUT/$s.log" ] && mv "$OUT/$s.log" "$OUT/$s.log.$(date +%H%M%S)"
  [ -f "$OUT/raw-$s.json" ] && cp "$OUT/raw-$s.json" "$OUT/raw-$s.json.$(date +%H%M%S).old"
  lab "container exec sg27-client sh -c 'cd /opt/sg27 && python3 -u run.py --only $s 2>&1'" | tee "$OUT/$s.log" | cut -c1-240 || true
  # a scenario that wrote no result (the driver broke before its first check) must not end the run
  lab "container cp sg27-client:/opt/sg27/out/raw-$s.json ~/sg27-work/out/raw-$s.json >/dev/null && cat ~/sg27-work/out/raw-$s.json" > "$OUT/raw-$s.json" \
    || { echo "no result of $s: see $OUT/$s.log" >&2; rm -f "$OUT/raw-$s.json"; }
done
for f in host-cpus host-mem; do lab "cat ~/sg27-work/out/$f" > "$OUT/$f"; done
# the evidence scenario 11 keeps when a block is left over
lab 'for f in $(container exec sg27-client sh -c "ls /opt/sg27/out/ 2>/dev/null" | grep evidence); do container cp sg27-client:/opt/sg27/out/$f ~/sg27-work/out/$f >/dev/null; done; true'
push "${SCHILD_LAB_HOST}:sg27-work/out/" "$OUT/host-out/" || true

python3 "$HERE/report.py" "$OUT" "$RESULTS" "$OUT/tables.md"
echo "raw results and logs: $OUT"
