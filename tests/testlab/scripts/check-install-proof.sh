#!/usr/bin/env bash
# D100 proof: `schild check install` sets the server check up on a host with
# systemd, for every way schild is installed. Per distribution one disposable
# container with systemd as PID 1 stands in for the host; nothing runs on
# this machine as a target.
#
#   tests/testlab/scripts/check-install-proof.sh
#   CHECK_INSTALL_IMAGES="debian:13" tests/testlab/scripts/check-install-proof.sh
#
# Two scenarios per image (steps in check-install-steps.sh):
#
#   container  schild runs as a container: the binary is "copied out" to a
#              scratch path, the gateway is a process with uid/gid 65532 (the
#              container's user) that sees the report and request directories
#              as the two mounts would show them.
#   service    schild runs as schild.service with the user schild (package or
#              binary install), with the unit of docs/ops/systemd.
#
# Each proves: units written and enabled, first report 0640 and readable by the
# reader group only, the gateway imports it (host_reports in schild.db), a
# request as the gateway starts a run, a broken schild.yaml does not wedge
# schild-check.path, a boot brings timer, path unit and request directory
# back, a second install changes nothing, uninstall removes the units and
# keeps the reports.
#
# Needs Docker with privileged containers and network for the package mirrors.
# Result: tests/results/runs/check-install/check-install.json. Exit 0 = all passed.
set -euo pipefail
root=$(cd "$(dirname "$0")/../../.." && pwd)
here=$(cd "$(dirname "$0")" && pwd)
docker=${DOCKER:-docker}
images=${CHECK_INSTALL_IMAGES:-debian:12 debian:13 ubuntu:22.04 ubuntu:24.04 rockylinux:9 almalinux:9}
out="$root/tests/results/runs/check-install"
rm -rf "$out"; mkdir -p "$out"
id=schild-check-install-$$

arch=$("$docker" version -f '{{.Server.Arch}}')
case "$arch" in aarch64) arch=arm64 ;; x86_64) arch=amd64 ;; esac
bin="$out/schild"
(cd "$root/gateway" && CGO_ENABLED=0 GOOS=linux GOARCH=$arch go build -o "$bin" ./cmd/schild)

cleanup() { "$docker" ps -aq --filter "label=schild-check-install=$id" | xargs -r "$docker" rm -f >/dev/null 2>&1 || true; }
trap cleanup EXIT

dockerfile() { # image
  case "$1" in
    debian:*|ubuntu:*) cat <<EOF
FROM $1
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
    systemd systemd-sysv openssh-server nftables iproute2 sqlite3 util-linux procps ca-certificates >/dev/null \
 && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
EOF
      ;;
    *) cat <<EOF
FROM $1
RUN dnf install -y -q systemd openssh-server nftables iproute sqlite util-linux procps-ng >/dev/null && dnf clean all >/dev/null
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
EOF
      ;;
  esac
}

results=()
fail=0
for image in $images; do
  tag="schild-check-install-host:$(echo "$image" | tr ':/.' '---')"
  dockerfile "$image" | "$docker" build -q -t "$tag" - >/dev/null
  for scenario in container service; do
    name="$id-$(echo "$image" | tr ':/.' '---')-$scenario"
    log="$out/$(echo "$image" | tr ':/.' '---')-$scenario.log"
    "$docker" run -d --name "$name" --label "schild-check-install=$id" --privileged --cgroupns=host \
      -v /sys/fs/cgroup:/sys/fs/cgroup:rw --tmpfs /run --tmpfs /tmp "$tag" >/dev/null
    "$docker" exec "$name" mkdir -p /opt/proof
    "$docker" cp -q "$bin" "$name:/opt/proof/schild"
    "$docker" cp -q "$here/check-install-steps.sh" "$name:/opt/proof/steps.sh"
    "$docker" cp -q "$root/docs/ops/systemd/schild.service" "$name:/opt/proof/schild.service"
    status=pass
    # Part 1, a boot of the "host", part 2.
    if ! "$docker" exec "$name" bash /opt/proof/steps.sh "$scenario" 1 > "$log" 2>&1; then status=fail; fi
    if [ "$status" = pass ]; then
      "$docker" restart "$name" >/dev/null
      if ! "$docker" exec "$name" bash /opt/proof/steps.sh "$scenario" 2 >> "$log" 2>&1; then status=fail; fi
    fi
    [ "$status" = pass ] || { fail=1; tail -15 "$log" | sed "s|^|  $image $scenario: |"; }
    echo "check-install-proof: $status: $image, $scenario"
    results+=("{\"image\":\"$image\",\"scenario\":\"$scenario\",\"status\":\"$status\"}")
    "$docker" rm -f "$name" >/dev/null
  done
done

verdict=pass; [ "$fail" = 0 ] || verdict=fail
printf '{"decision":"D100","proof":"check-install","status":"%s","finished":"%s","arch":"%s","runs":[%s]}\n' \
  "$verdict" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$arch" "$(IFS=,; echo "${results[*]}")" > "$out/check-install.json"
rm -f "$bin"
echo "check-install-proof: $verdict ($out/check-install.json)"
[ "$fail" = 0 ]
