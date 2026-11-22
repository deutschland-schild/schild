#!/usr/bin/env bash
# Steps of check-install-proof.sh, run as root inside the disposable "host"
# (a container with systemd as PID 1). TEST ONLY: never run this on a real
# server, it creates users, writes units and starts a gateway.
#
#   steps.sh container|service 1|2     (2: after a boot of the host)
set -euo pipefail
scenario=$1
part=$2
rdir=/var/lib/schild/host-check
req=/run/schild-check/request

step() { echo "== $*"; }
die() { echo "FAIL: $*" >&2; exit 1; }
reports() { find "$rdir" -maxdepth 1 -name '*.json' | wc -l | tr -d ' '; }
# wait_for SECONDS COMMAND...: until the command succeeds.
wait_for() {
  local n=$1; shift
  for _ in $(seq "$((n * 2))"); do
    if "$@" >/dev/null 2>&1; then return 0; fi
    sleep 0.5
  done
  return 1
}
booted() { [ "$(systemctl is-system-running 2>/dev/null)" != starting ] && [ -d /run/systemd/system ]; }
wait_for 60 booted || die "systemd did not come up"

if [ "$scenario" = container ]; then
  reader_uid=65532; reader_gid=65532
  schild=/usr/local/bin/schild
  cfg=/srv/gateway/schild.yaml
  data=/srv/gateway/data
else
  schild=/usr/bin/schild
  cfg=/etc/schild/schild.yaml
  data=/var/lib/schild
fi

# as_reader COMMAND...: what the gateway may do with the two directories.
as_reader() {
  if [ "$scenario" = container ]; then
    setpriv --reuid "$reader_uid" --regid "$reader_gid" --clear-groups "$@"
  else
    # Inside the mount namespace and sandbox of the running schild.service.
    nsenter -t "$(systemctl show schild -p MainPID --value)" -m setpriv --reuid schild --regid schild --clear-groups "$@"
  fi
}
imported() { [ "$(sqlite3 "file:$data/schild.db?mode=ro" 'SELECT COUNT(*) FROM host_reports WHERE host_id = "local"' 2>/dev/null)" -ge "$1" ]; }
has_reports() { [ "$(reports)" -ge "$1" ]; }

start_gateway() {
  if [ "$scenario" = container ]; then
    # The gateway as the container runs it: uid/gid 65532, no extra groups.
    systemd-run --quiet --unit proof-gateway --uid 65532 --gid 65532 \
      -E SCHILD_DATA_DIR="$data" -E SCHILD_HOST_CHECK_TRIGGER="$req" -E HOME="$data" \
      "$schild" run -config "$cfg"
  else
    systemctl restart schild
  fi
}

if [ "$part" = 1 ]; then
  step "the gateway of this scenario, without host_check"
  if [ "$scenario" = container ]; then
    # The image's user (distroless nonroot); the host itself has no such user.
    groupadd --gid 65532 nonroot && useradd --uid 65532 --gid 65532 --no-create-home --shell /usr/sbin/nologin nonroot
    install -d -o 65532 -g 65532 /srv/gateway "$data"
    /opt/proof/schild init -upstream http://127.0.0.1:3000 -config "$cfg" >/dev/null
    chown 65532:65532 "$cfg"
    sed -i "s|^\(\s*path:\s*\).*|\1$data|" "$cfg"
  else
    install -m 0755 /opt/proof/schild /usr/bin/schild
    sed 's|/usr/local/bin/schild|/usr/bin/schild|g' /opt/proof/schild.service > /usr/lib/systemd/system/schild.service
    groupadd --system schild
    useradd --system --gid schild --home-dir /var/lib/schild --no-create-home --shell /usr/sbin/nologin schild
    install -d -o schild -g schild -m 0750 /var/lib/schild
    schild init -upstream http://127.0.0.1:3000 >/dev/null
    systemctl daemon-reload
    systemctl enable --now schild >/dev/null 2>&1
    reader_gid=$(getent group schild | cut -d: -f3)
  fi

  step "dry run changes nothing"
  /opt/proof/schild check install -dry-run > /tmp/dry.txt
  grep -q 'run: systemctl enable --now schild-check.timer schild-check.path' /tmp/dry.txt || die "dry run output"
  [ ! -e /etc/systemd/system/schild-check.service ] && [ ! -e "$rdir" ] || die "dry run wrote files"

  step "install"
  if [ "$scenario" = container ]; then
    /opt/proof/schild check install > /tmp/install.txt
    [ -x /usr/local/bin/schild ] || die "binary not installed to /usr/local/bin"
    grep -q -- "-v $rdir:$rdir:ro" /tmp/install.txt || die "next steps lack the mounts"
  else
    schild check install > /tmp/install.txt
    [ ! -e /usr/local/bin/schild ] || die "service mode copied the binary"
    grep -q 'systemctl restart schild' /tmp/install.txt || die "next steps lack the restart"
    [ -f /etc/systemd/system/schild.service.d/50-host-check.conf ] || die "no drop-in"
  fi
  grep -q "^ExecStart=$schild check -dir $rdir\$" /etc/systemd/system/schild-check.service || die "ExecStart"
  [ "$(systemctl is-enabled schild-check.timer)" = enabled ] && [ "$(systemctl is-active schild-check.timer)" = active ] || die "timer"
  [ "$(systemctl is-enabled schild-check.path)" = enabled ] && [ "$(systemctl is-active schild-check.path)" = active ] || die "path unit"
  [ "$(systemctl show schild-check.service -p Result --value)" = success ] || die "first check: $(journalctl -u schild-check.service --no-pager | tail -5)"

  step "report and directories: readable by the reader group only"
  [ "$(reports)" = 1 ] || die "reports: $(reports)"
  [ "$(stat -c '%a %u %g' "$rdir")" = "2750 0 $reader_gid" ] || die "report dir: $(stat -c '%a %u %g' "$rdir")"
  [ "$(stat -c '%a %u %g' /run/schild-check)" = "770 0 $reader_gid" ] || die "request dir: $(stat -c '%a %u %g' /run/schild-check)"
  [ "$(stat -c '%a %u %g' "$rdir"/*.json)" = "640 0 $reader_gid" ] || die "report: $(stat -c '%a %u %g' "$rdir"/*.json)"
  if setpriv --reuid 65534 --regid 65534 --clear-groups ls "$rdir" >/dev/null 2>&1; then die "nobody can list the reports"; fi

  step "the check wrote nothing else: its unit is read only outside the report dir"
  systemctl show schild-check.service -p ProtectSystem --value | grep -q strict || die "ProtectSystem"

  step "gateway restarted (host_check is in the starter config): the report is imported"
  grep -q '^host_check:' "$cfg" || die "schild init wrote no host_check"
  start_gateway
  wait_for 40 imported 1 || die "gateway did not import the report: $(journalctl -u proof-gateway -u schild --no-pager | tail -8)"
  as_reader sh -c "head -c 1 $rdir/*.json >/dev/null" || die "gateway user cannot read the report"
  if as_reader sh -c "echo x > $rdir/x" 2>/dev/null; then die "gateway user can write into the report dir"; fi

  step "\"Jetzt prüfen\": a request as the gateway starts a run"
  as_reader sh -c "echo now > $req" || die "gateway user cannot write the request"
  wait_for 30 has_reports 2 || die "no run after the request"
  wait_for 10 test ! -e "$req" || die "request not removed"
  wait_for 90 imported 2 || die "gateway did not import the second report"

  step "a schild.yaml that does not load does not wedge the path unit"
  if [ "$scenario" = service ]; then
    cp "$cfg" /tmp/schild.yaml.good
    echo 'config_version: [broken' > "$cfg"
    as_reader sh -c "echo now > $req"
    wait_for 10 test ! -e "$req" || die "request stays with a broken config"
    sleep 3
    [ "$(systemctl is-active schild-check.path)" = active ] || die "path unit: $(systemctl is-active schild-check.path)"
    cp /tmp/schild.yaml.good "$cfg"
    systemctl reset-failed schild-check.service 2>/dev/null || true
    as_reader sh -c "echo now > $req"
    wait_for 30 has_reports 3 || die "no run after the config was repaired"
  fi

  step "a second install changes nothing and breaks nothing"
  before=$(cat /etc/systemd/system/schild-check.* /etc/tmpfiles.d/schild-host-check.conf | sha256sum)
  n=$(reports)
  "$schild" check install >/dev/null
  [ "$before" = "$(cat /etc/systemd/system/schild-check.* /etc/tmpfiles.d/schild-host-check.conf | sha256sum)" ] || die "second install changed the units"
  has_reports "$((n + 1))" || die "second install did not run a check"
  [ "$(systemctl is-active schild-check.timer)" = active ] && [ "$(systemctl is-active schild-check.path)" = active ] || die "units after the second install"
  echo "$(reports)" > /opt/proof/reports-before-boot
  echo "part 1: ok"
  exit 0
fi

# ---- part 2: after a boot (/run is new)
[ "$scenario" = service ] && reader_gid=$(getent group schild | cut -d: -f3)
step "after a boot: timer, path unit and request directory are back"
wait_for 30 systemctl is-active schild-check.timer || die "timer after boot"
wait_for 30 systemctl is-active schild-check.path || die "path unit after boot"
[ "$(stat -c '%a %u %g' /run/schild-check)" = "770 0 $reader_gid" ] || die "request dir after boot: $(stat -c '%a %u %g' /run/schild-check 2>&1)"
n=$(cat /opt/proof/reports-before-boot)
has_reports "$n" || die "reports lost over the boot"
if [ "$scenario" = container ]; then start_gateway; else wait_for 30 systemctl is-active schild || die "schild after boot"; fi
sleep 2
as_reader sh -c "echo now > $req" || die "gateway user cannot write the request after boot"
wait_for 30 has_reports "$((n + 1))" || die "no run after the request (after boot)"

step "uninstall: units gone, reports and binary stay"
n=$(reports)
"$schild" check uninstall >/dev/null
for f in /etc/systemd/system/schild-check.service /etc/systemd/system/schild-check.timer /etc/systemd/system/schild-check.path \
  /etc/tmpfiles.d/schild-host-check.conf /etc/systemd/system/schild.service.d/50-host-check.conf; do
  [ ! -e "$f" ] || die "$f still there"
done
if systemctl is-active schild-check.timer >/dev/null 2>&1; then die "timer still active"; fi
[ "$(reports)" = "$n" ] && [ -x "$schild" ] || die "uninstall removed reports or the binary"
echo "part 2: ok"
