#!/bin/sh
# The steps of pkgtest.sh that run inside a Debian or Ubuntu container. The
# repository under test is served at http://repo by pkgtest.sh, which swaps
# its content between the steps.
set -eu

step=${1:?usage: steps.sh STEP}
export SCHILD_REPO_URL=http://repo
export DEBIAN_FRONTEND=noninteractive

fail() {
	echo "pkgtest: FAIL ($step): $*" >&2
	exit 1
}

installed_version() {
	dpkg-query -W -f='${Version}' schild
}

run_installer() {
	curl -fsSL "$SCHILD_REPO_URL/install.sh" | sh -s -- "$@"
}

case "$step" in
prepare)
	apt-get update -qq
	apt-get install -y -qq curl ca-certificates >/dev/null
	;;

install)
	# The repository holds 0.9.0~alpha.1 only.
	if out=$(run_installer stable 2>&1); then
		fail "the installer succeeded on an empty stable channel"
	fi
	echo "$out" | grep -q 'has no version yet' || fail "no hint at the alpha channel: $out"
	if out=$(run_installer nightly 2>&1); then
		fail "the installer took an unknown channel"
	fi

	run_installer alpha
	[ "$(installed_version)" = "0.9.0~alpha.1" ] || fail "installed $(installed_version)"
	[ -x /usr/bin/schild ] || fail "no /usr/bin/schild"
	schild version | sed -n 1p | grep -q '^schild ' || fail "schild version does not answer"
	getent passwd schild | grep -q ':/var/lib/schild:/usr/sbin/nologin$' || fail "user schild: $(getent passwd schild)"
	[ "$(stat -c '%U:%G %a' /var/lib/schild)" = "schild:schild 750" ] || fail "/var/lib/schild: $(stat -c '%U:%G %a' /var/lib/schild)"
	for unit in schild.service schild-firewall.service; do
		grep -q '^ExecStart=/usr/bin/schild ' "/usr/lib/systemd/system/$unit" || fail "$unit does not start /usr/bin/schild"
	done
	[ -r /usr/share/schild/geo/country.mmdb ] || fail "no geo data"
	[ -s /usr/share/doc/schild/copyright ] || fail "no copyright file"
	# Installed, never enabled.
	if find /etc/systemd/system -name 'schild*' 2>/dev/null | grep -q .; then
		fail "the package enabled a unit: $(find /etc/systemd/system -name 'schild*')"
	fi
	[ ! -e /etc/schild/schild.yaml ] || fail "the package wrote a schild.yaml"

	schild init -upstream http://127.0.0.1:3000 >/dev/null
	[ -s /etc/schild/schild.yaml ] || fail "schild init wrote no /etc/schild/schild.yaml"
	runuser -u schild -- test -r /etc/schild/schild.yaml || fail "the user schild cannot read schild.yaml"
	cp /etc/schild/schild.yaml /tmp/schild.yaml.before
	touch /var/lib/schild/marker
	;;

upgrade)
	# The repository now holds 0.9.0~alpha.1, 0.9.0~alpha.2 and 0.9.0.
	apt-get update -qq
	apt-get install -y -qq schild >/dev/null
	[ "$(installed_version)" = "0.9.0" ] || fail "upgraded to $(installed_version), want 0.9.0 (a pre-release must sort before it)"
	cmp -s /etc/schild/schild.yaml /tmp/schild.yaml.before || fail "the upgrade changed schild.yaml"
	[ -e /var/lib/schild/marker ] || fail "the upgrade touched /var/lib/schild"
	[ "$(apt-cache madison schild | wc -l)" -eq 3 ] || fail "alpha lists $(apt-cache madison schild | wc -l) versions, want 3"
	;;

tampered)
	# pkgtest.sh changed one byte of the signed index.
	if apt-get update -o APT::Update::Error-Mode=any >/tmp/update.log 2>&1; then
		cat /tmp/update.log >&2
		fail "apt-get update accepted a changed InRelease"
	fi
	;;

channel)
	run_installer stable >/dev/null
	grep -q '^Suites: stable$' /etc/apt/sources.list.d/schild.sources || fail "the channel is not stable"
	[ "$(installed_version)" = "0.9.0" ] || fail "installed $(installed_version) after the switch"
	[ "$(apt-cache madison schild | wc -l)" -eq 1 ] || fail "stable lists $(apt-cache madison schild | wc -l) versions, want 1"
	;;

remove)
	apt-get remove -y -qq schild >/dev/null
	[ ! -e /usr/bin/schild ] || fail "remove left /usr/bin/schild"
	[ -s /etc/schild/schild.yaml ] || fail "remove deleted schild.yaml"
	[ -e /var/lib/schild/marker ] || fail "remove deleted /var/lib/schild"
	apt-get purge -y -qq schild >/dev/null
	[ ! -e /etc/schild ] || fail "purge left /etc/schild"
	[ ! -e /var/lib/schild ] || fail "purge left /var/lib/schild"
	;;

*)
	fail "unknown step"
	;;
esac

echo "pkgtest: ok ($step)"
