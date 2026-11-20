# TEST ONLY "app VM" of the MVP-11 agent lab (profile t1 overlay
# compose/docker-compose.t1.agents.yaml): an ordinary, somewhat neglected
# Debian application server behind the gateway schild.
#
#   docker build -f testlab/dockerfiles/app-vm.Dockerfile -t schild-testlab-app-vm:dev testlab/dockerfiles/app-vm
#   (make testlab-app-vm-image)
#
# What it plants for the server check (and the smoke expects, see
# cmd/smoke/agents.go checkPlanted):
#   - Debian 13 with PHP 8.1 (EOL 2025-12-31) as php-fpm on 127.0.0.1:9000 (loopback: no finding)
#   - nginx on :80 (a web server on a web server: expected)
#   - MariaDB listening on 0.0.0.0:3306 (public database: finding)
#   - sshd with PasswordAuthentication yes and PermitRootLogin yes (findings)
#   - nftables installed, no ruleset (no active firewall), no unattended-upgrades
#   - a pending update of the canary package schild-canary-pkg-q7m3x9 (1.0 installed,
#     1.1 in a local file repository; the apt lists are kept, no network needed)
#   - a WordPress-like tree in /var/www/html (version.php 6.4.2, one plugin) with
#     secret canaries in wp-config.php and .env that no report may ever carry
#
# The binaries are NOT built here (the test lab never builds schild): compose
# mounts /usr/local/bin of the schild:dev image at /opt/schild (image volume), so
# a rebuilt image is picked up without rebuilding this one. An app VM uses
# schild-agent (enrol, run, once, check); gw-host-check plays the gateway
# host and uses schild check.
#
# Base: php:8.1.34-fpm (Debian 13 trixie), pinned by digest.
ARG BASE=php:8.1.34-fpm@sha256:a3118db1911fdd3b3ac66605122ddc859286688ced86fc860fec6d19cc2d6c55
FROM ${BASE}
ARG CANARY_PKG=schild-canary-pkg-q7m3x9
ENV DEBIAN_FRONTEND=noninteractive

# Canary package: 1.0 installed, 1.1 offered by a local flat repository.
RUN set -eux; \
    mkdir -p /opt/schild-canary-repo /tmp/canary; \
    for v in 1.0 1.1; do \
      d=/tmp/canary/$v; mkdir -p $d/DEBIAN $d/usr/share/doc/$CANARY_PKG; \
      printf 'Package: %s\nVersion: %s\nArchitecture: all\nMaintainer: Schild test lab <testlab@schild.invalid>\nSection: misc\nPriority: optional\nDescription: TEST ONLY canary package of the Schild test lab (MVP-11)\n A host report may carry this name; a lab must never see it.\n' "$CANARY_PKG" "$v" > $d/DEBIAN/control; \
      echo "TEST ONLY canary package $v" > $d/usr/share/doc/$CANARY_PKG/README; \
      dpkg-deb --root-owner-group --build $d /tmp/canary/${CANARY_PKG}_${v}_all.deb; \
    done; \
    dpkg -i /tmp/canary/${CANARY_PKG}_1.0_all.deb; \
    f=${CANARY_PKG}_1.1_all.deb; cp /tmp/canary/$f /opt/schild-canary-repo/; \
    cd /opt/schild-canary-repo; \
    { dpkg-deb -f $f; echo "Filename: ./$f"; echo "Size: $(stat -c %s $f)"; echo "SHA256: $(sha256sum $f | cut -d' ' -f1)"; echo; } > Packages; \
    echo 'deb [trusted=yes] file:/opt/schild-canary-repo ./' > /etc/apt/sources.list.d/schild-canary.list; \
    rm -rf /tmp/canary

# A realistic package set. The apt lists stay (offline `apt list --upgradable`
# needs them; the check never refreshes them). The Docker-image apt tweaks go
# (docker-clean disables apt's binary cache, gzip-indexes compresses the
# lists): a VM has neither, and on a VM apt run as root rewrites
# /var/cache/apt/*.bin when it is missing or stale. The read-only proof must
# see that, so the image ends without those caches.
RUN set -eux; \
    rm -f /etc/apt/apt.conf.d/docker-clean /etc/apt/apt.conf.d/docker-gzip-indexes /etc/apt/apt.conf.d/docker-no-languages /etc/apt/apt.conf.d/docker-autoremove-suggests; \
    rm -rf /var/lib/apt/lists/*; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      openssh-server mariadb-server nginx nftables iproute2 procps cron less vim-tiny ca-certificates; \
    apt-get clean; \
    mkdir -p /run/sshd /run/mysqld; chown mysql:mysql /run/mysqld; \
    rm -f /etc/nginx/sites-enabled/default

COPY rootfs/ /
# The .env canary is kept as dotenv.canary because the repository ignores every .env file.
COPY dotenv.canary /var/www/html/.env
RUN set -eux; \
    ln -s /etc/nginx/sites-available/app /etc/nginx/sites-enabled/app; \
    ln -s /opt/schild/schild /usr/local/bin/schild; \
    ln -s /opt/schild/schild-agent /usr/local/bin/schild-agent; \
    chmod 0755 /usr/local/sbin/app-vm-entrypoint /usr/local/sbin/schild-testlab-agent; \
    chown -R www-data:www-data /var/www/html; chmod 0640 /var/www/html/wp-config.php /var/www/html/.env; \
    mkdir -p /var/lib/schild-agent /var/lib/schild/host-check /opt/schild; \
    nginx -t; sshd -t; \
    apt list --upgradable 2>/dev/null | grep -q "$CANARY_PKG"; \
    rm -f /var/cache/apt/*.bin

EXPOSE 22 80 3306
ENTRYPOINT ["/usr/local/sbin/app-vm-entrypoint"]
