# TEST ONLY (MVP-11 review): Debian 12 with a JRE installed outside the package
# manager (like a tarball JDK under /opt, linked into /usr/local/bin), so the
# check runs `java -version`; plus PHP, Node, Python; warm apt lists, docker
# apt tweaks removed like on a VM, /tmp empty.
FROM debian:12
ENV DEBIAN_FRONTEND=noninteractive
RUN rm -f /etc/apt/apt.conf.d/docker-clean /etc/apt/apt.conf.d/docker-gzip-indexes && \
    apt-get update && \
    apt-get install -y --no-install-recommends openjdk-17-jre-headless php-cli nodejs python3 openssh-server iproute2 nftables && \
    cp -a "$(dirname "$(dirname "$(readlink -f /usr/bin/java)")")" /opt/jre && \
    dpkg --purge --force-depends openjdk-17-jre-headless && \
    ln -s /opt/jre/bin/java /usr/local/bin/java && \
    rm -rf /tmp/* /var/cache/apt/*.bin
