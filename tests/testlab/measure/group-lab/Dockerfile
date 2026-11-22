# TEST ONLY image of the MVP-27 lab measurement: a development build of schild on Debian with the tools the
# harness needs in every VM. Never a release, never published.
FROM debian:trixie
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    iproute2 nftables iptables curl ca-certificates haproxy python3 procps iputils-ping netcat-openbsd tcpdump openssl \
    && rm -rf /var/lib/apt/lists/*
COPY schild /usr/local/bin/schild
COPY geo.mmdb /opt/geo.mmdb
RUN chmod 0755 /usr/local/bin/schild && mkdir -p /etc/schild /var/lib/schild /var/log/schild
CMD ["sleep", "infinity"]
