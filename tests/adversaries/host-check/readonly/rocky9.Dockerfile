# TEST ONLY (MVP-11 review, kill criterion "the check changes system state"):
# a Rocky Linux 9 host with a warm dnf cache, dnf-utils (needs-restarting),
# sshd and a Java runtime. The cache is filled at build time (network); the
# check itself runs with --network none (readonly-distros.sh).
FROM rockylinux/rockylinux:9
RUN dnf -y install openssh-server dnf-utils iproute nftables java-17-openjdk-headless php-cli && \
    dnf -y makecache && \
    ssh-keygen -A && \
    rm -f /var/log/dnf*.log /var/log/hawkey.log
