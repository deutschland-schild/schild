#!/usr/bin/env python3
"""Delay, jitter and loss for the packets this VM sends to some addresses (MVP-27 lab measurement).

The kernel of the lab VMs has no netem qdisc (CONFIG_NET_SCH_NETEM is not set). This does the same for the
packets toward the given peers, at the IP layer: a route sends them into a TUN device, this process reads each
packet, holds it for the delay and sends it out of eth0 unchanged through a raw socket. TCP stays end to end
between the two VMs; no connection is terminated in between.

usage: netdelay.py --src OWN_IP --delay-ms 100 [--jitter-ms 20] [--loss 0.05] PEER_IP [PEER_IP ...]
Stop with SIGTERM: routes and the device are removed.
"""
import argparse
import fcntl
import heapq
import os
import random
import select
import signal
import socket
import struct
import subprocess
import sys
import time

DEV = "sgd0"
TUNSETIFF = 0x400454CA
IFF_TUN, IFF_NO_PI = 0x0001, 0x1000


def sh(cmd):
    subprocess.run(cmd, shell=True, check=False, capture_output=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", required=True)
    ap.add_argument("--delay-ms", type=float, default=0)
    ap.add_argument("--jitter-ms", type=float, default=0)
    ap.add_argument("--loss", type=float, default=0)
    ap.add_argument("--seed", type=int, default=27)
    ap.add_argument("peers", nargs="+")
    a = ap.parse_args()
    rnd = random.Random(a.seed)

    tun = os.open("/dev/net/tun", os.O_RDWR)
    fcntl.ioctl(tun, TUNSETIFF, struct.pack("16sH", DEV.encode(), IFF_TUN | IFF_NO_PI))
    sh("ip link set %s up mtu 1280" % DEV)
    for f in ("all", "eth0", DEV):
        sh("sysctl -qw net.ipv4.conf.%s.rp_filter=0" % f)
    for p in a.peers:
        sh("ip route replace %s/32 dev %s src %s" % (p, DEV, a.src))

    out = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    out.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"eth0")

    def stop(*_):
        for p in a.peers:
            sh("ip route del %s/32 dev %s" % (p, DEV))
        sys.exit(0)

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)

    queue, n = [], 0
    while True:
        wait = max(0.0, queue[0][0] - time.monotonic()) if queue else 1.0
        r, _, _ = select.select([tun], [], [], wait)
        now = time.monotonic()
        if r:
            pkt = os.read(tun, 65535)
            if len(pkt) >= 20 and pkt[0] >> 4 == 4 and rnd.random() >= a.loss:
                d = a.delay_ms + (rnd.uniform(-a.jitter_ms, a.jitter_ms) if a.jitter_ms else 0)
                n += 1
                heapq.heappush(queue, (now + max(0.0, d) / 1000.0, n, pkt))
        while queue and queue[0][0] <= now:
            _, _, pkt = heapq.heappop(queue)
            try:
                out.sendto(pkt, (socket.inet_ntoa(pkt[16:20]), 0))
            except OSError:
                pass


if __name__ == "__main__":
    main()
