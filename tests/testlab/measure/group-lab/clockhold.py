#!/usr/bin/env python3
"""Keep the wall clock of this VM a fixed number of seconds off (MVP-27 lab measurement, scenario 3).

The hypervisor of the lab host sets the clock of a VM back to the host's time every few seconds, so `date -s`
alone does not last. This process takes the right time once (the clock as it is at its start, carried on by the
monotonic clock), sets the wall clock to that plus SHIFT and puts it back there whenever something moved it,
checking every 2 ms. Every correction is written to LOG with its time, so a check can say how often and for how
long the clock was right in between. SIGTERM sets the right time again and ends.

usage: clockhold.py SHIFT_SECONDS [LOG]
"""
import signal
import sys
import time

shift = float(sys.argv[1])
log = open(sys.argv[2] if len(sys.argv) > 2 else "/tmp/sg27-clockhold.log", "w")
mono0 = time.clock_gettime(time.CLOCK_MONOTONIC)
real0 = time.clock_gettime(time.CLOCK_REALTIME)


def right():
    return real0 + (time.clock_gettime(time.CLOCK_MONOTONIC) - mono0)


def stop(*_):
    time.clock_settime(time.CLOCK_REALTIME, right())
    log.write("%.3f end\n" % (time.clock_gettime(time.CLOCK_MONOTONIC) - mono0))
    log.close()
    sys.exit(0)


signal.signal(signal.SIGTERM, stop)
time.clock_settime(time.CLOCK_REALTIME, right() + shift)
log.write("0.000 set %+.1f\n" % shift)
log.flush()
while True:
    want = right() + shift
    off = time.clock_gettime(time.CLOCK_REALTIME) - want
    if abs(off) > 0.25:
        time.clock_settime(time.CLOCK_REALTIME, right() + shift)
        log.write("%.3f corrected, the clock was %+.2f s off the shifted time\n" % (time.clock_gettime(time.CLOCK_MONOTONIC) - mono0, off))
        log.flush()
    time.sleep(0.002)
