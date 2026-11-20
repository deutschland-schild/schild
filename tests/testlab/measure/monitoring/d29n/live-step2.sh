#!/bin/sh
# TEST ONLY: d29n live step 2 - wait until the 15 min blocks ended, check, re-offend.
cd /tmp/d36n/c; U=http://127.0.0.1:20200
sleep 910
./d29 status -url $U 10.1.0.10 10.0.0.10 10.20.0.10 > live-step1-expired.jsonl
./d29 probe -url $U 10.1.0.10 10.0.0.10 10.23.0.10 10.20.0.10 > live-step2-probe.jsonl
echo done > step2.done
