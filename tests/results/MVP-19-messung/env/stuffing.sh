#!/bin/sh
# Runs in m19-tools: distributed credential stuffing during the learning
# period: N addresses (198.51.100.0/24 and 203.0.113.0/24 via X-Forwarded-For),
# each a few failed logins with distinct user names. Prints status counts.
ING=10.219.19.10
N=${1:-400}
i=0
while [ $i -lt $N ]; do
  a=$(( i % 250 + 1 )); net=198.51.100; [ $i -ge 250 ] && net=203.0.113
  for k in 1 2 3; do
    curl -s -o /dev/null -w '%{http_code}\n' --cacert /st/pebble-root.pem --resolve shop.example.de:443:$ING \
      -H "X-Forwarded-For: $net.$a" -d "_token=abc&email=user$i-$k%40example.de&password=wrong" https://shop.example.de/login &
  done
  wait
  i=$((i+1))
done | sort | uniq -c
