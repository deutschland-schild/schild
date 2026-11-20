#!/bin/sh
# Go memory limit as logged by schild run for several container limits.
H=$(cd "$(dirname "$0")" && pwd); . $H/aenv.sh
O=$OUTA/gomemlimit.txt; : > $O
for c in "4g|" "1g|" "2g|" "512m|" "1g|-e GOMEMLIMIT=700MiB" "none|"; do
  mem=${c%%|*}; env=${c#*|}; ingress_rm
  if [ $mem = none ]; then INGRESS_EXTRA="$env" ingress_schild $ST/d-m3 $ST/s-ab-ml $E/Caddyfile.schild $H/schild-m3.yaml
  else INGRESS_EXTRA="--memory $mem --memory-swap $mem $env" ingress_schild $ST/d-m3 $ST/s-ab-ml $E/Caddyfile.schild $H/schild-m3.yaml; fi
  sleep 4; echo "== container memory=$mem $env" >> $O
  docker logs ingress 2>&1 | grep -E '"go memory limit"|"waf evaluation slots"' | sed 's/.*"msg"/  "msg"/' >> $O
done
ingress_rm
