#!/bin/sh
# start.sh <schild|stock> [memory] : (re)start the ingress, wait for HTTPS
H=$(cd "$(dirname "$0")" && pwd); . $H/aenv.sh
ingress_rm
MEM=${2:-4g}
rm -rf $ST/s-ab; mkdir -p $ST/s-ab
if [ "$1" = schild ]; then INGRESS_EXTRA="--memory $MEM --memory-swap $MEM $SCHILD_ENV" ingress_schild $ST/d-ab ${SD:-$ST/s-ab} ${CF:-$E/Caddyfile.schild} ${SY:-$H/schild-m3.yaml}
else INGRESS_EXTRA="--memory $MEM --memory-swap $MEM" ingress_stock $ST/d-ab ${CF:-$E/Caddyfile.stock}; fi
t0=$(date +%s)
wait_https shop.example.de && echo "https up after $(( $(date +%s) - t0 )) s"
