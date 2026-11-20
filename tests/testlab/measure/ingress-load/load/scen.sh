#!/bin/sh
# Runs inside m19-tools. scen.sh <scenario> <tag>: attack traffic plus normal
# GETs from 50 other clients (X-Forwarded-For 203.0.113.0/50) at the same
# time, 60 s. Output: /st/<tag>-<part>.json
ING=10.219.19.10
L="/bin2/m19m3load-linux -connect $ING:443 -ca /st/pebble-root.pem -timeout 30s"
S=$1; T=$2; F=application/x-www-form-urlencoded
NX="-xff 203.0.113.1/50"
normal() { $L -label $T-normal -url https://shop.example.de/ $NX -rps ${1:-50} -n $(( ${1:-50} * 60 )) > /st/$T-normal.json & }
# post <part> <rps> <file> <ctype> <xff-spec|-> ; xff "-" = one client (the tools container itself)
post() { x=""; [ "${5:--}" != - ] && x="-xff $5"
  $L -label $T-$1 -url https://shop.example.de/contact -method POST -body @/st/$3 -ctype $4 $x -rps $2 -n $(( $2 * 60 )) > /st/$T-$1.json & }
getq() { x=""; [ "${4:--}" != - ] && x="-xff $4"
  $L -label $T-$1 -url https://shop.example.de/search -query @/st/$3 $x -rps $2 -n $(( $2 * 60 )) > /st/$T-$1.json & }
geth() { x=""; [ "${4:--}" != - ] && x="-xff $4"
  $L -label $T-$1 -url https://shop.example.de/page -hfile /st/$3 $x -rps $2 -n $(( $2 * 60 )) > /st/$T-$1.json & }
MANY=198.18.0.1/500
# getqn: like getq, but every request is a browser navigation (headers from /e3/nav.hdr)
getqn() { $L -label $T-$1 -url https://shop.example.de/search -query @/st/$3 -hfile /e3/nav.hdr -xff $4 -rps $2 -n $(( $2 * 60 )) > /st/$T-$1.json & }
CG=100.64.12.34/1
case $S in
  idle)        normal 50 ;;
  q60k100)     normal 50; getq q60k 100 query-60k.txt $MANY ;;
  q30k100-1)   normal 50; getq q30k 100 query-30k.txt - ;;
  q30k100-m)   normal 50; getq q30k 100 query-30k.txt $MANY ;;
  q30kb100-m)  normal 50; getq q30kb 100 query-30k-benign.txt $MANY ;;
  q30k100-cg)  normal 50; getq q30k 100 query-30k.txt $CG ;;
  q990s100-m)  normal 50; getq q990s 100 query-990short.txt $MANY ;;
  q30k200-m)   normal 50; getq q30k 200 query-30k.txt $MANY ;;
  f100k10-m)   normal 50; post f100k 10 benign-100k.txt $F $MANY ;;
  f330k10-m)   normal 50; post f330k 10 form-330k.txt $F $MANY ;;
  f1m5-m)      normal 50; post f1m 5 form-1m.txt $F $MANY ;;
  f5m2-m)      normal 50; post f5m 2 form-5m.txt $F $MANY ;;
  f1m5-1)      normal 50; post f1m 5 form-1m.txt $F - ;;
  args30-m)    normal 50; post args 30 body-127k-args.txt $F $MANY ;;
  b1m20-m)     normal 50; post flood 20 body-1m.txt $F $MANY ;;
  cookies100-m) normal 50; geth cookies 100 cookies-149.hdr $MANY ;;
  headers100-m) normal 50; geth headers 100 headers-90x700.hdr $MANY ;;
  stress-m)    normal 50; getq q30k 200 query-30k.txt $MANY; getq q990s 200 query-990short.txt 198.19.0.1/500; post args 60 body-127k-args.txt $F 198.20.0.1/500; post f330k 10 form-330k.txt $F 198.21.0.1/500 ;;
  wpnav-m)     normal 50; getqn q30kn 200 query-30k.txt $MANY; getqn q990n 200 query-990short.txt 198.19.0.1/500 ;;
  wpapi-m)     normal 50; getq q30k 200 query-30k.txt $MANY; getq q990s 200 query-990short.txt 198.19.0.1/500 ;;
  combo-m)     normal 50; getq q30k 60 query-30k.txt $MANY; post f330k 5 form-330k.txt $F $MANY; post args 20 body-127k-args.txt $F $MANY; geth headers 50 headers-90x700.hdr $MANY ;;
esac
wait
