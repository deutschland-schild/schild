#!/bin/sh
# Runs inside m19-tools: one body flood (rate given) plus a light normal probe.
ING=10.219.19.10
L="/bin2/m19load-linux -connect $ING:443 -ca /st/pebble-root.pem -warmup 0 -timeout 30s"
P=$1; RATE=$2; N=$3; BODY=${4:-body-1m}
$L -label $P-flood -url https://shop.example.de/contact -method POST -ctype application/x-www-form-urlencoded -body @/st/$BODY.txt -rps $RATE -n $N > /st/$P-flood.json &
$L -label $P-normal -url https://shop.example.de/ -rps 20 -n $(( N * 20 / RATE )) > /st/$P-normal.json &
wait
