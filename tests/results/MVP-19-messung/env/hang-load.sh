#!/bin/sh
# Runs inside m19-tools: normal traffic plus requests that exceed the gate's
# eval budget plus a slow backend, all at once. Every request must get an
# answer (no client timeout = no hang).
ING=10.219.19.10
L="/bin2/m19load-linux -connect $ING:443 -ca /st/pebble-root.pem -warmup 0 -timeout 30s"
P=${1:-hang}
$L -label $P-normal-get -url https://shop.example.de/ -rps 400 -n 12000 > /st/$P-1.json &
$L -label $P-heavy-1m -url https://shop.example.de/contact -method POST -ctype application/x-www-form-urlencoded -body @/st/body-1m.txt -rps 20 -n 600 > /st/$P-2.json &
$L -label $P-200k -url https://api.example.de/v1/import -method POST -ctype application/x-www-form-urlencoded -body @/st/body-200k.txt -rps 50 -n 1500 > /st/$P-3.json &
$L -label $P-slow-backend -url 'https://portal.example.de/__sleep?ms=1500' -rps 20 -n 600 > /st/$P-4.json &
wait
