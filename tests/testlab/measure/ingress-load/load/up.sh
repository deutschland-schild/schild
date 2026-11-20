#!/bin/sh
H=$(cd "$(dirname "$0")" && pwd); . $H/aenv.sh
case $1 in up) net_up_a ;; down) net_down ;; esac
