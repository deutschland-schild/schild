#!/bin/sh
# locked.sh <description> <command...>: wait for /tmp/abend/heavy.lock to be free, hold it while the command runs.
L=/tmp/abend/heavy.lock; d=$1; shift
while :; do
  if ( set -C; echo "a $d $(date)" > $L ) 2>/dev/null; then break; fi
  sleep 10
done
echo "lock taken $(date +%T) load $(uptime | sed 's/.*averages: //')"
"$@"; rc=$?
rm -f $L
exit $rc
