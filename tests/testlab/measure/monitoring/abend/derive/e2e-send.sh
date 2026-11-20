#!/bin/bash
# TEST ONLY: D36 evening re-measurement, e2e traffic for results/messung-2026-10-29-abend/c/derive/e2e-handle-branches (Caddy on 127.0.0.1:22083)
send(){ host=$1; p=$2; n=$3; base=$4; for i in $(seq 1 $n); do curl -s -o /dev/null -w '%{http_code}\n' -H "Host: $host" -H "X-Forwarded-For: 10.9.$base.$i" "http://127.0.0.1:22083$p"; done | sort | uniq -c | sed "s|^|$host $p: |"; }
send full.test /api/x 20 1; send full.test /page 20 2; send hp.test /a/x 10 3; send hp.test /b/y 10 4; send hp.test /z 10 5; send nest.test /api/q 10 6; send nest.test / 10 7; send blog.test / 10 8; send mixed.test /api/m 5 9; send mixed.test /other 10 10
for h in full.test hp.test nest.test blog.test; do for p in "/api/?id=1%27%20OR%20%271%27=%271" "/a/?q=%3Cscript%3Ealert(1)%3C/script%3E"; do echo "$h attack $p: $(curl -s -o /dev/null -w '%{http_code}' -H "Host: $h" -H "X-Forwarded-For: 10.9.20.1" "http://127.0.0.1:22083$p")"; done; done
