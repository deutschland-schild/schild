#!/bin/bash
# TEST ONLY: MVP-29 measurement. Dashboard API call of an instance from inst.sh with its session and CSRF token.
#   dash.sh NAME METHOD PATH [JSON]      e.g. dash.sh a PUT /websites/shop.test/crawlers '{"preset":"block_ai_training"}'
D=/tmp/m29/i/$1; P=$(cat "$D/port")
if [ -n "${4:-}" ]; then
  curl -s -w '\n%{http_code}\n' -b "$D/cj" -H "X-CSRF-Token: $(cat "$D/csrf")" -H 'Content-Type: application/json' -X "$2" -d "$4" "http://127.0.0.1:${P}88/api/v0$3"
else
  curl -s -w '\n%{http_code}\n' -b "$D/cj" -H "X-CSRF-Token: $(cat "$D/csrf")" -X "$2" "http://127.0.0.1:${P}88/api/v0$3"
fi
