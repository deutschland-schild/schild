#!/bin/bash
# TEST ONLY: MVP-29 measurement. Tries to widen a crawler policy beyond the contract through the dashboard API and the
# agent API (MCP) of instance NAME. Prints the HTTP status (dashboard) or the problem detail (agent) per probe.
#   adv.sh NAME     (needs tok-crawlers in the instance directory)
N=${1:-d}; U=$(cd "$(dirname "$0")" && pwd)
dash() { printf '%-58s ' "dashboard: $1"; "$U/dash.sh" "$N" PUT /websites/${3:-shop.test}/crawlers "$2" | tail -1; }
agent() { printf '%-58s ' "agent: $1"; "$U/agent.sh" "$N" tok-crawlers schild_crawlers_set "$2" | head -1 | python3 -c 'import json,sys; r=json.load(sys.stdin); t=r.get("result",{}).get("content",[{}])[0].get("text",""); e=r.get("error"); print(("ERROR "+json.dumps(e)) if e else ("refused: " if r.get("result",{}).get("isError") else "accepted: ")+t.split("\n\n",1)[-1][:150].replace("\n"," "))'; }
dash "category likely_automated"            '{"categories":{"likely_automated":"block"}}'
dash "category likely_browser"              '{"categories":{"likely_browser":"block"}}'
dash "category unknown"                     '{"categories":{"humans":"block"}}'
dash "category value charge"                '{"categories":{"ai_training":"charge"}}'
dash "category value BLOCK (case)"          '{"categories":{"ai_training":"BLOCK"}}'
dash "category value empty"                 '{"categories":{"ai_training":""}}'
dash "bot unknown"                          '{"bots":{"evil-bot":"block"}}'
dash "bot id with case GPTBot"              '{"bots":{"GPTBot":"block"}}'
dash "impersonators charge"                 '{"impersonators":"charge"}'
dash "preset unknown"                       '{"preset":"block_everything"}'
dash "preset with categories"               '{"preset":"block_ai_training","categories":{"search_engine":"block"}}'
dash "unknown field"                        '{"robots_txt":"write"}'
dash "categories null"                      '{"categories":null}'
dash "array instead of object"              '[]'
dash "unknown website"                      '{}' nosuch.test
dash "website id traversal"                 '{}' '..%2F..%2Fsettings'
BIG=$(python3 -c 'import json; print(json.dumps({"bots":{f"b{i}":"block" for i in range(600)}}))')
dash "600 bot rules (unknown ids)"          "$BIG"
ALL=$(python3 -c 'import json; c=json.load(open("'"$U"'/../../client/internal/bots/catalogue.json")); print(json.dumps({"bots":{b["id"]:"block" for b in c["bots"]}}))')
dash "all 307 catalogue bots block"         "$ALL"
printf '%-58s ' "dashboard: 2 MiB body"; python3 -c 'print("{\"bots\":{\"" + "a"*2097152 + "\":\"block\"}}")' > /tmp/m29/out/big.json; D=/tmp/m29/i/$N; curl -s -o /dev/null -w '%{http_code}\n' -b "$D/cj" -H "X-CSRF-Token: $(cat "$D/csrf")" -H 'Content-Type: application/json' -X PUT --data-binary @/tmp/m29/out/big.json "http://127.0.0.1:$(cat "$D/port")88/api/v0/websites/shop.test/crawlers"
printf '%-58s ' "dashboard: PUT without CSRF"; curl -s -o /dev/null -w '%{http_code}\n' -b "$D/cj" -H 'Content-Type: application/json' -X PUT -d '{}' "http://127.0.0.1:$(cat "$D/port")88/api/v0/websites/shop.test/crawlers"
printf '%-58s ' "dashboard: PUT without session"; curl -s -o /dev/null -w '%{http_code}\n' -H "X-CSRF-Token: $(cat "$D/csrf")" -H 'Content-Type: application/json' -X PUT -d '{}' "http://127.0.0.1:$(cat "$D/port")88/api/v0/websites/shop.test/crawlers"
dash "reset to preset"                      '{"preset":"block_ai_training"}'
agent "category likely_automated"           '{"website":"shop.test","category":"likely_automated","action":"block","reason":"m29"}'
agent "category unknown"                    '{"website":"shop.test","category":"humans","action":"block","reason":"m29"}'
agent "category with inherit"               '{"website":"shop.test","category":"ai_training","action":"inherit","reason":"m29"}'
agent "bot unknown"                         '{"website":"shop.test","bot":"evil-bot","action":"block","reason":"m29"}'
agent "bot action charge"                   '{"website":"shop.test","bot":"gptbot","action":"charge","reason":"m29"}'
agent "two changes at once"                 '{"website":"shop.test","bot":"gptbot","category":"search_engine","action":"block","reason":"m29"}'
agent "nothing named"                       '{"website":"shop.test","reason":"m29"}'
agent "no reason"                           '{"website":"shop.test","bot":"gptbot","action":"block"}'
agent "reason with control char"            '{"website":"shop.test","bot":"gptbot","action":"block","reason":"a\u0007b"}'
R301=$(python3 -c 'print("x"*301)')
agent "reason 301 chars"                    '{"website":"shop.test","bot":"gptbot","action":"block","reason":"'"$R301"'"}'
agent "unknown field robots_txt"            '{"website":"shop.test","bot":"gptbot","action":"block","reason":"m29","robots_txt":"write"}'
agent "unknown website"                     '{"website":"nosuch.test","bot":"gptbot","action":"block","reason":"m29"}'
agent "impersonators with action"           '{"website":"shop.test","impersonators":"block","action":"block","reason":"m29"}'
agent "preset with action"                  '{"website":"shop.test","preset":"block_ai_training","action":"block","reason":"m29"}'
agent "preset unknown"                      '{"website":"shop.test","preset":"block_everything","reason":"m29"}'
R3K=$(python3 -c 'print("y"*3000)')
agent "body over 2 KiB"                     '{"website":"shop.test","bot":"gptbot","action":"block","reason":"'"$R3K"'"}'
agent "valid: block search_engine"          '{"website":"shop.test","category":"search_engine","action":"block","reason":"m29 accepted risk check"}'
agent "valid: back to allow"                '{"website":"shop.test","category":"search_engine","action":"allow","reason":"m29"}'
