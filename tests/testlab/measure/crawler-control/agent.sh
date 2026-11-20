#!/bin/bash
# TEST ONLY: MVP-29 measurement. One MCP tools/call against the agent API of an instance.
#   agent.sh NAME TOKENFILE TOOL 'JSON-ARGS'
D=/tmp/m29/i/$1; P=$(cat "$D/port")
curl -s -w '\n%{http_code} %{time_total}s\n' -H "Authorization: Bearer $(cat "$D/$2")" -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -X POST -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"$3\",\"arguments\":$4}}" "http://127.0.0.1:${P}89/mcp"
