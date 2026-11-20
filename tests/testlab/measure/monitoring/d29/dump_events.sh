#!/bin/sh
# dump_events.sh DB [TYPE-LIKE]  -> behaviour/ratelimit events as JSON lines (body column)
sqlite3 "$1" "SELECT CAST(body AS TEXT) FROM events WHERE type LIKE '${2:-schild.behaviour.%}' ORDER BY seq"
