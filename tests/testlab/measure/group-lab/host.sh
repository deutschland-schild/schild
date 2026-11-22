#!/bin/bash
# Runs ON the lab host (macOS with Apple's `container` CLI). Creates and removes the VMs of the MVP-27 lab
# measurement. Everything it creates is named sg27-*; it touches nothing else.
#
#   host.sh up NAME[:MEM[:CPUS]] ...   create the test network (if missing) and the named VMs, start their agents
#   host.sh inventory                  JSON: name -> IPv4 of every running sg27-* VM
#   host.sh down                       remove every sg27-* container, the network, the image and the work directory
set -u
WORK="$HOME/sg27-work"
NET=sg27-net
IMAGE=sg27-node:dev

inventory() {
  container list --format json | python3 -c '
import json, sys
out = {}
for c in json.load(sys.stdin):
    name = c["configuration"]["id"]
    if name.startswith("sg27-") and c["status"]["state"] == "running" and c["status"].get("networks"):
        out[name[5:]] = c["status"]["networks"][0]["ipv4Address"].split("/")[0]
print(json.dumps(out, sort_keys=True))'
}

case "${1:-}" in
  up)
    shift
    # the builtin network "default" of this host carried no packets when this was written; an own one does
    container network list | awk '{print $1}' | grep -qx "$NET" || container network create "$NET" >/dev/null || exit 1
    for spec in "$@"; do
      IFS=: read -r name mem cpus <<<"$spec"
      if container list --all --quiet | grep -qx "sg27-$name"; then continue; fi
      container run -d --name "sg27-$name" -m "${mem:-512M}" -c "${cpus:-2}" --network "$NET" --cap-add ALL \
        --progress none "$IMAGE" >/dev/null || { echo "could not start sg27-$name" >&2; exit 1; }
      container exec "sg27-$name" mkdir -p /opt/sg27
      for f in ctl.py app.py netdelay.py; do container cp "$WORK/lab/$f" "sg27-$name:/opt/sg27/$f"; done
      container exec -d "sg27-$name" python3 /opt/sg27/ctl.py
    done
    inventory
    ;;
  inventory) inventory ;;
  down)
    ids=$(container list --all --quiet | grep '^sg27-' || true)
    [ -n "$ids" ] && container delete --force $ids >/dev/null
    container network list | awk '{print $1}' | grep -qx "$NET" && container network delete "$NET" >/dev/null
    container image list | awk '$1 ~ /^sg27-/ {print $1":"$2}' | while read -r i; do container image delete "$i" >/dev/null; done
    rm -rf "$WORK"
    echo "left on the lab host with the prefix sg27-:"
    container list --all | grep sg27- || echo "  no container"
    container image list | grep sg27- || echo "  no image"
    ;;
  *) echo "usage: host.sh up NAME[:MEM[:CPUS]] ... | inventory | down" >&2; exit 2 ;;
esac
