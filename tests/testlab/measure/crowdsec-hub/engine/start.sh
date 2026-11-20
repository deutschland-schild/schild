#!/bin/bash
# TEST ONLY: MVP-26 measurement. Real CrowdSec engine (public image), no account, no CAPI, no route to the outside:
# the container sits on an --internal Docker network and online_client stays unset. A caddy sidecar with one foot in
# that network publishes the AppSec port on 127.0.0.1:29722, so the host can send requests; the sidecar is the only way in.
# The image's own start script is not used: it insists on a hub download, which this network refuses.
#   start.sh <prepared tree>     stop: docker rm -f m26-crowdsec m26-cs-front; docker network rm m26-cs-int m26-cs-ext
set -eu
T=$1
KEY=m26-testonly-appsec-key-0123456789
docker network inspect m26-cs-int >/dev/null 2>&1 || docker network create --internal --subnet 10.250.26.0/24 m26-cs-int >/dev/null
docker network inspect m26-cs-ext >/dev/null 2>&1 || docker network create --subnet 10.250.27.0/24 m26-cs-ext >/dev/null
docker rm -f m26-crowdsec m26-cs-front >/dev/null 2>&1 || true
cat > /tmp/m26/cs/boot.sh <<EOF
#!/bin/sh
rsync -a --ignore-existing /staging/etc/crowdsec/ /etc/crowdsec/
mkdir -p /var/lib/crowdsec/data
rsync -a --ignore-existing /staging/var/lib/crowdsec/ /var/lib/crowdsec/ 2>/dev/null
cscli -c /etc/crowdsec/config.yaml machines add -a --force
cscli -c /etc/crowdsec/config.yaml bouncers add m26 -k $KEY
exec crowdsec -c /etc/crowdsec/config.yaml
EOF
docker create --name m26-crowdsec --network m26-cs-int --entrypoint /bin/sh crowdsecurity/crowdsec:latest /boot.sh >/dev/null
docker cp "$T/." m26-crowdsec:/etc/crowdsec/
docker cp /tmp/m26/cs/boot.sh m26-crowdsec:/boot.sh
docker start m26-crowdsec >/dev/null
cat > /tmp/m26/cs/Caddyfile <<EOF
{
	admin off
	auto_https off
}
:7422 {
	reverse_proxy m26-crowdsec:7422
}
EOF
docker create --name m26-cs-front --network m26-cs-ext -p 127.0.0.1:29722:7422 caddy:2-alpine >/dev/null
docker cp /tmp/m26/cs/Caddyfile m26-cs-front:/etc/caddy/Caddyfile
docker network connect m26-cs-int m26-cs-front
docker start m26-cs-front >/dev/null
echo started
