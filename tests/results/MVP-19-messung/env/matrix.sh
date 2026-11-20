#!/bin/sh
# Request matrix for the stock-vs-schild comparison (runs in m19-tools).
# One line per request: id status http_version selected headers body-sha256.
ING=10.219.19.10
CA=/st/pebble-root.pem
HDRS='content-type|content-encoding|content-length|vary|cache-control|set-cookie|location|etag|last-modified|accept-ranges|content-range|server|alt-svc|x-app|retry-after|allow|x-content-type-options|strict-transport-security|via'
req() { # id scheme host path [curl args...]
  id=$1; sch=$2; h=$3; p=$4; shift 4
  port=443; [ "$sch" = http ] && port=80
  curl -s -o /tmp/b -D /tmp/h --max-time 10 --cacert $CA --resolve "$h:$port:$ING" "$@" "$sch://$h$p" >/dev/null 2>/tmp/e
  rc=$?
  st=$(head -1 /tmp/h | tr -d '\r')
  hs=$(grep -iE "^($HDRS):" /tmp/h | tr -d '\r' | sed 's/^\([^:]*\)/\L\1/' | sort | tr '\n' '|')
  sum=$(sha256sum /tmp/b | cut -c1-16)
  printf '%s\t%s\trc=%s\t%s\tbody=%s:%s\n' "$id" "$st" "$rc" "$hs" "$(wc -c < /tmp/b | tr -d ' ')" "$sum"
}
for h in shop.example.de www.shop.example.de portal.example.de booking.example.de academy.example.de; do
  req "$h-root" https $h /
  req "$h-root-gzip" https $h / -H 'Accept-Encoding: gzip'
  req "$h-root-zstd" https $h / -H 'Accept-Encoding: zstd'
  req "$h-root-br-gzip-zstd" https $h / -H 'Accept-Encoding: br, gzip, zstd'
  req "$h-http-redirect" http $h /login?x=1
  req "$h-login-post" https $h /login -d 'email=kunde%40example.de&password=geheim&_token=abc'
  req "$h-redirect" https $h /redirect
  req "$h-boom" https $h /boom
  req "$h-head" https $h / -I
  req "$h-options" https $h / -X OPTIONS
  req "$h-storage-html" https $h /storage/hello.html
  req "$h-storage-css-gzip" https $h /storage/app.css -H 'Accept-Encoding: gzip'
  req "$h-storage-css-zstd" https $h /storage/app.css -H 'Accept-Encoding: zstd'
  req "$h-storage-big-range" https $h /storage/big.txt -H 'Range: bytes=100-199'
  req "$h-storage-big" https $h /storage/big.txt
  req "$h-storage-missing" https $h /storage/missing.png
  req "$h-storage-dir" https $h /storage/
  req "$h-storage-traversal" https $h /storage/..%2f..%2fetc/passwd
  req "$h-storage-ims" https $h /storage/hello.html -H 'If-Modified-Since: Wed, 01 Jan 2031 00:00:00 GMT'
  for p in /.env /.env.backup /.git/config /.git/HEAD /composer.json /composer.lock /wp-login.php /wp-admin/setup-config.php /xmlrpc.php /phpmyadmin/index.php /.aws/credentials /vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php /backup.sql /index.php.bak; do
    req "$h-probe$p" https $h "$p"
  done
  req "$h-h1" https $h / --http1.1
done
h=api.example.de
req "$h-get" https $h /v1/items?page=2
req "$h-post-json" https $h /v1/items -H 'Content-Type: application/json' -d '{"name":"Ölkanne","tags":["a","b"],"meta":{"x":1}}'
req "$h-gzip" https $h /v1/items -H 'Accept-Encoding: gzip'
req "$h-probe-env" https $h /.env
req "$h-probe-git" https $h /.git/config
req "$h-storage" https $h /storage/hello.html
req "$h-http-redirect" http $h /v1/items
req "$h-boom" https $h /boom
# unknown host: TLS handshake without a certificate
req "unknown-host" https unknown.example.de /
# HTTP/2 explicitly
req "shop-h2" https shop.example.de / --http2
