#!/usr/bin/env python3
# TEST ONLY: MVP-26 / D40 measurement, review item 1.1. Own Caddyfile shapes around header_hidden_from_schild.
# Each shape: id, what we expect from the rule text of ingress-order.md 1a, site body, extra global options, extra
# server-level text. `refuse` = must be refused, `accept` = must keep working, `limit` = documented known limit.
# Every accepted shape that hides and restores a header also runs for real: the attack header must not reach the
# echo backend unseen.
#   ingress_variants.py <schild binary> <workdir> <out.json>
import http.client, json, os, shutil, socket, subprocess, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BIN, W, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
BACK = 26182
ING = 26180
DASH = 26188
SAVE = 'vars r {header.Referer}'
PROXY = f'reverse_proxy 127.0.0.1:{BACK}'

V = [
    # id, expect, site body, global, top-level text
    ('r01-v01', 'refuse', f'route {{\n{SAVE}\nrequest_header -Referer\nschild\nrequest_header Referer {{vars.r}}\n{PROXY}\n}}', '', ''),
    ('r02-case', 'refuse', f'route {{\n{SAVE}\nrequest_header -REFERER\nschild\nrequest_header referer {{vars.r}}\n{PROXY}\n}}', '', ''),
    ('r03-wild-suffix', 'refuse', f'route {{\n{SAVE}\nrequest_header -Ref*\nschild\nrequest_header Referer {{vars.r}}\n{PROXY}\n}}', '', ''),
    ('r04-wild-all', 'refuse', f'route {{\n{SAVE}\nrequest_header -*\nschild\nrequest_header Referer {{vars.r}}\n{PROXY}\n}}', '', ''),
    ('r05-set-hides', 'refuse', f'route {{\n{SAVE}\nrequest_header Referer clean\nschild\nrequest_header Referer {{vars.r}}\n{PROXY}\n}}', '', ''),
    ('r06-replace-hides', 'refuse', f'route {{\n{SAVE}\nrequest_header Referer .* clean\nschild\nrequest_header Referer {{vars.r}}\n{PROXY}\n}}', '', ''),
    ('r07-header-up', 'refuse', f'route {{\n{SAVE}\nrequest_header -Referer\nschild\nreverse_proxy 127.0.0.1:{BACK} {{\nheader_up Referer {{vars.r}}\n}}\n}}', '', ''),
    ('r08-header-up-plus', 'refuse', f'route {{\n{SAVE}\nrequest_header -Referer\nschild\nreverse_proxy 127.0.0.1:{BACK} {{\nheader_up +Referer {{vars.r}}\n}}\n}}', '', ''),
    ('r09-add-back', 'refuse', f'route {{\n{SAVE}\nrequest_header -Referer\nschild\nrequest_header +Referer {{vars.r}}\n{PROXY}\n}}', '', ''),
    ('r10-handle-errors', 'refuse', f'route {{\n{SAVE}\nrequest_header -Referer\nschild\nerror 500\n}}\nhandle_errors {{\nrequest_header Referer {{vars.r}}\n{PROXY}\n}}', '', ''),
    ('r11-nested-routes', 'refuse', f'route {{\n{SAVE}\nroute {{\nrequest_header -Referer\n}}\nroute {{\nschild\n}}\nroute {{\nrequest_header Referer {{vars.r}}\n{PROXY}\n}}\n}}', '', ''),
    ('r12-snippet', 'refuse', f'route {{\n{SAVE}\nimport hide\nimport schild\nimport back\n}}', '', f'(hide) {{\nrequest_header -Referer\n}}\n(back) {{\nrequest_header Referer {{vars.r}}\n{PROXY}\n}}\n'),
    ('r13-matcher-hider', 'refuse', f'@all path /*\nroute {{\n{SAVE}\nrequest_header @all -Referer\nschild\nrequest_header Referer {{vars.r}}\n{PROXY}\n}}', '', ''),
    ('r14-matcher-writer', 'refuse', f'@all path /*\nroute {{\n{SAVE}\nrequest_header -Referer\nschild\nrequest_header @all Referer {{vars.r}}\n{PROXY}\n}}', '', ''),
    ('r15-placeholder-name', 'refuse', f'route {{\n{SAVE}\nvars n Referer\nrequest_header -Referer\nschild\nrequest_header {{vars.n}} {{vars.r}}\n{PROXY}\n}}', '', ''),
    ('r16-global-order', 'refuse', f'{SAVE}\nrequest_header -Referer\nschild\n{PROXY}\nreverse_proxy_placeholder', 'order request_header first', ''),
    ('r17-handle-branch', 'refuse', f'handle /* {{\nroute {{\n{SAVE}\nrequest_header -Referer\nschild\nrequest_header Referer {{vars.r}}\n{PROXY}\n}}\n}}', '', ''),
    ('r18-invoke-named-route', 'refuse', f'route {{\n{SAVE}\nrequest_header -Referer\nschild\ninvoke back\n}}', '', ''),
    ('r19-handle-response', 'refuse', f'route {{\n{SAVE}\nrequest_header -Referer\nschild\nreverse_proxy 127.0.0.1:{BACK} {{\n@ok status 2xx\nhandle_response @ok {{\nrequest_header Referer {{vars.r}}\nreverse_proxy 127.0.0.1:{BACK}\n}}\n}}\n}}', '', ''),
    ('r20-subroute-in-handle-errors', 'refuse', f'route {{\n{SAVE}\nrequest_header -Referer\nschild\nerror 500\n}}\nhandle_errors {{\nroute {{\nroute {{\nrequest_header Referer {{vars.r}}\n}}\n{PROXY}\n}}\n}}', '', ''),
    ('r21-second-reverse-proxy-route', 'refuse', f'route {{\n{SAVE}\nrequest_header -Referer\nimport schild\n}}\nroute {{\nreverse_proxy 127.0.0.1:{BACK} {{\nheader_up Referer {{vars.r}}\n}}\n}}', '', ''),
    ('r22-map-saved', 'refuse', f'route {{\nmap {{header.Referer}} {{vars.r}} {{\ndefault {{header.Referer}}\n}}\nrequest_header -Referer\nschild\nrequest_header Referer {{vars.r}}\n{PROXY}\n}}', '', ''),
    ('r23-header-up-in-handle-response', 'refuse', f'route {{\n{SAVE}\nrequest_header -Referer\nschild\nreverse_proxy 127.0.0.1:{BACK} {{\n@ok status 2xx\nhandle_response @ok {{\nreverse_proxy 127.0.0.1:{BACK} {{\nheader_up Referer {{vars.r}}\n}}\n}}\n}}\n}}', '', ''),
    ('r24-intercept', 'refuse', f'route {{\n{SAVE}\nrequest_header -Referer\nschild\nintercept {{\n@ok status 2xx\nhandle_response @ok {{\nrequest_header Referer {{vars.r}}\nreverse_proxy 127.0.0.1:{BACK}\n}}\n}}\nreverse_proxy 127.0.0.1:{BACK}\n}}', '', ''),
    ('r25-hide-in-invoke', 'refuse', f'route {{\n{SAVE}\ninvoke hide\nschild\nrequest_header Referer {{vars.r}}\n{PROXY}\n}}', '', '&(hide) {\nrequest_header -Referer\n}\n'),
    ('r26-schild-in-invoke', 'refuse', f'route {{\n{SAVE}\nrequest_header -Referer\ninvoke guard\nrequest_header Referer {{vars.r}}\n{PROXY}\n}}', '', '&(guard) {\nschild\n}\n'),
    ('l01-other-name', 'limit', f'route {{\n{SAVE}\nrequest_header -Referer\nschild\nrequest_header X-Original-Referer {{vars.r}}\n{PROXY}\n}}', '', ''),
    ('l02-fastcgi-env', 'limit', f'route {{\n{SAVE}\nrequest_header -Referer\nschild\nphp_fastcgi 127.0.0.1:{BACK} {{\nenv HTTP_REFERER {{vars.r}}\n}}\n}}', '', ''),
    ('a01-site-header-up', 'accept', f'schild\nreverse_proxy 127.0.0.1:{BACK} {{\nheader_up X-Real-IP {{remote_host}}\nheader_up Host {{upstream_hostport}}\n}}', '', ''),
    ('a02-remove-only', 'accept', f'route {{\nrequest_header -Proxy\nschild\n{PROXY}\n}}', '', ''),
    ('a03-behind-schild', 'accept', f'route {{\nschild\nrequest_header X-Forwarded-Proto https\nrequest_header Referer {{vars.r}}\n{PROXY}\n}}', '', ''),
    ('a04-literal-writeback', 'accept', f'route {{\nrequest_header -Authorization\nschild\nreverse_proxy 127.0.0.1:{BACK} {{\nheader_up Authorization "Bearer TESTONLY"\n}}\n}}', '', ''),
    ('a05-site-level-order', 'accept', f'schild\nrequest_header -X-Debug\nrequest_header X-Site shop\n{PROXY}', '', ''),
    ('a06-set-before-no-writeback', 'accept', f'route {{\nrequest_header X-Tenant shop\nschild\n{PROXY}\n}}', '', ''),
    ('a07-laravel-fastcgi', 'accept', f'root * /tmp\nschild\nrequest_header -X-Forwarded-For\nphp_fastcgi 127.0.0.1:{BACK}\nfile_server', '', ''),
    ('a08-wordpress-route', 'accept', f'route {{\nschild\n@admin path /wp-admin/*\nrequest_header @admin X-Area admin\nphp_fastcgi 127.0.0.1:{BACK}\n}}', '', ''),
    ('a09-exclusive-handles', 'accept', f'handle /a/* {{\nrequest_header -Referer\n{PROXY}\n}}\nhandle {{\nschild\nrequest_header Referer {{header.Referer}}\n{PROXY}\n}}', '', ''),
    ('a10-before-schild-both', 'accept', f'route {{\nrequest_header -X-Old\nrequest_header X-Old {{vars.x}}\nschild\n{PROXY}\n}}', '', ''),
    # everyday shapes that hide with a value and write the same name with a placeholder, no client bytes involved
    ('a11-request-id-up', 'accept', f'route {{\nrequest_header X-Request-Id {{http.request.uuid}}\nschild\nreverse_proxy 127.0.0.1:{BACK} {{\nheader_up X-Request-Id {{http.request.uuid}}\n}}\n}}', '', ''),
    ('a12-proto-up', 'accept', f'route {{\nrequest_header X-Forwarded-Proto {{http.request.scheme}}\nschild\nreverse_proxy 127.0.0.1:{BACK} {{\nheader_up X-Forwarded-Proto {{http.request.scheme}}\n}}\n}}', '', ''),
    ('a13-host-up', 'accept', f'route {{\nrequest_header X-Forwarded-Host {{host}}\nschild\nreverse_proxy 127.0.0.1:{BACK} {{\nheader_up X-Forwarded-Host {{host}}\n}}\n}}', '', ''),
    ('a14-remoteip-site', 'accept', f'route {{\nrequest_header X-Real-IP {{remote_host}}\nschild\n{PROXY}\n}}', '', ''),
    ('a15-remove-then-up-literal', 'accept', f'route {{\nrequest_header -X-Forwarded-Host\nschild\nreverse_proxy 127.0.0.1:{BACK} {{\nheader_up X-Forwarded-Host shop.test\n}}\n}}', '', ''),
    ('a16-host-header-up-upstream', 'accept', f'route {{\nrequest_header -Forwarded\nschild\nreverse_proxy 127.0.0.1:{BACK} {{\nheader_up Forwarded "for={{remote_host}}"\n}}\n}}', '', ''),
]

SEEN = []


class Echo(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def _a(self):
        n = int(self.headers.get('Content-Length') or 0)
        if n:
            self.rfile.read(n)
        SEEN.append(dict(self.headers.items()))
        self.send_response(200)
        self.send_header('Content-Length', '3')
        self.end_headers()
        self.wfile.write(b'ok\n')

    do_GET = do_POST = _a

    def log_message(self, *a):
        pass


srv = ThreadingHTTPServer(('127.0.0.1', BACK), Echo)
threading.Thread(target=srv.serve_forever, daemon=True).start()
ATTACK = "https://x.example/<script>alert(1)</script>' OR 1=1--"
res = []
for vid, exp, body, glob, top in V:
    d = f'{W}/{vid}'
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    named = ''
    if 'invoke back' in body:
        named = f'&(back) {{\nrequest_header Referer {{vars.r}}\n{PROXY}\n}}\n'
    body2 = body.replace('reverse_proxy_placeholder', f'request_header Referer {{vars.r}}')
    cf = f'{{\nadmin off\nauto_https off\nhttp_port {ING}\n{glob}\n}}\n(schild) {{\nschild\n}}\n{top}{named}http://shop.test:{ING} {{\n{body2}\n}}\n'
    open(f'{d}/Caddyfile', 'w').write(cf)
    open(f'{d}/schild.yaml', 'w').write(f'''# TEST ONLY
config_version: 0
profile: production
mode: autoblock
node_name: m26-d40
network:
  enabled: false
listen:
  dashboard: "127.0.0.1:{DASH}"
  metrics: "127.0.0.1:26111"
ingress:
  caddyfile: {d}/Caddyfile
  storage: {d}/caddy
storage:
  path: {d}/data
''')
    p = subprocess.run([BIN, 'ingress', 'validate', '-config', f'{d}/schild.yaml'], capture_output=True, text=True, timeout=30)
    text = (p.stdout + p.stderr)
    verdict = 'pass' if p.returncode == 0 else 'refuse'
    code = next((w for w in ('header_hidden_from_schild', 'rewrite_before_schild', 'unprotected', 'adapt') if w in text), '')
    r = {'id': vid, 'expect': exp, 'verdict': verdict, 'code': code, 'tail': text.strip().splitlines()[-2:] if text.strip() else []}
    if verdict == 'pass':
        SEEN.clear()
        env = dict(os.environ, SCHILD_ALLOW_TEST_KEYS='1')
        q = subprocess.Popen([BIN, 'run', '-config', f'{d}/schild.yaml'], stdout=open(f'{d}/run.log', 'w'), stderr=subprocess.STDOUT, env=env)
        up = False
        for _ in range(100):
            try:
                c = socket.create_connection(('127.0.0.1', ING), timeout=0.3)
                c.close()
                up = True
                break
            except OSError:
                time.sleep(0.1)
        status = None
        if up:
            time.sleep(0.3)
            try:
                c = http.client.HTTPConnection('127.0.0.1', ING, timeout=8)
                c.putrequest('GET', '/', skip_host=True)
                c.putheader('Host', 'shop.test')
                c.putheader('Referer', ATTACK)
                c.putheader('User-Agent', 'Mozilla/5.0 m26')
                c.endheaders()
                status = c.getresponse().status
            except Exception as e:
                status = str(e)
        q.terminate()
        q.wait(10)
        leak = any(ATTACK in str(v) for h in SEEN for v in h.values())
        r.update({'run_started': up, 'status': status, 'attack_reached_backend': leak})
    res.append(r)
    print(vid, exp, verdict, code, r.get('status'), r.get('attack_reached_backend'), (r['tail'][-1][:150] if verdict == 'refuse' and r['tail'] else ''), flush=True)
json.dump(res, open(OUT, 'w'), indent=1)
