#!/usr/bin/env python3
# TEST ONLY: MVP-26 false positives. Real-looking benign requests of Laravel, Livewire, Filament, WordPress and
# WooCommerce sites, plus near-misses for the rules with a generic URI or no URI at all. Hosts are .example, addresses
# documentation ranges, tokens are made up. Sent through a schild instance in detect, read back from its events.
#   benign.py <ingress port> <schild.db> <out.json> [rounds]
import collections, ipaddress, json, random, socket, sqlite3, sys, time, urllib.parse

port, db, out = int(sys.argv[1]), sys.argv[2], sys.argv[3]
rounds = int(sys.argv[4]) if len(sys.argv) > 4 else 20
random.seed(26)
B = '----WebKitFormBoundaryTESTONLY26'
TOKEN = 'TESTONLYa1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0'
UA = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36'


def form(d):
    return urllib.parse.urlencode(d).encode()


def mp(fields, files):
    p = []
    for k, v in fields:
        p.append(f'--{B}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n'.encode())
    for k, fn, ct, data in files:
        p.append(f'--{B}\r\nContent-Disposition: form-data; name="{k}"; filename="{fn}"\r\nContent-Type: {ct}\r\n\r\n'.encode() + data + b'\r\n')
    return b''.join(p) + f'--{B}--\r\n'.encode()


def lw(component, updates, calls, data):
    snap = json.dumps({'data': data, 'memo': {'id': 'aB3dE5gH7jK9mN1pQ3sT', 'name': component, 'path': 'kontakt', 'method': 'GET', 'children': [], 'scripts': [], 'assets': [], 'errors': [], 'locale': 'de'},
                       'checksum': 'f0e1d2c3b4a5968778695a4b3c2d1e0f0f1e2d3c4b5a69788796a5b4c3d2e1f0'})
    return json.dumps({'_token': TOKEN, 'components': [{'snapshot': snap, 'updates': updates, 'calls': calls}]}).encode()


JPG = bytes(range(256)) * 40
PDF = b'%PDF-1.7\n1 0 obj\n<< /Type /Catalog >>\nendobj\ntrailer\n<<>>\n%%EOF\n' * 20
J = 'application/json'
F = 'application/x-www-form-urlencoded'
M = f'multipart/form-data; boundary={B}'
LV = 'laravel_session=eyJpdiI6IlRFU1RPTkxZIiwidmFsdWUiOiJURVNUIiwibWFjIjoiMDAwIn0%3D; XSRF-TOKEN=' + 'eyJpdiI6' + 'IlRFU1QifQ%3D%3D'  # TEST ONLY, made up
WP = 'wordpress_logged_in_0123456789abcdef=test%7C1793400000%7CTESTONLY%7C0123; wp-settings-1=libraryContent%3Dbrowse; wordpress_test_cookie=WP%20Cookie%20check'

reqs = [
    # Laravel
    ('laravel', 'GET', '/', None, None, {'Cookie': LV}),
    ('laravel', 'GET', '/login', None, None, {}),
    ('laravel', 'POST', '/login', F, form({'_token': TOKEN, 'email': 'person@shop.example', 'password': 'Sommer2026!', 'remember': 'on'}), {'Cookie': LV, 'Referer': 'https://app.example/login', 'Origin': 'https://app.example'}),
    ('laravel', 'POST', '/register', F, form({'_token': TOKEN, 'name': "Anna O'Neil", 'email': 'anna@shop.example', 'password': 'p@ss;word&1', 'password_confirmation': 'p@ss;word&1'}), {'Cookie': LV}),
    ('laravel', 'POST', '/password/email', F, form({'_token': TOKEN, 'email': 'person@shop.example'}), {'Cookie': LV}),
    ('laravel', 'POST', '/password/reset', F, form({'_token': TOKEN, 'token': 'abcdef' + '0123456789', 'email': 'person@shop.example', 'password': 'x' * 14, 'password_confirmation': 'x' * 14}), {'Cookie': LV}),
    ('laravel', 'POST', '/users/password', F, form({'_token': TOKEN, 'user[email]': 'person@shop.example'}), {'Cookie': LV}),
    ('laravel', 'GET', '/sanctum/csrf-cookie', None, None, {'Accept': J}),
    ('laravel', 'GET', '/api/user', None, None, {'Authorization': 'Bearer 1|TESTONLYtokenvalue0123456789', 'Accept': J}),
    ('laravel', 'POST', '/api/orders', J, json.dumps({'items': [{'sku': 'A-1', 'qty': 2}], 'note': "Bitte klingeln; 2. Stock, Tür links (Müller's)", 'address': {'city': 'Köln', 'zip': '50667'}}).encode(), {'Authorization': 'Bearer 1|TESTONLY', 'Accept': J}),
    ('laravel', 'POST', '/api/query', J, json.dumps({'query': 'schuhe rot', 'filters': {'size': [42, 43]}, 'status': 'resolved'}).encode(), {'Accept': J}),
    ('laravel', 'POST', '/api/v1/validate/code', J, json.dumps({'code': 'ABC123'}).encode(), {'Accept': J}),
    ('laravel', 'POST', '/broadcasting/auth', F, form({'socket_id': '1234.5678', 'channel_name': 'private-orders.1'}), {'Cookie': LV}),
    ('laravel', 'GET', '/up', None, None, {}),
    ('laravel', 'GET', '/_ignition/health-check', None, None, {}),
    ('laravel', 'GET', '/telescope/requests', None, None, {'Cookie': LV}),
    ('laravel', 'POST', '/telescope/telescope-api/requests', J, b'{"before":null,"tag":"","family_hash":"","take":50}', {'Cookie': LV}),
    ('laravel', 'GET', '/horizon/api/stats', None, None, {'Cookie': LV}),
    ('laravel', 'GET', '/storage/uploads/rechnung-2026.pdf', None, None, {}),
    ('laravel', 'GET', '/vendor/livewire/livewire.min.js?id=abc123', None, None, {}),
    ('laravel', 'GET', '/build/assets/app-Bx3dF1.js', None, None, {}),
    ('laravel', 'GET', '/.well-known/security.txt', None, None, {}),
    ('laravel', 'GET', '/search?q=..%2F..%2Fetc+pfad+erkl%C3%A4rt&sort=-created_at&page=2', None, None, {}),
    ('laravel', 'GET', '/products?filter[color]=rot&filter[size]=42&include=variants,images&sort=-price', None, None, {}),
    ('laravel', 'GET', '/docs/env-setup', None, None, {}),
    ('laravel', 'POST', '/settings', F, form({'_token': TOKEN, '_method': 'PUT', 'APP_ENV': 'staging', 'notes': 'php artisan migrate --env=staging; siehe ../docs/README.md'}), {'Cookie': LV}),
    ('laravel', 'POST', '/admin/posts', J, json.dumps({'title': 'Sicherheit im Web', 'body': '<p>Ein Beispiel: <code>&lt;script&gt;alert(1)&lt;/script&gt;</code> und <code>SELECT * FROM users</code>, Pfad <code>../../etc/passwd</code></p>'}).encode(), {'Cookie': LV}),
    # Livewire
    ('livewire', 'POST', '/livewire/update', J, lw('contact-form', {'name': 'Max Müller', 'email': 'max@shop.example'}, [{'path': '', 'method': 'save', 'params': []}], {'name': '', 'email': '', 'message': ''}), {'Cookie': LV, 'X-Livewire': '', 'X-Requested-With': 'XMLHttpRequest'}),
    ('livewire', 'POST', '/livewire/update', J, lw('product-table', {'search': "o'brien", 'sortField': 'created_at', 'perPage': 25}, [{'path': '', 'method': '$refresh', 'params': []}], {'search': '', 'rows': [[{'id': 1, 'name': 'A'}, {'s': 'arr'}]]}), {'Cookie': LV, 'X-Livewire': ''}),
    ('livewire', 'POST', '/livewire/update', J, lw('filament.pages.dashboard', {'tableFilters.status.value': 'open', 'tableSearch': 'rechnung'}, [{'path': '', 'method': 'callMountedAction', 'params': [{'k': 'v'}]}], {'mountedActions': [], 'data': [{'title': 'x'}, {'s': 'arr'}]}), {'Cookie': LV, 'X-Livewire': ''}),
    ('livewire', 'POST', '/livewire/upload-file?expires=1793400000&signature=0123456789abcdef0123456789abcdef', M, mp([], [('files[]', 'foto urlaub (1).jpg', 'image/jpeg', JPG)]), {'Cookie': LV, 'X-CSRF-TOKEN': TOKEN, 'Accept': J}),
    ('livewire', 'POST', '/livewire/upload-file?expires=1793400000&signature=0123456789abcdef0123456789abcdef', M, mp([], [('files[]', 'vertrag.pdf', 'application/pdf', PDF), ('files[]', 'liste.csv', 'text/csv', b'a,b\n1,2\n')]), {'Cookie': LV, 'X-CSRF-TOKEN': TOKEN}),
    ('livewire', 'GET', '/livewire/preview-file/abcdef.jpg?expires=1793400000&signature=0123456789abcdef', None, None, {'Cookie': LV}),
    ('livewire', 'GET', '/livewire/livewire.js?id=abc123', None, None, {}),
    ('livewire', 'GET', '/filament/assets/app.js?v=3.2.0', None, None, {}),
    ('livewire', 'POST', '/livewire/message/contact-form', J, json.dumps({'fingerprint': {'id': 'abc', 'name': 'contact-form', 'locale': 'de', 'path': 'kontakt', 'method': 'GET'}, 'serverMemo': {'data': {'name': ''}, 'checksum': 'abc'}, 'updates': [{'type': 'syncInput', 'payload': {'id': 'x', 'name': 'name', 'value': 'Max'}}]}).encode(), {'Cookie': LV}),
    # WordPress
    ('wordpress', 'GET', '/wp-login.php', None, None, {}),
    ('wordpress', 'POST', '/wp-login.php', F, form({'log': 'redaktion', 'pwd': 'Sommer2026!', 'wp-submit': 'Anmelden', 'redirect_to': 'https://wp.example/wp-admin/', 'testcookie': '1'}), {'Cookie': 'wordpress_test_cookie=WP%20Cookie%20check', 'Referer': 'https://wp.example/wp-login.php'}),
    ('wordpress', 'POST', '/wp-login.php?action=lostpassword', F, form({'user_login': 'redaktion@shop.example', 'redirect_to': '', 'wp-submit': 'Neues Passwort'}), {}),
    ('wordpress', 'GET', '/wp-admin/', None, None, {'Cookie': WP}),
    ('wordpress', 'POST', '/wp-admin/admin-ajax.php', F, form({'action': 'heartbeat', '_nonce': 'abc123def4', 'interval': 60, 'screen_id': 'dashboard', 'has_focus': 'false'}), {'Cookie': WP}),
    ('wordpress', 'POST', '/wp-admin/admin-ajax.php', F, form({'action': 'query-attachments', 'query[posts_per_page]': 80, 'query[paged]': 1, 'query[orderby]': 'date'}), {'Cookie': WP}),
    ('wordpress', 'POST', '/wp-admin/admin-ajax.php', F, form({'action': 'elementor_ajax', 'actions': json.dumps({'save_builder': {'action': 'save_builder', 'data': {'status': 'publish', 'elements': []}}}), 'editor_post_id': 42, '_nonce': 'abc'}), {'Cookie': WP}),
    ('wordpress', 'POST', '/wp-admin/post.php', F, form({'action': 'editpost', 'post_ID': 42, 'post_title': 'Neuer Beitrag', 'content': '<!-- wp:paragraph --><p>Hallo <a href="https://shop.example/?a=1&amp;b=2">Link</a></p><!-- /wp:paragraph -->', '_wpnonce': 'abc123'}), {'Cookie': WP}),
    ('wordpress', 'POST', '/wp-admin/async-upload.php', M, mp([('name', 'foto.jpg'), ('action', 'upload-attachment'), ('_wpnonce', 'abc123')], [('async-upload', 'foto.jpg', 'image/jpeg', JPG)]), {'Cookie': WP}),
    ('wordpress', 'POST', '/wp-admin/plugins.php', F, form({'action': 'activate', 'plugin': 'woocommerce/woocommerce.php', '_wpnonce': 'abc123'}), {'Cookie': WP}),
    ('wordpress', 'GET', '/wp-admin/plugin-install.php?tab=search&s=elementor', None, None, {'Cookie': WP}),
    ('wordpress', 'GET', '/wp-admin/upload.php?mode=list', None, None, {'Cookie': WP}),
    ('wordpress', 'GET', '/wp-json/', None, None, {}),
    ('wordpress', 'GET', '/wp-json/wp/v2/posts?per_page=10&_embed=true', None, None, {}),
    ('wordpress', 'GET', '/wp-json/wp/v2/users/me?context=edit', None, None, {'Cookie': WP, 'X-WP-Nonce': 'abc123'}),
    ('wordpress', 'POST', '/wp-json/wp/v2/posts/42', J, json.dumps({'title': 'Titel', 'content': '<!-- wp:paragraph --><p>Text</p><!-- /wp:paragraph -->', 'status': 'publish'}).encode(), {'Cookie': WP, 'X-WP-Nonce': 'abc123'}),
    ('wordpress', 'POST', '/wp-json/contact-form-7/v1/contact-forms/123/feedback', M, mp([('_wpcf7', '123'), ('your-name', 'Max'), ('your-email', 'max@shop.example'), ('your-message', 'Hallo, ich habe eine Frage.')], []), {}),
    ('wordpress', 'GET', '/wp-json/wc/store/v1/cart', None, None, {}),
    ('wordpress', 'POST', '/?wc-ajax=get_refreshed_fragments', F, form({'time': '1793400000'}), {}),
    ('wordpress', 'POST', '/?wc-ajax=checkout', F, form({'billing_first_name': 'Max', 'billing_email': 'max@shop.example', 'payment_method': 'stripe', 'woocommerce-process-checkout-nonce': 'abc'}), {}),
    ('wordpress', 'GET', '/?s=wie+funktioniert+.env&post_type=product', None, None, {}),
    ('wordpress', 'GET', '/wp-content/uploads/2026/10/foto.jpg', None, None, {}),
    ('wordpress', 'GET', '/wp-content/themes/twentytwentyfive/style.css?ver=1.2', None, None, {}),
    ('wordpress', 'GET', '/wp-content/plugins/woocommerce/assets/js/frontend/cart.min.js?ver=9.3', None, None, {}),
    ('wordpress', 'GET', '/wp-content/plugins/elementor/assets/js/frontend.min.js?ver=3.25', None, None, {}),
    ('wordpress', 'GET', '/wp-content/plugins/contact-form-7/includes/js/index.js?ver=6.0', None, None, {}),
    ('wordpress', 'GET', '/wp-includes/js/jquery/jquery.min.js?ver=3.7.1', None, None, {}),
    ('wordpress', 'GET', '/wp-cron.php?doing_wp_cron=1793400000.1234', None, None, {}),
    ('wordpress', 'POST', '/xmlrpc.php', 'text/xml', b'<?xml version="1.0"?><methodCall><methodName>demo.sayHello</methodName></methodCall>', {}),
    ('wordpress', 'GET', '/feed/', None, None, {}),
    ('wordpress', 'GET', '/wp-sitemap.xml', None, None, {}),
    ('wordpress', 'GET', '/robots.txt', None, None, {}),
    ('wordpress', 'GET', '/index.php?rest_route=/wp/v2/posts', None, None, {}),
    # generic URIs that border on hub rules
    ('near', 'GET', '/password.html', None, None, {}),
    ('near', 'GET', '/docs/rpc2-overview', None, None, {}),
    ('near', 'POST', '/run/report', F, form({'a': '1'}), {}),
    ('near', 'POST', '/cli/help', F, form({'a': '1'}), {}),
    ('near', 'POST', '/batch/v1/jobs', J, b'{"a":1}', {}),
    ('near', 'GET', '/misc/styles.css', None, None, {}),
    ('near', 'GET', '/static/link/a.png', None, None, {}),
    ('near', 'GET', '/public/plugins/grafana-clock/logo.svg', None, None, {}),
    ('near', 'GET', '/api/v1/repos/acme/app/contents/README.md', None, None, {}),
    ('near', 'GET', '/config/.env.example', None, None, {}),
    ('near', 'GET', '/env', None, None, {}),
    ('near', 'GET', '/.gitignore', None, None, {}),
    ('near', 'GET', '/git/config', None, None, {}),
    ('near', 'GET', '/?--env=staging', None, None, {}),
    ('near', 'GET', '/?environment=staging&env=dev', None, None, {}),
    ('near', 'POST', '/upload', F, form({'upload_filename': 'bericht.pdf'}), {}),
    ('near', 'POST', '/upload', F, form({'filename': 'bilder/2026/foto.jpg'}), {}),
    ('near', 'GET', '/', None, None, {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8'}),
    ('near', 'GET', '/_next/data/abc/index.json', None, None, {'x-nextjs-data': '1'}),
    ('near', 'POST', '/', 'text/x-component', b'[1]', {'Next-Action': 'abcdef0123456789', 'Accept': 'text/x-component'}),
    ('near', 'POST', '/api/session/reset_password', J, b'{"email":"person@shop.example"}', {}),
    ('near', 'POST', '/users/password', J, json.dumps({'user': {'email': 'person@shop.example'}}).encode(), {}),
    ('near', 'GET', '/login/index.php?login=max.mustermann', None, None, {}),
    ('near', 'GET', '/remote_agent.php?poller_id=12', None, None, {}),
    ('near', 'POST', '/dns/getresetstatus', J, json.dumps({'statusfile': 'tmp/abc123'}).encode(), {}),
]
sent = collections.Counter()
ids = {}
res = []
i = 0
for r in range(rounds):
    for rq in reqs:
        cat, method, target, ct, body, hdr = rq
        i += 1
        ip = '2001:db8:26:cc:%x:%x::1' % (i >> 16, i & 0xffff)
        ids[str(ipaddress.ip_address(ip))] = rq
        lines = [f'{method} {target} HTTP/1.1', 'Host: app.example' if cat != 'wordpress' else 'Host: wp.example', f'X-Forwarded-For: {ip}', 'User-Agent: ' + UA, 'Connection: close']
        if 'Accept' not in hdr:
            lines.append('Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')
        lines.append('Accept-Language: de-DE,de;q=0.9,en;q=0.8')
        lines += [f'{k}: {v}' for k, v in hdr.items()]
        data = b''
        if body is not None:
            lines.append('Content-Type: ' + ct)
            lines.append(f'Content-Length: {len(body)}')
            data = body
        s = socket.create_connection(('127.0.0.1', port), timeout=20)
        s.sendall(('\r\n'.join(lines) + '\r\n\r\n').encode('latin-1', 'replace') + data)
        buf = b''
        try:
            while True:
                x = s.recv(65536)
                if not x:
                    break
                buf += x
        except OSError:
            pass
        s.close()
        res.append((ip, int(buf[9:12] or 0)))
        sent[cat] += 1
time.sleep(4)
con = sqlite3.connect(db)
hub = collections.Counter()
crs = collections.Counter()
detail = collections.defaultdict(collections.Counter)
status = collections.Counter(s for _, s in res)
for ip, body in con.execute("select ip, body from events where type='schild.request.evaluated.v1' and ip like '2001:db8:26:cc:%'"):
    d = json.loads(body)['data']
    cat, method, target = ids[ip][:3] if ip in ids else ('?', '?', '?')
    for x in d.get('rules', []):
        if x.get('source') == 'crowdsec_hub':
            hub[x['hub']['name']] += 1
            detail[x['hub']['name']][f'{cat} {method} {target[:70]}'] += 1
        elif x.get('source') == 'crs' and x['id'] < 949000:
            crs[(x['id'], x.get('msg', '')[:50])] += 1
o = {'sent': sent, 'distinct_requests': len(reqs), 'status': {str(k): v for k, v in status.items()}, 'hub_matches': hub, 'hub_detail': {k: dict(v) for k, v in detail.items()},
     'crs_matches': [[k[0], k[1], v] for k, v in crs.most_common(20)]}
json.dump(o, open(out, 'w'), indent=1, default=dict)
print(json.dumps(o, indent=1, default=dict)[:2500])
