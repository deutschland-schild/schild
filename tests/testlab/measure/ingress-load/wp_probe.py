# TEST ONLY: waiting page (D37) black-box checks against a running schild.
# Every probe carries a query of 990 short arguments, which with
# waf.eval_timeout_ms 5 always ends in 503 waf_timeout (or waf_busy under a
# flood). Usage: wp_probe.py <host:port> <query file> <out.jsonl> [n_dist]
import sys, json, re, http.client, collections
HP, QF, OUT = sys.argv[1], sys.argv[2], sys.argv[3]
NDIST = int(sys.argv[4]) if len(sys.argv) > 4 else 0
Q = open(QF).read().strip()
NAV = {'Sec-Fetch-Dest': 'document', 'Sec-Fetch-Mode': 'navigate', 'Sec-Fetch-Site': 'none',
       'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'}
def req(method, host='shop.example.de', headers=None, body=None, path='/search'):
    c = http.client.HTTPConnection(*HP.split(':'), timeout=30)
    h = {'Host': host}
    h.update(headers or {})
    c.putrequest(method, f'{path}?{Q}', skip_host=True, skip_accept_encoding=True)
    for k, v in h.items(): c.putheader(k, v)
    if body is not None:
        c.putheader('Content-Type', 'application/x-www-form-urlencoded'); c.putheader('Content-Length', str(len(body)))
    c.endheaders(body.encode() if body is not None else None)
    r = c.getresponse(); b = r.read(); c.close()
    hd = {k.lower(): v for k, v in r.getheaders()}
    t = b.decode('utf-8', 'replace')
    m = re.search(r'<meta http-equiv="refresh" content="(\d+)"', t)
    return {'status': r.status, 'ctype': hd.get('content-type', ''), 'retry_after': hd.get('retry-after'),
            'cache': hd.get('cache-control'), 'csp': hd.get('content-security-policy'), 'vary': hd.get('vary'),
            'clang': hd.get('content-language'), 'incident_hdr': hd.get('x-schild-incident'), 'len': len(b),
            'refresh': m.group(1) if m else None, 'html_lang': (re.search(r'<html lang="(\w+)"', t) or [None, None])[1],
            'script': '<script' in t.lower(), 'noindex': 'noindex' in t,
            'countdown_items': len(re.findall(r'<b[ >]', (re.search(r'<span class="n">(.*?)</span>', t) or [None, ''])[1])),
            'bar_s': (re.search(r'animation:fill (\d+)s', t) or [None, None])[1],
            'form_copy': 'go back one step' in t or 'einen Schritt zurück' in t,
            'reload_copy': 'von selbst neu' in t or 'reloads by itself' in t,
            'site': (re.search(r'<strong>([^<]*)</strong>', t) or [None, None])[1],
            'generic': 'Diese Website bekommt' in t or 'This website is getting' in t,
            'json': json.loads(t) if 'json' in hd.get('content-type', '') and t else None, 'body_head': t[:120]}
cases = [
 ('nav-get', 'GET', {}, NAV, None), ('nav-head', 'HEAD', {}, NAV, None),
 ('nav-post-form', 'POST', {}, NAV, 'name=Max&msg=hallo'),
 ('fetch-json', 'GET', {}, {'Sec-Fetch-Dest': 'empty', 'Sec-Fetch-Mode': 'cors', 'Accept': '*/*'}, None),
 ('fetch-html-htmx', 'GET', {}, {'Sec-Fetch-Dest': 'empty', 'Sec-Fetch-Mode': 'cors', 'Accept': 'text/html', 'HX-Request': 'true'}, None),
 ('xhr-jquery-html', 'GET', {}, {'X-Requested-With': 'XMLHttpRequest', 'Accept': 'text/html, */*; q=0.01'}, None),
 ('xhr-post', 'POST', {}, {'X-Requested-With': 'XMLHttpRequest', 'Accept': 'text/html'}, 'a=1'),
 ('curl-default', 'GET', {}, {'Accept': '*/*', 'User-Agent': 'curl/8.7.1'}, None),
 ('no-accept', 'GET', {}, {}, None),
 ('old-browser-no-fm', 'GET', {}, {'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'}, None),
 ('old-browser-post', 'POST', {}, {'Accept': 'text/html,application/xhtml+xml'}, 'a=1'),
 ('tie-json-html', 'GET', {}, {'Accept': 'application/json, text/html'}, None),
 ('html-over-json', 'GET', {}, {'Accept': 'text/html;q=0.9, application/json;q=0.8'}, None),
 ('json-over-html', 'GET', {}, {'Accept': 'text/html;q=0.5, application/ld+json;q=0.8'}, None),
 ('html-q0', 'GET', {}, {'Accept': 'text/html;q=0'}, None),
 ('iframe', 'GET', {}, {'Sec-Fetch-Dest': 'iframe', 'Sec-Fetch-Mode': 'navigate', 'Accept': 'text/html'}, None),
 ('image', 'GET', {}, {'Sec-Fetch-Dest': 'image', 'Sec-Fetch-Mode': 'no-cors', 'Accept': 'image/avif,*/*'}, None),
 ('websocket-mode', 'GET', {}, {'Sec-Fetch-Mode': 'websocket', 'Accept': 'text/html'}, None),
 ('put-nav', 'PUT', {}, NAV, 'a=1'), ('delete-nav', 'DELETE', {}, NAV, None), ('options-nav', 'OPTIONS', {}, NAV, None),
 ('dest-document-accept-any', 'GET', {}, {'Sec-Fetch-Dest': 'document', 'Accept': '*/*'}, None),
 ('googlebot', 'GET', {}, {'User-Agent': 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)', 'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'}, None),
 ('nav-mode-upper', 'GET', {}, {'Sec-Fetch-Dest': ' DOCUMENT ', 'Sec-Fetch-Mode': 'Navigate', 'Accept': 'text/html'}, None),
]
langs = [('de-CH', 'de'), ('en-GB,en;q=0.9', 'en'), ('fr, en;q=0.5', 'en'), ('en;q=0, de', 'de'), ('*', 'de'),
         ('en-US;q=0.8, de;q=0.8', 'en'), ('en;q=2, de', 'de'), ('fr-FR', 'de'), ('EN', 'en'), ('de;q=0.5, en;q=0.6', 'en'),
         ('', 'de'), ('ru, en;q=0.001', 'en')]
hosts = [('shop.example.de', 'shop.example.de'), ('www.shop.example.de', 'www.shop.example.de'),
         ('SHOP.Example.DE', 'shop.example.de'), ('shop.example.de.', 'shop.example.de'), ('shop.example.de:21080', 'shop.example.de'),
         ('x.wild.example.de', 'x.wild.example.de'), ('xn--bcher-kva.wild.example.de', 'xn--bcher-kva.wild.example.de'),
         ('-bad.wild.example.de', None), ('a_b.wild.example.de', None), ('x' * 64 + '.wild.example.de', None),
         ('evil.test', None), ('127.0.0.1', None), ('[::1]', None), ('localhost', None),
         ('<script>alert(1)</script>.wild.example.de', 'reject'), ('"><img src=x onerror=alert(1)>', 'reject'),
         ('shop.example.de%3Cscript%3E', None), ('x.wild.example.de\t', None)]
out = open(OUT, 'w')
res = {}
for name, m, _, h, b in cases:
    try: r = req(m, headers=h, body=b)
    except Exception as e: r = {'error': repr(e)}
    r['case'] = name; res[name] = r; out.write(json.dumps(r) + '\n')
for al, want in langs:
    h = dict(NAV); 
    if al: h['Accept-Language'] = al
    r = req('GET', headers=h); r['case'] = f'lang:{al!r}'; r['want'] = want; out.write(json.dumps(r) + '\n')
for host, want in hosts:
    try: r = req('GET', host=host, headers=NAV)
    except Exception as e: r = {'error': repr(e)}
    r['case'] = f'host:{host!r}'; r['want'] = want; out.write(json.dumps(r) + '\n')
dist = collections.Counter(); mism = 0; cd_mism = 0
for i in range(NDIST):
    r = req('GET', headers=NAV)
    dist[r['retry_after']] += 1
    if r['refresh'] != r['retry_after']: mism += 1
    if str(r['countdown_items']) != r['retry_after'] or r['bar_s'] != r['retry_after']: cd_mism += 1
out.write(json.dumps({'case': 'distribution', 'n': NDIST, 'retry_after': dict(dist), 'refresh_mismatch': mism, 'countdown_mismatch': cd_mism}) + '\n')
