#!/usr/bin/env python3
# TEST ONLY: abend api409 measurement. Replays, per page load, the API calls the
# client dashboard (dashboard/apps/client-dashboard, commit c54de1b, i.e. after
# a34c2a6) makes, with the same gating as the Vue code, and records every HTTP
# status. One "load" = a fresh browser session (monitoring probe and request-ring
# probe unknown), as after a hard reload.
#
# Gating mirrored from the source (file: condition):
#   api/monitoring.ts whileOn(): every monitoring/website-number query waits for
#     ONE probe GET /monitoring/now; whileOn() starts the probe even when the
#     query itself is disabled.
#   api/websites.ts useAnnotations/useAlerts: NOT behind whileOn (sent at mount).
#     WebsiteOverviewView passes `on` = !monitoringOff && !unprotected && !notFound,
#     which is true while the probe is still unknown -> annotations go out at mount.
#   components/monitoring/NowSection.vue: /monitoring/stream opens at mount with
#     on = !off && !nowQ.isError (true before the probe answers).
#   useRequestRing: GET /requests once per session, only after the probe said on.
#   useFalsePositiveHints: only when the ring probe answered true.
#   WebsiteOverviewView: without ring, 1 filter max, panels unfiltered, filtered
#     series asks resolution=10m; main metric falls back to requests:rate.
#
# Usage: python3 -I uiseq.py --base http://127.0.0.1:22688/api/v0 --cookies cj.txt \
#          --site shop.test --out calls.jsonl [--label on]
# Cookies: a curl cookie jar after POST /auth/setup or /auth/login.
import argparse, http.cookiejar, json, sys, time, urllib.error, urllib.parse, urllib.request
from concurrent.futures import ThreadPoolExecutor

ap = argparse.ArgumentParser()
ap.add_argument('--base', required=True)
ap.add_argument('--cookies', required=True)
ap.add_argument('--site', default='shop.test')
ap.add_argument('--out', required=True)
ap.add_argument('--label', default='')
a = ap.parse_args()

cj = http.cookiejar.MozillaCookieJar(a.cookies)
cj.load(ignore_discard=True, ignore_expires=True)
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
OUT = open(a.out, 'a')


def iso(ms):
    return time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(ms / 1000))


def win(seconds, step_s, now=None):
    now = now or int(time.time() * 1000)
    step = step_s * 1000
    frm = (now - seconds * 1000) // step * step + step
    return {'from': iso(frm), 'to': iso(now)}


def call(page, case, phase, path, q=None, stream=False):
    qs = urllib.parse.urlencode(q or {}, doseq=True)
    url = a.base + path + ('?' + qs if qs else '')
    t0 = time.time()
    code, problem = None, None
    try:
        r = opener.open(url, timeout=3 if stream else 30)
        code = r.status
        if not stream:
            r.read()
        r.close()
    except urllib.error.HTTPError as e:
        code = e.code
        try:
            problem = json.loads(e.read().decode()).get('code')
        except Exception:
            problem = None
    except Exception as e:  # stream read timeouts etc.
        code, problem = -1, str(e)[:80]
    rec = {'label': a.label, 'page': page, 'case': case, 'phase': phase, 'path': path, 'query': qs[:300],
           'status': code, 'problem': problem, 'ms': round((time.time() - t0) * 1000, 1)}
    OUT.write(json.dumps(rec) + '\n'); OUT.flush()
    return code, problem


def par(*fns):
    with ThreadPoolExecutor(8) as ex:
        return [f.result() for f in [ex.submit(fn) for fn in fns]]


WR = {  # api/websites.ts WEBSITE_RANGES
    'echtzeit': (1800, 10, '10s'), '6h': (21600, 60, '1m'), '24h': (86400, 600, '10m'),
    '48h': (172800, 600, '10m'), '7d': (604800, 1800, 'auto'), '14d': (1209600, 1800, 'auto')}
ALERT_DIMS = {'path', 'country', 'net_class', 'asn', 'rule', 'bot_category'}
PANELS = [('referrer', 8), ('path', 10), ('country', 8), ('browser', 8), ('bot_category', 13), ('rule', 8)]


def app_shell(page, case):
    # App.vue: useOverview(authed), useWebsites(authed); auth/session from the router guard
    call(page, case, 'shell', '/auth/session')
    par(lambda: call(page, case, 'shell', '/overview'), lambda: call(page, case, 'shell', '/websites'))


def probe(page, case):
    code, prob = call(page, case, 'probe', '/monitoring/now')
    return 'off' if (code == 409 and prob == 'monitoring_off') else 'on'


def page_websites(case='load'):
    pg = '/'
    app_shell(pg, case)
    st = probe(pg, case)  # WebsiteCard -> useWebsiteSeries -> whileOn -> probe, even if not tracked
    if st == 'on':
        ws = json.loads(opener.open(a.base + '/websites').read())
        for w in ws.get('websites', []):
            if w.get('protection') != 'unprotected' and w.get('tracked') and w.get('now'):
                s, step, res = WR['24h']
                call(pg, case, 'after-probe', '/monitoring/series', {'metric': ['traffic.requests:rate'], **win(s, step), 'resolution': res, 'site': w['id']})
    return st


def page_status(case='load'):
    pg = '/status'
    app_shell(pg, case)
    # mount: rules list, probe and the SSE stream in parallel
    res = par(lambda: call(pg, case, 'mount', '/rules', {'limit': 500}),
              lambda: probe(pg, case),
              lambda: call(pg, case, 'mount-stream', '/monitoring/stream', stream=True))
    st = res[1]
    if st == 'on':
        call(pg, case, 'after-probe', '/monitoring/now')
        now = int(time.time() * 1000)
        step = 10000; frm = (now - 3600000) // step * step + step
        call(pg, case, 'after-probe', '/monitoring/series', {'metric': ['traffic.requests:rate', 'traffic.stopped:rate', 'traffic.would_block:rate', 'traffic.requests:sum', 'traffic.latency_total:p95', 'server.cpu_usage:avg', 'server.memory_used:avg', 'server.disk_used_ratio:avg'], 'from': iso(frm), 'to': iso(now), 'resolution': '10s'})
    return st


def page_overview(rng='24h', filt=None, case='load'):
    pg = f'/w/{a.site}'
    s, step, res = WR[rng]
    w = win(s, step)
    app_shell(pg, case)
    alert_f = filt if (filt and filt.split(':')[0] in ALERT_DIMS) else None
    # mount (not gated by the probe): website, annotations (on=true while unknown), alerts, probe
    out = par(lambda: call(pg, case, 'mount', f'/websites/{a.site}'),
              lambda: call(pg, case, 'mount', f'/websites/{a.site}/annotations', w),
              lambda: call(pg, case, 'mount', f'/websites/{a.site}/alerts', {**w, 'limit': 50, **({'filter': [alert_f]} if alert_f else {})}),
              lambda: probe(pg, case))
    st = out[3]
    if st != 'on':
        return st
    rc, _ = call(pg, case, 'after-probe', '/requests', {'from': iso(time.time() * 1000 - 60000), 'to': iso(time.time() * 1000)})
    ring = rc == 200
    filters = [filt] if filt else []
    in_ring = s <= 48 * 3600
    panel_f = filters if (ring and in_ring) else []
    ser_res = '10m' if (filters and not (ring and in_ring)) else res
    main_metric = 'traffic.requests:rate' if (filters and not panel_f) else 'traffic.clients_unique'
    fq = {'filter': filters} if filters else {}
    call(pg, case, 'after-probe', f'/websites/{a.site}/kpis', {**w, **fq})
    call(pg, case, 'after-probe', '/monitoring/series', {'metric': [main_metric], **w, 'resolution': ser_res, 'site': a.site, **fq})
    call(pg, case, 'after-probe', '/monitoring/series', {'metric': ['traffic.stopped:rate', 'traffic.would_block:rate'], **w, 'resolution': ser_res, 'site': a.site, **fq})
    call(pg, case, 'after-probe', f'/websites/{a.site}/realtime')
    call(pg, case, 'after-probe', '/monitoring/buckets', {'resolution': '10m', 'from': iso(time.time() * 1000 - 1800000), 'limit': 3})
    for by, top in PANELS:
        call(pg, case, 'after-probe', '/monitoring/traffic/breakdown', {'by': by, **w, 'site': a.site, 'top': top, **({'filter': panel_f} if panel_f else {})})
    return st


def page_attacks(case='load'):
    pg = f'/w/{a.site}/angriffe'
    app_shell(pg, case)
    now = time.time() * 1000
    s, step, _ = WR['24h']
    par(lambda: call(pg, case, 'mount', f'/websites/{a.site}'),
        lambda: call(pg, case, 'mount', '/incidents', {'from': iso(now - 7 * 86400000), 'to': iso(now), 'limit': 100, 'site': a.site}),
        lambda: call(pg, case, 'mount', '/behaviour/hits', {'active': 'true', 'kind': 'scenario', 'site': a.site, 'limit': 100}),
        lambda: call(pg, case, 'mount', f'/websites/{a.site}/alerts', {**win(s, step), 'limit': 50}))


def page_exceptions(case='load'):
    pg = f'/w/{a.site}/exceptions'
    app_shell(pg, case)
    call(pg, case, 'mount', f'/websites/{a.site}')
    st = probe(pg, case)  # useFalsePositiveHints -> useRequestRing -> whileOn
    if st == 'on':
        rc, _ = call(pg, case, 'after-probe', '/requests', {'from': iso(time.time() * 1000 - 60000), 'to': iso(time.time() * 1000)})
        if rc == 200:
            call(pg, case, 'after-ring', '/requests/alerts/hints', {'site': a.site})
    return st


def page_charts(rng='6h', site=True, case='load'):
    pg = f'/w/{a.site}/charts' if site else '/diagramme'
    app_shell(pg, case)
    if site:
        call(pg, case, 'mount', f'/websites/{a.site}')
    st = probe(pg, case)
    if st != 'on':
        return st
    secs = {'1h': (3600, 10, '10s'), '6h': (21600, 60, '1m'), '48h': (172800, 600, '10m'), '14d': (1209600, 600, '10m')}[rng]
    now = int(time.time() * 1000); step = secs[1] * 1000
    frm = (now - secs[0] * 1000) // step * step + step
    sq = {'site': a.site} if site else {}
    call(pg, case, 'after-probe', '/monitoring/now')
    for chunk_from in range(frm, now, 1000 * step):
        q = {'from': iso(chunk_from), 'to': iso(min(now, chunk_from + 1000 * step)), 'resolution': secs[2], **sq}
        call(pg, case, 'after-probe', '/monitoring/series', {'metric': ['traffic.forwarded', 'traffic.would_block', 'traffic.stopped', 'traffic.fail_closed', 'traffic.blocked_waf', 'traffic.blocked_behaviour', 'traffic.rate_limited', 'traffic.rejected_limit', 'traffic.status_2xx', 'traffic.status_3xx', 'traffic.status_4xx', 'traffic.status_5xx', 'traffic.bytes_in', 'traffic.bytes_out', 'traffic.page_views', 'traffic.detections'], **q})
        call(pg, case, 'after-probe', '/monitoring/series', {'metric': ['traffic.latency_total:p50', 'traffic.latency_total:p95', 'traffic.latency_total:p99', 'traffic.latency_upstream:p95', 'traffic.latency_overhead:p95', 'traffic.clients_unique', 'traffic.clients_new', 'traffic.upstream_errors:sum', 'traffic.upstream_timeouts:sum', 'traffic.fail_closed:sum'], **q})
    for by in ['path', 'rule', 'country', 'asn', 'net_class', 'referrer', 'bot_category', 'ua_class', 'browser', 'os', 'device', 'method']:
        call(pg, case, 'after-probe', '/monitoring/traffic/breakdown', {'by': by, 'from': iso(now - secs[0] * 1000), 'to': iso(now), 'top': 13 if by == 'bot_category' else 10 if by == 'path' else 10, **sq})
    if not site:
        call(pg, case, 'after-probe', '/monitoring/traffic/breakdown', {'by': 'site', 'from': iso(now - secs[0] * 1000), 'to': iso(now), 'top': 10})
    return st


def page_server(case='load'):
    pg = '/server'
    app_shell(pg, case)
    st = probe(pg, case)
    if st == 'on':
        call(pg, case, 'after-probe', '/monitoring/server')
        now = int(time.time() * 1000); step = 60000; frm = (now - 21600000) // step * step + step
        call(pg, case, 'after-probe', '/monitoring/series', {'metric': ['server.cpu_usage:avg', 'server.cpu_usage:max', 'server.cpu_iowait', 'server.load1', 'server.load5', 'server.memory_used', 'server.swap_used', 'server.disk_used_ratio', 'server.net_rx_bytes', 'server.net_tx_bytes', 'server.tcp_established', 'server.tcp_time_wait', 'process.cpu_usage', 'process.rss'], 'from': iso(frm), 'to': iso(now), 'resolution': '1m'})
    return st


page_websites()
page_status()
for rng in ['echtzeit', '6h', '24h', '48h', '7d', '14d']:
    page_overview(rng, None, case=f'{rng}')
# one click filter per panel dimension (value taken from the panel's first row) at 6h, 48h, 7d
if a.label.startswith('on'):
    vals = {}
    s, step, _ = WR['24h']
    for by, top in PANELS + [('net_class', 8), ('asn', 8), ('os', 8), ('device', 8)]:
        r = json.loads(opener.open(a.base + '/monitoring/traffic/breakdown?' + urllib.parse.urlencode({'by': by, **win(s, step), 'site': a.site, 'top': top})).read())
        items = [i for i in r.get('items', []) if i.get('key')]
        if items:
            vals[by] = items[0]['key']
    for rng in ['echtzeit', '6h', '24h', '48h', '7d', '14d']:
        for by, v in vals.items():
            page_overview(rng, f'{by}:{v}', case=f'{rng} filter {by}')
page_attacks()
page_exceptions()
page_charts('6h', True)
page_charts('6h', False)
page_charts('48h', True)
page_server()
OUT.close()
