import json,sys
CSP = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
for l in open(sys.argv[1]):
    d=json.loads(l)
    if d['case']=='distribution': print(d); continue
    if 'error' in d: print(f"{d['case']:<34} ERROR {d['error'][:80]}"); continue
    kind='PAGE' if d['ctype'].startswith('text/html') else ('JSON' if 'json' in d['ctype'] else d['ctype'])
    j=d.get('json') or {}
    csp='ok' if d['csp']==CSP else d['csp']
    print(f"{d['case'][:40]:<40} {d['status']} {kind:<4} RA={d['retry_after']} refresh={d['refresh']} countdown={d['countdown_items']} bar={d.get('bar_s')} lang={d['clang']}/{d['html_lang']} want={d.get('want','')} site={d['site']!r} generic={d['generic']} form_copy={d['form_copy']} reload_copy={d['reload_copy']} bytes={d['len']} incident_hdr={d['incident_hdr']} json_retry_after={j.get('retry_after')} code={j.get('code')} script={d['script']} noindex={d['noindex']} csp={csp} cache={d['cache']}")
