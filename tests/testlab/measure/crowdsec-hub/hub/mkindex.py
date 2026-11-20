#!/usr/bin/env python3
# TEST ONLY: MVP-26 update safety. Writes index variants from one real hub index. No variant leaves this machine.
#   mkindex.py <real index.json> <outdir>
import base64, copy, gzip, hashlib, json, os, random, sys

real = json.load(open(sys.argv[1]))
out = sys.argv[2]
os.makedirs(out, exist_ok=True)
COLL = 'crowdsecurity/appsec-virtual-patching'


def save(name, doc):
    b = json.dumps(doc).encode()
    open(f'{out}/{name}.json', 'wb').write(b)
    print(name, len(b))


def add(doc, short, yaml_text, version='0.1', digest=None, in_coll=True):
    name = 'crowdsecurity/' + short
    body = yaml_text.encode()
    dg = digest or hashlib.sha256(body).hexdigest()
    doc['appsec-rules'][name] = {'path': f'appsec-rules/{name}.yaml', 'version': version, 'content': base64.b64encode(body).decode(), 'description': 'TEST ONLY',
                                 'versions': {version: {'deprecated': False, 'digest': dg}}, 'author': 'm26'}
    if in_coll:
        l = doc['collections'][COLL]['appsec-rules']
        if name not in l:
            l.append(name)


def rule(short, zones, mtype, value, transform=None, variables=None, label='TEST ONLY rule'):
    y = f'name: crowdsecurity/{short}\ndescription: TEST ONLY\nrules:\n  - zones: [{",".join(zones)}]\n'
    if variables:
        y += f'    variables: [{",".join(variables)}]\n'
    if transform:
        y += f'    transform: [{",".join(transform)}]\n'
    y += f"    match:\n      type: {mtype}\n      value: '{value}'\nlabels:\n  label: {label}\n  classification:\n    - cve.CVE-2099-0001\n"
    return y


def selected(doc):
    return [n for n in doc['collections'][COLL]['appsec-rules'] if n.startswith('crowdsecurity/vpatch-')]


save('ok', real)

d = copy.deepcopy(real)
add(d, 'vpatch-M26-new', rule('vpatch-M26-new', ['URI'], 'contains', '/m26-new-rule-probe'))
save('newrule', d)

d = copy.deepcopy(real)
# one rule gets a new text: the path of vpatch-env-access stays, a second way in is added
n = 'crowdsecurity/vpatch-env-access'
t = base64.b64decode(d['appsec-rules'][n]['content']).decode()
t = t.replace('value: .env', 'value: .envx')
body = t.encode()
v = '9.9'
d['appsec-rules'][n].update({'version': v, 'content': base64.b64encode(body).decode()})
d['appsec-rules'][n]['versions'][v] = {'deprecated': False, 'digest': hashlib.sha256(body).hexdigest()}
save('changed', d)

d = copy.deepcopy(real)
sel = selected(d)
gone = sel[:30]
for n in gone:
    del d['appsec-rules'][n]
    d['collections'][COLL]['appsec-rules'].remove(n)
save('removed30', d)

d = copy.deepcopy(real)
sel = selected(d)
for n in sel[:120]:
    del d['appsec-rules'][n]
    d['collections'][COLL]['appsec-rules'].remove(n)
save('shrink', d)

d = copy.deepcopy(real)
n = 'crowdsecurity/vpatch-env-access'
vv = d['appsec-rules'][n]['version']
d['appsec-rules'][n]['versions'][vv]['digest'] = '0' * 64
save('digest1', d)

d = copy.deepcopy(real)
for n in selected(d):
    vv = d['appsec-rules'][n]['version']
    d['appsec-rules'][n]['versions'][vv]['digest'] = '0' * 64
save('digestall', d)

d = copy.deepcopy(real)
del d['collections'][COLL]
save('nocoll', d)

d = copy.deepcopy(real)
del d['appsec-rules']
save('norules', d)

d = copy.deepcopy(real)
d['appsec-rules']['crowdsecurity/vpatch-env-access']['content'] = '***not base64***'
save('badb64', d)

d = copy.deepcopy(real)
del d['appsec-rules']['crowdsecurity/vpatch-env-access']['version']
save('noversion', d)

d = copy.deepcopy(real)
for i in range(1001):
    add(d, f'vpatch-M26-many-{i}', rule(f'vpatch-M26-many-{i}', ['URI'], 'contains', f'/m26-many-{i}'))
save('toomany', d)

# one rule above the 4096 instruction bound: 1024 characters of bounded repeats
d = copy.deepcopy(real)
rx = '(?:' + '|'.join(f'[a-c]{{50}}{chr(100 + i % 20)}' for i in range(60)) + ')'
add(d, 'vpatch-M26-regex-cost', rule('vpatch-M26-regex-cost', ['URI'], 'regex', rx))
add(d, 'vpatch-M26-regex-nested', rule('vpatch-M26-regex-nested', ['URI'], 'regex', '/m26(a+)+$'))
add(d, 'vpatch-M26-after', rule('vpatch-M26-after', ['URI'], 'contains', '/m26-after-probe'))
save('exprx', d)

# bad items among good ones
d = copy.deepcopy(real)
add(d, 'vpatch-M26-yamlbomb', 'a: &a [x,x]\nb: &b [*a,*a]\nname: crowdsecurity/vpatch-M26-yamlbomb\nrules:\n  - zones: [URI]\n    match: {type: contains, value: /x}\n')
add(d, 'vpatch-M26-rawsec', 'name: crowdsecurity/vpatch-M26-rawsec\nseclang_rules:\n  - SecAction "id:1,phase:1,deny"\nrules:\n  - zones: [URI]\n    match: {type: contains, value: /m26-raw}\n')
add(d, 'vpatch-M26-inject', "name: crowdsecurity/vpatch-M26-inject\nrules:\n  - zones: [URI]\n    match: {type: contains, value: 'x\" \"id:1,deny'}\n")
add(d, 'vpatch-M26-bigyaml', 'name: crowdsecurity/vpatch-M26-bigyaml\n# ' + 'x' * 70000 + '\nrules:\n  - zones: [URI]\n    match: {type: contains, value: /m26-big}\n')
add(d, 'vpatch-M26-deep', 'name: crowdsecurity/vpatch-M26-deep\nrules:\n  ' + '- and:\n'.join('' for _ in range(2)) + '- zones: [URI]\n    match: {type: nope, value: /m26}\n')
add(d, 'vpatch-M26-after', rule('vpatch-M26-after', ['URI'], 'contains', '/m26-after-probe'))
save('badrules', d)

# a rule that passes the catch-all heuristic but hits nearly every path
d = copy.deepcopy(real)
add(d, 'vpatch-M26-broad', rule('vpatch-M26-broad', ['URI'], 'regex', '^/[^ifrs]'))
save('broad', d)
d = copy.deepcopy(real)
add(d, 'vpatch-M26-broad2', rule('vpatch-M26-broad2', ['HEADERS'], 'contains', 'mozilla/5.0 (', ['lowercase'], ['User-Agent']))
save('broad2', d)

# hostile set inside every per-rule and per-set bound: many large alternations, each one below the program bound
random.seed(26)


def big_alt(i):
    parts = []
    while sum(len(p) + 1 for p in parts) < 960:
        parts.append(''.join(random.choice('bcdfghjkmpqtvwxz') for _ in range(5)))
    return '(?:' + '|'.join(parts) + f')/m{i}'


def heavy(zones, n_rules, groups, name):
    d = copy.deepcopy(real)
    room = n_rules - len(selected(d))
    for i in range(room):
        short = f'vpatch-M26-heavy-{i}'
        y = f'name: crowdsecurity/{short}\ndescription: TEST ONLY\nrules:\n'
        for g in range(groups):
            y += f"  - zones: [{','.join(zones)}]\n    match:\n      type: regex\n      value: '{big_alt(i * 10 + g)}'\n"
        y += 'labels:\n  label: TEST ONLY\n'
        add(d, short, y)
    save(name, d)


heavy(['URI'], 1000, 6, 'heavy_uri')
heavy(['URI', 'ARGS', 'BODY_ARGS'], 1000, 6, 'heavy_args')

g = gzip.compress(b'{"appsec-rules":{},"pad":"' + b'a' * (40 << 20) + b'"}', 1)
open(f'{out}/bomb.gz', 'wb').write(g)
print('bomb', len(g))
