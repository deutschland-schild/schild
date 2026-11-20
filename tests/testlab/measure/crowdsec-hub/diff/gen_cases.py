#!/usr/bin/env python3
# TEST ONLY: MVP-26 measurement. Builds one request per AND-group of every hub rule from the rule's own YAML, then
# variants. The requests carry the literal strings of the published rules and go to local engines only.
# The real CrowdSec engine is the oracle: this generator only has to come close, a request neither engine matches
# counts as "generator missed", not as a result.
#   gen_cases.py <snapshot.json> <cases.json>
import base64, json, random, re, sys, urllib.parse
import re._parser as sre  # noqa
import re._constants as src  # noqa
import yaml

random.seed(2603)
SAFE_PATH = "/-._~!$&'()*+,;=:@"


def flatten(node):
    if 'and' in node:
        out = [[]]
        for c in node['and']:
            sub = flatten(c)
            out = [a + b for a in out for b in sub]
        return out
    if 'or' in node:
        out = []
        for c in node['or']:
            out += flatten(c)
        return out
    return [[node]]


def covered(c, av):
    o = ord(c)
    for k, a in av:
        if k is src.LITERAL and a == o:
            return True
        if k is src.RANGE and a[0] <= o <= a[1]:
            return True
        if k is src.CATEGORY:
            n = str(a)
            if 'SPACE' in n and c.isspace():
                return True
            if 'WORD' in n and (c.isalnum() or c == '_'):
                return True
            if 'DIGIT' in n and c.isdigit():
                return True
    return False


def sample_item(op, av, st):
    if op is src.LITERAL:
        return chr(av)
    if op is src.NOT_LITERAL:
        return 'a' if chr(av) != 'a' else 'b'
    if op is src.ANY:
        return 'a'
    if op is src.IN:
        neg = any(o is src.NEGATE for o, _ in av)
        cands = []
        for o, a in av:
            if o is src.LITERAL:
                cands.append(chr(a))
            elif o is src.RANGE:
                cands.append(chr(a[0]))
                if a[1] - a[0] > 1:
                    cands.append(chr(a[0] + 1))
            elif o is src.CATEGORY:
                n = str(a)
                cands.append({'CATEGORY_DIGIT': '1', 'CATEGORY_SPACE': ' ', 'CATEGORY_WORD': 'a'}.get(n, 'a' if 'NOT' in n else 'a'))
        if neg:
            for c in "';|`$<>(){} &,~^!#@":
                if not covered(c, av):
                    return c
            return '~'
        lower = [c for c in cands if c.islower() or c.isdigit()]
        return (lower or cands or ['a'])[0]
    if op is src.BRANCH:
        return sample_seq(av[1][0], st)
    if op is src.SUBPATTERN:
        return sample_seq(av[3], st)
    if op in (src.MAX_REPEAT, src.MIN_REPEAT, getattr(src, 'POSSESSIVE_REPEAT', None)):
        lo, hi, sub = av
        n = max(lo, 1 if hi > 0 else 0)
        n = min(n, 4)
        return ''.join(sample_seq(sub, st) for _ in range(n))
    if op is src.AT:
        return ''
    if op is src.CATEGORY:
        return 'a'
    if op is getattr(src, 'ATOMIC_GROUP', None):
        return sample_seq(av, st)
    return ''


def sample_seq(seq, st):
    return ''.join(sample_item(op, av, st) for op, av in seq)


def sample_regex(rx):
    try:
        p = sre.parse(rx.replace('(?s)', ''))
    except Exception:
        return None
    return sample_seq(p, p)


class Unsolved(Exception):
    pass


def text_for(leaf):
    m = leaf.get('match', {})
    t, v = m.get('type'), m.get('value')
    v = '' if v is None else (str(v).lower() if isinstance(v, bool) else str(v))
    tr = leaf.get('transform') or []
    if t in ('contains', 'equals', 'startsWith', 'endsWith'):
        s = v
    elif t == 'regex':
        s = sample_regex(v)
        if s is None:
            raise Unsolved('regex')
    elif t == 'libinjectionSQL':
        s = "1' OR '1'='1' -- "
    elif t == 'libinjectionXSS':
        s = '<script>alert(1)</script>'
    elif t in ('gte', 'gt', 'eq', 'lte', 'lt'):
        n = int(v) + (1 if t == 'gt' else 0)
        n = max(n, 0)
        if 'length' in tr:
            s = 'a' * n
        else:
            s = str(n)
    else:
        raise Unsolved('match ' + str(t))
    return t, s


class Req:
    def __init__(self):
        self.method = None
        self.eq = None
        self.start = ''
        self.mid = []
        self.end = ''
        self.query = []
        self.rawq = []
        self.headers = {}
        self.cookies = []
        self.body = []
        self.json = {}
        self.names = []
        self.files = []
        self.filenames = []
        self.raw = None
        self.notes = []
        self.b64 = {}

    def add_path(self, kind, s, encoded):
        if kind == 'equals':
            self.eq = s
        elif kind == 'startsWith':
            self.start = s
        elif kind == 'endsWith':
            self.end = s
        else:
            self.mid.append(s)

    def path(self):
        if self.eq is not None:
            p = self.eq
        else:
            p = self.start
            for m in self.mid:
                if p and not p.endswith('/') and not m.startswith('/'):
                    p += '/'
                p += m
            if self.end:
                if not p.endswith('/') and not self.end.startswith('/') and not self.end.startswith('.'):
                    p += '/'
                p += self.end
        if not p.startswith('/'):
            p = '/' + p
        return p


def enc_path(p):
    # keep what a URL can carry raw, percent-encode the rest once
    return ''.join(c if (c.isalnum() or c in SAFE_PATH or c == '%') else urllib.parse.quote(c) for c in p)


def apply_leaf(r, leaf, text, kind, zone=None):
    z = zone or leaf['zones'][0]
    vs = leaf.get('variables') or []
    tr = leaf.get('transform') or []
    if 'b64decode' in tr:
        key = (z, vs[0] if vs else None)
        r.b64[key] = r.b64.get(key, '') + text
        text = base64.b64encode(r.b64[key].encode()).decode()
        for lst in (r.query, r.body):
            lst[:] = [(k, v) for k, v in lst if k != (vs[0] if vs else None)]
    if 'count' in tr:
        for _ in range(int(text) - 1):
            r.body.append((vs[0], 'a')) if z == 'BODY_ARGS' else r.query.append((vs[0], 'a'))
        text = 'a'
    v = vs[0] if vs else None
    if v and v.startswith('/') and v.endswith('/') and len(v) > 2:
        v = sample_regex(v[1:-1]) or 'm26'
    if z == 'URI':
        r.add_path(kind, text, True)
    elif z == 'URI_FULL':
        if '?' in text:
            a, b = text.split('?', 1)
            if a:
                r.add_path('contains', a, True)
            r.rawq.append(b)
        else:
            r.add_path(kind if kind != 'regex' else 'contains', text, True)
    elif z == 'ARGS':
        r.query.append((v or 'm26q', text))
    elif z == 'ARGS_NAMES':
        r.query.append((text, '1'))
    elif z == 'BODY_ARGS':
        if v and v.startswith('json.'):
            cur = r.json
            parts = v.split('.')[1:]
            for p in parts[:-1]:
                cur = cur.setdefault(p, {})
            cur[parts[-1]] = text
        else:
            r.body.append((v or 'm26b', text))
    elif z == 'BODY_ARGS_NAMES':
        r.body.append((text, '1'))
    elif z == 'HEADERS':
        if not v:
            raise Unsolved('headers')
        r.headers[v] = (r.headers.get(v, '') + text) if v.lower() in ('content-type',) and False else text
    elif z == 'HEADERS_NAMES':
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", text):
            raise Unsolved('header name')
        r.headers[text] = '1'
    elif z == 'COOKIES':
        r.cookies.append((v or 'm26c', text))
    elif z == 'METHOD':
        r.method = text
    elif z in ('FILENAMES', 'FILES'):
        r.filenames.append(text)
    elif z == 'FILES_NAMES':
        r.files.append(text)
    elif z == 'RAW_BODY':
        r.raw = text
    else:
        raise Unsolved('zone ' + z)


def has_header(r, name):
    return next((v for k, v in r.headers.items() if k.lower() == name), None)


def build(r, bodyform='auto'):
    """returns method, target, headers(list), body(bytes), notes"""
    path = enc_path(r.path())
    qs = [urllib.parse.quote(k, safe='') + '=' + urllib.parse.quote(v, safe='') for k, v in r.query] + r.rawq
    target = path + ('?' + '&'.join(qs) if qs else '')
    headers = dict(r.headers)
    if r.cookies:
        headers['Cookie'] = '; '.join(k + '=' + v for k, v in r.cookies)
    body = b''
    ct = has_header(r, 'content-type')
    multipart = bool(r.files or r.filenames)
    if bodyform == 'multipart' or multipart:
        b = 'm26boundaryTESTONLY'
        parts = []
        for k, v in r.body:
            parts.append(f'--{b}\r\nContent-Disposition: form-data; name="{k}"\r\n\r\n{v}\r\n')
        for i, n in enumerate(r.filenames):
            parts.append(f'--{b}\r\nContent-Disposition: form-data; name="file{i}"; filename="{n}"\r\nContent-Type: application/octet-stream\r\n\r\nTEST ONLY\r\n')
        for n in r.files:
            parts.append(f'--{b}\r\nContent-Disposition: form-data; name="{n}"; filename="a.txt"\r\nContent-Type: text/plain\r\n\r\nTEST ONLY\r\n')
        if r.json:
            parts.append(f'--{b}\r\nContent-Disposition: form-data; name="data"\r\n\r\n{json.dumps(r.json)}\r\n')
        body = (''.join(parts) + f'--{b}--\r\n').encode('utf-8', 'replace')
        for k in list(headers):
            if k.lower() == 'content-type':
                del headers[k]
        headers['Content-Type'] = 'multipart/form-data; boundary=' + b
    elif r.raw is not None:
        body = r.raw.encode('utf-8', 'replace')
        if not ct:
            headers['Content-Type'] = 'application/json' if r.raw.lstrip()[:1] in '{[' else 'application/x-www-form-urlencoded'
    elif r.json or bodyform == 'json':
        o = json.loads(json.dumps(r.json))
        for k, v in r.body:
            o[k] = v
        body = json.dumps(o).encode()
        if not ct or 'json' not in ct.lower():
            for k in list(headers):
                if k.lower() == 'content-type':
                    del headers[k]
            headers['Content-Type'] = ct if ct and bodyform != 'json' else 'application/json'
    elif r.body:
        body = '&'.join(urllib.parse.quote(k, safe='') + '=' + urllib.parse.quote(v, safe='') for k, v in r.body).encode()
        if not ct:
            headers['Content-Type'] = 'application/x-www-form-urlencoded'
    method = r.method or ('POST' if body else 'GET')
    return method, target, headers, body


def mutate(s):
    # one changed spot in the middle of the longest alphanumeric run: a near miss
    runs = list(re.finditer(r'[A-Za-z0-9]{3,}', s))
    if not runs:
        return s + 'zq' if s else 'zq'
    m = max(runs, key=lambda x: len(x.group()))
    i = m.start() + len(m.group()) // 2
    return s[:i] + 'zq' + s[i:]


def flipcase(s):
    return ''.join(c.upper() if i % 2 == 0 else c for i, c in enumerate(s))


def pct(s):
    return ''.join('%%%02X' % ord(c) if c.isalnum() else c for c in s[:6]) + s[6:]


def group_req(g, breakidx=None, how=None, swap=False, altzone=False):
    r = Req()
    for i, leaf in enumerate(g):
        kind, text = text_for(leaf)
        if i == breakidx:
            if how == 'mutate':
                text = mutate(text)
            elif how == 'case':
                text = flipcase(text)
            elif how == 'pct':
                text = pct(text)
        z = leaf['zones'][0]
        if altzone and len(leaf['zones']) > 1:
            z = leaf['zones'][1]
        if i == breakidx and how == 'swap':
            z = {'ARGS': 'BODY_ARGS', 'BODY_ARGS': 'ARGS'}.get(z, z)
        apply_leaf(r, leaf, text, kind, z)
    return r


def main():
    d = json.load(open(sys.argv[1]))
    cases = []
    miss = []
    n = 0

    def add(rule, g, kind, r, form='auto', chunked=False, note=''):
        nonlocal n
        try:
            method, target, headers, body = build(r, form)
        except Exception as e:
            miss.append((rule, g, kind, repr(e)))
            return
        if any(ord(c) > 126 or ord(c) < 32 for c in target) or any(ord(c) < 32 or ord(c) > 126 for v in headers.values() for c in str(v)):
            miss.append((rule, g, kind, 'bytes'))
            return
        n += 1
        cases.append({'id': n, 'rule': rule, 'group': g, 'kind': kind, 'method': method, 'target': target, 'headers': headers,
                      'body': base64.b64encode(body).decode(), 'chunked': chunked, 'note': note})

    for it in d['rules']:
        y = yaml.safe_load(base64.b64decode(it['content']))
        name = it['name']
        groups = []
        for e in y.get('rules') or []:
            groups += flatten(e)
        for gi, g in enumerate(groups):
            try:
                r = group_req(g)
            except Unsolved as e:
                miss.append((name, gi, 'hit', str(e)))
                continue
            add(name, gi, 'hit', r)
            zs = [l['zones'][0] for l in g]
            # chunked and multipart forms of the same request
            mt, tg, hd, bd = build(r)
            if bd:
                add(name, gi, 'chunked', r, chunked=True)
            if r.body and not r.raw and not r.files and not r.filenames and not has_header(r, 'content-type'):
                add(name, gi, 'multipart', r, form='multipart')
            if r.json:
                add(name, gi, 'json-as-multipart', r, form='multipart')
            if 'RAW_BODY' in zs and r.raw is not None:
                for label, ct, wrap in (('raw-json', 'application/json', json.dumps({'m26': r.raw})),
                                        ('raw-urlencoded', 'application/x-www-form-urlencoded', 'm26=' + r.raw),
                                        ('raw-xml', 'application/xml', '<m26>' + r.raw.replace('&', '&amp;').replace('<', '&lt;') + '</m26>'),
                                        ('raw-text', 'text/plain', r.raw),
                                        ('raw-octet', 'application/octet-stream', r.raw)):
                    r2 = group_req(g)
                    r2.raw = wrap
                    r2.headers = {k: v for k, v in r2.headers.items() if k.lower() != 'content-type'}
                    r2.headers['Content-Type'] = ct
                    add(name, gi, label, r2)
            if any(len(l['zones']) > 1 for l in g):
                add(name, gi, 'alt-zone', group_req(g, altzone=True))
            if r.raw is not None:
                r2 = group_req(g)
                b = 'm26boundaryTESTONLY'
                r2.raw = f'--{b}\r\nContent-Disposition: form-data; name="m26"\r\n\r\n{r.raw}\r\n--{b}--\r\n'
                r2.headers = {k: v for k, v in r2.headers.items() if k.lower() != 'content-type'}
                r2.headers['Content-Type'] = 'multipart/form-data; boundary=' + b
                add(name, gi, 'raw-multipart', r2)
            if r.json:
                for label, ct in (('json-charset', 'application/json; charset=utf-8'), ('json-upper', 'APPLICATION/JSON'), ('json-api', 'application/vnd.api+json'), ('json-text', 'text/plain')):
                    r2 = group_req(g)
                    r2.headers = {k: v for k, v in r2.headers.items() if k.lower() != 'content-type'}
                    r2.headers['Content-Type'] = ct
                    add(name, gi, label, r2)
            # near misses, one leaf at a time
            for li, leaf in enumerate(g):
                if leaf.get('match', {}).get('type') in ('gte', 'gt', 'lt', 'lte', 'eq') or 'length' in (leaf.get('transform') or []):
                    continue
                z = leaf['zones'][0]
                if z == 'METHOD':
                    continue
                try:
                    add(name, gi, 'near-mutate', group_req(g, li, 'mutate'), note=z)
                    tr = leaf.get('transform') or []
                    if 'lowercase' not in tr and 'uppercase' not in tr and any(c.isalpha() for c in text_for(leaf)[1]) and leaf['match'].get('type') != 'regex':
                        add(name, gi, 'near-case', group_req(g, li, 'case'), note=z)
                    if 'urldecode' not in tr and z in ('URI', 'URI_FULL'):
                        add(name, gi, 'near-pct', group_req(g, li, 'pct'), note=z)
                    if z in ('ARGS', 'BODY_ARGS') and (leaf.get('variables') or ['x'])[0][:5] != 'json.':
                        add(name, gi, 'near-swap', group_req(g, li, 'swap'), note=z)
                except Unsolved:
                    pass
    json.dump({'cases': cases, 'miss': miss}, open(sys.argv[2], 'w'), indent=0)
    from collections import Counter
    print(len(cases), Counter(c['kind'] for c in cases))
    print('not generated', len(miss), Counter(m[3] for m in miss).most_common(8))


main()
