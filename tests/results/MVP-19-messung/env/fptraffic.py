#!/usr/bin/env python3
"""TEST ONLY synthetic legitimate traffic for the MVP-19 false-positive
measurement: Laravel/Livewire 3 sessions and a JSON API, sent through the
ingress with a per-session client address in X-Forwarded-For (the tools
container is a trusted proxy in the measurement config). Every request class
gets its own address block 10.66.<class>.<n>, so schild events map back to
the class. Prints per-class request/session counts and statuses as JSON.

Usage: fptraffic.py <ingress-ip> <ca.pem> <sessions-per-class> [cgnat]
"""
import base64, hashlib, http.client, json, random, ssl, sys, threading, time, urllib.parse
from collections import Counter, defaultdict

ING, CA, PER = sys.argv[1], sys.argv[2], int(sys.argv[3])
MODE = sys.argv[4] if len(sys.argv) > 4 else "classes"
rnd = random.Random(19)
ctx = ssl.create_default_context(cafile=CA)

NAMES = ["Jürgen Müller", "Zoë Weiß", "Björn Öztürk", "Anna-Lena Groß", "Renée O'Connor", "Ægir Ødegård",
         "Dr. Hans-Peter Schäfer", "Søren Kierkegaard", "François Dupont", "Łukasz Żółć", "Ana María Núñez"]
CITIES = ["Köln", "München", "Düsseldorf", "Lüneburg", "Görlitz", "Fürth", "Saarbrücken"]
TEXTS = [
    "Hallo, ich hätte gern eine Rückmeldung zu meiner Bestellung #12345 vom 03.10.",
    "Können Sie mir sagen, ob das Produkt \"Größe M\" wieder lieferbar ist? Danke & Grüße",
    "Die Union Berlin Fanartikel: select one size, drop-down funktioniert nicht.",
    "50% Rabatt auf alles? Gilt das auch für C++ / C# Bücher?",
    "Mein Passwort enthält ' und \" – ist das ein Problem?",
    "Termin: Mo–Fr 9:00–17:00, Tel. +49 (0)221 123-456; E-Mail an info@example.de",
    "Siehe https://www.example.de/produkte/kategorie?utm_source=newsletter&utm_medium=email&id=42",
    "Lieferadresse: c/o Firma Müller & Söhne GmbH, Hauptstr. 1a, 50667 Köln",
    "1 + 1 = 2; 3 < 4 and 5 > 4 -- ganz normal, oder?",
    "Ich habe die Datei /home/user/Dokumente/rechnung.pdf hochgeladen.",
]
RICH = [
    "<p>Hallo <strong>Team</strong>,</p><p>bitte prüft <a href=\"https://www.example.de/hilfe?x=1&amp;y=2\">diese Seite</a>.</p>",
    "<h2>Agenda</h2><ul><li>Begrüßung</li><li>Rückblick Q3</li><li>Ausblick &amp; Fragen</li></ul>",
    "<p><em>Zitat:</em> „Das ist großartig“ – <code>SELECT name FROM kunden</code> lief in 3 ms.</p>",
    "<p><img src=\"https://cdn.example.de/bilder/team.jpg\" alt=\"Team-Foto\" width=\"600\"></p><p>Unser Team in Köln.</p>",
    "<blockquote><p>Wer nicht fragt, bleibt dumm.</p></blockquote><p>— Sesamstraße</p>",
    "<p>Tabelle:</p><table><tr><td>Größe</td><td>Preis</td></tr><tr><td>M</td><td>19,99 €</td></tr></table>",
    "<p>Link zur <a href=\"mailto:service@example.de?subject=Frage%20zur%20Bestellung\">Mail</a> und <a href=\"tel:+492211234\">Telefon</a></p>",
    "<p>Formel: <span style=\"color: rgb(15, 135, 59);\">a &lt; b &amp;&amp; c &gt; d</span></p>",
]

def token(n=40):
    return "".join(rnd.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789") for _ in range(n))

def laravel_cookie():
    payload = json.dumps({"iv": base64.b64encode(rnd.randbytes(16)).decode(), "value": base64.b64encode(rnd.randbytes(96)).decode(),
                          "mac": hashlib.sha256(rnd.randbytes(8)).hexdigest(), "tag": ""}, separators=(",", ":"))
    return urllib.parse.quote(base64.b64encode(payload.encode()).decode())

def snapshot(component, data):
    snap = {"data": data, "memo": {"id": token(20), "name": component, "path": "kontakt", "method": "GET", "children": [],
            "scripts": [], "assets": [], "errors": [], "locale": "de"}, "checksum": hashlib.sha256(rnd.randbytes(8)).hexdigest()}
    return json.dumps(snap, ensure_ascii=False, separators=(",", ":"))

def lw_body(csrf, component, data, updates, calls):
    return json.dumps({"_token": csrf, "components": [{"snapshot": snapshot(component, data), "updates": updates, "calls": calls}]},
                      ensure_ascii=False, separators=(",", ":"))

class Session:
    def __init__(self, host, ip):
        self.host, self.ip = host, ip
        self.csrf = token()
        self.cookie = f"XSRF-TOKEN={laravel_cookie()}; laravel_session={laravel_cookie()}"
        self.conn = None
    def req(self, method, path, body=None, ctype=None, extra=None):
        h = {"Host": self.host, "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15",
             "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", "Accept-Language": "de-DE,de;q=0.9",
             "Accept-Encoding": "gzip, deflate, br", "Cookie": self.cookie, "X-Forwarded-For": self.ip}
        if ctype: h["Content-Type"] = ctype
        if extra: h.update(extra)
        data = body.encode() if isinstance(body, str) else body
        for attempt in range(2):
            try:
                if self.conn is None:
                    self.conn = http.client.HTTPSConnection(ING, 443, context=ctx, timeout=30)
                    self.conn.sock = ctx.wrap_socket(__import__("socket").create_connection((ING, 443), timeout=30), server_hostname=self.host)
                self.conn.request(method, path, body=data, headers=h)
                r = self.conn.getresponse(); r.read()
                return r.status
            except Exception as e:
                self.conn = None
                if attempt: return "err:" + type(e).__name__

def lw_headers(s):
    return {"X-Livewire": "", "X-CSRF-TOKEN": s.csrf, "Accept": "application/json", "Referer": f"https://{s.host}/kontakt", "Origin": f"https://{s.host}"}

def cls_browse(s):
    out = []
    for p in ["/", "/produkte?page=2&sort=-created_at&filter%5Bstatus%5D=open", "/suche?q=" + urllib.parse.quote(rnd.choice(TEXTS)),
              "/kategorie/schuhe?farbe=gr%C3%BCn&groesse=42&preis_max=99.90", "/konto/bestellungen", "/storage/hello.html",
              "/kontakt?ref=" + urllib.parse.quote("https://www.example.de/a?b=c&d=e")]:
        out.append(s.req("GET", p))
    return out

def cls_login(s):
    pw = rnd.choice(["Sommer2026!", "p@ss'word\"--", "Grüne#Wiese&1", "<geheim>", "1' or '1'='1", "abc;DROP", "Passwort123"])
    body = urllib.parse.urlencode({"_token": s.csrf, "email": "kunde%d@example.de" % rnd.randint(1, 9999), "password": pw, "remember": "on"})
    return [s.req("GET", "/login"), s.req("POST", "/login", body, "application/x-www-form-urlencoded", {"Referer": f"https://{s.host}/login"}), s.req("GET", "/dashboard")]

def cls_lw_simple(s):
    out = []
    for _ in range(4):
        name, city = rnd.choice(NAMES), rnd.choice(CITIES)
        b = lw_body(s.csrf, "contact-form", {"name": name, "city": city, "email": "a.b@example.de", "message": rnd.choice(TEXTS), "accepted": True},
                    {"name": name, "message": rnd.choice(TEXTS)}, [{"path": "", "method": "save", "params": []}])
        out.append(s.req("POST", "/livewire/update", b, "application/json", lw_headers(s)))
    return out

def cls_lw_richtext(s):
    out = []
    for _ in range(4):
        html = rnd.choice(RICH)
        b = lw_body(s.csrf, "editor.post-form", {"title": rnd.choice(TEXTS)[:40], "body": html, "tags": ["news", "intern"]},
                    {"body": html}, [{"path": "", "method": "publish", "params": [{"notify": True}]}])
        out.append(s.req("POST", "/livewire/update", b, "application/json", lw_headers(s)))
    return out

def cls_lw_search(s):
    out = []
    for q in rnd.sample(TEXTS, 4):
        b = lw_body(s.csrf, "product-search", {"query": "", "page": 1, "filters": {"brand": [], "price": [0, 200]}},
                    {"query": q, "filters.brand": ["Müller & Söhne", "O'Neill"]}, [{"path": "", "method": "$refresh", "params": []}])
        out.append(s.req("POST", "/livewire/update", b, "application/json", lw_headers(s)))
    return out

def cls_lw_upload_urls(s):
    out = []
    for _ in range(3):
        b = lw_body(s.csrf, "profile-form", {"website": "https://www.example.de/ueber-uns?lang=de#team", "avatar": None},
                    {"website": "https://shop.example.de/p/123?ref=abc&utm_campaign=herbst-2026", "social.linkedin": "https://www.linkedin.com/in/max-mustermann-1234/"},
                    [{"path": "", "method": "_startUpload", "params": ["avatar", [{"name": "Foto Köln 2026.jpg", "size": 182934, "type": "image/jpeg"}], False]}])
        out.append(s.req("POST", "/livewire/update", b, "application/json", lw_headers(s)))
    return out

def cls_api(s):
    out = []
    for _ in range(4):
        doc = {"order": {"id": rnd.randint(1, 10**6), "customer": {"name": rnd.choice(NAMES), "address": {"street": "Hauptstraße 1", "city": rnd.choice(CITIES), "zip": "50667"}},
               "items": [{"sku": "SKU-%04d" % i, "qty": i, "price": 9.99 * i, "note": rnd.choice(TEXTS)} for i in range(1, 4)],
               "meta": {"source": "app", "tags": ["a", "b"], "nested": {"l1": {"l2": {"l3": {"l4": [1, 2, {"x": None}]}}}}},
               "attachment": {"filename": "rechnung.pdf", "mime": "application/pdf", "data": base64.b64encode(rnd.randbytes(3000)).decode()},
               "signature": base64.urlsafe_b64encode(rnd.randbytes(64)).decode().rstrip("=")}}
        out.append(s.req("POST", "/v1/orders", json.dumps(doc, ensure_ascii=False), "application/json",
                         {"Authorization": "Bearer eyJhbGciOiJIUzI1NiJ9." + base64.urlsafe_b64encode(json.dumps({"sub": "42", "scope": "orders:write"}).encode()).decode().rstrip("=") + "." + token(43),
                          "Accept": "application/json"}))
        out.append(s.req("GET", "/v1/orders?filter[created_at][gte]=2026-10-01T00:00:00Z&include=items,customer&page[size]=50", None, None, {"Accept": "application/json"}))
    out.append(s.req("PATCH", "/v1/orders/42", json.dumps({"status": "shipped", "tracking": "JJD0099" + str(rnd.randint(10**8, 10**9))}), "application/json"))
    out.append(s.req("DELETE", "/v1/carts/7"))
    return out

CLASSES = [("browse", "shop.example.de", cls_browse), ("login", "shop.example.de", cls_login), ("lw_simple", "portal.example.de", cls_lw_simple),
           ("lw_richtext", "academy.example.de", cls_lw_richtext), ("lw_search", "booking.example.de", cls_lw_search),
           ("lw_urls", "portal.example.de", cls_lw_upload_urls), ("api", "api.example.de", cls_api)]

def main():
    res = defaultdict(lambda: {"requests": 0, "sessions": 0, "status": Counter(), "sessions_with_403": 0})
    lock = threading.Lock()
    jobs = []
    if MODE == "cgnat":
        # MVP-17 CGNAT simulation: PER users behind ONE address each for a CGNAT range address and a residential one.
        for ci, ip in [(90, "100.64.12.34"), (91, "198.51.100.77")]:
            for n in range(PER):
                name, host, fn = rnd.choice([c for c in CLASSES if c[0] in ("browse", "login", "lw_simple", "lw_search")])
                jobs.append(("cgnat_" + ip, host, fn, ip))
    else:
        for ci, (name, host, fn) in enumerate(CLASSES, start=1):
            for n in range(PER):
                jobs.append((name, host, fn, "10.66.%d.%d" % (ci, n % 250 + 1)))
    rnd.shuffle(jobs)
    def worker(chunk):
        for name, host, fn, ip in chunk:
            st = fn(Session(host, ip))
            with lock:
                r = res[name]; r["sessions"] += 1; r["requests"] += len(st)
                for x in st: r["status"][str(x)] += 1
                if 403 in st or 429 in st: r["sessions_with_403"] += 1
    W = 16
    ts = [threading.Thread(target=worker, args=(jobs[i::W],)) for i in range(W)]
    t0 = time.time()
    [t.start() for t in ts]; [t.join() for t in ts]
    print(json.dumps({"mode": MODE, "elapsed_s": round(time.time() - t0, 1), "classes": res}, default=dict, ensure_ascii=False))

main()
