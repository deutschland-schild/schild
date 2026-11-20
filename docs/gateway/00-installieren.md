---
short: Installieren
description: "Schild Gateway installieren: als Caddy-Distribution oder hinter nginx, Apache oder einem Load Balancer, mit Docker, als Binary mit systemd oder mit Docker Compose. Dazu die ersten Schritte bis zum Dashboard und der Weg wieder heraus."
---

# Schild Gateway installieren

**Status:** Alpha · Stand 20.11.2026 · technische Quelle: [gateway/README.md](../../gateway/README.md)

**Kurz:**

- Schild ist eine Caddy-Distribution: Caddy mit eingebautem WAF-Modul. Nutzt du Caddy, wechselst du darauf: gleiches Caddyfile, gleiche Zertifikate, gleiche Ports. Das ist der Standardweg. Hinter nginx, Apache oder einem Load Balancer läuft Schild als Proxy auf Port 8080.
- Drei Wege für beide Fälle: Docker, Binary mit systemd, Docker Compose. Aktuell ist die Alpha `0.1.0-alpha.1`.
- Nach der Installation sperrt das Core Rule Set bekannte Angriffe. Die Limits für Login, Passwort vergessen und `xmlrpc.php` begrenzen sofort. Vier der fünf Szenarien sperren nach 14 Tagen Lernzeit. Die übrigen Limits und die Regeln aus dem CrowdSec Hub zählen erst nur mit. Als Caddy-Distribution trägt Schild sofort deinen ganzen Traffic.
- Das Dashboard hört nur auf dem Server selbst. Du erreichst es über einen SSH-Tunnel.
- Der Weg zurück dauert eine Minute. An deiner Anwendung und an Caddys Zertifikaten ändert Schild nichts.

## Voraussetzungen

- Linux auf amd64 oder arm64, mit Docker oder mit systemd. Schild ist ein statisches Binary und bringt alles mit, was es braucht.
- Entweder ein Caddy mit Caddyfile, von dem du auf Schild wechselst, oder eine Anwendung, die auf dem Server per HTTP erreichbar ist, zum Beispiel auf `http://127.0.0.1:3000`. Diese Adresse heißt bei Schild „Upstream“.
- Ein Verzeichnis für Daten (Standard `/var/lib/schild`). Wie viel Platz Schild höchstens braucht, rechnet `schild preflight` vor. Ist zu wenig da, startet Schild nicht.

## Schild bekommen

Quellcode und Releases liegen auf GitHub: [github.com/deutschland-schild/schild](https://github.com/deutschland-schild/schild). Jeder Release hat eine feste Versionsnummer, ein `latest` gibt es nicht. Du entscheidest, wann du aktualisierst.

| Weg | Für wen | Was du bekommst |
| --- | --- | --- |
| **Docker** | Server mit Docker, der Standardweg; auch für Kamal | das Image `ghcr.io/deutschland-schild/schild:0.1.0-alpha.1` für amd64 und arm64 und die Start-Konfiguration `schild.yaml` |
| **Binary mit systemd** | Server ohne Docker | ein Archiv mit dem Binary `schild`, den systemd-Units `schild.service` und `schild-firewall.service`, den Geodaten für die Länderanzeige (`geo/`), einer kurzen `README.txt` und den Lizenztexten (`LICENSE`, `NOTICE`, `THIRD_PARTY_LICENSES`) |
| **Docker Compose** | Entwicklungsrechner und Setups, die schon mit Compose laufen | zwei Dateien aus `gateway/deploy/quickstart/`: `compose.yaml` und `schild.yaml`. Die Fassung für den Wechsel von Caddy liegt in `gateway/deploy/quickstart/caddy/` |

Das Image ist mit cosign signiert und bringt eine Stückliste (SBOM) mit. Für die Archive hängen die Prüfsummen am Release (`checksums.txt`, SHA-256). Zu Image und Archiven gibt es einen signierten Herkunftsnachweis, den `gh attestation verify` prüft. Wie du Signatur und Nachweis prüfst, steht in den Hinweisen zum [Release](https://github.com/deutschland-schild/schild/releases).

Pakete für apt und dnf gibt es noch nicht, sie sind [geplant](01-funktionen.md#geplant-noch-nicht-gebaut).

## Installieren

Es gibt zwei Fälle. Such dir den aus, der zu deinem Server passt:

| | Du nutzt Caddy | Du nutzt nginx, Apache oder einen Load Balancer |
| --- | --- | --- |
| Was Schild wird | dein Webserver: Caddy mit WAF-Modul | ein Proxy hinter deinem Webserver |
| Ports | 80 und 443, wie dein Caddyfile sagt | 8080 |
| Zertifikate | Schild nutzt eine Kopie von Caddys Zertifikaten und erneuert sie selbst | macht weiter dein Webserver |
| Ab wann Schild Traffic sieht | ab dem Wechsel, den ganzen | sobald dein Webserver an Port 8080 weitergibt |
| Wenn Schild nicht läuft | Websites nicht erreichbar, bis Schild oder dein bisheriger Caddy wieder läuft | dein Webserver antwortet mit 502, mit unserer nginx-Vorlage schickt er direkt an die Anwendung |

In beiden Fällen sperrt Schild ab dem Start bekannte Angriffe über das Core Rule Set, und das Dashboard hört auf `127.0.0.1:8788`.

## Du nutzt Caddy: Schild als Caddy-Distribution

Caddy bleibt dein Webserver. Schild ist eine Caddy-Distribution, also Caddy mit eingebautem WAF-Modul. Es lädt dein Caddyfile, hört auf denselben Ports und stellt Zertifikate aus wie Caddy. Du trägst zwei Dinge in dein Caddyfile ein, kopierst Caddys Zertifikate und wechselst dann den Dienst. Vorher prüft `schild ingress validate`, während Caddy noch läuft: ob dein Caddyfile lädt und jede Website mit Backend die Zeile für Schild hat, ob Schild in sein Datenverzeichnis schreiben kann, ob es die Kopie der Zertifikate lesen und schreiben kann und ob es in die Logdateien schreiben darf, die dein Caddyfile nennt. Deine Anwendung und die Ports prüft der Befehl nicht.

In den Befehlen unten heißt dein Caddy-Container `caddy` und sein Volume `caddy_data`. Das sind Beispielnamen. `docker ps` und `docker volume ls` zeigen, wie beides bei dir heißt.

### Die Zeilen im Caddyfile

Einmal, oben in der Datei, das Snippet:

```
(schild) {
	schild
}
```

Und in jeder Website, die an ein Backend weiterreicht (`reverse_proxy`, `php_fastcgi`), die Zeile `import schild`:

```
example.org {
	import schild
	reverse_proxy 127.0.0.1:3000
}
```

Schild schreibt dein Caddyfile nie selbst um. `schild init` und `schild ingress validate` nennen dir jede Website, in der die Zeile noch fehlt, und Schild startet nicht, solange eine Website mit Backend ohne sie bleibt. Websites, die nur Dateien ausliefern oder umleiten, brauchen die Zeile nicht.

Dein laufender Caddy merkt von der Änderung nichts, solange du ihn nicht neu lädst oder neu startest. Lass das bis zum Wechsel, denn Caddy kennt die Zeile `schild` nicht und würde die Datei ablehnen. Trag die Zeilen deshalb erst ein, wenn du gleich danach wechselst.

### Mit Docker

Das ist der Standardweg. Geh in den Ordner, in dem dein Caddyfile liegt, und lade die Start-Konfiguration. Ändern musst du daran nichts:

```bash
curl -fsSLo schild.yaml https://raw.githubusercontent.com/deutschland-schild/schild/v0.1.0-alpha.1/gateway/deploy/quickstart/caddy/schild.yaml
```

Lass Schild dein Caddyfile prüfen. Mit `-adapt-only` sieht der Befehl nur das Caddyfile an. Die Ausgabe zählt deine Websites auf und nennt die Zeilen, die noch fehlen. Trag sie ein und wiederhole den Befehl, bis die Ausgabe `result: PASS (Caddyfile)` meldet:

```bash
docker run --rm \
  -v "$PWD/schild.yaml:/etc/schild/schild.yaml:ro" \
  -v "$PWD/Caddyfile:/etc/caddy/Caddyfile:ro" \
  ghcr.io/deutschland-schild/schild:0.1.0-alpha.1 ingress validate -adapt-only
```

Kopiere Caddys Zertifikate in ein eigenes Volume für Schild. `caddy_data` ist das Volume, das dein Caddy unter `/data` einbindet. Caddys Volume wird nur gelesen. Der zweite Befehl ist die ganze Prüfung, im selben Container, in dem Schild gleich läuft: Caddyfile, Datenverzeichnis, Kopie der Zertifikate und Dateirechte. Er muss mit `result: PASS` enden. Bei `result: REFUSE` nennt die Zeile darüber den Grund und den Befehl, der ihn behebt:

```bash
docker run --rm -v caddy_data:/from:ro -v schild-data:/to caddy:2 sh -c \
  'mkdir -p /to/caddy && cp -a /from/caddy/. /to/caddy/ && chmod 700 /to/caddy && chown -R 65532:65532 /to'
docker run --rm --read-only --cap-drop ALL \
  -v "$PWD/schild.yaml:/etc/schild/schild.yaml:ro" \
  -v "$PWD/Caddyfile:/etc/caddy/Caddyfile:ro" \
  -v schild-data:/var/lib/schild \
  ghcr.io/deutschland-schild/schild:0.1.0-alpha.1 ingress validate
```

Halte Caddy an und starte Schild auf denselben Ports:

```bash
docker stop caddy
docker run -d --name schild --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --add-host host.docker.internal:host-gateway \
  -p 80:80 -p 443:443 -p 127.0.0.1:8788:8788 \
  -v "$PWD/schild.yaml:/etc/schild/schild.yaml:ro" \
  -v "$PWD/Caddyfile:/etc/caddy/Caddyfile:ro" \
  -v schild-data:/var/lib/schild \
  ghcr.io/deutschland-schild/schild:0.1.0-alpha.1
docker exec schild schild dashboard setup-code
```

Die letzte Zeile zeigt den Einmal-Code für die erste Anmeldung im Dashboard. Er steht auch im Log, im Feld `setup_code`.

Worauf du achten solltest:

- Nennt dein Caddyfile andere Container beim Namen (`reverse_proxy app:3000`), muss Schild im selben Docker-Netz hängen wie vorher dein Caddy. Ergänze dafür `--network <name>`. Eine Anwendung direkt auf dem Server erreicht der Container unter `host.docker.internal`.
- Bindet dein Caddy weitere Ordner ein, etwa für statische Dateien, gib sie Schild genauso mit (`-v`).
- Der Container läuft ohne Root-Rechte (Benutzer 65532), mit schreibgeschütztem Dateisystem und ohne Sonderrechte. Die Ports 80 und 443 darf er trotzdem öffnen, weil Docker das in seinen eigenen Netzen jedem Benutzer erlaubt. Mit `--network host` gilt das nicht.
- Das `127.0.0.1` vor Port 8788 muss bleiben. Ohne es wäre das Dashboard aus dem Internet erreichbar.
- Port 443 ist nur für TCP veröffentlicht. Schild kündigt HTTP/3 in seinen Antworten weiter an (Header `alt-svc`), der UDP-Port dafür ist aber zu. Browser bleiben deshalb bei HTTP/2.

### Als Binary mit systemd

Für einen Caddy aus dem Paket deiner Distribution (apt, dnf), der als Dienst `caddy` läuft. Lade das Archiv und vergleiche die Prüfsumme:

```bash
VERSION=0.1.0-alpha.1
ARCH=amd64   # oder arm64
curl -fsSLO https://github.com/deutschland-schild/schild/releases/download/v$VERSION/schild_${VERSION}_linux_$ARCH.tar.gz
curl -fsSLO https://github.com/deutschland-schild/schild/releases/download/v$VERSION/checksums.txt
sha256sum -c --ignore-missing checksums.txt
```

Die letzte Zeile muss `OK` melden. Dann entpackst du das Archiv und legst Binary, Unit, Geodaten und Benutzer an:

```bash
tar -xzf schild_${VERSION}_linux_$ARCH.tar.gz
sudo install -m 0755 schild /usr/local/bin/schild
sudo install -m 0644 schild.service /etc/systemd/system/schild.service
sudo install -d /usr/share/schild/geo
sudo install -m 0644 geo/* /usr/share/schild/geo/
sudo useradd --system --home-dir /var/lib/schild --create-home --shell /usr/sbin/nologin schild
sudo systemctl daemon-reload
```

Die Geodaten braucht Schild für die Länderanzeige. Ohne sie läuft Schild auch, zeigt keine Länder und meldet im Dashboard, dass die Geodaten fehlen.

`schild init -caddyfile` liest dein Caddyfile, schreibt `/etc/schild/schild.yaml` und nennt dir die Zeilen, die im Caddyfile noch fehlen, und die Befehle für die nächsten Schritte. Trag die Zeilen ein:

```bash
sudo /usr/local/bin/schild init -caddyfile /etc/caddy/Caddyfile
sudo nano /etc/caddy/Caddyfile
```

Kopiere Caddys Zertifikate in Schilds Datenverzeichnis und starte die Prüfung als Benutzer `schild`. Caddy läuft dabei weiter. `schild init` nennt den Ordner, in dem es Caddys Zertifikate gefunden hat; beim Paket-Caddy ist es dieser:

```bash
sudo mkdir -p /var/lib/schild/caddy
sudo cp -a /var/lib/caddy/.local/share/caddy/. /var/lib/schild/caddy/
sudo chown -R schild:schild /var/lib/schild/caddy
sudo -u schild /usr/local/bin/schild ingress validate
```

Die Prüfung zählt deine Websites auf, sagt, wie viele Zertifikate Schild beim Start weiter nutzt, und endet mit `result: PASS`. Bei `result: REFUSE` wechselst du noch nicht. Die Zeile darüber nennt den Grund, die Folge und den Befehl, der ihn behebt, zum Beispiel das `chown` für die Kopie der Zertifikate: Kann Schild sie nicht lesen, startet es nicht oder deine Websites antworten nicht. Kann es sie nicht schreiben, startet es, kann die Zertifikate aber später nicht erneuern. Bei `PASS with warnings` lies die Zeilen mit `warning`, bevor du wechselst. Dann wechselst du und lässt dir den Einmal-Code anzeigen:

```bash
sudo systemctl disable --now caddy && sudo systemctl enable --now schild
sudo /usr/local/bin/schild dashboard setup-code
```

Zwischen den beiden Diensten liegt ein kurzer Moment, in dem niemand auf Port 443 antwortet.

Worauf du achten solltest:

- Der Dienst läuft als Benutzer `schild`, nicht als root. Die Ports 80 und 443 darf er über genau ein Sonderrecht öffnen (`CAP_NET_BIND_SERVICE`), schreiben darf er nur nach `/var/lib/schild`.
- Schreibt dein Caddyfile Logdateien, etwa nach `/var/log/caddy`, gehören die dem Benutzer `caddy`. Die Prüfung meldet das und nennt den Befehl: `sudo chown -R schild /var/log/caddy`. Für den Weg zurück gibst du den Ordner wieder `caddy`.
- Liegen die Logs woanders, etwa in `/var/log/my-sites`, reicht das `chown` nicht: Die Unit lässt Schild nur nach `/var/lib/schild` und `/var/log/caddy` schreiben. Die Prüfung fragt systemd nach der Unit und lehnt ab, bis der Ordner dort eingetragen ist. Dafür legst du mit `sudo systemctl edit schild` eine Ergänzung mit zwei Zeilen an, `[Service]` und `ReadWritePaths=/var/log/my-sites`. Die Prüfung nennt dir beide Zeilen mit deinem Ordner. Kann sie systemd als Benutzer `schild` nicht fragen, warnt sie statt abzulehnen und endet mit `PASS with warnings`. Dann zeigt `sudo /usr/local/bin/schild ingress validate`, ob der Eintrag da ist.
- **HTTP/3 (UDP 443):** Wie bei Caddy öffnet Schild Port 443 auch für UDP. HTTP/3 ignoriert derzeit aber das `read_body`-Timeout gegen langsame Request-Bodies (im Docker-Setup bleibt UDP 443 deshalb zu). Willst du HTTP/3 wie im Container abschalten, ergänze in den globalen Optionen deines Caddyfiles `servers { protocols h1 h2 }`.
- Spricht dein Caddyfile PHP-FPM über einen Unix-Socket an, muss der Benutzer `schild` ihn öffnen dürfen. Unter Debian und Ubuntu reicht meist `sudo usermod -aG www-data schild`.
- `schild init -caddyfile` kennt `-caddy-storage` für einen anderen Ordner mit Caddys Zertifikaten, `-node-name` für den Namen des Gateways im Dashboard und `-force`, um eine vorhandene Datei zu überschreiben.
- Findet `sudo` den Befehl `schild` nicht, fehlt `/usr/local/bin` in seinem Suchpfad. Dann schreibst du wie oben `/usr/local/bin/schild` aus.

### Mit Docker Compose

Für Setups, in denen dein Caddy als Container läuft. Die Compose-Datei beschreibt denselben Container wie der Weg mit Docker. Die Zertifikate kopiert sie selbst, und zwar erst im letzten Schritt, direkt vor dem Wechsel. Leg für Schild einen eigenen Ordner an:

```bash
mkdir schild && cd schild
curl -fsSLO https://raw.githubusercontent.com/deutschland-schild/schild/v0.1.0-alpha.1/gateway/deploy/quickstart/caddy/compose.yaml
curl -fsSLO https://raw.githubusercontent.com/deutschland-schild/schild/v0.1.0-alpha.1/gateway/deploy/quickstart/caddy/schild.yaml
```

Trag in einer Datei `.env` ein, wo dein Caddyfile liegt und wie das Volume heißt, das dein Caddy unter `/data` einbindet (`docker volume ls` zeigt es):

```bash
cat > .env <<'EOF'
CADDYFILE=/pfad/zu/deinem/Caddyfile
CADDY_DATA_VOLUME=caddy_data
EOF
```

Lass Schild dein Caddyfile prüfen, trag die fehlenden Zeilen ein und wiederhole den Befehl, bis die Ausgabe `result: PASS (Caddyfile)` meldet. Mit `--no-deps` und `-adapt-only` sieht der Befehl nur das Caddyfile an und kopiert noch nichts:

```bash
docker compose run --rm --no-deps schild ingress validate -adapt-only
```

Der nächste Befehl kopiert Caddys Zertifikate in Schilds Volume und prüft alles zusammen: Caddyfile, Kopie und Dateirechte. Endet er mit `result: PASS`, hältst du deinen Caddy-Container an und startest Schild:

```bash
docker compose run --rm schild ingress validate
docker stop caddy
docker compose up -d
docker compose exec schild schild dashboard setup-code
```

Die Kopie entsteht einmal, beim ersten dieser Befehle, und wird danach nicht mehr überschrieben. Lass deshalb zwischen Prüfung und Wechsel keine Tage vergehen: Ein Zertifikat, das Caddy in der Zwischenzeit erneuert, käme bei Schild nicht mehr an. Schild würde es dann selbst erneuern.

Nennt dein Caddyfile andere Container beim Namen, trägst du deren Netz in `compose.yaml` ein. Die Stelle ist dort vorbereitet und auskommentiert.

### Was sich mit dem Wechsel ändert

Ab dem Wechsel ist Schild dein Webserver. Es nimmt jede Anfrage an, mit deinem Caddyfile und deinen Zertifikaten, und reicht sie an deine Anwendung weiter. Das Core Rule Set sperrt bekannte Angriffe von Anfang an. Szenarien, Limits und die Regeln aus dem CrowdSec Hub schreiben erst nur mit, was sie gesperrt hätten. Abgelehnt werden außerdem Anfragen, die sich gar nicht prüfen lassen, etwa ein viel zu großer Body. Das sind die [harten Grenzen](01-funktionen.md#harte-grenzen).

Anders als hinter einem Webserver gibt es hier niemanden, der einspringt: Läuft Schild nicht, sind deine Websites nicht erreichbar, bis Schild oder Caddy wieder läuft. Halte den Weg zurück deshalb bereit.

Zertifikate, die bald ablaufen, erneuert jetzt Schild, in seinem eigenen Speicher. Caddys Speicher bleibt auf dem Stand vom Wechsel.

### Zurück zu Caddy

1. Setz im Caddyfile im Snippet `(schild)` ein `#` vor die Zeile `schild`. Caddy kennt sie nicht und startet sonst nicht. Die Zeilen `import schild` können bleiben, das Snippet ist dann leer.
2. Hast du für Schild einen Log-Ordner umgestellt, gib ihn wieder Caddy: `sudo chown -R caddy /var/log/caddy`.
3. Wechsle zurück zu deinem bisherigen Caddy: `sudo systemctl disable --now schild && sudo systemctl enable --now caddy`, `docker rm -f schild && docker start caddy` oder `docker compose down && docker start caddy`.
4. Sieh nach, ob Caddy läuft: `systemctl is-active caddy` oder `docker ps --filter name=caddy`. `docker start` meldet auch dann keinen Fehler, wenn Caddy sich gleich wieder beendet, weil das `#` fehlt. `docker logs caddy` zeigt in dem Fall den Grund.

Caddy startet mit seinen eigenen Zertifikaten, die Schild nie angefasst hat. Ist eines davon in der Zwischenzeit abgelaufen, holt Caddy sich beim Start ein neues.

## Du nutzt nginx, Apache oder einen Load Balancer: Schild dahinter

Schild läuft als Proxy auf Port 8080 und reicht an deine Anwendung weiter. Solange dein Webserver nicht auf Port 8080 zeigt, sieht Schild keine einzige Anfrage, und für deine Besucher:innen ändert sich nichts.

### Dahinter mit Docker

Lade die Start-Konfiguration:

```bash
curl -fsSLO https://raw.githubusercontent.com/deutschland-schild/schild/v0.1.0-alpha.1/gateway/deploy/quickstart/schild.yaml
```

Trag in `schild.yaml` unter `upstream.url` die Adresse deiner Anwendung ein. Läuft sie direkt auf dem Server, erreicht der Container sie unter `http://host.docker.internal:<port>`. Läuft sie in einem Container im selben Docker-Netz, nimmst du deren Namen, zum Beispiel `http://app:3000`.

```bash
docker run -d --name schild --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --add-host host.docker.internal:host-gateway \
  -p 127.0.0.1:8080:8080 -p 127.0.0.1:8788:8788 \
  -v "$PWD/schild.yaml:/etc/schild/schild.yaml:ro" \
  -v schild-data:/var/lib/schild \
  ghcr.io/deutschland-schild/schild:0.1.0-alpha.1
docker exec schild schild dashboard setup-code
```

Die letzte Zeile zeigt den Einmal-Code für die erste Anmeldung im Dashboard. Er steht auch im Log, im Feld `setup_code`. Der Container läuft ohne Root-Rechte, mit schreibgeschütztem Dateisystem und ohne Sonderrechte. Schreiben kann er nur in sein Daten-Volume.

Das `127.0.0.1` vor beiden Ports muss bleiben. Ohne es wäre das Dashboard aus dem Internet erreichbar, und an Port 8080 könnte jeder an deinem Webserver vorbei eine falsche Absenderadresse behaupten. Dein Webserver auf dem Server erreicht Schild unter `127.0.0.1:8080`.

### Dahinter als Binary mit systemd

Archiv laden, prüfen und entpacken wie [oben](#als-binary-mit-systemd). Dann schreibt `schild init` eine Start-Konfiguration: Schild vor einer Anwendung. Statt `3000` schreibst du den Port, auf dem deine Anwendung lauscht. Danach startest du den Dienst und lässt dir den Einmal-Code anzeigen:

```bash
sudo /usr/local/bin/schild init -upstream http://127.0.0.1:3000
sudo systemctl enable --now schild
sudo /usr/local/bin/schild dashboard setup-code
```

`schild init` kennt außerdem `-config` für einen anderen Ort der Datei, `-node-name` für den Namen des Gateways im Dashboard und `-force`, um eine vorhandene Datei zu überschreiben. `-upstream` und `-caddyfile` schließen sich aus. Der Dienst läuft als Benutzer `schild` und darf nur nach `/var/lib/schild` schreiben. Schild lauscht auf `127.0.0.1:8080`, nur dein Webserver auf demselben Server erreicht es.

### Dahinter mit Docker Compose

Es ist derselbe Container mit denselben Einstellungen, beschrieben in einer `compose.yaml`:

```bash
mkdir schild && cd schild
curl -fsSLO https://raw.githubusercontent.com/deutschland-schild/schild/v0.1.0-alpha.1/gateway/deploy/quickstart/compose.yaml
curl -fsSLO https://raw.githubusercontent.com/deutschland-schild/schild/v0.1.0-alpha.1/gateway/deploy/quickstart/schild.yaml
```

Trag wie beim Weg mit Docker in `schild.yaml` die Adresse deiner Anwendung ein, dann:

```bash
docker compose up -d
docker compose exec schild schild dashboard setup-code
```

### Traffic über Schild leiten

Lass deinen Webserver an Port 8080 weitergeben statt direkt an die Anwendung. Ab dann sieht Schild Anfragen und sperrt bekannte Angriffe. Alles andere reicht es an deine Anwendung durch.

Mit **nginx** ersetzt du in der Website das bisherige `proxy_pass`:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

Mit **Apache** (Module `proxy` und `proxy_http`):

```apache
ProxyPreserveHost On
ProxyPass        / http://127.0.0.1:8080/
ProxyPassReverse / http://127.0.0.1:8080/
```

Apache setzt `X-Forwarded-For` selbst. Danach `sudo nginx -t && sudo systemctl reload nginx` oder `sudo apachectl configtest && sudo systemctl reload apache2`.

Fällt Schild aus, antwortet dein Webserver mit diesen Zeilen mit 502. Soll nginx dann direkt an die Anwendung weiterreichen, nimm die Vorlage [nginx-front.conf](../../gateway/deploy/nginx-front.conf); sie erklärt auch, warum das nur bei einem Absturz geschieht und nie bei einer Zeitüberschreitung.

Läuft Schild in Docker, oder steht ein Load Balancer oder Cloudflare vor deinem Webserver, lies [Echte Adresse der Besucher:innen](02-betrieb.md#echte-adresse-der-besucherinnen). Sonst sieht Schild alle als eine Adresse.

Schild prüft nur, was über Schild kommt. Deine Anwendung darf deshalb von außen nicht direkt erreichbar sein, auch nicht über IPv6: Lass sie auf `127.0.0.1` lauschen, oder sperr ihren Port in der Firewall für IPv4 und IPv6. Das gilt genauso, wenn Schild als dein Caddy läuft. Der [Server-Check](01-funktionen.md#server-check) meldet, wenn die Firewall nur IPv4 filtert.

## Erste Schritte

1. **Dashboard öffnen.** Es hört nur auf dem Server selbst. Von deinem Rechner baust du einen SSH-Tunnel auf: `ssh -N -L 8788:127.0.0.1:8788 du@dein-server`. Dann öffnest du `http://127.0.0.1:8788` im Browser.
2. **Passwort setzen.** Beim ersten Aufruf fragt das Dashboard nach dem Einmal-Code. Ein Standardpasswort gibt es nicht. Solange noch kein Passwort gesetzt ist, zeigt `schild dashboard setup-code` den Code noch einmal an (mit systemd mit `sudo`, mit Docker über `docker exec schild …` oder `docker compose exec schild …`). Er steht auch im Log im Feld `setup_code`. Hast du später das Passwort vergessen, setzt `schild dashboard reset-password` den Zugang zurück und gibt einen neuen Code aus.
3. **Eigene Adresse freischalten:** in einer SSH-Sitzung auf dem Server mit `sudo schild allow "${SSH_CONNECTION%% *}"`. Die Variable enthält die Adresse, von der deine SSH-Verbindung kommt. Bist du direkt als root angemeldet, reicht `schild allow --mine`. Hinter `sudo` findet `--mine` die Adresse nicht, weil `sudo` die Variable nicht weitergibt. Mit Docker: `docker exec schild schild allow <deine-adresse>`, denn im Container kennt Schild deine SSH-Verbindung nicht.
4. **Nachsehen, ob Traffic ankommt.** Als Caddy-Distribution zeigt das Dashboard sofort Anfragen. Hinter nginx, Apache oder einem Load Balancer erst, wenn dein Webserver [an Port 8080 weitergibt](#traffic-über-schild-leiten).
5. **Hinschauen.** Unter „Ereignisse“ siehst du, was gestoppt und was nur erkannt wurde, unter „Sperren“, welche Adressen gerade gesperrt sind. Fehlalarme löst du mit einer [Ausnahme](01-funktionen.md#ausnahmen). Bei einer empfindlichen Anwendung stellst du das Core Rule Set vorher für ein paar Tage auf „erkennen“, unter „Regeln“ oder mit `rules.crs.state: detect`.
6. **Mehr sperren.** Den CrowdSec Hub und die Limits, die ab Werk nur mitzählen, stellst du einzeln um, siehe [Was sperrt](02-betrieb.md#was-sperrt). Die Szenarien stehen ab Werk auf der Empfehlung: Vier sperren, „Aggressives Abrufen“ beobachtet. Sie sperren erst nach 14 Tagen Lernzeit ab dem ersten Start.

### Was Schild mit deinem Traffic macht

Schild reicht jede Anfrage an deine Anwendung durch, die keine Regel auf „sperren“ trifft. Was nur erkennt, zählt mit, was es gesperrt hätte. Ab Werk sind das die Limits für Suche, Kontaktformulare und schreibende API-Aufrufe, die Regeln aus dem CrowdSec Hub und das Szenario „Aggressives Abrufen“. Abgelehnt werden außerdem Anfragen, die sich gar nicht prüfen lassen, etwa ein viel zu großer Body. Das sind die [harten Grenzen](01-funktionen.md#harte-grenzen).

Auch „erkennen“ heißt nicht, dass Schild neben deinem Traffic steht. Jede Anfrage läuft durch Schild. Nutzt du es als Caddy-Distribution, hängt die Erreichbarkeit deiner Websites an Schild.

## Wieder raus

- **Schild als Caddy-Distribution:** ein `#` ins Caddyfile, dann zurück zu deinem bisherigen Caddy wechseln. Die Schritte stehen unter [Zurück zu Caddy](#zurück-zu-caddy).
- **Schild hinter deinem Webserver:** Zeig mit deinem Webserver wieder direkt auf deine Anwendung und stoppe Schild: `docker rm -f schild`, `sudo systemctl disable --now schild` oder `docker compose down`.

Mehr unter [In einer Minute wieder raus](02-betrieb.md#in-einer-minute-wieder-raus).

## Wie es weitergeht

- [Betrieb](02-betrieb.md): die zwei Arten des Einbaus, was sperrt, Regeln, aktualisieren, Daten und Befehle.
- [Funktionen](01-funktionen.md): was das Gateway prüft und wie es selbst abgesichert ist.
