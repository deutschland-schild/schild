# Deutschland-Schild

**Schild Gateway ist eine kostenlose, quelloffene Firewall für deine Website.** Es läuft auf deinem eigenen Server vor deiner Anwendung, prüft jede Anfrage und zeigt dir in einem Dashboard, was los ist. Deine Daten bleiben auf deinem Server.

**Stand: Alpha (`0.1.0-alpha.1`).** Das Gateway mit Dashboard läuft für sich allein und ist im Live-Betrieb. Befehle, Konfiguration und Dashboard können sich noch ändern, Fehler sind möglich. Labs und Relays, aus denen später ein Netz werden soll, sind geplant und laufen bisher nur im Testlabor.

Website und Dokumentation: [deutschland-schild.de](https://deutschland-schild.de) · [Releases](https://github.com/deutschland-schild/schild/releases)

## Installieren

Es gibt zwei Einbauwege. Such dir den aus, der zu deinem Server passt:

- **Du nutzt nginx, Apache oder einen Load Balancer:** Schild läuft als Proxy auf `127.0.0.1:8080` hinter deinem Webserver. Deine Zertifikate bleiben bei deinem Webserver; erst wenn du `proxy_pass` / `ProxyPass` auf Port 8080 umstellst, fließt Traffic durch Schild.
- **Du nutzt Caddy:** Schild ist eine Caddy-Distribution (Caddy mit eingebautem WAF-Modul). Es lädt dein Caddyfile, hört auf den Ports 80 und 443 und startet mit einer Kopie von Caddys Zertifikaten.

Beide Wege gibt es für Docker, Docker Compose und als statisches Linux-Binary (amd64, arm64) mit systemd-Unit.

### Hinter nginx, Apache oder einem Load Balancer (Docker)

```bash
curl -fsSLO https://raw.githubusercontent.com/deutschland-schild/schild/v0.1.0-alpha.1/gateway/deploy/quickstart/schild.yaml
# In schild.yaml unter upstream.url die Adresse deiner Anwendung eintragen
# (auf dem Host: http://host.docker.internal:<port>, im Docker-Netz: http://app:3000).

docker run -d --name schild --restart unless-stopped \
  --read-only --cap-drop ALL --security-opt no-new-privileges:true \
  --add-host host.docker.internal:host-gateway \
  -p 127.0.0.1:8080:8080 -p 127.0.0.1:8788:8788 \
  -v "$PWD/schild.yaml:/etc/schild/schild.yaml:ro" \
  -v schild-data:/var/lib/schild \
  ghcr.io/deutschland-schild/schild:0.1.0-alpha.1
docker exec schild schild dashboard setup-code
```

Danach leitest du deinen Webserver auf `http://127.0.0.1:8080` weiter (nginx: `proxy_pass http://127.0.0.1:8080;` mit `Host`, `X-Forwarded-For` und `X-Forwarded-Proto`; Apache: `ProxyPreserveHost On` und `ProxyPass / http://127.0.0.1:8080/`). Mit der Vorlage [gateway/deploy/nginx-front.conf](gateway/deploy/nginx-front.conf) schickt nginx bei einem Absturz von Schild direkt an die Anwendung weiter.

### Als Caddy-Distribution (Docker)

Im Ordner deines Caddyfiles:

```bash
curl -fsSLo schild.yaml https://raw.githubusercontent.com/deutschland-schild/schild/v0.1.0-alpha.1/gateway/deploy/quickstart/caddy/schild.yaml

# 1. Caddyfile prüfen. Die Ausgabe nennt die Zeilen, die noch fehlen
#    (einmal das Snippet "(schild)", dazu "import schild" pro Website mit Backend).
docker run --rm \
  -v "$PWD/schild.yaml:/etc/schild/schild.yaml:ro" \
  -v "$PWD/Caddyfile:/etc/caddy/Caddyfile:ro" \
  ghcr.io/deutschland-schild/schild:0.1.0-alpha.1 ingress validate -adapt-only

# 2. Caddys Zertifikate in ein eigenes Volume kopieren (caddy_data: Caddys Volume unter /data),
#    dann alles zusammen prüfen: Caddyfile, Datenverzeichnis, Kopie, Dateirechte. Muss mit "result: PASS" enden.
docker run --rm -v caddy_data:/from:ro -v schild-data:/to caddy:2 sh -c \
  'mkdir -p /to/caddy && cp -a /from/caddy/. /to/caddy/ && chmod 700 /to/caddy && chown -R 65532:65532 /to'
docker run --rm --read-only --cap-drop ALL \
  -v "$PWD/schild.yaml:/etc/schild/schild.yaml:ro" \
  -v "$PWD/Caddyfile:/etc/caddy/Caddyfile:ro" \
  -v schild-data:/var/lib/schild \
  ghcr.io/deutschland-schild/schild:0.1.0-alpha.1 ingress validate

# 3. Caddy anhalten, Schild starten
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

Ab dem Start sperrt das Core Rule Set bekannte Angriffe. Die Limits für Login, Passwort vergessen und `xmlrpc.php` begrenzen sofort. Vier der fünf Szenarien sperren nach 14 Tagen Lernzeit. Die übrigen Limits, „Aggressives Abrufen“, die Erkennung von Wellen und der CrowdSec Hub zählen erst nur mit. Für einen vorsichtigen Start stellst du `rules.crs.state: detect` ein. Als Caddy-Distribution ist Schild ab dem Wechsel dein Webserver und trägt deinen ganzen Traffic: Läuft Schild nicht, sind deine Websites nicht erreichbar, bis du Caddy wieder startest.

Das Dashboard hört nur auf dem Server selbst (`http://127.0.0.1:8788`), von außen kommst du per SSH-Tunnel hinein. Die letzte Zeile zeigt den Einmal-Code für die erste Anmeldung.

Wieder raus: Hinter nginx/Apache zeigst du im Webserver wieder direkt auf die Anwendung und stoppst Schild (`docker rm -f schild`). Als Caddy-Distribution setzt du im Caddyfile im Snippet `(schild)` ein `#` vor `schild`, dann `docker rm -f schild && docker start caddy` (`docker ps` zeigt, ob Caddy läuft; Caddys eigene Zertifikate hat Schild nicht angefasst). Der Container `caddy` und das Volume `caddy_data` sind Beispielnamen.

Alle Wege (auch ohne Docker als statisches Binary mit systemd und mit Docker Compose) und die ersten Schritte stehen in [docs/gateway/00-installieren.md](docs/gateway/00-installieren.md), Updates, Backup, Monitoring und Rückbau in [docs/gateway/02-betrieb.md](docs/gateway/02-betrieb.md), alle Funktionen in [docs/gateway/01-funktionen.md](docs/gateway/01-funktionen.md).

## Was in diesem Repository liegt

Code, Dokumentation, Konzept, Marke und Website liegen hier zusammen und werden gemeinsam versioniert.

| Pfad | Inhalt |
| --- | --- |
| [`docs/gateway/`](docs/gateway/README.md) | Doku zum Schild Gateway: alle Funktionen und Betrieb (gerendert unter `/doku/gateway`) |
| [`docs/concept/`](docs/concept/README.md) | Konzept v1 – Grundsätze, Strategie, Spezifikation, Tests, Risiken (gerendert unter `/doku/konzept`) |
| [`docs/brand/`](docs/brand/README.md) | Marke, Sprache und Gestaltung in einem Dokument, Design Tokens (gerendert unter `/doku/marke`) |
| [`docs/stories/`](docs/stories/README.md) | Personas und User Stories (gerendert unter `/doku/personas`) |
| [`docs/AGENTS.md`](docs/AGENTS.md) | Regeln für Menschen und KI-Agenten, die hier arbeiten – inkl. Aufbau von `/doku` |
| [`site/`](site/) | Website (Nuxt, statisch generiert) – Landingpage und die Dokumentation unter `/doku` |
| [`gateway/`](gateway/README.md) | Schild Gateway: das Programm `schild` (Go) |
| [`lab/`](lab/README.md), [`relay/`](relay/README.md) | Schild Lab und Relay, geplant, bisher nur im Testlabor |
| [`dashboard/`](dashboard/README.md) | Dashboards von Gateway und Lab (Vue), werden ins Programm eingebaut |
| [`contracts/`](contracts/README.md), [`contract/`](contract/) | Verträge zwischen den Bausteinen: Schemas, Testvektoren, Entscheidungen; Go-Bibliothek dazu |
| [`tests/`](tests/README.md) | Systemtests: Testlabor, Angriffs-Suite, Specs, Messergebnisse. Unit-Tests liegen beim Code |
| [`DEVELOPMENT.md`](DEVELOPMENT.md) | Bauen und Testen, Aufbau, Regeln für Agenten |

Die Website rendert die Markdown-Dateien aus `docs/` unter `/doku`, ohne Kopien. Diskutiert wird per Issue oder Pull Request auf die jeweilige Datei.

## Entwickeln

Du brauchst Go (Version in `go.work`) und GNU make, für das Image Docker:

```bash
make gateway-test     # go vet und Tests des Gateways
make gateway-run      # lokal mit Testschlüsseln: Proxy 127.0.0.1:8080 vor einer App auf 127.0.0.1:8081
make gateway-image    # Image schild:dev mit Geo-Testdaten, ohne Download
```

Die Website startest du mit `cd site && npm install && npm run dev`. Alle Make-Ziele, das Testlabor und die Regeln für Agenten: [`DEVELOPMENT.md`](DEVELOPMENT.md). Technische Referenz des Gateways: [`gateway/README.md`](gateway/README.md).

## Lizenz

Code und Dokumentation in diesem Repository stehen unter der [MIT-Lizenz](LICENSE). Fremdbestandteile behalten ihre eigenen Lizenzen, etwa `skills/humanizer`, die Daten unter `contracts/vectors/crowdsec-hub`, die in [`gateway/NOTICE`](gateway/NOTICE) genannten Module und Daten des Gateways und [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) (CC BY-SA 4.0). Die Lizenz gibt keine Rechte an Namen und Logos von Deutschland-Schild.

Mitmachen: [`CONTRIBUTING.md`](CONTRIBUTING.md). Sicherheitslücken bitte nur vertraulich melden: [`SECURITY.md`](SECURITY.md).
