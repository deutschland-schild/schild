# Deutschland-Schild

**Schild Gateway ist eine kostenlose, quelloffene Firewall für deine Website.** Es läuft auf deinem eigenen Server vor deiner Anwendung, prüft jede Anfrage und zeigt dir in einem Dashboard, was los ist. Deine Daten bleiben auf deinem Server.

**Stand: Alpha.** Das Gateway mit Dashboard läuft für sich allein und ist im Live-Betrieb. Befehle, Konfiguration und Dashboard können sich noch ändern, Fehler sind möglich. Labs und Relays, aus denen später ein Netz werden soll, sind geplant und laufen bisher nur im Testlabor.

Website und Dokumentation: [deutschland-schild.de](https://deutschland-schild.de) · [Releases](https://github.com/deutschland-schild/schild/releases)

## Installieren

Der kürzeste Weg: Schild als Container hinter deinem Webserver (nginx, Apache oder ein Load Balancer), mit Docker Compose.

```bash
mkdir schild && cd schild
curl -fsSLO https://raw.githubusercontent.com/deutschland-schild/schild/main/gateway/deploy/quickstart/compose.yaml
curl -fsSLO https://raw.githubusercontent.com/deutschland-schild/schild/main/gateway/deploy/quickstart/schild.yaml
# In schild.yaml unter upstream.url die Adresse deiner Anwendung eintragen, dann:
docker compose up -d
docker compose exec schild schild dashboard setup-code
```

Die letzte Zeile zeigt den Einmal-Code für die erste Anmeldung. Das Dashboard hört nur auf dem Server selbst (`http://127.0.0.1:8788`), von außen kommst du per SSH-Tunnel hinein.

Schild läuft jetzt auf `127.0.0.1:8080`. Traffic fließt erst hindurch, wenn du deinen Webserver dorthin weiterleitest. Deine Zertifikate bleiben beim Webserver. Wieder raus: Den Webserver wieder direkt auf die Anwendung zeigen lassen, dann `docker compose down`.

Ab dem Start sperrt das Core Rule Set bekannte Angriffe, und die Limits für Login, Passwort vergessen und `xmlrpc.php` begrenzen. Vier der fünf Szenarien sperren nach 14 Tagen Lernzeit. Alles Weitere zählt erst nur mit, bis du es im Dashboard umstellst.

Die anderen Wege stehen in der [Installationsanleitung](docs/gateway/00-installieren.md):

- **Du nutzt Caddy:** Schild ist eine Caddy-Distribution, lädt dein Caddyfile und ersetzt Caddy als Webserver.
- **Ohne Docker:** ein statisches Linux-Binary (amd64, arm64) mit systemd-Unit.
- **Den Webserver weiterleiten:** die Zeilen für nginx und Apache.

Updates, Backup, Monitoring und Rückbau: [Betrieb](docs/gateway/02-betrieb.md). Alle Funktionen: [Funktionen](docs/gateway/01-funktionen.md).

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
